//! Adaptive DoS-cookie machinery: rotating secrets, per-HELLO
//! cookie generation and validation, the client-side CHALLENGE
//! handler, and the background rotation task.
//!
//! `cookie_required_sync` is the fast-path gate that
//! `handle_hello` consults before doing any peer allocation or
//! X25519 work — see the comment on that method for the exact
//! trigger semantics.

use super::Inner;
use crate::crypto::PeerId;
use crate::error::{CodecError, PeerError, Result};
use crate::header::Header;
use crate::identity::{NONCE_LEN, STATIC_KEY_LEN};
use crate::session::HandshakeState;
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;

// DoS-cookie wire sizes now live in `drift_proto::wire` (phase 4
// slice 1). Cookie blob = timestamp(u64 BE, 8) + MAC(16) = 24, also
// the CHALLENGE packet body. Re-exported so existing `super::*` /
// `cookies::*` references keep working.
pub(crate) use drift_proto::wire::{COOKIE_BLOB_LEN, HELLO_WITH_COOKIE_LEN};

/// Rotating server-side secret used to MAC stateless DoS cookies.
/// Keeps the previous secret around for one rotation window so
/// that cookies issued just before a rotation still validate
/// after it.
pub(crate) struct CookieSecrets {
    pub(crate) current: [u8; 32],
    pub(crate) previous: Option<[u8; 32]>,
    pub(crate) rotated_at: Instant,
}

impl CookieSecrets {
    pub(crate) fn new() -> Self {
        let mut current = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut current);
        Self {
            current,
            previous: None,
            rotated_at: Instant::now(),
        }
    }

    pub(crate) fn rotate(&mut self) {
        let mut fresh = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut fresh);
        self.previous = Some(self.current);
        self.current = fresh;
        self.rotated_at = Instant::now();
    }
}

// `cookie_input`, `addr_bytes`, and `ct_eq` now live in
// `drift_proto::wire` — the single source of truth for the cookie
// MAC input, shared with the sans-IO engine (phase 4 slice 1).
// Re-exported so existing `cookies::ct_eq` references (path.rs,
// rtt.rs) keep working; byte-identity was proven before the swap.
pub(crate) use drift_proto::wire::ct_eq;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Inner {
    /// Return true if the server is currently in cookie-required
    /// mode: either `cookie_always` is set, or the in-flight
    /// handshake gauge (peers parked in `AwaitingData`) has met
    /// or exceeded `cookie_threshold`. O(1) — reads a single
    /// atomic; no peer-table lock.
    pub(crate) fn cookie_required_sync(&self) -> bool {
        if self.config.cookie_always {
            return true;
        }
        if self.config.cookie_threshold == u32::MAX {
            return false;
        }
        let inflight = self.metrics.handshakes_inflight.load(Ordering::Relaxed);
        inflight >= self.config.cookie_threshold as usize
    }

    /// Emit a CHALLENGE packet to a client whose HELLO arrived
    /// without a valid cookie. Allocates no state — just MACs
    /// `(src, client_static, client_ephemeral, client_nonce,
    /// timestamp)` with the current rotating secret and ships it.
    pub(crate) async fn send_challenge(
        &self,
        iface_idx: usize,
        client_peer_id: PeerId,
        src: SocketAddr,
        client_static_pub: &[u8; STATIC_KEY_LEN],
        client_ephemeral_pub: &[u8; STATIC_KEY_LEN],
        client_nonce: &[u8; NONCE_LEN],
    ) -> Result<()> {
        let timestamp = now_unix_secs();
        let current = self.cookies.lock().await.current;
        let mac = drift_proto::wire::cookie_mac_for(
            &current,
            &src,
            client_static_pub,
            client_ephemeral_pub,
            client_nonce,
            timestamp,
        );
        let wire = drift_proto::wire::build_challenge_wire(
            self.local_peer_id,
            client_peer_id,
            timestamp,
            &mac,
        );

        self.ifaces.send_for(iface_idx, &wire, src).await?;
        self.metrics
            .challenges_issued
            .fetch_add(1, Ordering::Relaxed);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(wire.len() as u64, Ordering::Relaxed);
        debug!(dst = ?client_peer_id, "sent CHALLENGE");
        Ok(())
    }

    /// Verify a cookie tail from an incoming HELLO. Accepts a MAC
    /// computed with either the current or the previous rotation
    /// secret (so cookies remain valid across a rotation
    /// boundary), and requires the timestamp to be within
    /// `cookie_max_age_secs` of wall-clock now.
    pub(crate) async fn validate_cookie(
        &self,
        src: &SocketAddr,
        client_static_pub: &[u8; STATIC_KEY_LEN],
        client_ephemeral_pub: &[u8; STATIC_KEY_LEN],
        client_nonce: &[u8; NONCE_LEN],
        tail: &[u8],
    ) -> bool {
        if tail.len() != COOKIE_BLOB_LEN {
            return false;
        }
        let (current, previous) = {
            let cookies = self.cookies.lock().await;
            (cookies.current, cookies.previous)
        };
        drift_proto::wire::validate_cookie(
            &current,
            previous.as_ref(),
            src,
            client_static_pub,
            client_ephemeral_pub,
            client_nonce,
            tail,
            self.config.cookie_max_age_secs,
            now_unix_secs(),
        )
    }

    /// Client-side: we issued a HELLO and the server came back
    /// with a CHALLENGE asking us to prove reachability. Stash
    /// the cookie blob in the AwaitingAck state and immediately
    /// retransmit HELLO with the cookie appended — same
    /// client_nonce and ephemeral key, so the server recognizes
    /// this as a retry of the same handshake.
    pub(crate) async fn handle_challenge(&self, header: &Header, body: &[u8]) -> Result<()> {
        if body.len() < COOKIE_BLOB_LEN {
            return Err(CodecError::PacketTooShort {
                got: body.len(),
                need: COOKIE_BLOB_LEN,
            }
            .into());
        }
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let server_peer_id = header.src_id;
        let mut blob = [0u8; COOKIE_BLOB_LEN];
        blob.copy_from_slice(&body[..COOKIE_BLOB_LEN]);

        let mesh_next_hop = self.routes.lock().unwrap().lookup(&server_peer_id);

        let retry = {
            let mut peers = self.peers.lock_for(&server_peer_id).await;
            let Some(peer) = peers.get_mut(&server_peer_id) else {
                debug!("CHALLENGE for unknown peer, ignoring");
                return Ok(());
            };
            match &mut peer.handshake {
                HandshakeState::AwaitingAck {
                    client_nonce,
                    ephemeral,
                    last_sent,
                    cookie,
                    pq,
                    ..
                } => {
                    *cookie = Some(blob);
                    *last_sent = Instant::now();
                    let pq_ek = pq.as_ref().map(|(ek, _)| ek.as_slice());
                    let wire = super::build_hello_wire(
                        self.local_peer_id,
                        peer.id,
                        &self.identity,
                        ephemeral.public_bytes(),
                        *client_nonce,
                        mesh_next_hop.is_some(),
                        Some(&blob),
                        pq_ek,
                    );
                    let target = mesh_next_hop.unwrap_or(peer.addr);
                    Some((wire, target))
                }
                _ => {
                    debug!("CHALLENGE received outside AwaitingAck, ignoring");
                    None
                }
            }
        };

        if let Some((wire, target)) = retry {
            let iface = self.iface_for(&server_peer_id).await;
            self.ifaces.send_for(iface, &wire, target).await?;
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_sent
                .fetch_add(wire.len() as u64, Ordering::Relaxed);
            debug!("retransmitted HELLO with cookie to {:?}", target);
        }
        Ok(())
    }

    /// Periodically roll the server-side cookie secret. The
    /// previous secret is kept alive for one rotation window so
    /// in-flight cookies still validate across the boundary.
    pub(crate) async fn run_cookie_rotate_loop(self: std::sync::Arc<Self>) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            self.config.cookie_rotate_secs.max(1),
        ));
        ticker.tick().await; // skip first immediate tick
        loop {
            ticker.tick().await;
            let mut cookies = self.cookies.lock().await;
            cookies.rotate();
            debug!("rotated DoS cookie secret");
        }
    }
}
