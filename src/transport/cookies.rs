//! Adaptive DoS-cookie machinery: rotating secrets, per-HELLO
//! cookie generation and validation, the client-side CHALLENGE
//! handler, and the background rotation task.
//!
//! `cookie_required_sync` is the fast-path gate that
//! `handle_hello` consults before doing any peer allocation or
//! X25519 work — see the comment on that method for the exact
//! trigger semantics.

use super::{Inner, HELLO_PAYLOAD_LEN};
use crate::crypto::{cookie_mac, PeerId, COOKIE_MAC_LEN};
use crate::error::{DriftError, Result};
use crate::header::{Header, PacketType, HEADER_LEN};
use crate::identity::{NONCE_LEN, STATIC_KEY_LEN};
use crate::session::HandshakeState;
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;

// DoS-cookie wire sizes. Cookie blob appended to an extended HELLO
// is timestamp(u64 BE, 8 bytes) + MAC(16 bytes) = 24 bytes total.
// The CHALLENGE packet body carries the same blob.
pub(crate) const COOKIE_TS_LEN: usize = 8;
pub(crate) const COOKIE_BLOB_LEN: usize = COOKIE_TS_LEN + COOKIE_MAC_LEN; // 24
pub(crate) const HELLO_WITH_COOKIE_LEN: usize = HELLO_PAYLOAD_LEN + COOKIE_BLOB_LEN;

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

/// Serialize a SocketAddr to canonical bytes for use inside a
/// cookie MAC input. v4: [0x04][4 addr bytes][2 port bytes].
/// v6: [0x06][16 addr bytes][2 port bytes].
fn addr_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut out = Vec::with_capacity(1 + 4 + 2);
            out.push(0x04);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
            out
        }
        SocketAddr::V6(v6) => {
            let mut out = Vec::with_capacity(1 + 16 + 2);
            out.push(0x06);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
            out
        }
    }
}

/// Constant-time equality for byte slices of the same length.
/// Used to compare cookie MACs so an attacker can't use timing to
/// probe for valid prefixes.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build the MAC input for a DoS cookie. Binds together:
///   - client source address
///   - client long-term pubkey
///   - client ephemeral pubkey
///   - `client_nonce` (critical: without this, an attacker can
///     reuse one valid cookie to force unlimited X25519 work by
///     replaying HELLOs with fresh nonces)
///   - server-side issue timestamp
fn cookie_input(
    src: &SocketAddr,
    client_static_pub: &[u8; STATIC_KEY_LEN],
    client_ephemeral_pub: &[u8; STATIC_KEY_LEN],
    client_nonce: &[u8; NONCE_LEN],
    timestamp: u64,
) -> Vec<u8> {
    let a = addr_bytes(src);
    let mut out = Vec::with_capacity(a.len() + 64 + NONCE_LEN + COOKIE_TS_LEN);
    out.extend_from_slice(&a);
    out.extend_from_slice(client_static_pub);
    out.extend_from_slice(client_ephemeral_pub);
    out.extend_from_slice(client_nonce);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out
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
        let inflight = self
            .metrics
            .handshakes_inflight
            .load(Ordering::Relaxed);
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
        let mac = {
            let cookies = self.cookies.lock().await;
            let input = cookie_input(
                &src,
                client_static_pub,
                client_ephemeral_pub,
                client_nonce,
                timestamp,
            );
            cookie_mac(&cookies.current, &input)
        };

        let mut header =
            Header::new(PacketType::Challenge, 0, self.local_peer_id, client_peer_id);
        header.payload_len = COOKIE_BLOB_LEN as u16;
        let mut hbuf = [0u8; HEADER_LEN];
        header.encode(&mut hbuf);

        let mut wire = Vec::with_capacity(HEADER_LEN + COOKIE_BLOB_LEN);
        wire.extend_from_slice(&hbuf);
        wire.extend_from_slice(&timestamp.to_be_bytes());
        wire.extend_from_slice(&mac);

        self.ifaces.send_for(iface_idx, &wire, src).await?;
        self.metrics.challenges_issued.fetch_add(1, Ordering::Relaxed);
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
        let mut ts_buf = [0u8; COOKIE_TS_LEN];
        ts_buf.copy_from_slice(&tail[..COOKIE_TS_LEN]);
        let timestamp = u64::from_be_bytes(ts_buf);
        let now = now_unix_secs();
        if now.saturating_sub(timestamp) > self.config.cookie_max_age_secs {
            return false;
        }
        let presented = &tail[COOKIE_TS_LEN..];
        let input = cookie_input(
            src,
            client_static_pub,
            client_ephemeral_pub,
            client_nonce,
            timestamp,
        );
        let cookies = self.cookies.lock().await;
        let expected_current = cookie_mac(&cookies.current, &input);
        if ct_eq(presented, &expected_current) {
            return true;
        }
        if let Some(prev) = cookies.previous {
            let expected_prev = cookie_mac(&prev, &input);
            if ct_eq(presented, &expected_prev) {
                return true;
            }
        }
        false
    }

    /// Client-side: we issued a HELLO and the server came back
    /// with a CHALLENGE asking us to prove reachability. Stash
    /// the cookie blob in the AwaitingAck state and immediately
    /// retransmit HELLO with the cookie appended — same
    /// client_nonce and ephemeral key, so the server recognizes
    /// this as a retry of the same handshake.
    pub(crate) async fn handle_challenge(
        &self,
        header: &Header,
        body: &[u8],
    ) -> Result<()> {
        if body.len() < COOKIE_BLOB_LEN {
            return Err(DriftError::PacketTooShort {
                got: body.len(),
                need: COOKIE_BLOB_LEN,
            });
        }
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let server_peer_id = header.src_id;
        let mut blob = [0u8; COOKIE_BLOB_LEN];
        blob.copy_from_slice(&body[..COOKIE_BLOB_LEN]);

        let mesh_next_hop = self.routes.lock().await.lookup(&server_peer_id);

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
                    ..
                } => {
                    *cookie = Some(blob);
                    *last_sent = Instant::now();
                    let wire = super::build_hello_wire(
                        self.local_peer_id,
                        peer.id,
                        &self.identity,
                        ephemeral.public_bytes(),
                        *client_nonce,
                        mesh_next_hop.is_some(),
                        Some(&blob),
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
