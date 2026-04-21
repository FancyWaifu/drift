//! Per-neighbor RTT measurement for RTT-weighted mesh routing.
//!
//! DRIFT's mesh routing layer (`src/transport/mesh.rs`) used
//! to pick next-hops by hop count alone. On a heterogeneous
//! network — satellite, cellular, mixed WAN — hop count is a
//! terrible proxy for actual path cost. This module adds a
//! lightweight RTT estimator per direct neighbor and feeds it
//! into the routing table so `update_if_better` can pick by
//! measured latency.
//!
//! # Sources of RTT samples
//!
//! * **Handshake**: when HELLO_ACK arrives, the delta from
//!   when we sent HELLO is a clean one-shot sample.
//! * **Path probe**: PathChallenge → PathResponse round trips
//!   already happen during migration — free sample on the
//!   way.
//! * **Rekey**: RekeyRequest → RekeyAck same deal.
//! * **Periodic Ping/Pong**: once the session is established,
//!   a background task emits a small `Ping` to every direct
//!   neighbor on a timer (default 5 s). The receiver echoes
//!   with a `Pong`; the sender times the round trip. This
//!   keeps the RTT estimate fresh even on long-idle
//!   sessions.
//!
//! All sources feed through a single smoother (RFC 6298-style
//! SRTT/RTTVAR like the stream-layer congestion controller) so
//! a spike from a single sample doesn't whiplash routing
//! decisions.
//!
//! # Cost
//!
//! One Ping + one Pong per neighbor per 5s. At 32 bytes of
//! DATA + AEAD + header (~ 60 bytes wire) that's 24 bytes/s
//! each way — negligible compared to app traffic. Disabled by
//! default; opt in via `TransportConfig::rtt_probe_interval_ms`.

use super::Inner;
use crate::crypto::PeerId;
use crate::error::{DriftError, Result};
use crate::header::{canonical_aad, Header, PacketType, AUTH_TAG_LEN, HEADER_LEN};
use crate::session::HandshakeState;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Wire-format length of the Ping / Pong body nonce. 8 bytes
/// is enough to make replay-matching unambiguous without
/// bloating the packet.
pub(crate) const PING_NONCE_LEN: usize = 8;

impl Inner {
    /// Emit a Ping to every direct neighbor whose session is
    /// currently `Established`. Called on a fixed interval by
    /// `run_rtt_probe_loop` when the feature is enabled.
    pub(crate) async fn emit_pings(&self) -> Result<()> {
        // Snapshot the peer list under one short lock, then
        // do the actual sends outside any lock so a slow
        // socket can't back up the peer table.
        let targets: Vec<(PeerId, SocketAddr, u32, [u8; PING_NONCE_LEN])> = {
            let mut peers = self.peers.lock_all().await;
            peers
                .iter_mut()
                .filter_map(|p| {
                    if !matches!(p.handshake, HandshakeState::Established { .. }) {
                        return None;
                    }
                    let seq = p.next_seq_checked()?;
                    let mut nonce = [0u8; PING_NONCE_LEN];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
                    // Remember when we sent it so the
                    // matching Pong can be timed.
                    p.pending_ping = Some((nonce, Instant::now()));
                    Some((p.id, p.addr, seq, nonce))
                })
                .collect()
        };

        for (dst_id, addr, seq, nonce) in targets {
            let wire = {
                let mut peers = self.peers.lock_for(&dst_id).await;
                let Some(peer) = peers.get_mut(&dst_id) else {
                    continue;
                };
                let mut header = peer.make_header(PacketType::Ping, seq, self.local_peer_id);
                header.payload_len = (PING_NONCE_LEN + AUTH_TAG_LEN) as u16;
                let mut hbuf = [0u8; HEADER_LEN];
                header.encode(&mut hbuf);
                let aad = canonical_aad(&hbuf);
                let (tx, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
                let mut wire = Vec::with_capacity(HEADER_LEN + PING_NONCE_LEN + AUTH_TAG_LEN);
                wire.extend_from_slice(&hbuf);
                tx.seal_into(seq, PacketType::Ping as u8, &aad, &nonce, &mut wire)?;
                wire
            };
            self.ifaces
                .send_for(self.iface_for(&dst_id).await, &wire, addr)
                .await?;
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_sent
                .fetch_add(wire.len() as u64, Ordering::Relaxed);
            self.metrics.pings_sent.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Background task: every `rtt_probe_interval_ms` fire a
    /// round of Pings at every direct neighbor. Only spawned
    /// when the feature is enabled in config.
    pub(crate) async fn run_rtt_probe_loop(self: Arc<Self>) {
        let interval_ms = self.config.rtt_probe_interval_ms;
        if interval_ms == 0 {
            return;
        }
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
        // Skip the first tick so we don't ping before any
        // handshake has completed.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(e) = self.emit_pings().await {
                debug!(error = %e, "ping emission failed");
            }
        }
    }

    /// Received a Ping from a peer: decrypt the nonce, echo
    /// it back in a Pong sealed under our tx. No state
    /// changes on the receive side — the sender is the one
    /// measuring RTT.
    pub(crate) async fn handle_ping(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
        src: SocketAddr,
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let peer_id = header.src_id;

        let pong_wire = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;
            let (_, rx) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;

            // Decrypt the Ping body to retrieve the nonce.
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            let nonce_vec = rx.open(header.seq, PacketType::Ping as u8, &aad, body)?;
            if nonce_vec.len() != PING_NONCE_LEN {
                return Err(DriftError::PacketTooShort {
                    got: nonce_vec.len(),
                    need: PING_NONCE_LEN,
                });
            }
            let mut nonce = [0u8; PING_NONCE_LEN];
            nonce.copy_from_slice(&nonce_vec);

            // Build the Pong reply, sealing the same nonce.
            let seq = peer
                .next_seq_checked()
                .ok_or(DriftError::SessionExhausted)?;
            let mut pong_header = peer.make_header(PacketType::Pong, seq, self.local_peer_id);
            pong_header.payload_len = (PING_NONCE_LEN + AUTH_TAG_LEN) as u16;
            let mut pong_hbuf = [0u8; HEADER_LEN];
            pong_header.encode(&mut pong_hbuf);
            let pong_aad = canonical_aad(&pong_hbuf);
            let (tx, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
            let mut wire = Vec::with_capacity(HEADER_LEN + PING_NONCE_LEN + AUTH_TAG_LEN);
            wire.extend_from_slice(&pong_hbuf);
            tx.seal_into(seq, PacketType::Pong as u8, &pong_aad, &nonce, &mut wire)?;
            wire
        };

        self.ifaces
            .send_for(self.iface_for(&peer_id).await, &pong_wire, src)
            .await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(pong_wire.len() as u64, Ordering::Relaxed);
        self.metrics.pongs_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Received a Pong from a peer: verify the echoed nonce
    /// matches our outstanding ping, compute the RTT, and
    /// feed it into the peer's RTT estimator. A Pong without
    /// a matching ping (or with a mismatched nonce) is
    /// silently dropped — probably a stale one from before
    /// the last probe.
    pub(crate) async fn handle_pong(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let peer_id = header.src_id;

        let mut peers = self.peers.lock_for(&peer_id).await;
        let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;
        let (_, rx) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;

        let mut hbuf = [0u8; HEADER_LEN];
        hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
        let aad = canonical_aad(&hbuf);
        let echoed = rx.open(header.seq, PacketType::Pong as u8, &aad, body)?;
        if echoed.len() != PING_NONCE_LEN {
            return Ok(());
        }

        // Constant-time compare against the pending ping nonce.
        let Some((pending_nonce, sent_at)) = peer.pending_ping else {
            return Ok(());
        };
        if !crate::transport::cookies::ct_eq(&echoed, &pending_nonce) {
            return Ok(());
        }
        peer.pending_ping = None;

        let sample = Instant::now().duration_since(sent_at);
        peer.update_neighbor_rtt(sample);
        self.metrics.pongs_received.fetch_add(1, Ordering::Relaxed);
        debug!(peer = ?peer_id, rtt_us = sample.as_micros(), "rtt sample");
        Ok(())
    }
}
