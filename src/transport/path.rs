//! Path validation: challenge-response probing before committing
//! a peer-address migration triggered by DATA arriving from a new
//! source.
//!
//! When `handle_data` sees AEAD-valid DATA from an address that
//! doesn't match the currently-trusted `peer.addr`, it records a
//! `PathProbe` on the peer and sends a 16-byte random challenge
//! (AEAD-sealed) to the new source. Migration only commits once
//! a matching `PathResponse` comes back from that same new source
//! — which an off-path replay attacker cannot produce, because
//! the challenge bytes are hidden behind the session key they
//! don't have.

use super::{cookies::ct_eq, Inner};
use crate::error::{DriftError, Result};
use crate::header::{canonical_aad, Header, PacketType, AUTH_TAG_LEN, HEADER_LEN};
use crate::session::{HandshakeState, PathProbe, Peer};
use crate::PeerId;
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tracing::debug;

/// Length (in bytes) of a path-validation challenge. Fixed at 16
/// — enough entropy that an off-path attacker can't guess it.
pub(crate) const PATH_CHALLENGE_LEN: usize = 16;

/// How long a pending path-validation probe stays live. If a
/// matching `PathResponse` doesn't arrive in this window, a fresh
/// DATA packet from a new source can retrigger a probe.
pub(crate) const PATH_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Minimum interval between re-issuing a challenge for the SAME
/// candidate address. Rate-limits the bandwidth an attacker
/// replaying packets can force us to spend on probes.
pub(crate) const PATH_PROBE_RETRY: Duration = Duration::from_millis(500);

/// Build a `PathChallenge` wire packet for `peer`, sealing the
/// supplied 16-byte challenge under the peer's session key. Must
/// be called while holding the peer lock — it bumps the peer's
/// tx seq.
pub(crate) fn build_path_challenge_packet(
    local_peer_id: PeerId,
    peer: &mut Peer,
    challenge: &[u8; PATH_CHALLENGE_LEN],
) -> Result<Vec<u8>> {
    let seq = peer
        .next_seq_checked()
        .ok_or(DriftError::SessionExhausted)?;
    let mut header = peer.make_header(PacketType::PathChallenge, seq, local_peer_id);
    header.payload_len = (PATH_CHALLENGE_LEN + AUTH_TAG_LEN) as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);
    let (tx, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
    let mut wire = Vec::with_capacity(HEADER_LEN + PATH_CHALLENGE_LEN + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(
        seq,
        PacketType::PathChallenge as u8,
        &aad,
        challenge,
        &mut wire,
    )?;
    Ok(wire)
}

/// Build a `PathResponse` wire packet that echoes the given
/// 16-byte challenge back to the sender, AEAD-sealed.
pub(crate) fn build_path_response_packet(
    local_peer_id: PeerId,
    peer: &mut Peer,
    challenge: &[u8; PATH_CHALLENGE_LEN],
) -> Result<Vec<u8>> {
    let seq = peer
        .next_seq_checked()
        .ok_or(DriftError::SessionExhausted)?;
    let mut header = peer.make_header(PacketType::PathResponse, seq, local_peer_id);
    header.payload_len = (PATH_CHALLENGE_LEN + AUTH_TAG_LEN) as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);
    let (tx, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
    let mut wire = Vec::with_capacity(HEADER_LEN + PATH_CHALLENGE_LEN + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(
        seq,
        PacketType::PathResponse as u8,
        &aad,
        challenge,
        &mut wire,
    )?;
    Ok(wire)
}

impl Inner {
    /// Graceful migration: kick off a path-validation probe to a
    /// candidate address that the app has been told about (e.g.,
    /// from an OS network-change notification). On success, the
    /// peer's `addr` swaps to the validated candidate without
    /// any traffic stall — the existing session keys, cwnd, and
    /// stream state all carry over.
    ///
    /// Unlike the reactive probe path (triggered by AEAD-valid
    /// DATA arriving from a new src in `handle_data`), this one
    /// is initiated by the app *before* any traffic from the
    /// candidate has been seen. Useful for mobile handoff
    /// (wifi → cellular), where the OS knows a few seconds in
    /// advance that the current path is about to break.
    ///
    /// The probe is rejected if the peer isn't currently
    /// `Established` (no session key to seal the challenge with)
    /// or if a probe is already in flight to a different
    /// candidate — the existing one has to time out first.
    pub(crate) async fn probe_candidate_path(
        &self,
        peer_id: &PeerId,
        candidate_addr: SocketAddr,
    ) -> Result<()> {
        let wire = {
            let mut peers = self.peers.lock_for(peer_id).await;
            let peer = peers.get_mut(peer_id).ok_or(DriftError::UnknownPeer)?;
            if !matches!(peer.handshake, HandshakeState::Established { .. }) {
                return Err(DriftError::UnknownPeer);
            }
            // Don't clobber an in-flight probe to a different
            // candidate — wait for it to time out or succeed.
            // A duplicate probe to the SAME candidate just
            // refreshes the timer.
            if let Some(p) = &peer.probing {
                if p.addr != candidate_addr
                    && Instant::now().duration_since(p.started) < PATH_PROBE_TIMEOUT
                {
                    return Err(DriftError::QueueFull);
                }
            }
            let mut challenge = [0u8; PATH_CHALLENGE_LEN];
            rand::thread_rng().fill_bytes(&mut challenge);
            peer.probing = Some(PathProbe {
                addr: candidate_addr,
                challenge,
                started: Instant::now(),
            });
            build_path_challenge_packet(self.local_peer_id, peer, &challenge)?
        };

        self.ifaces.send_for(self.iface_for(peer_id).await, &wire, candidate_addr).await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(wire.len() as u64, Ordering::Relaxed);
        self.metrics
            .path_probes_sent
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .graceful_probes_initiated
            .fetch_add(1, Ordering::Relaxed);
        debug!(peer = ?peer_id, candidate = ?candidate_addr, "graceful path probe sent");
        Ok(())
    }

    /// Received a `PathChallenge` from a peer. Decrypt the 16-byte
    /// challenge and bounce it back in a `PathResponse` from our
    /// current address. No state changes — the response is purely
    /// reactive and authenticates "yes, I'm reachable at this src
    /// with the live session key."
    pub(crate) async fn handle_path_challenge(
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

        let response_bytes = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;
            let (_, rx) = peer
                .handshake
                .session()
                .ok_or(DriftError::UnknownPeer)?;

            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            let challenge =
                rx.open(header.seq, PacketType::PathChallenge as u8, &aad, body)?;
            if challenge.len() != PATH_CHALLENGE_LEN {
                return Err(DriftError::PacketTooShort {
                    got: challenge.len(),
                    need: PATH_CHALLENGE_LEN,
                });
            }
            let mut challenge_bytes = [0u8; PATH_CHALLENGE_LEN];
            challenge_bytes.copy_from_slice(&challenge);

            build_path_response_packet(self.local_peer_id, peer, &challenge_bytes)?
        };

        self.ifaces.send_for(self.iface_for(&peer_id).await, &response_bytes, src).await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(response_bytes.len() as u64, Ordering::Relaxed);
        debug!("sent PathResponse to {:?}", src);
        Ok(())
    }

    /// Received a `PathResponse`. If it matches an outstanding
    /// probe's challenge AND comes from the address we probed,
    /// commit the migration. Otherwise drop silently.
    pub(crate) async fn handle_path_response(
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

        let mut peers = self.peers.lock_for(&peer_id).await;
        let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;
        let (_, rx) = peer
            .handshake
            .session()
            .ok_or(DriftError::UnknownPeer)?;

        let mut hbuf = [0u8; HEADER_LEN];
        hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
        let aad = canonical_aad(&hbuf);
        let echoed = rx.open(header.seq, PacketType::PathResponse as u8, &aad, body)?;
        if echoed.len() != PATH_CHALLENGE_LEN {
            return Ok(());
        }

        let (probe_addr, probe_challenge, probe_started) = match &peer.probing {
            Some(p) => (p.addr, p.challenge, p.started),
            None => return Ok(()), // no probe outstanding
        };

        // Timeout check: if the probe is stale, ignore the response.
        if Instant::now().duration_since(probe_started) > PATH_PROBE_TIMEOUT {
            peer.probing = None;
            return Ok(());
        }

        // The response must come from the address we probed AND
        // echo the exact challenge bytes we put on the wire.
        if src != probe_addr {
            return Ok(());
        }
        if !ct_eq(&echoed, &probe_challenge) {
            return Ok(());
        }

        debug!(
            old = ?peer.addr,
            new = ?probe_addr,
            "path-validated migration"
        );
        // Feed the round-trip time into the neighbor RTT
        // estimator — a valid PathResponse is a clean
        // sample of the candidate path's cost.
        peer.update_neighbor_rtt(Instant::now().duration_since(probe_started));
        peer.addr = probe_addr;
        peer.probing = None;
        self.metrics
            .path_probes_succeeded
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
