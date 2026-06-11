//! Session-keyed frame builders shared by the engine and the
//! transport (phase 4 slice 2 — `docs/PHASE4_DESIGN.md`).
//!
//! Unlike [`crate::wire`] — which is purely stateless byte layout —
//! these builders operate on a live `drift_core::session::Peer`
//! and/or AEAD-seal with a `SessionKey`. They're still a single
//! source of truth shared by both `drift_proto::Endpoint` and
//! `drift::Transport`, so the two can't diverge on the byte format
//! of the Close packet or the HELLO_ACK response.
//!
//! Both packets these build are AEAD-sealed, so any byte divergence
//! between callers would break tag verification on the peer — the
//! `proto_interop` cross-implementation suite (engine ↔ transport,
//! both roles, classical + PQ + Close) is therefore an exact
//! byte-identity guard, on top of the per-crate handshake/close
//! tests.

use drift_core::crypto::{PeerId, SessionKey};
use drift_core::error::{PeerError, Result};
use drift_core::header::{canonical_aad, Header, PacketType, AUTH_TAG_LEN, HEADER_LEN};
use drift_core::identity::{NONCE_LEN, STATIC_KEY_LEN};
use drift_core::session::Peer;

use crate::wire::HELLO_ACK_PAYLOAD_LEN;

/// Build an authenticated `Close` packet for `peer`: an AEAD-sealed
/// empty body — the tag is the message. Consumes one tx seq slot.
/// The peer must hold a live session (`AwaitingData`/`Established`).
pub fn build_close_packet(local_peer_id: PeerId, peer: &mut Peer) -> Result<Vec<u8>> {
    let seq = peer.next_seq_checked()?;
    let mut header = peer.make_header(PacketType::Close, seq, local_peer_id);
    header.payload_len = AUTH_TAG_LEN as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);
    let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
    let mut wire = Vec::with_capacity(HEADER_LEN + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(seq, PacketType::Close as u8, &aad, b"", &mut wire)?;
    Ok(wire)
}

/// Assemble a `HELLO_ACK` wire packet from the server's freshly
/// generated handshake material and the responder-direction send
/// key `tx`. Pure given its inputs — the caller does the DH and key
/// derivation and owns the peer-state transition; this only builds
/// the bytes:
///
/// ```text
/// header(HelloAck, seq 1, hop_ttl=DEFAULT_MESH_TTL → FLAG_ROUTED,
///        FLAG_PQ_HYBRID iff ct)
///   ‖ server_eph_pub(32) ‖ server_nonce(16) ‖ tag(16) ‖ [ct]
/// ```
///
/// The auth tag is sealed over `canonical_aad(header) ‖ server_eph
/// ‖ server_nonce ‖ [ct]`, so a man-in-the-middle who edits the
/// in-the-clear ML-KEM ciphertext flips the client's derived key and
/// the client's `open()` fails cleanly.
pub fn build_hello_ack_wire(
    local_peer_id: PeerId,
    client_peer_id: PeerId,
    server_eph_pub: &[u8; STATIC_KEY_LEN],
    server_nonce: &[u8; NONCE_LEN],
    server_mlkem_ct: Option<&[u8]>,
    tx: &SessionKey,
) -> Result<Vec<u8>> {
    let mut ack_header = Header::new(PacketType::HelloAck, 1, local_peer_id, client_peer_id)
        .with_hop_ttl(drift_core::session::DEFAULT_MESH_TTL);
    if server_mlkem_ct.is_some() {
        ack_header.flags |= drift_core::header::FLAG_PQ_HYBRID;
    }
    let ack_payload_len = HELLO_ACK_PAYLOAD_LEN + server_mlkem_ct.map(|ct| ct.len()).unwrap_or(0);
    ack_header.payload_len = ack_payload_len as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    ack_header.encode(&mut hbuf);

    let canon = canonical_aad(&hbuf);
    let mut aad = Vec::with_capacity(
        HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN + server_mlkem_ct.map(|ct| ct.len()).unwrap_or(0),
    );
    aad.extend_from_slice(&canon);
    aad.extend_from_slice(server_eph_pub);
    aad.extend_from_slice(server_nonce);
    if let Some(ct) = server_mlkem_ct {
        aad.extend_from_slice(ct);
    }
    let tag = tx.seal(1, PacketType::HelloAck as u8, &aad, b"")?;

    let mut wire = Vec::with_capacity(HEADER_LEN + ack_payload_len);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(server_eph_pub);
    wire.extend_from_slice(server_nonce);
    wire.extend_from_slice(&tag);
    if let Some(ct) = server_mlkem_ct {
        wire.extend_from_slice(ct);
    }
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use drift_core::crypto::Direction;
    use drift_core::session::{HandshakeState, Peer};
    use drift_core::Zeroizing;
    use std::net::SocketAddr;

    fn established_peer() -> Peer {
        let key = Zeroizing::new([0x42u8; 32]);
        let tx = SessionKey::new(&key, Direction::Responder);
        let rx = SessionKey::new(&key, Direction::Initiator);
        let mut peer = Peer::new(
            [9; 8],
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
            [7; 32],
            Direction::Responder,
        );
        peer.handshake = HandshakeState::Established {
            tx,
            rx,
            key_bytes: key,
            prev: None,
        };
        peer
    }

    #[test]
    fn close_packet_structure() {
        let mut peer = established_peer();
        let next = peer.next_tx_seq;
        let wire = build_close_packet([1; 8], &mut peer).unwrap();
        // header(36) + tag(16) = 52, empty sealed body.
        assert_eq!(wire.len(), HEADER_LEN + AUTH_TAG_LEN);
        assert_eq!(wire[1], PacketType::Close as u8);
        assert_eq!(
            u16::from_be_bytes([wire[30], wire[31]]),
            AUTH_TAG_LEN as u16
        );
        // It consumed exactly one tx seq slot.
        assert_eq!(peer.next_tx_seq, next + 1);
    }

    #[test]
    fn hello_ack_wire_structure_classical_and_pq() {
        let key = [0x55u8; 32];
        let tx = SessionKey::new(&key, Direction::Responder);
        let eph = [0x22u8; STATIC_KEY_LEN];
        let nonce = [0x33u8; NONCE_LEN];

        // Classical: no ct tail.
        let wire = build_hello_ack_wire([1; 8], [2; 8], &eph, &nonce, None, &tx).unwrap();
        assert_eq!(wire[1], PacketType::HelloAck as u8);
        // hop_ttl = DEFAULT_MESH_TTL and FLAG_ROUTED set.
        assert_eq!(wire[28], drift_core::session::DEFAULT_MESH_TTL);
        assert_eq!(
            wire[0] & drift_core::header::FLAG_ROUTED,
            drift_core::header::FLAG_ROUTED
        );
        assert_eq!(wire[0] & drift_core::header::FLAG_PQ_HYBRID, 0);
        assert_eq!(wire.len(), HEADER_LEN + HELLO_ACK_PAYLOAD_LEN);
        // body = server_eph(32) ‖ server_nonce(16) ‖ tag(16).
        assert_eq!(&wire[HEADER_LEN..HEADER_LEN + 32], &eph);
        assert_eq!(&wire[HEADER_LEN + 32..HEADER_LEN + 48], &nonce);

        // PQ: ct tail appended, FLAG_PQ_HYBRID set.
        let ct = vec![0x66u8; crate::wire::HELLO_ACK_PQ_TAIL_LEN];
        let wire = build_hello_ack_wire([1; 8], [2; 8], &eph, &nonce, Some(&ct), &tx).unwrap();
        assert_eq!(
            wire[0] & drift_core::header::FLAG_PQ_HYBRID,
            drift_core::header::FLAG_PQ_HYBRID
        );
        assert_eq!(wire.len(), HEADER_LEN + HELLO_ACK_PAYLOAD_LEN + ct.len());
        assert_eq!(&wire[HEADER_LEN + HELLO_ACK_PAYLOAD_LEN..], &ct[..]);
    }

    #[test]
    fn hello_ack_tag_verifies_with_matching_rx() {
        // Round-trip: a client holding the same key derives the same
        // AAD and opens the empty-body tag — proves the AAD layout
        // (canon ‖ eph ‖ nonce ‖ [ct]) is self-consistent.
        let key = [0x77u8; 32];
        let tx = SessionKey::new(&key, Direction::Responder);
        // The opener of a Responder-sealed packet uses a
        // Responder-direction key (the AEAD nonce embeds the
        // direction, so it must match the sealer's).
        let rx = SessionKey::new(&key, Direction::Responder);
        let eph = [0x22u8; STATIC_KEY_LEN];
        let nonce = [0x33u8; NONCE_LEN];
        let wire = build_hello_ack_wire([1; 8], [2; 8], &eph, &nonce, None, &tx).unwrap();

        let hbuf: [u8; HEADER_LEN] = wire[..HEADER_LEN].try_into().unwrap();
        let mut aad = canonical_aad(&hbuf).to_vec();
        aad.extend_from_slice(&eph);
        aad.extend_from_slice(&nonce);
        let tag = &wire[HEADER_LEN + 48..HEADER_LEN + 64];
        rx.open(1, PacketType::HelloAck as u8, &aad, tag).unwrap();
    }
}
