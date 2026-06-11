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
use drift_core::session::{HandshakeState, Peer, PendingSend, DEFAULT_MESH_TTL};
use drift_core::Zeroizing;

use crate::wire::HELLO_ACK_PAYLOAD_LEN;

/// What the caller needs after a responder-side `AwaitingData →
/// Established` transition completes — see [`complete_server_transition`].
pub struct ServerEstablished {
    /// The session key, for short-header CID installation.
    pub key_bytes: Zeroizing<[u8; 32]>,
    /// Whether the handshake was PQ-hybrid (for the caller's metric).
    pub was_hybrid_pq: bool,
    /// DATA the app queued while the handshake was still in flight,
    /// for the caller to build + route as flush packets (each driver
    /// wraps these in its own action type).
    pub pending: Vec<PendingSend>,
}

/// Promote a responder-side peer from `AwaitingData` to `Established`
/// on the first authenticated DATA, and hand back the bits the caller
/// needs to finish the job. Returns `None` if the peer was already
/// `Established` (the common steady-state case).
///
/// This is the single source of truth for the trickiest shared
/// receive-path state mutation: the `AwaitingData → Established`
/// swap, clearing the amplification counters (the source address is
/// now validated by an AEAD-authenticated round trip), and draining
/// the pending queue. The caller layers its own side effects around
/// it — the transport bumps metrics / qlog / installs CIDs after the
/// peer lock releases; the engine emits `Connected`, installs CIDs,
/// and issues a resumption ticket — and builds the flush packets in
/// its own action type. Pure peer-state mutation; no crypto, no I/O.
pub fn complete_server_transition(peer: &mut Peer) -> Option<ServerEstablished> {
    if !matches!(peer.handshake, HandshakeState::AwaitingData { .. }) {
        return None;
    }
    let HandshakeState::AwaitingData {
        tx,
        rx,
        key_bytes,
        was_hybrid_pq,
        ..
    } = std::mem::replace(&mut peer.handshake, HandshakeState::Pending)
    else {
        // Guarded by the matches! above.
        unreachable!("peer was AwaitingData");
    };
    let key_for_caller = key_bytes.clone();
    peer.handshake = HandshakeState::Established {
        tx,
        rx,
        key_bytes,
        prev: None,
    };
    peer.clear_unauth_counters();
    let pending = std::mem::take(&mut peer.pending);
    Some(ServerEstablished {
        key_bytes: key_for_caller,
        was_hybrid_pq,
        pending,
    })
}

/// Seal a DATA packet for `peer` and return the wire bytes. The
/// short-header CID fast path applies when an outgoing CID is
/// installed and no mesh / deadline / coalesce feature is in play
/// (7-byte header vs the 36-byte long header); otherwise the long
/// header carries the full feature set. Consumes one tx seq slot.
///
/// Returns only the bytes — each driver wraps them in its own action
/// type (`drift::transport::SendAction` / `drift_proto::Transmit`)
/// and computes its own destination, so the transport keeps its
/// interface routing and the engine its single-pipe addressing.
/// The long path takes a pooled buffer (`drift_core::pool`), so the
/// transport's allocation optimization is preserved.
///
/// `mesh` gates the short-header eligibility and stamps the
/// hop-TTL/`FLAG_ROUTED` budget; the caller decides whether to pass
/// `out_cid` (e.g. the engine withholds it until `next_tx_seq > 1`
/// so a responder can CID-route the first DATA).
pub fn seal_data_wire(
    local_peer_id: PeerId,
    peer: &mut Peer,
    payload: &[u8],
    deadline_ms: u16,
    coalesce_group: u32,
    out_cid: Option<u16>,
    mesh: bool,
) -> Result<Vec<u8>> {
    let seq = peer.next_seq_checked()?;

    // Short-header fast path: CID installed, direct session, no
    // deadline/coalesce. 7-byte header + 16-byte tag = 23 vs the
    // long header's 36 + 16 = 52.
    if let Some(cid) = out_cid {
        if !mesh && deadline_ms == 0 && coalesce_group == 0 {
            let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            return drift_core::short_header::encode_short(cid, seq, tx, payload);
        }
    }

    // Long header: full 36 bytes, all features available.
    let send_time_ms = peer.send_time_ms();
    let mut header =
        Header::new(PacketType::Data, seq, local_peer_id, peer.id).with_deadline(deadline_ms);
    if coalesce_group != 0 {
        header = header.with_supersedes(coalesce_group);
    }
    if mesh {
        header = header.with_hop_ttl(DEFAULT_MESH_TTL);
    }
    header.payload_len = payload.len() as u16;
    header.send_time_ms = send_time_ms;

    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);

    let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;

    let mut wire = drift_core::pool::take_wire_buf(HEADER_LEN + payload.len() + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(seq, PacketType::Data as u8, &aad, payload, &mut wire)?;
    Ok(wire)
}

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
    fn seal_data_wire_short_and_long_paths() {
        use drift_core::short_header::{is_short_header, SHORT_HEADER_LEN};
        let payload = b"data-path-payload";

        // No CID -> long header (type=Data, 36-byte header).
        let mut peer = established_peer();
        peer.next_tx_seq = 5;
        let long = seal_data_wire([1; 8], &mut peer, payload, 0, 0, None, false).unwrap();
        assert!(!is_short_header(&long));
        assert_eq!(long[1], PacketType::Data as u8);
        assert_eq!(long.len(), HEADER_LEN + payload.len() + AUTH_TAG_LEN);

        // CID + direct + no deadline/coalesce -> short header (0x2 nibble).
        let mut peer = established_peer();
        peer.next_tx_seq = 5;
        let short = seal_data_wire([1; 8], &mut peer, payload, 0, 0, Some(0x1234), false).unwrap();
        assert!(is_short_header(&short));
        assert_eq!(short.len(), SHORT_HEADER_LEN + payload.len() + AUTH_TAG_LEN);

        // A CID but with a deadline -> long header (feature forces it).
        let mut peer = established_peer();
        peer.next_tx_seq = 5;
        let forced_long =
            seal_data_wire([1; 8], &mut peer, payload, 500, 0, Some(0x1234), false).unwrap();
        assert!(!is_short_header(&forced_long));

        // A CID but mesh -> long header with the hop-TTL budget.
        let mut peer = established_peer();
        peer.next_tx_seq = 5;
        let mesh = seal_data_wire([1; 8], &mut peer, payload, 0, 0, Some(0x1234), true).unwrap();
        assert!(!is_short_header(&mesh));
        assert_eq!(mesh[28], drift_core::session::DEFAULT_MESH_TTL);
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
