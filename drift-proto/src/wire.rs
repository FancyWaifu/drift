//! Pure, stateless DRIFT wire-format builders and constants.
//!
//! Phase 4 slice 1 of the sans-IO arc (`docs/PHASE4_DESIGN.md`):
//! this is the single source of truth for the byte layout of the
//! handshake packets and the DoS-cookie MAC input. Both
//! `drift_proto::Endpoint` and `drift::Transport` build their wire
//! bytes here, so the two implementations can't drift apart on the
//! format. Every function is a pure function of its arguments — no
//! peer state, no I/O, no clocks, no crypto sealing (that needs a
//! live session key and lives one layer up).
//!
//! A byte-identity test in the `drift` crate
//! (`transport::wire_parity_tests`) asserts the transport's
//! historical private builders produce output identical to these,
//! so adopting this module was a proven no-op on the wire.

use drift_core::crypto::{cookie_mac, PeerId, COOKIE_MAC_LEN};
use drift_core::header::{Header, PacketType, AUTH_TAG_LEN, FLAG_PQ_HYBRID, HEADER_LEN};
use drift_core::identity::{Identity, NONCE_LEN, STATIC_KEY_LEN};
use drift_core::session::DEFAULT_MESH_TTL;
use std::net::SocketAddr;

// ── handshake payload sizes ──────────────────────────────────────

/// HELLO payload: `client_static(32) ‖ client_eph(32) ‖ nonce(16)`.
pub const HELLO_PAYLOAD_LEN: usize = STATIC_KEY_LEN + STATIC_KEY_LEN + NONCE_LEN; // 80
/// HELLO_ACK payload: `server_eph(32) ‖ server_nonce(16) ‖ tag(16)`.
pub const HELLO_ACK_PAYLOAD_LEN: usize = STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN; // 64
/// ML-KEM-768 encapsulation key appended to a hybrid HELLO.
pub const HELLO_PQ_TAIL_LEN: usize = drift_core::pq::ML_KEM_EK_LEN; // 1184
/// ML-KEM-768 ciphertext appended to a hybrid HELLO_ACK.
pub const HELLO_ACK_PQ_TAIL_LEN: usize = drift_core::pq::ML_KEM_CT_LEN; // 1088

// ── DoS-cookie sizes ─────────────────────────────────────────────

/// Cookie timestamp width (u64 BE).
pub const COOKIE_TS_LEN: usize = 8;
/// Cookie blob appended to an extended HELLO: `timestamp(8) ‖ MAC(16)`.
pub const COOKIE_BLOB_LEN: usize = COOKIE_TS_LEN + COOKIE_MAC_LEN; // 24
/// A HELLO carrying a cookie tail (before any PQ ek).
pub const HELLO_WITH_COOKIE_LEN: usize = HELLO_PAYLOAD_LEN + COOKIE_BLOB_LEN; // 104

// ── HELLO / ResumeHello builders ─────────────────────────────────

/// Build a HELLO wire packet. `mesh` stamps the hop-TTL budget (and
/// thereby `FLAG_ROUTED`) so bridges forward the handshake toward a
/// peer not reachable directly. `cookie` appends the DoS-cookie
/// tail; `pq_ek` appends an ML-KEM encapsulation key and sets
/// `FLAG_PQ_HYBRID`.
#[allow(clippy::too_many_arguments)]
pub fn build_hello_wire(
    local_peer_id: PeerId,
    dst_id: PeerId,
    identity: &Identity,
    ephemeral_pub: [u8; STATIC_KEY_LEN],
    client_nonce: [u8; NONCE_LEN],
    mesh: bool,
    cookie: Option<&[u8; COOKIE_BLOB_LEN]>,
    pq_ek: Option<&[u8]>,
) -> Vec<u8> {
    let mut header = Header::new(PacketType::Hello, 0, local_peer_id, dst_id);
    if mesh {
        header = header.with_hop_ttl(DEFAULT_MESH_TTL);
    }
    if pq_ek.is_some() {
        header.flags |= FLAG_PQ_HYBRID;
    }
    let base_len = if cookie.is_some() {
        HELLO_WITH_COOKIE_LEN
    } else {
        HELLO_PAYLOAD_LEN
    };
    let payload_len = base_len + pq_ek.map(|ek| ek.len()).unwrap_or(0);
    header.payload_len = payload_len as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);

    let mut wire = Vec::with_capacity(HEADER_LEN + payload_len);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&identity.public_bytes());
    wire.extend_from_slice(&ephemeral_pub);
    wire.extend_from_slice(&client_nonce);
    if let Some(c) = cookie {
        wire.extend_from_slice(c);
    }
    if let Some(ek) = pq_ek {
        wire.extend_from_slice(ek);
    }
    wire
}

/// Build a `ResumeHello` wire packet:
/// `header ‖ ticket_id(16) ‖ client_eph(32) ‖ client_nonce(16)`.
/// `body_len` is the caller's `RESUME_HELLO_BODY_LEN`
/// (`ticket_id + eph + nonce`), passed in so this module need not
/// depend on the resumption layer's constant.
pub fn build_resume_hello_wire(
    local_peer_id: PeerId,
    dst_id: PeerId,
    client_eph_pub: [u8; STATIC_KEY_LEN],
    client_nonce: [u8; NONCE_LEN],
    ticket_id: &[u8],
    body_len: usize,
    mesh: bool,
) -> Vec<u8> {
    let mut header = Header::new(PacketType::ResumeHello, 0, local_peer_id, dst_id);
    if mesh {
        header = header.with_hop_ttl(DEFAULT_MESH_TTL);
    }
    header.payload_len = body_len as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);

    let mut wire = Vec::with_capacity(HEADER_LEN + body_len);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(ticket_id);
    wire.extend_from_slice(&client_eph_pub);
    wire.extend_from_slice(&client_nonce);
    wire
}

// ── DoS-cookie MAC input ─────────────────────────────────────────

/// Canonical address bytes inside the cookie MAC input.
/// v4: `[0x04][addr 4][port 2]`, v6: `[0x06][addr 16][port 2]`.
pub fn addr_bytes(addr: &SocketAddr) -> Vec<u8> {
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

/// Build the MAC input for a DoS cookie. Binds the client source
/// address, both client pubkeys, the client nonce (critical — its
/// absence lets an attacker reuse one cookie for unlimited X25519
/// work), and the server-side issue timestamp.
pub fn cookie_input(
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

/// Compute a DoS cookie MAC over `cookie_input(...)` with `secret`.
/// Thin convenience over [`cookie_input`] + `drift_core::crypto::cookie_mac`.
pub fn cookie_mac_for(
    secret: &[u8; 32],
    src: &SocketAddr,
    client_static_pub: &[u8; STATIC_KEY_LEN],
    client_ephemeral_pub: &[u8; STATIC_KEY_LEN],
    client_nonce: &[u8; NONCE_LEN],
    timestamp: u64,
) -> [u8; COOKIE_MAC_LEN] {
    let input = cookie_input(
        src,
        client_static_pub,
        client_ephemeral_pub,
        client_nonce,
        timestamp,
    );
    cookie_mac(secret, &input)
}

/// Constant-time MAC comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use drift_core::identity::Identity;

    // Known-answer tests pinning the exact byte layout. These lock
    // the wire format: any change to a builder that alters output
    // for these fixed inputs is a wire-format regression and fails
    // here. The transport shares this module (phase 4 slice 1), so
    // these vectors guard both implementations at once.

    fn fixed_identity() -> Identity {
        Identity::from_secret_bytes([0x11; 32])
    }

    #[test]
    fn hello_wire_layout_classical_no_cookie() {
        let id = fixed_identity();
        let wire = build_hello_wire(
            [1, 2, 3, 4, 5, 6, 7, 8],
            [8, 7, 6, 5, 4, 3, 2, 1],
            &id,
            [0x22; STATIC_KEY_LEN],
            [0x33; NONCE_LEN],
            false,
            None,
            None,
        );
        // header(36) + static(32) + eph(32) + nonce(16) = 116.
        assert_eq!(wire.len(), HEADER_LEN + HELLO_PAYLOAD_LEN);
        // Header byte 0 = (version<<4)|flags; version 1, no flags.
        assert_eq!(wire[0], 0x10);
        // packet_type byte = Hello (1).
        assert_eq!(wire[1], PacketType::Hello as u8);
        // payload_len field (BE u16 at header[30..32]) = 80.
        assert_eq!(
            u16::from_be_bytes([wire[30], wire[31]]),
            HELLO_PAYLOAD_LEN as u16
        );
        // static pubkey immediately follows the header.
        assert_eq!(&wire[HEADER_LEN..HEADER_LEN + 32], &id.public_bytes());
        assert_eq!(&wire[HEADER_LEN + 32..HEADER_LEN + 64], &[0x22; 32]);
        assert_eq!(&wire[HEADER_LEN + 64..HEADER_LEN + 80], &[0x33; 16]);
    }

    #[test]
    fn hello_wire_mesh_sets_routed_flag_and_ttl() {
        let id = fixed_identity();
        let wire = build_hello_wire(
            [1; 8],
            [2; 8],
            &id,
            [0x22; STATIC_KEY_LEN],
            [0x33; NONCE_LEN],
            true, // mesh
            None,
            None,
        );
        // FLAG_ROUTED is bit 0 of the low nibble.
        assert_eq!(
            wire[0] & 0x0F & drift_core::header::FLAG_ROUTED,
            drift_core::header::FLAG_ROUTED
        );
        // hop_ttl lives at header[28] = DEFAULT_MESH_TTL.
        assert_eq!(wire[28], DEFAULT_MESH_TTL);
    }

    #[test]
    fn hello_wire_cookie_and_pq_tails_in_order() {
        let id = fixed_identity();
        let cookie = [0x44u8; COOKIE_BLOB_LEN];
        let ek = vec![0x55u8; HELLO_PQ_TAIL_LEN];
        let wire = build_hello_wire(
            [1; 8],
            [2; 8],
            &id,
            [0x22; STATIC_KEY_LEN],
            [0x33; NONCE_LEN],
            false,
            Some(&cookie),
            Some(&ek),
        );
        // FLAG_PQ_HYBRID set; cookie tail then ek tail, in that order.
        assert_eq!(wire[0] & FLAG_PQ_HYBRID, FLAG_PQ_HYBRID);
        let base = HEADER_LEN + HELLO_PAYLOAD_LEN;
        assert_eq!(&wire[base..base + COOKIE_BLOB_LEN], &cookie);
        assert_eq!(&wire[base + COOKIE_BLOB_LEN..], &ek[..]);
        assert_eq!(
            wire.len(),
            HEADER_LEN + HELLO_WITH_COOKIE_LEN + HELLO_PQ_TAIL_LEN
        );
    }

    #[test]
    fn resume_hello_wire_layout() {
        let ticket = [0x66u8; 16];
        let wire = build_resume_hello_wire(
            [1; 8],
            [2; 8],
            [0x77; STATIC_KEY_LEN],
            [0x88; NONCE_LEN],
            &ticket,
            16 + STATIC_KEY_LEN + NONCE_LEN,
            false,
        );
        assert_eq!(wire[1], PacketType::ResumeHello as u8);
        // body = ticket_id(16) ‖ eph(32) ‖ nonce(16), in that order.
        assert_eq!(&wire[HEADER_LEN..HEADER_LEN + 16], &ticket);
        assert_eq!(&wire[HEADER_LEN + 16..HEADER_LEN + 48], &[0x77; 32]);
        assert_eq!(&wire[HEADER_LEN + 48..HEADER_LEN + 64], &[0x88; 16]);
    }

    #[test]
    fn cookie_input_field_order_and_addr_encoding() {
        let src = "192.168.1.7:51820".parse().unwrap();
        let input = cookie_input(
            &src,
            &[0xAA; 32],
            &[0xBB; 32],
            &[0xCC; 16],
            0x0102030405060708,
        );
        // addr_bytes(v4) = [0x04][4 octets][2 port BE] = 7 bytes.
        assert_eq!(input[0], 0x04);
        assert_eq!(&input[1..5], &[192, 168, 1, 7]);
        assert_eq!(u16::from_be_bytes([input[5], input[6]]), 51820);
        // then static, eph, nonce, timestamp(BE).
        assert_eq!(&input[7..39], &[0xAA; 32]);
        assert_eq!(&input[39..71], &[0xBB; 32]);
        assert_eq!(&input[71..87], &[0xCC; 16]);
        assert_eq!(&input[87..95], &0x0102030405060708u64.to_be_bytes());
    }

    #[test]
    fn ct_eq_matches_and_rejects() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2]));
    }
}
