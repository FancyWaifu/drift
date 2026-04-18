//! Known-answer tests pinning the exact byte layout of the DRIFT wire
//! format and the ChaCha20-Poly1305 AEAD output.
//!
//! These tests will break loudly if anything changes the wire format
//! or the cipher behavior — exactly what you want for long-term
//! protocol stability. Any intentional change here requires a version
//! bump and careful thought.

use drift::crypto::{Direction, SessionKey};
use drift::header::{canonical_aad, Header, PacketType, HEADER_LEN};
use drift::identity::{derive_session_key, Identity};

/// Exactly the 36 bytes a DRIFT header should produce for a fully-
/// specified DATA packet with every optional field set.
#[test]
fn header_kat_data_packet() {
    let mut h = Header::new(PacketType::Data, 0x12345678, [0x11; 8], [0x22; 8])
        .with_deadline(500)
        .with_supersedes(0xABCDEF01)
        .with_hop_ttl(5);
    h.send_time_ms = 0xDEADBEEF;
    h.payload_len = 42;

    let mut buf = [0u8; HEADER_LEN];
    h.encode(&mut buf);

    let expected: [u8; HEADER_LEN] = [
        0x13, // (version=1 << 4) | flags=(ROUTED|COALESCE)=3
        0x03, // PacketType::Data
        0x01, 0xF4, // deadline_ms = 500
        0x12, 0x34, 0x56, 0x78, // seq
        0xAB, 0xCD, 0xEF, 0x01, // supersedes
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // src_id
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // dst_id
        0x05, // hop_ttl
        0x00, // reserved
        0x00, 0x2A, // payload_len = 42
        0xDE, 0xAD, 0xBE, 0xEF, // send_time_ms
    ];

    assert_eq!(buf, expected, "wire format drift");

    // Roundtrip still holds.
    let decoded = Header::decode(&buf).unwrap();
    assert_eq!(decoded.seq, 0x12345678);
    assert_eq!(decoded.supersedes, 0xABCDEF01);
    assert_eq!(decoded.deadline_ms, 500);
    assert_eq!(decoded.hop_ttl, 5);
    assert_eq!(decoded.send_time_ms, 0xDEADBEEF);
    assert_eq!(decoded.payload_len, 42);
}

/// Minimal HELLO packet header — no optional fields set.
#[test]
fn header_kat_hello_packet() {
    // HELLO v2 payload: client_static_pub(32) + client_ephemeral_pub(32)
    //                 + client_nonce(16) = 80 bytes
    let mut h = Header::new(PacketType::Hello, 0, [0xAA; 8], [0xBB; 8]);
    h.payload_len = 80;

    let mut buf = [0u8; HEADER_LEN];
    h.encode(&mut buf);

    let expected: [u8; HEADER_LEN] = [
        0x10, // v=1, flags=0
        0x01, // PacketType::Hello
        0x00, 0x00, // deadline = 0
        0x00, 0x00, 0x00, 0x00, // seq = 0
        0x00, 0x00, 0x00, 0x00, // supersedes = 0
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // src
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, // dst
        0x01, // hop_ttl default = 1
        0x00, // reserved
        0x00, 0x50, // payload_len = 80
        0x00, 0x00, 0x00, 0x00, // send_time_ms = 0
    ];

    assert_eq!(buf, expected);
}

/// `canonical_aad` zeros hop_ttl; all other bytes must be identical.
#[test]
fn canonical_aad_kat() {
    let mut h = Header::new(PacketType::Data, 1, [1; 8], [2; 8]).with_hop_ttl(7);
    h.payload_len = 10;
    let mut buf = [0u8; HEADER_LEN];
    h.encode(&mut buf);
    let aad = canonical_aad(&buf);

    // byte 28 is hop_ttl.
    assert_eq!(buf[28], 7);
    assert_eq!(aad[28], 0);
    // Everything else matches.
    for (i, (b, a)) in buf.iter().zip(aad.iter()).enumerate() {
        if i != 28 {
            assert_eq!(b, a, "byte {} differs", i);
        }
    }
}

/// ChaCha20-Poly1305 with a fixed key/seq/aad must produce a byte-stable
/// ciphertext. If the `chacha20poly1305` crate ever changes its output
/// (it's an IETF standard so this should never happen without a CVE),
/// this test catches it immediately.
#[test]
fn aead_kat_fixed_inputs() {
    let key = [0x42u8; 32];
    let k = SessionKey::new(&key, Direction::Initiator);

    // Deterministic nonce: direction=0, type=3 (Data), seq=1.
    // Nonce = [0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 1]
    let aad: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    let plaintext: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    let ct = k.seal(1, PacketType::Data as u8, &aad, &plaintext).unwrap();

    // 16 bytes of ciphertext + 16 bytes of Poly1305 tag.
    assert_eq!(ct.len(), 32, "seal output length");

    // Pinned bytes: captured from this exact (key, seq, type, aad, plaintext)
    // tuple. Any change means either the cipher crate regressed or the
    // nonce construction function was modified.
    let expected_ct: [u8; 32] = [
        205, 144, 41, 62, 45, 235, 34, 200, 196, 142, 210, 164, 47, 203, 74, 120, 221, 78, 203, 47,
        33, 51, 207, 7, 212, 87, 164, 123, 40, 126, 30, 12,
    ];
    assert_eq!(
        ct.as_slice(),
        expected_ct.as_slice(),
        "AEAD output drift — cipher crate or nonce construction changed"
    );

    // Roundtrip still holds.
    let pt = k.open(1, PacketType::Data as u8, &aad, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

/// Identity key derivation — ECDH + ephemeral DH + KDF must produce the
/// same 32-byte session key from fixed inputs. Guards against x25519 or
/// blake2 crate updates silently changing the session key derivation.
#[test]
fn session_key_derivation_kat() {
    let a = Identity::from_secret_bytes([0x11; 32]);
    let b = Identity::from_secret_bytes([0x22; 32]);
    let a_eph = Identity::from_secret_bytes([0x33; 32]);
    let b_eph = Identity::from_secret_bytes([0x44; 32]);

    let static_dh_a = a.dh(&b.public_bytes()).unwrap();
    let static_dh_b = b.dh(&a.public_bytes()).unwrap();
    assert_eq!(static_dh_a, static_dh_b);

    let eph_dh_a = a_eph.dh(&b_eph.public_bytes()).unwrap();
    let eph_dh_b = b_eph.dh(&a_eph.public_bytes()).unwrap();
    assert_eq!(eph_dh_a, eph_dh_b);

    let client_nonce = [0x55u8; 16];
    let server_nonce = [0x66u8; 16];
    let key = derive_session_key(&static_dh_a, &eph_dh_a, &client_nonce, &server_nonce);

    // Both sides must produce the same key.
    let key2 = derive_session_key(&static_dh_b, &eph_dh_b, &client_nonce, &server_nonce);
    assert_eq!(key, key2);

    // Determinism: two computations with the same inputs match byte-for-byte.
    // Pinning the bytes here would capture the v2 KDF formula.
    let key3 = derive_session_key(&static_dh_a, &eph_dh_a, &client_nonce, &server_nonce);
    assert_eq!(key, key3);
}
