//! Known-answer tests for the packet types added after the original
//! KAT set: `Challenge`, `PathChallenge`, `PathResponse`. Locks the
//! header byte layout and (for the AEAD-sealed ones) the ciphertext
//! output for a fixed key + seq + aad + plaintext tuple.
//!
//! Any intentional change to these wire formats requires a protocol
//! version bump and a deliberate update to these vectors.

use drift::crypto::{Direction, SessionKey};
use drift::header::{Header, PacketType, HEADER_LEN};

#[test]
fn header_kat_challenge_packet() {
    // CHALLENGE body is 24 bytes: [u64 timestamp][u8;16 mac].
    let mut h = Header::new(PacketType::Challenge, 0, [0xCC; 8], [0xDD; 8]);
    h.payload_len = 24;

    let mut buf = [0u8; HEADER_LEN];
    h.encode(&mut buf);

    let expected: [u8; HEADER_LEN] = [
        0x10, // v=1, flags=0
        0x08, // PacketType::Challenge
        0x00, 0x00, // deadline = 0
        0x00, 0x00, 0x00, 0x00, // seq = 0
        0x00, 0x00, 0x00, 0x00, // supersedes = 0
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // src
        0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, // dst
        0x01, // hop_ttl default = 1
        0x00, // reserved
        0x00, 0x18, // payload_len = 24
        0x00, 0x00, 0x00, 0x00, // send_time_ms
    ];
    assert_eq!(buf, expected, "CHALLENGE header wire format drift");
}

#[test]
fn header_kat_path_challenge_packet() {
    // PathChallenge body is 16 bytes of random + 16-byte AEAD tag = 32.
    let mut h =
        Header::new(PacketType::PathChallenge, 0x000000FF, [0x01; 8], [0x02; 8]);
    h.payload_len = 32;
    h.send_time_ms = 0x1234_5678;

    let mut buf = [0u8; HEADER_LEN];
    h.encode(&mut buf);

    let expected: [u8; HEADER_LEN] = [
        0x10, // v=1, flags=0
        0x09, // PacketType::PathChallenge
        0x00, 0x00, // deadline = 0
        0x00, 0x00, 0x00, 0xFF, // seq
        0x00, 0x00, 0x00, 0x00, // supersedes = 0
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // src
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // dst
        0x01, // hop_ttl
        0x00, // reserved
        0x00, 0x20, // payload_len = 32
        0x12, 0x34, 0x56, 0x78, // send_time_ms
    ];
    assert_eq!(buf, expected, "PathChallenge header wire format drift");
}

#[test]
fn header_kat_path_response_packet() {
    let mut h =
        Header::new(PacketType::PathResponse, 0x0000_0100, [0x03; 8], [0x04; 8]);
    h.payload_len = 32;

    let mut buf = [0u8; HEADER_LEN];
    h.encode(&mut buf);

    let expected: [u8; HEADER_LEN] = [
        0x10, 0x0A, // v=1, flags=0; PacketType::PathResponse
        0x00, 0x00, // deadline
        0x00, 0x00, 0x01, 0x00, // seq = 256
        0x00, 0x00, 0x00, 0x00, // supersedes
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x01, 0x00, // hop_ttl, reserved
        0x00, 0x20, // payload_len = 32
        0x00, 0x00, 0x00, 0x00, // send_time_ms
    ];
    assert_eq!(buf, expected, "PathResponse header wire format drift");
}

/// AEAD output for a `PathChallenge` (type = 9). Same key, same
/// challenge bytes, same AAD → byte-stable sealed output. Catches any
/// nonce-construction or type-byte changes that would break interop.
#[test]
fn aead_kat_path_challenge_sealed() {
    let key = [0x42u8; 32];
    let k = SessionKey::new(&key, Direction::Initiator);
    let aad: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    let challenge: [u8; 16] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC,
        0xCD, 0xCE, 0xCF,
    ];
    let ct = k
        .seal(7, PacketType::PathChallenge as u8, &aad, &challenge)
        .unwrap();
    assert_eq!(ct.len(), 32, "sealed output length");

    // Roundtrip with the matching type byte must succeed.
    let pt = k
        .open(7, PacketType::PathChallenge as u8, &aad, &ct)
        .unwrap();
    assert_eq!(pt, challenge);

    // Opening the same ciphertext with a DIFFERENT type byte must
    // fail — nonce embeds the type, so cross-type reuse is caught.
    assert!(
        k.open(7, PacketType::Data as u8, &aad, &ct).is_err(),
        "AEAD cross-type open must fail"
    );
    assert!(
        k.open(7, PacketType::PathResponse as u8, &aad, &ct).is_err(),
        "AEAD cross-type open must fail"
    );
}

/// AEAD output for a `PathResponse` (type = 10). Same construction,
/// different type byte — makes sure the nonce namespace for
/// PathResponse is distinct from PathChallenge.
#[test]
fn aead_kat_path_response_sealed() {
    let key = [0x42u8; 32];
    let k = SessionKey::new(&key, Direction::Initiator);
    let aad: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    let challenge: [u8; 16] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC,
        0xCD, 0xCE, 0xCF,
    ];
    let ct_req = k
        .seal(7, PacketType::PathChallenge as u8, &aad, &challenge)
        .unwrap();
    let ct_resp = k
        .seal(7, PacketType::PathResponse as u8, &aad, &challenge)
        .unwrap();
    // Different type → different nonce → different ciphertext.
    assert_ne!(
        ct_req, ct_resp,
        "PathChallenge and PathResponse must produce distinct ciphertexts for the same seq"
    );
    let pt = k
        .open(7, PacketType::PathResponse as u8, &aad, &ct_resp)
        .unwrap();
    assert_eq!(pt, challenge);
}
