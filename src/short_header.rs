//! Compact wire format for established direct sessions.
//!
//! On an established, non-forwarded session, most of the
//! 36-byte long header is redundant:
//!
//!   * `src_id` / `dst_id` (16 bytes) — both sides already
//!     know each other's identity.
//!   * `deadline_ms`, `supersedes`, `send_time_ms` (10 bytes)
//!     — only needed for deadline-aware / coalescing traffic.
//!   * `payload_len` (2 bytes) — UDP is self-delimiting.
//!   * `hop_ttl`, `reserved` (2 bytes) — only for mesh.
//!
//! The short header replaces all of that with a 2-byte
//! **Connection ID (CID)** that the receiver maps back to a
//! peer identity via a negotiation-free lookup table. Both
//! sides derive each other's CIDs deterministically from the
//! shared session key, so no extra wire exchange is needed.
//!
//! ## Wire format
//!
//! ```text
//! byte 0:      0x20 | flags(4 bits)    — version nibble 0x2
//!                                         distinguishes short
//!                                         from long (0x1)
//! bytes 1-2:   connection_id (u16 BE)  — receiver looks up
//!                                         in CID map → PeerId
//! bytes 3-6:   seq (u32 BE)            — AEAD nonce + replay
//! bytes 7..N:  ciphertext + auth_tag   — payload encrypted
//!                                         under the session key
//! ```
//!
//! Total overhead: **7 header + 16 tag = 23 bytes** vs the
//! long header's 36 + 16 = 52 bytes — a **56% reduction**.
//!
//! ## CID derivation
//!
//! ```text
//! initiator_rx_cid = BLAKE2b("drift-cid-init-v1" ‖ session_key)[0..2]
//! responder_rx_cid = BLAKE2b("drift-cid-resp-v1" ‖ session_key)[0..2]
//! ```
//!
//! The Initiator puts `responder_rx_cid` in its outgoing
//! short headers (so the Responder can look it up). Vice
//! versa. Both sides compute both CIDs locally — zero
//! extra round trips.
//!
//! ## When short headers are used
//!
//! Only for `PacketType::Data` on **Established** sessions
//! with no mesh forwarding (hop_ttl == 1, no learned route).
//! Everything else — HELLOs, beacons, rekeys, path probes,
//! mesh-forwarded packets, deadline/coalesce-tagged traffic
//! — still uses the long header. The send path checks these
//! conditions and falls back to long header automatically.

use crate::crypto::SessionKey;
use crate::error::{DriftError, Result};
use crate::header::AUTH_TAG_LEN;
use blake2::{digest::consts::U32, Blake2b, Digest};

/// Short-header length: version+flags (1) + CID (2) + seq (4).
pub const SHORT_HEADER_LEN: usize = 7;

/// Version nibble value that distinguishes short headers
/// from long headers on the wire. Long headers use 0x1;
/// short headers use 0x2.
pub const SHORT_HEADER_VERSION: u8 = 0x2;

/// Derive the receive-side CID for the Initiator direction.
/// The Responder puts this in its outgoing short headers so
/// the Initiator's recv loop can look it up.
pub fn derive_initiator_rx_cid(session_key: &[u8; 32]) -> u16 {
    derive_cid(session_key, b"drift-cid-init-v1")
}

/// Derive the receive-side CID for the Responder direction.
pub fn derive_responder_rx_cid(session_key: &[u8; 32]) -> u16 {
    derive_cid(session_key, b"drift-cid-resp-v1")
}

fn derive_cid(session_key: &[u8; 32], tag: &[u8]) -> u16 {
    let mut h = Blake2b::<U32>::new();
    h.update(tag);
    h.update(session_key);
    let out = h.finalize();
    u16::from_be_bytes([out[0], out[1]])
}

/// Encode a short-header DATA packet. Returns the full wire
/// bytes (header + sealed ciphertext + tag).
pub fn encode_short(cid: u16, seq: u32, tx: &SessionKey, payload: &[u8]) -> Result<Vec<u8>> {
    // Build the 7-byte header as a stack array so we have
    // a stable AAD reference while extending `wire`.
    let mut hdr = [0u8; SHORT_HEADER_LEN];
    hdr[0] = SHORT_HEADER_VERSION << 4;
    hdr[1..3].copy_from_slice(&cid.to_be_bytes());
    hdr[3..7].copy_from_slice(&seq.to_be_bytes());

    let mut wire = Vec::with_capacity(SHORT_HEADER_LEN + payload.len() + AUTH_TAG_LEN);
    wire.extend_from_slice(&hdr);

    // AEAD seal. Use packet_type = Data (3) for the nonce
    // prefix so nonces don't collide with other packet
    // types even if seqs overlap (they shouldn't, but
    // defense in depth).
    tx.seal_into(seq, 3, &hdr, payload, &mut wire)?;
    Ok(wire)
}

/// Peek at byte 0 of a received datagram and return true if
/// it's a short-header packet (version nibble == 0x2).
pub fn is_short_header(data: &[u8]) -> bool {
    !data.is_empty() && (data[0] >> 4) == SHORT_HEADER_VERSION
}

/// Decode a short-header packet's fixed fields. Does NOT
/// decrypt — the caller needs to look up the CID first
/// to find the session key. Returns `(cid, seq, ciphertext_with_tag)`.
pub fn decode_short(data: &[u8]) -> Result<(u16, u32, &[u8])> {
    if data.len() < SHORT_HEADER_LEN + AUTH_TAG_LEN {
        return Err(DriftError::PacketTooShort {
            got: data.len(),
            need: SHORT_HEADER_LEN + AUTH_TAG_LEN,
        });
    }
    let cid = u16::from_be_bytes([data[1], data[2]]);
    let seq = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
    let body = &data[SHORT_HEADER_LEN..];
    Ok((cid, seq, body))
}

/// Full decryption of a short-header packet given the
/// session's rx key. Returns the plaintext payload.
pub fn open_short(data: &[u8], rx: &SessionKey) -> Result<(u16, u32, Vec<u8>)> {
    let (cid, seq, body) = decode_short(data)?;
    let aad = &data[..SHORT_HEADER_LEN];
    let plaintext = rx.open(seq, 3, aad, body)?;
    Ok((cid, seq, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Direction;

    #[test]
    fn short_header_roundtrip() {
        let key = [0x42u8; 32];
        let tx = SessionKey::new(&key, Direction::Initiator);
        let rx = SessionKey::new(&key, Direction::Initiator);

        let cid = 0x1234u16;
        let seq = 7u32;
        let payload = b"compact-header-test";

        let wire = encode_short(cid, seq, &tx, payload).unwrap();
        assert!(is_short_header(&wire));
        assert_eq!(wire.len(), SHORT_HEADER_LEN + payload.len() + AUTH_TAG_LEN);

        let (dec_cid, dec_seq, plaintext) = open_short(&wire, &rx).unwrap();
        assert_eq!(dec_cid, cid);
        assert_eq!(dec_seq, seq);
        assert_eq!(plaintext, payload);
    }

    #[test]
    fn long_header_not_detected_as_short() {
        // Version nibble 0x1 (long header) should NOT trigger
        // the short-header path.
        let long = [0x10u8; 36]; // version=1, flags=0
        assert!(!is_short_header(&long));
    }

    #[test]
    fn cid_derivation_is_deterministic_and_directional() {
        let key = [0x77u8; 32];
        let init_cid = derive_initiator_rx_cid(&key);
        let resp_cid = derive_responder_rx_cid(&key);

        // Same key → same CIDs on repeated calls.
        assert_eq!(init_cid, derive_initiator_rx_cid(&key));
        assert_eq!(resp_cid, derive_responder_rx_cid(&key));

        // Different directions → different CIDs (with
        // overwhelming probability — only fails on a
        // 1-in-65536 hash collision, which this test key
        // doesn't hit).
        assert_ne!(init_cid, resp_cid);
    }

    #[test]
    fn short_header_rejects_truncated_packet() {
        // Fewer than SHORT_HEADER_LEN + AUTH_TAG_LEN bytes
        // must fail.
        let too_short = [0x20, 0x12, 0x34]; // 3 bytes
        assert!(decode_short(&too_short).is_err());
    }

    #[test]
    fn overhead_comparison() {
        let payload = b"hello-world"; // 11 bytes
        let key = [0x99u8; 32];
        let tx = SessionKey::new(&key, Direction::Initiator);

        let short_wire = encode_short(1, 1, &tx, payload).unwrap();
        let short_overhead = short_wire.len() - payload.len();

        // Long header: 36 header + 16 tag = 52 overhead.
        let long_overhead: usize = 36 + 16;

        println!(
            "payload={} short_overhead={} long_overhead={} saving={}%",
            payload.len(),
            short_overhead,
            long_overhead,
            (long_overhead - short_overhead) * 100 / long_overhead
        );
        assert_eq!(short_overhead, SHORT_HEADER_LEN + AUTH_TAG_LEN); // 23
        assert!(
            short_overhead < long_overhead,
            "short header must be smaller than long"
        );
    }
}
