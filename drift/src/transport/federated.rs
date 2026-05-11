//! Federated envelope codec + helpers for `PacketType::Federated`.
//!
//! See `drift_core::header::PacketType::Federated` for the wire
//! layout. This module only encodes/decodes the envelope; the
//! transport-level recv handler and the wire-builder live in
//! `transport/mod.rs` where they have access to `Inner`, `Peer`,
//! and the federation table.
//!
//! Envelope wire (inside the AEAD-sealed body of the outer packet):
//!
//! ```text
//!   [0..32]    target_bridge_pub  — bridge that should next-hop this
//!   [32..64]   target_client_pub  — final recipient
//!   [64..96]   source_bridge_pub  — bridge the originator is connected
//!                                   to. Carried unchanged across hops
//!                                   so the recipient can auto-route a
//!                                   reply without needing to know the
//!                                   sender's bridge out-of-band.
//!   [96..128]  source_client_pub  — originating client
//!   [128..130] payload_len (u16 BE)
//!   [130..]    payload (payload_len bytes)
//! ```

use crate::error::DriftError;

/// Fixed header length (everything before the variable payload).
pub const FED_HEADER_LEN: usize = 32 + 32 + 32 + 32 + 2;

/// Parsed view of a federated envelope. Borrows from the
/// decrypted body so callers can avoid copying.
#[derive(Debug)]
pub struct FederatedEnvelope<'a> {
    pub target_bridge_pub: [u8; 32],
    pub target_client_pub: [u8; 32],
    pub source_bridge_pub: [u8; 32],
    pub source_client_pub: [u8; 32],
    pub payload: &'a [u8],
}

/// Serialize an envelope into a fresh `Vec<u8>`.
pub fn build(
    target_bridge_pub: &[u8; 32],
    target_client_pub: &[u8; 32],
    source_bridge_pub: &[u8; 32],
    source_client_pub: &[u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FED_HEADER_LEN + payload.len());
    out.extend_from_slice(target_bridge_pub);
    out.extend_from_slice(target_client_pub);
    out.extend_from_slice(source_bridge_pub);
    out.extend_from_slice(source_client_pub);
    let len = payload.len() as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Borrow-parse a federated envelope. Returns
/// `DriftError::DecodeError` on truncation or length-tag mismatch.
pub fn parse(bytes: &[u8]) -> Result<FederatedEnvelope<'_>, DriftError> {
    if bytes.len() < FED_HEADER_LEN {
        return Err(DriftError::DecodeError);
    }
    let mut target_bridge_pub = [0u8; 32];
    target_bridge_pub.copy_from_slice(&bytes[0..32]);
    let mut target_client_pub = [0u8; 32];
    target_client_pub.copy_from_slice(&bytes[32..64]);
    let mut source_bridge_pub = [0u8; 32];
    source_bridge_pub.copy_from_slice(&bytes[64..96]);
    let mut source_client_pub = [0u8; 32];
    source_client_pub.copy_from_slice(&bytes[96..128]);
    let payload_len = u16::from_be_bytes([bytes[128], bytes[129]]) as usize;
    if bytes.len() != FED_HEADER_LEN + payload_len {
        return Err(DriftError::DecodeError);
    }
    Ok(FederatedEnvelope {
        target_bridge_pub,
        target_client_pub,
        source_bridge_pub,
        source_client_pub,
        payload: &bytes[FED_HEADER_LEN..],
    })
}

// ─── FederationDirectory codec ───────────────────────────────────
//
// Bridge-to-bridge announcement of connected clients. Wire format
// inside the AEAD-sealed body of a PacketType::FederationDirectory:
//
// ```text
//   [0]        version  (u8) = 1
//   [1]        reserved (u8) = 0
//   [2..4]     count    (u16 BE) — number of pubkey entries
//   [4..]      entries  ([32 bytes] * count)
// ```
//
// Capped at MAX_DIRECTORY_ENTRIES per packet so a single
// announcement fits comfortably under MAX_PAYLOAD. Bridges with
// more clients send multiple packets.

const DIRECTORY_HEADER_LEN: usize = 4;
const DIRECTORY_VERSION: u8 = 1;
pub const MAX_DIRECTORY_ENTRIES: usize = 40;

/// Build a FederationDirectory payload from a slice of client
/// pubkeys. Callers MUST keep `pubs.len() <= MAX_DIRECTORY_ENTRIES`.
pub fn build_directory(pubs: &[[u8; 32]]) -> Vec<u8> {
    debug_assert!(
        pubs.len() <= MAX_DIRECTORY_ENTRIES,
        "directory chunk too large: {}",
        pubs.len()
    );
    let count = pubs.len() as u16;
    let mut out = Vec::with_capacity(DIRECTORY_HEADER_LEN + pubs.len() * 32);
    out.push(DIRECTORY_VERSION);
    out.push(0); // reserved
    out.extend_from_slice(&count.to_be_bytes());
    for p in pubs {
        out.extend_from_slice(p);
    }
    out
}

/// Parse a FederationDirectory payload into an owned vector of
/// pubkeys. Returns `DecodeError` on truncation or version
/// mismatch — a peer running an incompatible version of the
/// announcement format is silently ignored rather than treated
/// as malicious.
pub fn parse_directory(bytes: &[u8]) -> Result<Vec<[u8; 32]>, DriftError> {
    if bytes.len() < DIRECTORY_HEADER_LEN {
        return Err(DriftError::DecodeError);
    }
    if bytes[0] != DIRECTORY_VERSION {
        return Err(DriftError::DecodeError);
    }
    let count = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let expected_len = DIRECTORY_HEADER_LEN + count * 32;
    if bytes.len() != expected_len {
        return Err(DriftError::DecodeError);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = DIRECTORY_HEADER_LEN + i * 32;
        let mut p = [0u8; 32];
        p.copy_from_slice(&bytes[off..off + 32]);
        out.push(p);
    }
    Ok(out)
}

/// Sentinel `target_bridge_pub` value meaning "I don't know which
/// bridge holds the target; consult the directory". Bridges treat
/// this as a directory-lookup request instead of a federation-
/// table lookup. Set on Federated envelopes by clients that have
/// no `via_bridge` for the target.
pub const UNKNOWN_BRIDGE_PUB: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let tb = [0xAA; 32];
        let tc = [0xBB; 32];
        let sb = [0xDD; 32];
        let sc = [0xCC; 32];
        let payload = b"hello federated world";
        let wire = build(&tb, &tc, &sb, &sc, payload);
        let env = parse(&wire).unwrap();
        assert_eq!(env.target_bridge_pub, tb);
        assert_eq!(env.target_client_pub, tc);
        assert_eq!(env.source_bridge_pub, sb);
        assert_eq!(env.source_client_pub, sc);
        assert_eq!(env.payload, payload);
    }

    #[test]
    fn truncated_errors() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0u8; 10]).is_err());
        let mut short = build(&[0; 32], &[0; 32], &[0; 32], &[0; 32], b"hi");
        short.truncate(short.len() - 1);
        assert!(parse(&short).is_err());
    }

    #[test]
    fn empty_payload() {
        let wire = build(&[1; 32], &[2; 32], &[4; 32], &[3; 32], b"");
        let env = parse(&wire).unwrap();
        assert!(env.payload.is_empty());
    }

    #[test]
    fn directory_roundtrip() {
        let pubs = vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]];
        let wire = build_directory(&pubs);
        let parsed = parse_directory(&wire).unwrap();
        assert_eq!(parsed, pubs);
    }

    #[test]
    fn directory_empty() {
        let wire = build_directory(&[]);
        assert_eq!(parse_directory(&wire).unwrap(), Vec::<[u8; 32]>::new());
    }

    #[test]
    fn directory_rejects_wrong_version() {
        let mut wire = build_directory(&[[1; 32]]);
        wire[0] = 0xFF;
        assert!(parse_directory(&wire).is_err());
    }

    #[test]
    fn directory_rejects_truncation() {
        let wire = build_directory(&[[1; 32], [2; 32]]);
        // Drop the last byte → length mismatch.
        let short = &wire[..wire.len() - 1];
        assert!(parse_directory(short).is_err());
    }
}
