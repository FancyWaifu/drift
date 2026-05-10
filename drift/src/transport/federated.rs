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
//!   [0..32]   target_bridge_pub
//!   [32..64]  target_client_pub
//!   [64..96]  source_client_pub
//!   [96..98]  payload_len (u16 BE)
//!   [98..]    payload (payload_len bytes)
//! ```

use crate::error::DriftError;

/// Fixed header length (everything before the variable payload).
pub const FED_HEADER_LEN: usize = 32 + 32 + 32 + 2;

/// Parsed view of a federated envelope. Borrows from the
/// decrypted body so callers can avoid copying.
#[derive(Debug)]
pub struct FederatedEnvelope<'a> {
    pub target_bridge_pub: [u8; 32],
    pub target_client_pub: [u8; 32],
    pub source_client_pub: [u8; 32],
    pub payload: &'a [u8],
}

/// Serialize an envelope into a fresh `Vec<u8>`.
pub fn build(
    target_bridge_pub: &[u8; 32],
    target_client_pub: &[u8; 32],
    source_client_pub: &[u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FED_HEADER_LEN + payload.len());
    out.extend_from_slice(target_bridge_pub);
    out.extend_from_slice(target_client_pub);
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
    let mut source_client_pub = [0u8; 32];
    source_client_pub.copy_from_slice(&bytes[64..96]);
    let payload_len = u16::from_be_bytes([bytes[96], bytes[97]]) as usize;
    if bytes.len() != FED_HEADER_LEN + payload_len {
        return Err(DriftError::DecodeError);
    }
    Ok(FederatedEnvelope {
        target_bridge_pub,
        target_client_pub,
        source_client_pub,
        payload: &bytes[FED_HEADER_LEN..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let tb = [0xAA; 32];
        let tc = [0xBB; 32];
        let sc = [0xCC; 32];
        let payload = b"hello federated world";
        let wire = build(&tb, &tc, &sc, payload);
        let env = parse(&wire).unwrap();
        assert_eq!(env.target_bridge_pub, tb);
        assert_eq!(env.target_client_pub, tc);
        assert_eq!(env.source_client_pub, sc);
        assert_eq!(env.payload, payload);
    }

    #[test]
    fn truncated_errors() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0u8; 10]).is_err());
        let mut short = build(&[0; 32], &[0; 32], &[0; 32], b"hi");
        short.truncate(short.len() - 1);
        assert!(parse(&short).is_err());
    }

    #[test]
    fn empty_payload() {
        let wire = build(&[1; 32], &[2; 32], &[3; 32], b"");
        let env = parse(&wire).unwrap();
        assert!(env.payload.is_empty());
    }
}
