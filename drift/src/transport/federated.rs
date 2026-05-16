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

// ─── Presence tickets (XEdDSA) ───────────────────────────────────
//
// A presence ticket is a client's cryptographic attestation that
// "yes, I really am connected to bridge B, and B may announce me
// in its FederationDirectory." Without tickets, a malicious
// federated bridge could lie — claiming pubkeys it doesn't host —
// and remote receivers would have no way to detect it.
//
// The client signs `(bridge_pub || expiry_ms || nonce)` with its
// X25519 static identity key (via XEdDSA — see
// `drift_core::xeddsa`). The bridge stores the (expiry, nonce, sig)
// tuple alongside the client's pubkey. When the bridge announces
// in FederationDirectory v2, it embeds the tuple per entry.
// Receivers reconstruct the signed message — using the *announcing
// bridge's* pubkey as `bridge_pub` — and verify with the announced
// client's pubkey. A bridge that tries to announce a pubkey it
// doesn't have a real ticket for produces a signature that fails
// verification against any honest receiver.
//
// Wire (96 bytes — ticket-on-the-wire, client → bridge):
// ```text
//   [0..8]    expiry_ms (u64 BE)  — unix-ms after which the ticket is invalid
//   [8..32]   nonce     ([u8; 24])
//   [32..96]  sig       ([u8; 64], XEdDSA over the canonical message)
// ```
// The signed message is built by `ticket_signed_msg(bridge_pub,
// expiry_ms, nonce)`; the bridge pubkey is implicit on the wire
// (every ticket is for the bridge it's sent to / announced from).

/// On-wire length of a presence ticket.
pub const TICKET_LEN: usize = 8 + 24 + 64;
pub const TICKET_NONCE_LEN: usize = 24;

/// A presence ticket as it travels on the wire and as the bridge
/// stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceTicket {
    /// Unix milliseconds after which the ticket must be rejected.
    pub expiry_ms: u64,
    /// 24 bytes of caller-supplied randomness. Prevents a stolen
    /// ticket from being replayed across bridges (the nonce is
    /// part of the signed message; the bridge it was signed for
    /// is implicit).
    pub nonce: [u8; TICKET_NONCE_LEN],
    /// XEdDSA signature over `ticket_signed_msg(bridge_pub,
    /// expiry_ms, nonce)`.
    pub sig: [u8; 64],
}

/// Canonical bytes the client signs. Receivers reconstruct this
/// exactly to verify — `bridge_pub` is the *announcing* bridge in
/// the FederationDirectory case, or the local bridge in the
/// PresenceTicket-from-client case.
pub fn ticket_signed_msg(
    bridge_pub: &[u8; 32],
    expiry_ms: u64,
    nonce: &[u8; TICKET_NONCE_LEN],
) -> [u8; 32 + 8 + TICKET_NONCE_LEN] {
    let mut out = [0u8; 32 + 8 + TICKET_NONCE_LEN];
    out[..32].copy_from_slice(bridge_pub);
    out[32..40].copy_from_slice(&expiry_ms.to_be_bytes());
    out[40..].copy_from_slice(nonce);
    out
}

/// Build a fresh ticket. `client_secret` is the X25519 private
/// identity bytes; `bridge_pub` is the bridge the ticket is for;
/// `expiry_ms` is when this ticket goes invalid; `nonce_extra` is
/// 64 bytes of CSPRNG entropy for the XEdDSA hedged-deterministic
/// signing.
pub fn build_ticket(
    client_secret: &[u8; 32],
    bridge_pub: &[u8; 32],
    expiry_ms: u64,
    nonce: [u8; TICKET_NONCE_LEN],
    nonce_extra: &[u8; 64],
) -> PresenceTicket {
    let msg = ticket_signed_msg(bridge_pub, expiry_ms, &nonce);
    let sig = drift_core::xeddsa::sign(client_secret, &msg, nonce_extra);
    PresenceTicket {
        expiry_ms,
        nonce,
        sig,
    }
}

/// Serialize a ticket onto the wire (96 bytes).
pub fn encode_ticket(t: &PresenceTicket) -> [u8; TICKET_LEN] {
    let mut out = [0u8; TICKET_LEN];
    out[..8].copy_from_slice(&t.expiry_ms.to_be_bytes());
    out[8..32].copy_from_slice(&t.nonce);
    out[32..].copy_from_slice(&t.sig);
    out
}

/// Parse a 96-byte on-wire ticket.
pub fn decode_ticket(bytes: &[u8]) -> Result<PresenceTicket, DriftError> {
    if bytes.len() != TICKET_LEN {
        return Err(DriftError::DecodeError);
    }
    let expiry_ms = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    let mut nonce = [0u8; TICKET_NONCE_LEN];
    nonce.copy_from_slice(&bytes[8..32]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[32..]);
    Ok(PresenceTicket {
        expiry_ms,
        nonce,
        sig,
    })
}

/// Verify a ticket against `client_pub` for the announcing/local
/// `bridge_pub`. Checks the expiry, then the XEdDSA signature.
///
/// `now_ms` is the receiver's wall-clock in unix ms. The ticket
/// MUST be non-expired AND the signature MUST verify under
/// `client_pub` over `ticket_signed_msg(bridge_pub, …)`.
pub fn verify_ticket(
    client_pub: &[u8; 32],
    bridge_pub: &[u8; 32],
    ticket: &PresenceTicket,
    now_ms: u64,
) -> Result<(), DriftError> {
    if ticket.expiry_ms <= now_ms {
        return Err(DriftError::AuthFailed);
    }
    let msg = ticket_signed_msg(bridge_pub, ticket.expiry_ms, &ticket.nonce);
    drift_core::xeddsa::verify(client_pub, &msg, &ticket.sig)
}

// ─── FederationDirectory codec (v2) ──────────────────────────────
//
// Bridge-to-bridge announcement of connected clients. Wire format
// inside the AEAD-sealed body of a PacketType::FederationDirectory:
//
// ```text
//   [0]        version  (u8) = 2
//   [1]        reserved (u8) = 0
//   [2..4]     count    (u16 BE) — number of (pubkey, ticket) entries
//   [4..]      entries  ((32-byte pubkey ‖ 96-byte ticket) * count)
// ```
//
// Each entry is 128 bytes. Capped at MAX_DIRECTORY_ENTRIES per
// packet so a single announcement fits comfortably under
// MAX_PAYLOAD (~10 entries × 128 + 4 header = 1284 bytes).
// Bridges with more clients send multiple packets.
//
// v1 (32-byte-per-entry, no tickets) was the announcement format
// before XEdDSA presence tickets landed. v2 is incompatible with
// v1 — peers running v1 receive a `DecodeError` and silently
// drop the announcement, which is the correct behavior for a
// peer running an outdated DRIFT.

const DIRECTORY_HEADER_LEN: usize = 4;
const DIRECTORY_VERSION_V2: u8 = 2;
/// Current wire version. v3 adds a 1-byte `hops` field per entry
/// for proactive multi-hop announce (Phase C). v3 receivers also
/// accept v2 payloads on the wire and treat each entry as hops=0
/// — the previous version is upgrade-equivalent. v2 receivers
/// reject v3 (silent drop, expected during rolling upgrade).
const DIRECTORY_VERSION_V3: u8 = 3;
/// Phase F. v4 appends an optional DP-noised bloom filter
/// section after the v3-shaped entries. v4 receivers accept
/// v3 and v2 (treating each older entry as hops=0 and the
/// filter as absent). v3-and-older receivers reject v4
/// (silent drop, expected during rolling upgrade).
const DIRECTORY_VERSION_V4: u8 = 4;
/// Back-compat alias — old call sites assume v2. Kept around to
/// avoid touching every test that hard-codes version 2.
const DIRECTORY_VERSION: u8 = DIRECTORY_VERSION_V2;
const DIRECTORY_ENTRY_LEN: usize = 32 + TICKET_LEN;
/// v3+ entry: client_pub (32) + ticket (96) + hops (1) = 129 bytes.
const DIRECTORY_ENTRY_V3_LEN: usize = 32 + TICKET_LEN + 1;
/// Maximum entries per directory packet (v2/v3 default and v4
/// without a bloom). Sized so that `DIRECTORY_HEADER_LEN +
/// MAX_DIRECTORY_ENTRIES * 129` fits comfortably under
/// MAX_PAYLOAD (10 * 129 + 4 = 1294 bytes).
pub const MAX_DIRECTORY_ENTRIES: usize = 10;
/// v4-with-bloom entry cap. Drops to 8 to leave room for the
/// ~150-byte bloom-filter section (128 bytes filter + ~20
/// metadata). 8 * 129 + 4 + 150 ≈ 1186 bytes < MAX_PAYLOAD.
pub const MAX_DIRECTORY_ENTRIES_V4: usize = 8;

/// Maximum hop count a re-announced directory entry may carry.
/// Caps the radius of proactive propagation; reactive `FindPeer`
/// covers the long tail (see `FEDERATION_DISCOVERY.md` §8).
/// A direct-client entry has hops=0; an entry forwarded once has
/// hops=1; an entry forwarded twice has hops=2 — caps here. We
/// don't re-announce entries with hops >= MAX_ANNOUNCE_HOPS.
pub const MAX_ANNOUNCE_HOPS: u8 = 2;

/// Build a FederationDirectory v2 payload from a slice of
/// (pubkey, ticket) pairs. Callers MUST keep
/// `entries.len() <= MAX_DIRECTORY_ENTRIES`.
pub fn build_directory(entries: &[([u8; 32], PresenceTicket)]) -> Vec<u8> {
    debug_assert!(
        entries.len() <= MAX_DIRECTORY_ENTRIES,
        "directory chunk too large: {}",
        entries.len()
    );
    let count = entries.len() as u16;
    let mut out = Vec::with_capacity(DIRECTORY_HEADER_LEN + entries.len() * DIRECTORY_ENTRY_LEN);
    out.push(DIRECTORY_VERSION);
    out.push(0); // reserved
    out.extend_from_slice(&count.to_be_bytes());
    for (pubkey, ticket) in entries {
        out.extend_from_slice(pubkey);
        out.extend_from_slice(&encode_ticket(ticket));
    }
    out
}

/// Build a FederationDirectory **v3** payload from a slice of
/// (pubkey, ticket, hops) triples. v3 is the current format —
/// hops=0 indicates a directly-connected client; hops>0 means
/// the entry was learned transitively from another bridge.
///
/// Callers MUST keep `entries.len() <= MAX_DIRECTORY_ENTRIES`.
pub fn build_directory_v3(entries: &[([u8; 32], PresenceTicket, u8)]) -> Vec<u8> {
    debug_assert!(
        entries.len() <= MAX_DIRECTORY_ENTRIES,
        "directory v3 chunk too large: {}",
        entries.len()
    );
    let count = entries.len() as u16;
    let mut out =
        Vec::with_capacity(DIRECTORY_HEADER_LEN + entries.len() * DIRECTORY_ENTRY_V3_LEN);
    out.push(DIRECTORY_VERSION_V3);
    out.push(0); // reserved
    out.extend_from_slice(&count.to_be_bytes());
    for (pubkey, ticket, hops) in entries {
        out.extend_from_slice(pubkey);
        out.extend_from_slice(&encode_ticket(ticket));
        out.push(*hops);
    }
    out
}

/// Parse a FederationDirectory payload. Accepts v2 (treats every
/// entry as hops=0) AND v3 (reads the hops byte). Returns triples
/// `(pubkey, ticket, hops)`. Does NOT verify ticket signatures —
/// see `handle_federation_directory` for that.
///
/// Used as the unified parse path; new callers should prefer this
/// over the legacy v2-only `parse_directory`.
pub fn parse_directory_v3(
    bytes: &[u8],
) -> Result<Vec<([u8; 32], PresenceTicket, u8)>, DriftError> {
    if bytes.len() < DIRECTORY_HEADER_LEN {
        return Err(DriftError::DecodeError);
    }
    let version = bytes[0];
    let entry_len = match version {
        DIRECTORY_VERSION_V2 => DIRECTORY_ENTRY_LEN,
        DIRECTORY_VERSION_V3 => DIRECTORY_ENTRY_V3_LEN,
        _ => return Err(DriftError::DecodeError),
    };
    if bytes[1] != 0 {
        return Err(DriftError::DecodeError);
    }
    let count = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let expected_len = DIRECTORY_HEADER_LEN + count * entry_len;
    if bytes.len() != expected_len {
        return Err(DriftError::DecodeError);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = DIRECTORY_HEADER_LEN + i * entry_len;
        let mut p = [0u8; 32];
        p.copy_from_slice(&bytes[off..off + 32]);
        let ticket = decode_ticket(&bytes[off + 32..off + 32 + TICKET_LEN])?;
        let hops = if version == DIRECTORY_VERSION_V3 {
            bytes[off + 32 + TICKET_LEN]
        } else {
            0
        };
        out.push((p, ticket, hops));
    }
    Ok(out)
}

// ─── FederationDirectory v4 (Phase F — DP bloom filter) ──────────
//
// v4 is v3 with an optional bloom filter section appended:
//
// ```text
//   [0]            version (u8) = 4
//   [1]            reserved (u8) = 0
//   [2..4]         count (u16 BE) — direct entries, each 129 bytes
//   [4..N]         entries (count × 129 bytes, v3-shaped)
//   [N..N+2]       filter_bytes_len (u16 BE) — length of the bloom bits
//   [N+2..M]       bloom_bytes (filter_bytes_len bytes)
//   [M]            k (u8) — number of hash functions
//   [M+1..M+1+16]  salt (BLOOM_SALT_LEN bytes)
// ```
//
// `filter_bytes_len == 0` means "no bloom on this announce"
// (signal-equivalent to a v3 packet, but still labelled v4 so
// receivers know the sender is on this protocol version).

use crate::transport::dp_bloom::{DpBloomFilter, BLOOM_SALT_LEN};

/// Build a v4 directory payload from (pubkey, ticket, hops)
/// triples + an optional bloom filter.
///
/// Cap on direct entries when a bloom is included:
/// `MAX_DIRECTORY_ENTRIES_V4` (8) — leaves room for a
/// ~150-byte bloom under MAX_PAYLOAD. Callers MUST observe
/// the cap; the function will panic in debug builds otherwise.
pub fn build_directory_v4(
    entries: &[([u8; 32], PresenceTicket, u8)],
    bloom: Option<&DpBloomFilter>,
) -> Vec<u8> {
    debug_assert!(
        if bloom.is_some() {
            entries.len() <= MAX_DIRECTORY_ENTRIES_V4
        } else {
            entries.len() <= MAX_DIRECTORY_ENTRIES
        },
        "v4 chunk too large: {} entries with bloom={}",
        entries.len(),
        bloom.is_some()
    );
    let bloom_bytes_len = bloom.map(|b| b.bits.len()).unwrap_or(0);
    let bloom_metadata = if bloom.is_some() { 2 + 1 + BLOOM_SALT_LEN } else { 2 };
    let count = entries.len() as u16;
    let mut out = Vec::with_capacity(
        DIRECTORY_HEADER_LEN
            + entries.len() * DIRECTORY_ENTRY_V3_LEN
            + bloom_metadata
            + bloom_bytes_len,
    );
    out.push(DIRECTORY_VERSION_V4);
    out.push(0); // reserved
    out.extend_from_slice(&count.to_be_bytes());
    for (pubkey, ticket, hops) in entries {
        out.extend_from_slice(pubkey);
        out.extend_from_slice(&encode_ticket(ticket));
        out.push(*hops);
    }
    // Bloom section.
    let len = bloom_bytes_len as u16;
    out.extend_from_slice(&len.to_be_bytes());
    if let Some(b) = bloom {
        out.extend_from_slice(&b.bits);
        out.push(b.k);
        out.extend_from_slice(&b.salt);
    }
    out
}

/// Parse a directory payload (v2, v3, or v4). Returns the
/// entries plus the optional bloom filter on v4.
///
/// v2 entries are returned as hops=0 (same as `parse_directory_v3`).
/// v4 with `filter_bytes_len == 0` returns `None` for the filter.
pub fn parse_directory_v4(
    bytes: &[u8],
) -> Result<(Vec<([u8; 32], PresenceTicket, u8)>, Option<DpBloomFilter>), DriftError> {
    if bytes.len() < DIRECTORY_HEADER_LEN {
        return Err(DriftError::DecodeError);
    }
    let version = bytes[0];
    if bytes[1] != 0 {
        return Err(DriftError::DecodeError);
    }
    let count = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    match version {
        DIRECTORY_VERSION_V2 | DIRECTORY_VERSION_V3 => {
            // Delegate to v3 parser (which already accepts v2).
            let entries = parse_directory_v3(bytes)?;
            Ok((entries, None))
        }
        DIRECTORY_VERSION_V4 => {
            let entries_end = DIRECTORY_HEADER_LEN + count * DIRECTORY_ENTRY_V3_LEN;
            if bytes.len() < entries_end + 2 {
                return Err(DriftError::DecodeError);
            }
            let mut entries = Vec::with_capacity(count);
            for i in 0..count {
                let off = DIRECTORY_HEADER_LEN + i * DIRECTORY_ENTRY_V3_LEN;
                let mut p = [0u8; 32];
                p.copy_from_slice(&bytes[off..off + 32]);
                let ticket = decode_ticket(&bytes[off + 32..off + 32 + TICKET_LEN])?;
                let hops = bytes[off + 32 + TICKET_LEN];
                entries.push((p, ticket, hops));
            }
            let filter_bytes_len =
                u16::from_be_bytes([bytes[entries_end], bytes[entries_end + 1]]) as usize;
            if filter_bytes_len == 0 {
                if bytes.len() != entries_end + 2 {
                    return Err(DriftError::DecodeError);
                }
                return Ok((entries, None));
            }
            let expected =
                entries_end + 2 + filter_bytes_len + 1 + BLOOM_SALT_LEN;
            if bytes.len() != expected {
                return Err(DriftError::DecodeError);
            }
            let bits_start = entries_end + 2;
            let bits = bytes[bits_start..bits_start + filter_bytes_len].to_vec();
            let k = bytes[bits_start + filter_bytes_len];
            let mut salt = [0u8; BLOOM_SALT_LEN];
            salt.copy_from_slice(
                &bytes[bits_start + filter_bytes_len + 1..bits_start + filter_bytes_len + 1 + BLOOM_SALT_LEN],
            );
            // Sanity: m must be at most bits.len() * 8 and > 0.
            let m_bytes = filter_bytes_len;
            let m_bits = (m_bytes * 8) as u16;
            if m_bits == 0 || k == 0 {
                return Err(DriftError::DecodeError);
            }
            Ok((
                entries,
                Some(DpBloomFilter {
                    bits,
                    m: m_bits,
                    k,
                    salt,
                }),
            ))
        }
        _ => Err(DriftError::DecodeError),
    }
}

/// Parse a FederationDirectory v2 payload into (pubkey, ticket)
/// pairs. Returns `DecodeError` on truncation, wrong version, or
/// non-zero reserved.
///
/// Does NOT verify ticket signatures — that's the receiver's job
/// in `handle_federation_directory` (where it can drop bad
/// entries one at a time without invalidating the whole packet
/// and can apply per-entry metrics).
pub fn parse_directory(bytes: &[u8]) -> Result<Vec<([u8; 32], PresenceTicket)>, DriftError> {
    if bytes.len() < DIRECTORY_HEADER_LEN {
        return Err(DriftError::DecodeError);
    }
    if bytes[0] != DIRECTORY_VERSION {
        return Err(DriftError::DecodeError);
    }
    // Reserved byte must be 0 — any other value is non-conforming
    // and reserved for future protocol extensions. Reject rather
    // than silently accept so build∘parse stays an identity and
    // future-version peers get a clean version bump signal.
    if bytes[1] != 0 {
        return Err(DriftError::DecodeError);
    }
    let count = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let expected_len = DIRECTORY_HEADER_LEN + count * DIRECTORY_ENTRY_LEN;
    if bytes.len() != expected_len {
        return Err(DriftError::DecodeError);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = DIRECTORY_HEADER_LEN + i * DIRECTORY_ENTRY_LEN;
        let mut p = [0u8; 32];
        p.copy_from_slice(&bytes[off..off + 32]);
        let ticket = decode_ticket(&bytes[off + 32..off + DIRECTORY_ENTRY_LEN])?;
        out.push((p, ticket));
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

    /// Test helper: synthesize a (pubkey, ticket) entry signed by
    /// `client_secret` for the given `bridge_pub`. Used across the
    /// directory and ticket-verification tests.
    fn fake_entry(
        client_secret: &[u8; 32],
        bridge_pub: &[u8; 32],
        expiry_ms: u64,
    ) -> ([u8; 32], PresenceTicket) {
        let client_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*client_secret))
                .to_bytes();
        let ticket = build_ticket(
            client_secret,
            bridge_pub,
            expiry_ms,
            [0x11; TICKET_NONCE_LEN],
            &[0x22; 64],
        );
        (client_pub, ticket)
    }

    #[test]
    fn directory_roundtrip() {
        let bridge_pub = [0xDD; 32];
        let entries = vec![
            fake_entry(&[0x01; 32], &bridge_pub, 9_999_999_999_999),
            fake_entry(&[0x02; 32], &bridge_pub, 9_999_999_999_999),
            fake_entry(&[0x03; 32], &bridge_pub, 9_999_999_999_999),
        ];
        let wire = build_directory(&entries);
        let parsed = parse_directory(&wire).unwrap();
        assert_eq!(parsed, entries);
    }

    #[test]
    fn directory_empty() {
        let wire = build_directory(&[]);
        let parsed = parse_directory(&wire).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn directory_rejects_wrong_version() {
        let entries = vec![fake_entry(&[0x07; 32], &[0xDD; 32], 9_999_999_999_999)];
        let mut wire = build_directory(&entries);
        wire[0] = 0xFF;
        assert!(parse_directory(&wire).is_err());
    }

    #[test]
    fn directory_rejects_truncation() {
        let entries = vec![
            fake_entry(&[0x08; 32], &[0xDD; 32], 9_999_999_999_999),
            fake_entry(&[0x09; 32], &[0xDD; 32], 9_999_999_999_999),
        ];
        let wire = build_directory(&entries);
        let short = &wire[..wire.len() - 1];
        assert!(parse_directory(short).is_err());
    }

    /// Regression: fuzzer (`federation_directory_decode`) caught
    /// the reserved byte being unvalidated — `[2, 86, 0, 0]` would
    /// parse to an empty Vec while `build_directory` always emits
    /// reserved=0, breaking `build∘parse` identity. Parser now
    /// rejects any non-zero reserved.
    #[test]
    fn directory_rejects_non_zero_reserved() {
        let wire = [DIRECTORY_VERSION, 0x56, 0x00, 0x00];
        assert!(parse_directory(&wire).is_err());
    }

    // ─── Presence-ticket tests ───────────────────────────────────

    #[test]
    fn ticket_codec_roundtrips() {
        let (_pub, ticket) = fake_entry(&[0x41; 32], &[0xAB; 32], 1_000);
        let wire = encode_ticket(&ticket);
        let parsed = decode_ticket(&wire).unwrap();
        assert_eq!(parsed, ticket);
    }

    #[test]
    fn ticket_verify_accepts_legitimate() {
        let bridge_pub = [0x55; 32];
        let (client_pub, ticket) = fake_entry(&[0x42; 32], &bridge_pub, 9_999_999_999_999);
        verify_ticket(&client_pub, &bridge_pub, &ticket, 0).expect("must verify");
    }

    /// A ticket signed for bridge X MUST NOT verify when presented
    /// to a third party as a ticket-for-bridge-Y. This is the
    /// core anti-hijack property — a malicious bridge B_evil can't
    /// re-use a real ticket signed for B_real.
    #[test]
    fn ticket_verify_rejects_wrong_bridge() {
        let bridge_a = [0x55; 32];
        let bridge_b = [0x66; 32];
        let (client_pub, ticket) = fake_entry(&[0x43; 32], &bridge_a, 9_999_999_999_999);
        assert!(verify_ticket(&client_pub, &bridge_b, &ticket, 0).is_err());
    }

    /// Expired tickets MUST be rejected even with valid signatures.
    #[test]
    fn ticket_verify_rejects_expired() {
        let bridge_pub = [0x55; 32];
        let (client_pub, ticket) = fake_entry(&[0x44; 32], &bridge_pub, 1_000);
        // now_ms = expiry exactly → rejected (strict-less-than).
        assert!(verify_ticket(&client_pub, &bridge_pub, &ticket, 1_000).is_err());
        // now_ms > expiry → rejected.
        assert!(verify_ticket(&client_pub, &bridge_pub, &ticket, 5_000).is_err());
    }

    /// Tampered signature MUST NOT verify.
    #[test]
    fn ticket_verify_rejects_tampered_sig() {
        let bridge_pub = [0x55; 32];
        let (client_pub, mut ticket) = fake_entry(&[0x45; 32], &bridge_pub, 9_999_999_999_999);
        ticket.sig[10] ^= 0x80;
        assert!(verify_ticket(&client_pub, &bridge_pub, &ticket, 0).is_err());
    }

    /// Wrong client pubkey MUST NOT verify (a malicious bridge
    /// can't claim someone else's pubkey).
    #[test]
    fn ticket_verify_rejects_wrong_client() {
        let bridge_pub = [0x55; 32];
        let (_real_client, ticket) = fake_entry(&[0x46; 32], &bridge_pub, 9_999_999_999_999);
        let attacker_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            [0x47u8; 32],
        ))
        .to_bytes();
        assert!(verify_ticket(&attacker_pub, &bridge_pub, &ticket, 0).is_err());
    }

    // ─── Directory v3 (Phase C) ──────────────────────────────────

    #[test]
    fn directory_v3_roundtrip_with_mixed_hops() {
        let bridge = [0x10; 32];
        let (pa, ta) = fake_entry(&[0x20; 32], &bridge, 9_999_999_999_999);
        let (pb, tb) = fake_entry(&[0x21; 32], &bridge, 9_999_999_999_999);
        let (pc, tc) = fake_entry(&[0x22; 32], &bridge, 9_999_999_999_999);
        let entries = vec![(pa, ta.clone(), 0u8), (pb, tb.clone(), 1u8), (pc, tc.clone(), 2u8)];
        let wire = build_directory_v3(&entries);
        let parsed = parse_directory_v3(&wire).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], (pa, ta, 0));
        assert_eq!(parsed[1], (pb, tb, 1));
        assert_eq!(parsed[2], (pc, tc, 2));
    }

    #[test]
    fn directory_v3_parser_accepts_v2_as_hops_zero() {
        // Build an old-style v2 payload, parse with the v3
        // parser, expect hops=0 for every entry.
        let bridge = [0xAB; 32];
        let (pa, ta) = fake_entry(&[0xA0; 32], &bridge, 9_999_999_999_999);
        let v2_payload = build_directory(&[(pa, ta.clone())]);
        let parsed = parse_directory_v3(&v2_payload).unwrap();
        assert_eq!(parsed, vec![(pa, ta, 0)]);
    }

    #[test]
    fn directory_v3_parser_rejects_unknown_version() {
        let mut bytes = vec![99u8, 0, 0, 0];
        assert!(parse_directory_v3(&bytes).is_err());
        // And truncated.
        bytes.clear();
        bytes.push(3);
        assert!(parse_directory_v3(&bytes).is_err());
    }

    #[test]
    fn directory_v3_legacy_v2_parser_rejects_v3() {
        // Old v2-only callers must reject v3 payloads (silent
        // drop in the receive path).
        let bridge = [0xCC; 32];
        let (p, t) = fake_entry(&[0xC0; 32], &bridge, 9_999_999_999_999);
        let v3 = build_directory_v3(&[(p, t, 0)]);
        assert!(parse_directory(&v3).is_err());
    }

    // ─── Directory v4 (Phase F — bloom filter) ───────────────────

    #[test]
    fn directory_v4_roundtrip_without_bloom() {
        let bridge = [0xD0; 32];
        let (p, t) = fake_entry(&[0xD1; 32], &bridge, 9_999_999_999_999);
        let entries = vec![(p, t.clone(), 0u8)];
        let wire = build_directory_v4(&entries, None);
        let (parsed_entries, parsed_bloom) = parse_directory_v4(&wire).unwrap();
        assert_eq!(parsed_entries.len(), 1);
        assert_eq!(parsed_entries[0], (p, t, 0));
        assert!(parsed_bloom.is_none());
    }

    #[test]
    fn directory_v4_roundtrip_with_bloom() {
        use crate::transport::dp_bloom::DpBloomFilter;
        let bridge = [0xE0; 32];
        let (p, t) = fake_entry(&[0xE1; 32], &bridge, 9_999_999_999_999);
        let entries = vec![(p, t.clone(), 0u8)];
        let mut bloom = DpBloomFilter::new(1024, 4, [0xAA; 16]);
        bloom.insert(&[0xE1; 32]);
        let wire = build_directory_v4(&entries, Some(&bloom));
        let (parsed_entries, parsed_bloom) = parse_directory_v4(&wire).unwrap();
        assert_eq!(parsed_entries, vec![(p, t, 0)]);
        let parsed_bloom = parsed_bloom.expect("bloom missing");
        assert_eq!(parsed_bloom.bits, bloom.bits);
        assert_eq!(parsed_bloom.m, bloom.m);
        assert_eq!(parsed_bloom.k, bloom.k);
        assert_eq!(parsed_bloom.salt, bloom.salt);
        // Roundtrip preserves membership tests.
        assert!(parsed_bloom.contains(&[0xE1; 32]));
        assert!(!parsed_bloom.contains(&[0xFF; 32]));
    }

    #[test]
    fn directory_v4_parser_accepts_v3_and_v2_as_no_bloom() {
        let bridge = [0xF0; 32];
        let (p, t) = fake_entry(&[0xF1; 32], &bridge, 9_999_999_999_999);
        let v3 = build_directory_v3(&[(p, t.clone(), 1)]);
        let (entries, bloom) = parse_directory_v4(&v3).unwrap();
        assert_eq!(entries, vec![(p, t.clone(), 1)]);
        assert!(bloom.is_none());

        let v2 = build_directory(&[(p, t.clone())]);
        let (entries2, bloom2) = parse_directory_v4(&v2).unwrap();
        assert_eq!(entries2, vec![(p, t, 0)]);
        assert!(bloom2.is_none());
    }

    #[test]
    fn directory_v4_rejects_unknown_version_and_truncation() {
        let mut bytes = vec![99u8, 0, 0, 0];
        assert!(parse_directory_v4(&bytes).is_err());
        // Truncated v4 with claimed bloom-filter-len overshoot.
        let bridge = [0; 32];
        let (p, t) = fake_entry(&[0x10; 32], &bridge, 9_999_999_999_999);
        let mut wire = build_directory_v4(&[(p, t, 0)], None);
        wire.pop(); // truncate one byte
        assert!(parse_directory_v4(&wire).is_err());
        bytes.clear();
        bytes.push(DIRECTORY_VERSION_V4);
        assert!(parse_directory_v4(&bytes).is_err());
    }

    #[test]
    fn directory_v3_parser_rejects_v4() {
        // v3 receivers must drop v4 packets silently.
        use crate::transport::dp_bloom::DpBloomFilter;
        let bridge = [0x11; 32];
        let (p, t) = fake_entry(&[0x12; 32], &bridge, 9_999_999_999_999);
        let bloom = DpBloomFilter::new(64, 2, [0; 16]);
        let v4 = build_directory_v4(&[(p, t, 0)], Some(&bloom));
        assert!(parse_directory_v3(&v4).is_err());
        assert!(parse_directory(&v4).is_err());
    }
}
