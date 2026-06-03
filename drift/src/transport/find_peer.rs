//! Wire codecs for federation peer discovery (Phase A).
//!
//! See `FEDERATION_DISCOVERY.md` §5 for the full protocol spec.
//! Three new message types are defined here:
//!
//! - `FindPeer`  (PacketType 22) — "does any federation peer host
//!   pubkey X?" — bridge originates when its local directory lookup
//!   misses.
//! - `PeerHere` (PacketType 23) — reply carrying a chain of
//!   `(bridge_pub, PresenceTicket)` entries proving the target's
//!   location. For Phase A the chain has exactly one entry.
//! - `PeerGone` (PacketType 24) — "client X just disconnected from
//!   me; flush caches." Broadcast to every federation peer on local
//!   session teardown.
//!
//! Encoded payloads travel inside the AEAD-sealed body of their
//! respective `PacketType`. This module is wire-only — handler logic
//! and per-bridge state live in `transport/mod.rs`.
//!
//! ## Wire layouts
//!
//! `FindPeer` — 81 bytes:
//!
//! ```text
//!   [0..32]    target_client_pub
//!   [32..40]   query_id            (u64 BE)
//!   [40..41]   ttl                 (u8 — hops remaining; Phase A = 1)
//!   [41..73]   originator_bridge   (the bridge that originated; reply destination)
//!   [73..81]   originator_query_at_ms (u64 BE — for deadline enforcement)
//! ```
//!
//! `PeerHere` — 41 + path_len * 128 bytes:
//!
//! ```text
//!   [0..32]    target_client_pub
//!   [32..40]   query_id            (u64 BE)
//!   [40..41]   path_len            (u8; 1..=MAX_FIND_TTL)
//!   [41..]     path_entries        (path_len * 128 bytes)
//!
//! Each path_entry (128 bytes):
//!   [0..32]    bridge_pub
//!   [32..128]  ticket              (96 bytes — see federated::TICKET_LEN)
//! ```
//!
//! `PeerGone` — 72 bytes:
//!
//! ```text
//!   [0..32]    client_pub
//!   [32..40]   emitted_at_ms       (u64 BE)
//!   [40..72]   bridge_pub          (emitting bridge — for cache eviction matching)
//! ```

use crate::error::{CodecError, DriftError, Result};
use crate::transport::federated::{
    decode_ticket, encode_ticket, PresenceTicket, TICKET_LEN, TICKET_NONCE_LEN,
};

// ─── Hop attestations (intermediate path-entry signing) ──────────
//
// Phase B used zero-padded "stub" tickets for the intermediate
// entries in `PeerHere.path`. That left the path[1..] entries
// cryptographically unverifiable — a downstream receiver could
// only verify path[0] (the terminal client-signed ticket).
//
// This module adds **bridge-self-signed hop attestations** for
// the intermediate entries. Each forwarder signs a message
// binding (bridge_pub, query_id, expiry, nonce) with its own
// XEdDSA key. Receivers verify every hop. A malicious bridge can
// still drop or refuse to forward, but it cannot:
//   - forge a path entry claiming a bridge that didn't participate
//   - replay an attestation from one query into another
//     (query_id is part of the signed message)
//   - replay an old attestation past its expiry
//
// On-wire the attestation reuses `PresenceTicket`'s 96-byte
// shape — the bytes are identical to a presence ticket on the
// wire, but the SIGNED MESSAGE differs: presence tickets sign
// `bridge_pub || expiry || nonce`; hop attestations sign
// `"DRIFT-HOP" || bridge_pub || query_id || expiry || nonce`.
// Domain separation via the 9-byte tag prevents one being
// substituted for the other.

/// Domain-separation prefix for hop-attestation signed messages.
/// Distinct from presence-ticket signing so an attacker can't
/// re-purpose a presence ticket as a hop attestation or vice
/// versa.
pub const HOP_DOMAIN_TAG: &[u8] = b"DRIFT-HOP";

/// Canonical message bytes a forwarder signs to attest its
/// position in the path. Verifier reconstructs this exactly.
pub fn hop_attestation_signed_msg(
    bridge_pub: &[u8; 32],
    query_id: u64,
    expiry_ms: u64,
    nonce: &[u8; TICKET_NONCE_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HOP_DOMAIN_TAG.len() + 32 + 8 + 8 + TICKET_NONCE_LEN);
    out.extend_from_slice(HOP_DOMAIN_TAG);
    out.extend_from_slice(bridge_pub);
    out.extend_from_slice(&query_id.to_be_bytes());
    out.extend_from_slice(&expiry_ms.to_be_bytes());
    out.extend_from_slice(nonce);
    out
}

/// Build a fresh hop attestation. The caller provides a signer
/// closure that signs the canonical message. Typical caller
/// passes `|msg| identity.xeddsa_sign(msg, &nonce_extra)`.
pub fn build_hop_attestation<S: FnOnce(&[u8]) -> [u8; 64]>(
    bridge_pub: &[u8; 32],
    query_id: u64,
    expiry_ms: u64,
    nonce: [u8; TICKET_NONCE_LEN],
    sign: S,
) -> PresenceTicket {
    let msg = hop_attestation_signed_msg(bridge_pub, query_id, expiry_ms, &nonce);
    let sig = sign(&msg);
    PresenceTicket {
        expiry_ms,
        nonce,
        sig,
    }
}

/// Verify a hop attestation against the forwarder's pubkey. The
/// `query_id` is rebuilt by the caller from the surrounding
/// `PeerHere` reply.
pub fn verify_hop_attestation(
    bridge_pub: &[u8; 32],
    query_id: u64,
    ticket: &PresenceTicket,
    now_ms: u64,
) -> Result<()> {
    if ticket.expiry_ms <= now_ms {
        return Err(DriftError::AuthFailed);
    }
    let msg = hop_attestation_signed_msg(bridge_pub, query_id, ticket.expiry_ms, &ticket.nonce);
    drift_core::xeddsa::verify(bridge_pub, &msg, &ticket.sig).map_err(|_| DriftError::AuthFailed)
}

// ─── Protocol constants ──────────────────────────────────────────

/// Maximum number of bridge hops a `FindPeer` query may traverse.
/// Phase A pins this to 1 (direct federation neighbors only); Phase B
/// raises to 4 once loop-detection + multi-hop reply assembly land.
pub const MAX_FIND_TTL: u8 = 4;

/// Hard deadline a `FindPeer` query is valid for, from the
/// originator's emission timestamp. Receivers MUST drop queries whose
/// `originator_query_at_ms + MAX_FIND_DEADLINE_MS < now_ms()`.
pub const MAX_FIND_DEADLINE_MS: u64 = 2_000;

/// How long a bridge remembers `query_id`s for loop-detection.
/// Identical `query_id` arrivals within this window are silently
/// dropped.
pub const QUERY_DEDUP_TTL_MS: u64 = 10_000;

/// How long a "not found" answer is cached. Bounds re-query storms
/// for peers that don't exist anywhere in the federation.
pub const NEG_CACHE_TTL_MS: u64 = 5_000;

// ─── FindPeer ────────────────────────────────────────────────────

/// On-wire length of a `FindPeer` payload.
pub const FIND_PEER_LEN: usize = 32 + 8 + 1 + 32 + 8;

/// Parsed view of a `FindPeer` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindPeer {
    pub target_client_pub: [u8; 32],
    pub query_id: u64,
    pub ttl: u8,
    pub originator_bridge: [u8; 32],
    pub originator_query_at_ms: u64,
}

/// Serialize a `FindPeer` to a fresh `Vec<u8>`.
pub fn build_find_peer(q: &FindPeer) -> Vec<u8> {
    let mut out = Vec::with_capacity(FIND_PEER_LEN);
    out.extend_from_slice(&q.target_client_pub);
    out.extend_from_slice(&q.query_id.to_be_bytes());
    out.push(q.ttl);
    out.extend_from_slice(&q.originator_bridge);
    out.extend_from_slice(&q.originator_query_at_ms.to_be_bytes());
    out
}

/// Parse a `FindPeer` payload. Rejects non-canonical lengths and
/// `ttl == 0` (queries must carry at least one hop's worth of TTL
/// on the wire).
pub fn parse_find_peer(bytes: &[u8]) -> Result<FindPeer> {
    if bytes.len() != FIND_PEER_LEN {
        return Err(CodecError::Malformed.into());
    }
    let mut target_client_pub = [0u8; 32];
    target_client_pub.copy_from_slice(&bytes[0..32]);
    let query_id = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let ttl = bytes[40];
    if ttl == 0 {
        return Err(CodecError::Malformed.into());
    }
    let mut originator_bridge = [0u8; 32];
    originator_bridge.copy_from_slice(&bytes[41..73]);
    let originator_query_at_ms = u64::from_be_bytes(bytes[73..81].try_into().unwrap());
    Ok(FindPeer {
        target_client_pub,
        query_id,
        ttl,
        originator_bridge,
        originator_query_at_ms,
    })
}

// ─── FindPeerHashed (Phase E privacy) ────────────────────────────

/// Length of the per-query salt used by `FindPeerHashed`. Short
/// enough to keep the wire compact, long enough that an adversary
/// can't brute-force collisions across queries.
pub const FIND_PEER_HASHED_SALT_LEN: usize = 16;

/// Length of the SHA-256 hash of `target_pub || salt`.
pub const FIND_PEER_HASHED_DIGEST_LEN: usize = 32;

/// On-wire length of a `FindPeerHashed` payload.
pub const FIND_PEER_HASHED_LEN: usize =
    FIND_PEER_HASHED_SALT_LEN + FIND_PEER_HASHED_DIGEST_LEN + 8 + 1 + 32 + 8;

/// Hashed variant of `FindPeer` for privacy-conscious lookups.
/// The originator hashes the target pubkey with a fresh per-query
/// salt; transit bridges see only the hash. Bridges hosting local
/// clients scan their presence tickets, hashing each client_pub
/// with the same salt, and reply with `PeerHere` on a match (the
/// reply carries the *real* target pubkey, since once found the
/// route needs to be addressable).
///
/// See `FEDERATION_DISCOVERY.md` §5.5 for the threat model and
/// the asymmetric privacy property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindPeerHashed {
    pub salt: [u8; FIND_PEER_HASHED_SALT_LEN],
    pub target_hash: [u8; FIND_PEER_HASHED_DIGEST_LEN],
    pub query_id: u64,
    pub ttl: u8,
    pub originator_bridge: [u8; 32],
    pub originator_query_at_ms: u64,
}

/// Hash a candidate pubkey under the query's salt. Used both by
/// originators (when building a `FindPeerHashed`) and by receivers
/// (when scanning their local clients for a match).
pub fn hash_target_pub(
    target_pub: &[u8; 32],
    salt: &[u8; FIND_PEER_HASHED_SALT_LEN],
) -> [u8; FIND_PEER_HASHED_DIGEST_LEN] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(target_pub);
    h.update(salt);
    let out = h.finalize();
    let mut arr = [0u8; FIND_PEER_HASHED_DIGEST_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// Serialize a `FindPeerHashed` to a fresh `Vec<u8>`.
pub fn build_find_peer_hashed(q: &FindPeerHashed) -> Vec<u8> {
    let mut out = Vec::with_capacity(FIND_PEER_HASHED_LEN);
    out.extend_from_slice(&q.salt);
    out.extend_from_slice(&q.target_hash);
    out.extend_from_slice(&q.query_id.to_be_bytes());
    out.push(q.ttl);
    out.extend_from_slice(&q.originator_bridge);
    out.extend_from_slice(&q.originator_query_at_ms.to_be_bytes());
    out
}

/// Parse a `FindPeerHashed` payload. Rejects non-canonical lengths
/// and `ttl == 0`.
pub fn parse_find_peer_hashed(bytes: &[u8]) -> Result<FindPeerHashed> {
    if bytes.len() != FIND_PEER_HASHED_LEN {
        return Err(CodecError::Malformed.into());
    }
    let mut salt = [0u8; FIND_PEER_HASHED_SALT_LEN];
    salt.copy_from_slice(&bytes[0..16]);
    let mut target_hash = [0u8; FIND_PEER_HASHED_DIGEST_LEN];
    target_hash.copy_from_slice(&bytes[16..48]);
    let query_id = u64::from_be_bytes(bytes[48..56].try_into().unwrap());
    let ttl = bytes[56];
    if ttl == 0 {
        return Err(CodecError::Malformed.into());
    }
    let mut originator_bridge = [0u8; 32];
    originator_bridge.copy_from_slice(&bytes[57..89]);
    let originator_query_at_ms = u64::from_be_bytes(bytes[89..97].try_into().unwrap());
    Ok(FindPeerHashed {
        salt,
        target_hash,
        query_id,
        ttl,
        originator_bridge,
        originator_query_at_ms,
    })
}

// ─── PeerHere ────────────────────────────────────────────────────

/// On-wire length of a single `PathEntry`: bridge_pub (32) + ticket
/// (96) = 128 bytes.
pub const PATH_ENTRY_LEN: usize = 32 + TICKET_LEN;

/// Fixed header length of a `PeerHere` payload (everything before
/// the variable path_entries section).
pub const PEER_HERE_HEADER_LEN: usize = 32 + 8 + 1;

/// One hop in a discovered route. `bridge_pub` is the bridge that
/// signed this entry's `ticket`; the ticket is the client's
/// XEdDSA-signed presence attestation for that bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathEntry {
    pub bridge_pub: [u8; 32],
    pub ticket: PresenceTicket,
}

/// Parsed view of a `PeerHere` payload. `path[0]` is the terminal
/// bridge that actually holds the client; later entries (Phase B+)
/// are forwarding hops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHere {
    pub target_client_pub: [u8; 32],
    pub query_id: u64,
    pub path: Vec<PathEntry>,
}

/// Serialize a `PeerHere` to a fresh `Vec<u8>`. Caller MUST keep
/// `path.len()` in `1..=MAX_FIND_TTL as usize`.
pub fn build_peer_here(reply: &PeerHere) -> Vec<u8> {
    debug_assert!(
        !reply.path.is_empty() && reply.path.len() <= MAX_FIND_TTL as usize,
        "PeerHere path_len out of range: {}",
        reply.path.len()
    );
    let mut out = Vec::with_capacity(PEER_HERE_HEADER_LEN + reply.path.len() * PATH_ENTRY_LEN);
    out.extend_from_slice(&reply.target_client_pub);
    out.extend_from_slice(&reply.query_id.to_be_bytes());
    out.push(reply.path.len() as u8);
    for entry in &reply.path {
        out.extend_from_slice(&entry.bridge_pub);
        out.extend_from_slice(&encode_ticket(&entry.ticket));
    }
    out
}

/// Parse a `PeerHere` payload. Rejects truncated buffers, `path_len`
/// outside `1..=MAX_FIND_TTL`, and any extra trailing bytes.
pub fn parse_peer_here(bytes: &[u8]) -> Result<PeerHere> {
    if bytes.len() < PEER_HERE_HEADER_LEN {
        return Err(CodecError::Malformed.into());
    }
    let mut target_client_pub = [0u8; 32];
    target_client_pub.copy_from_slice(&bytes[0..32]);
    let query_id = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let path_len = bytes[40] as usize;
    if path_len == 0 || path_len > MAX_FIND_TTL as usize {
        return Err(CodecError::Malformed.into());
    }
    let expected = PEER_HERE_HEADER_LEN + path_len * PATH_ENTRY_LEN;
    if bytes.len() != expected {
        return Err(CodecError::Malformed.into());
    }
    let mut path = Vec::with_capacity(path_len);
    for i in 0..path_len {
        let off = PEER_HERE_HEADER_LEN + i * PATH_ENTRY_LEN;
        let mut bridge_pub = [0u8; 32];
        bridge_pub.copy_from_slice(&bytes[off..off + 32]);
        let ticket = decode_ticket(&bytes[off + 32..off + PATH_ENTRY_LEN])?;
        path.push(PathEntry { bridge_pub, ticket });
    }
    Ok(PeerHere {
        target_client_pub,
        query_id,
        path,
    })
}

// ─── PeerGone ────────────────────────────────────────────────────

/// On-wire length of a `PeerGone` payload.
pub const PEER_GONE_LEN: usize = 32 + 8 + 32;

/// "Client X just disconnected from bridge Y." Sent to every
/// federation peer on local-session teardown. Receivers evict
/// matching cache entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerGone {
    pub client_pub: [u8; 32],
    pub emitted_at_ms: u64,
    pub bridge_pub: [u8; 32],
}

/// Serialize a `PeerGone` to a fresh `Vec<u8>`.
pub fn build_peer_gone(p: &PeerGone) -> Vec<u8> {
    let mut out = Vec::with_capacity(PEER_GONE_LEN);
    out.extend_from_slice(&p.client_pub);
    out.extend_from_slice(&p.emitted_at_ms.to_be_bytes());
    out.extend_from_slice(&p.bridge_pub);
    out
}

/// Parse a `PeerGone` payload. Rejects non-canonical lengths.
pub fn parse_peer_gone(bytes: &[u8]) -> Result<PeerGone> {
    if bytes.len() != PEER_GONE_LEN {
        return Err(CodecError::Malformed.into());
    }
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&bytes[0..32]);
    let emitted_at_ms = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let mut bridge_pub = [0u8; 32];
    bridge_pub.copy_from_slice(&bytes[40..72]);
    Ok(PeerGone {
        client_pub,
        emitted_at_ms,
        bridge_pub,
    })
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_ticket(seed: u8) -> PresenceTicket {
        PresenceTicket {
            expiry_ms: 0x0102_0304_0506_0708,
            nonce: [seed; 24],
            sig: [seed.wrapping_add(1); 64],
        }
    }

    #[test]
    fn find_peer_roundtrip() {
        let q = FindPeer {
            target_client_pub: [0xAA; 32],
            query_id: 0xDEAD_BEEF_CAFE_BABE,
            ttl: 1,
            originator_bridge: [0xBB; 32],
            originator_query_at_ms: 1_700_000_000_000,
        };
        let wire = build_find_peer(&q);
        assert_eq!(wire.len(), FIND_PEER_LEN);
        let parsed = parse_find_peer(&wire).unwrap();
        assert_eq!(parsed, q);
    }

    #[test]
    fn find_peer_rejects_ttl_zero() {
        let mut q = FindPeer {
            target_client_pub: [0; 32],
            query_id: 0,
            ttl: 1,
            originator_bridge: [0; 32],
            originator_query_at_ms: 0,
        };
        q.ttl = 0;
        let wire = build_find_peer(&q);
        assert!(parse_find_peer(&wire).is_err());
    }

    #[test]
    fn find_peer_truncation_errors() {
        let q = FindPeer {
            target_client_pub: [0; 32],
            query_id: 1,
            ttl: 1,
            originator_bridge: [0; 32],
            originator_query_at_ms: 0,
        };
        let wire = build_find_peer(&q);
        assert!(parse_find_peer(&wire[..wire.len() - 1]).is_err());
        let mut too_long = wire.clone();
        too_long.push(0);
        assert!(parse_find_peer(&too_long).is_err());
    }

    #[test]
    fn peer_here_single_hop_roundtrip() {
        let reply = PeerHere {
            target_client_pub: [0x42; 32],
            query_id: 0xABCD_1234_DEAD_FEED,
            path: vec![PathEntry {
                bridge_pub: [0x11; 32],
                ticket: dummy_ticket(7),
            }],
        };
        let wire = build_peer_here(&reply);
        assert_eq!(wire.len(), PEER_HERE_HEADER_LEN + PATH_ENTRY_LEN);
        let parsed = parse_peer_here(&wire).unwrap();
        assert_eq!(parsed, reply);
    }

    #[test]
    fn peer_here_max_hop_roundtrip() {
        let path: Vec<PathEntry> = (0..MAX_FIND_TTL)
            .map(|i| PathEntry {
                bridge_pub: [i; 32],
                ticket: dummy_ticket(i),
            })
            .collect();
        let reply = PeerHere {
            target_client_pub: [0xCC; 32],
            query_id: 0,
            path,
        };
        let wire = build_peer_here(&reply);
        let parsed = parse_peer_here(&wire).unwrap();
        assert_eq!(parsed, reply);
    }

    #[test]
    fn peer_here_rejects_zero_or_overflow_path_len() {
        let reply = PeerHere {
            target_client_pub: [0; 32],
            query_id: 0,
            path: vec![PathEntry {
                bridge_pub: [0; 32],
                ticket: dummy_ticket(0),
            }],
        };
        let mut wire = build_peer_here(&reply);
        // Tamper the path_len byte.
        wire[40] = 0;
        assert!(parse_peer_here(&wire).is_err());
        wire[40] = MAX_FIND_TTL + 1;
        assert!(parse_peer_here(&wire).is_err());
    }

    #[test]
    fn peer_here_rejects_truncation() {
        let reply = PeerHere {
            target_client_pub: [0; 32],
            query_id: 0,
            path: vec![PathEntry {
                bridge_pub: [0; 32],
                ticket: dummy_ticket(0),
            }],
        };
        let wire = build_peer_here(&reply);
        assert!(parse_peer_here(&wire[..wire.len() - 1]).is_err());
    }

    #[test]
    fn peer_gone_roundtrip() {
        let p = PeerGone {
            client_pub: [0x55; 32],
            emitted_at_ms: 0x0011_2233_4455_6677,
            bridge_pub: [0x99; 32],
        };
        let wire = build_peer_gone(&p);
        assert_eq!(wire.len(), PEER_GONE_LEN);
        let parsed = parse_peer_gone(&wire).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn peer_gone_rejects_short_or_long() {
        let p = PeerGone {
            client_pub: [0; 32],
            emitted_at_ms: 0,
            bridge_pub: [0; 32],
        };
        let wire = build_peer_gone(&p);
        assert!(parse_peer_gone(&wire[..wire.len() - 1]).is_err());
        let mut too_long = wire.clone();
        too_long.push(0);
        assert!(parse_peer_gone(&too_long).is_err());
    }

    #[test]
    fn hop_attestation_roundtrip() {
        let secret = [0x66u8; 32];
        let pubkey =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
        let nonce = [0xAA; 24];
        let nonce_extra = [0xBB; 64];
        let now_ms = 1_700_000_000_000u64;
        let expiry = now_ms + 60_000;
        let ticket = build_hop_attestation(&pubkey, 0xDEAD_BEEF_u64, expiry, nonce, |msg| {
            drift_core::xeddsa::sign(&secret, msg, &nonce_extra)
        });
        verify_hop_attestation(&pubkey, 0xDEAD_BEEF, &ticket, now_ms).unwrap();
    }

    #[test]
    fn hop_attestation_rejects_wrong_query_id() {
        let secret = [0x66u8; 32];
        let pubkey =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
        let nonce_extra = [0xCC; 64];
        let now_ms = 1_700_000_000_000u64;
        let expiry = now_ms + 60_000;
        let ticket = build_hop_attestation(&pubkey, 1, expiry, [0; 24], |msg| {
            drift_core::xeddsa::sign(&secret, msg, &nonce_extra)
        });
        // Replay into a different query_id: must fail.
        assert!(verify_hop_attestation(&pubkey, 2, &ticket, now_ms).is_err());
    }

    #[test]
    fn hop_attestation_rejects_expired() {
        let secret = [0x66u8; 32];
        let pubkey =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
        let nonce_extra = [0xDD; 64];
        let ticket = build_hop_attestation(&pubkey, 1, 1000, [0; 24], |msg| {
            drift_core::xeddsa::sign(&secret, msg, &nonce_extra)
        });
        // now_ms > expiry → reject.
        assert!(verify_hop_attestation(&pubkey, 1, &ticket, 5000).is_err());
    }

    #[test]
    fn hop_attestation_rejects_wrong_signer() {
        let signer_secret = [0x66u8; 32];
        let signer_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(signer_secret))
                .to_bytes();
        let imposter_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x99u8; 32]))
                .to_bytes();
        let nonce_extra = [0xEE; 64];
        let now_ms = 1_700_000_000_000u64;
        let expiry = now_ms + 60_000;
        let ticket = build_hop_attestation(&signer_pub, 1, expiry, [0; 24], |msg| {
            drift_core::xeddsa::sign(&signer_secret, msg, &nonce_extra)
        });
        // Verifier reconstructs the canonical msg using
        // imposter_pub — sig won't match.
        assert!(verify_hop_attestation(&imposter_pub, 1, &ticket, now_ms).is_err());
    }

    #[test]
    fn wire_size_constants_match_doc() {
        // FEDERATION_DISCOVERY.md §5.1
        assert_eq!(FIND_PEER_LEN, 81);
        // §5.2 (path_len = 1): 41 + 1*128 = 169
        assert_eq!(PEER_HERE_HEADER_LEN + PATH_ENTRY_LEN, 169);
        // §5.3
        assert_eq!(PEER_GONE_LEN, 72);
        // §5.5 (Phase E hashed lookup): salt 16 + digest 32 +
        // query_id 8 + ttl 1 + originator_bridge 32 +
        // originator_query_at_ms 8 = 97.
        assert_eq!(FIND_PEER_HASHED_LEN, 97);
    }

    // ─── FindPeerHashed (Phase E v2) ─────────────────────────────

    #[test]
    fn find_peer_hashed_roundtrip() {
        let q = FindPeerHashed {
            salt: [0xAA; FIND_PEER_HASHED_SALT_LEN],
            target_hash: [0xBB; FIND_PEER_HASHED_DIGEST_LEN],
            query_id: 0xDEAD_BEEF_CAFE_BABE,
            ttl: MAX_FIND_TTL,
            originator_bridge: [0xCC; 32],
            originator_query_at_ms: 1_700_000_000_000,
        };
        let wire = build_find_peer_hashed(&q);
        assert_eq!(wire.len(), FIND_PEER_HASHED_LEN);
        let parsed = parse_find_peer_hashed(&wire).unwrap();
        assert_eq!(parsed, q);
    }

    #[test]
    fn find_peer_hashed_rejects_ttl_zero_and_truncation() {
        let q = FindPeerHashed {
            salt: [0; 16],
            target_hash: [0; 32],
            query_id: 1,
            ttl: 1,
            originator_bridge: [0; 32],
            originator_query_at_ms: 0,
        };
        let mut wire = build_find_peer_hashed(&q);
        // Tamper ttl to 0 — must reject.
        wire[56] = 0;
        assert!(parse_find_peer_hashed(&wire).is_err());
        // Restore + truncate.
        wire[56] = 1;
        assert!(parse_find_peer_hashed(&wire[..wire.len() - 1]).is_err());
        // Append byte — must reject.
        let mut too_long = wire.clone();
        too_long.push(0);
        assert!(parse_find_peer_hashed(&too_long).is_err());
    }

    #[test]
    fn hash_target_pub_is_deterministic_and_salt_sensitive() {
        let pubkey = [0x42; 32];
        let salt_a = [0x01; 16];
        let salt_b = [0x02; 16];
        assert_eq!(
            hash_target_pub(&pubkey, &salt_a),
            hash_target_pub(&pubkey, &salt_a)
        );
        assert_ne!(
            hash_target_pub(&pubkey, &salt_a),
            hash_target_pub(&pubkey, &salt_b)
        );
        // Different pubkeys with same salt → different hashes.
        assert_ne!(
            hash_target_pub(&pubkey, &salt_a),
            hash_target_pub(&[0x43; 32], &salt_a)
        );
    }
}
