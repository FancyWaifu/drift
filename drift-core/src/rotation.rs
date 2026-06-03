//! Identity rotation — owner-driven key roll for DRIFT identities.
//!
//! ## What this solves
//!
//! "I want to retire pubkey OLD and start using NEW going forward.
//! How do my peers learn about the switch without me re-pasting hex
//! into every config file by hand?"
//!
//! Answer: the owner of OLD signs a `RotationAnnounce` saying "OLD →
//! NEW, valid from issued_at_ms, nonce N". Peers verify the
//! signature with OLD, recognize NEW as the same logical peer, and
//! update their state.
//!
//! ## What this does NOT solve
//!
//! **Lost-laptop / compromised-key rotation.** If the attacker has
//! OLD's secret, they can sign their own RotationAnnounce pointing
//! at a key they control. There is no central authority to break
//! the tie. For lost-laptop the workflow is the same as
//! WireGuard/Tailscale: edit each peer's config file by hand. Future
//! work can add multi-peer cosigning ("M of N other peers vouch for
//! the new key") to close this, but that's intentionally out of
//! scope for v1.
//!
//! ## Threat model
//!
//! - The signing key OLD is held by the legitimate owner only.
//! - An attacker may observe announces in flight but cannot forge a
//!   signature without OLD.
//! - Replay protection: a 32-byte random nonce + a monotonic
//!   `issued_at_ms`. Receivers MUST track recently-seen nonces and
//!   reject duplicates. They SHOULD reject announces with a stale
//!   `issued_at_ms` (more than ROTATION_FRESHNESS_WINDOW_MS old).
//!
//! ## Wire format
//!
//! `[old_pub (32) || new_pub (32) || issued_at_ms (8, big-endian)
//!   || nonce (32) || sig (64)]` — 168 bytes.
//!
//! The signed message body is everything except the trailing
//! signature: `[old_pub || new_pub || issued_at_ms || nonce]`, 104
//! bytes. The XEdDSA construction signs this body with OLD's
//! secret; verification recovers it using OLD's public key.

use crate::error::Result;
use crate::xeddsa::{sign as xeddsa_sign, verify as xeddsa_verify, XEDDSA_SIG_LEN};

/// Reasonable upper bound on how stale a freshly-issued
/// `RotationAnnounce` should ever be by the time a peer processes
/// it. Five minutes is generous for offline distribution (e.g.,
/// emailing the blob) but tight enough that an attacker who later
/// captured the signing key can't pre-date an announce. Receivers
/// are free to use a tighter or looser bound.
pub const ROTATION_FRESHNESS_WINDOW_MS: u64 = 5 * 60 * 1000;

/// Wire-format length of an encoded `RotationAnnounce`.
pub const ROTATION_ANNOUNCE_LEN: usize = 32 + 32 + 8 + 32 + XEDDSA_SIG_LEN;

/// A signed assertion that the holder of `old_pub` is rotating to
/// `new_pub` as of `issued_at_ms`. Created with [`build`] (which
/// signs with the old secret); verified with [`verify`] (which
/// checks the signature against the old public key).
#[derive(Debug, Clone)]
pub struct RotationAnnounce {
    pub old_pub: [u8; 32],
    pub new_pub: [u8; 32],
    pub issued_at_ms: u64,
    pub nonce: [u8; 32],
    pub sig: [u8; XEDDSA_SIG_LEN],
}

/// Build the byte sequence that gets signed. Keep this in lockstep
/// with [`verify`] — any change here is a wire-incompatible break.
fn signed_body(
    old_pub: &[u8; 32],
    new_pub: &[u8; 32],
    issued_at_ms: u64,
    nonce: &[u8; 32],
) -> [u8; 104] {
    let mut buf = [0u8; 104];
    buf[0..32].copy_from_slice(old_pub);
    buf[32..64].copy_from_slice(new_pub);
    buf[64..72].copy_from_slice(&issued_at_ms.to_be_bytes());
    buf[72..104].copy_from_slice(nonce);
    buf
}

/// Sign a fresh `RotationAnnounce`. Caller supplies:
///
/// - `old_secret`: the 32-byte X25519 private bytes whose pubkey is
///   being retired. (`Identity::secret_bytes()` from drift-core.)
/// - `new_pub`: the 32-byte X25519 public bytes that will replace
///   it.
/// - `issued_at_ms`: a wall-clock unix-ms timestamp. Receivers reject
///   announces too far in the past (or in the future).
/// - `nonce`: 32 bytes of fresh CSPRNG output. Receivers track these
///   to drop replays.
/// - `xeddsa_nonce_extra`: 64 bytes of fresh CSPRNG output, mixed
///   into XEdDSA's hedged signing per the spec. Independent of
///   `nonce` — both are required.
///
/// `old_pub` is derived internally from `old_secret` so the
/// announce's stated source can't disagree with the signature.
pub fn build(
    old_secret: &[u8; 32],
    new_pub: &[u8; 32],
    issued_at_ms: u64,
    nonce: &[u8; 32],
    xeddsa_nonce_extra: &[u8; 64],
) -> RotationAnnounce {
    let old_pub = derive_montgomery_pub(old_secret);
    let body = signed_body(&old_pub, new_pub, issued_at_ms, nonce);
    let sig = xeddsa_sign(old_secret, &body, xeddsa_nonce_extra);
    RotationAnnounce {
        old_pub,
        new_pub: *new_pub,
        issued_at_ms,
        nonce: *nonce,
        sig,
    }
}

/// Verify a `RotationAnnounce`'s signature using its self-declared
/// `old_pub`. Returns the validated announce on success.
///
/// Freshness and nonce-replay are NOT checked here — those are
/// orthogonal concerns the caller (with a clock + a nonce-cache)
/// owns. This function answers exactly one question: "is the
/// signature valid for the body, given the claimed old pubkey?"
pub fn verify(announce: &RotationAnnounce) -> Result<()> {
    let body = signed_body(
        &announce.old_pub,
        &announce.new_pub,
        announce.issued_at_ms,
        &announce.nonce,
    );
    // `?` converts the crypto-layer `CryptoError::SignatureInvalid`
    // into the umbrella `DriftError::AuthFailed` for callers still
    // on the flat error type.
    xeddsa_verify(&announce.old_pub, &body, &announce.sig)?;
    Ok(())
}

/// Verify a `RotationAnnounce` against an **expected** old pubkey.
/// This is what peers receiving an announce should typically call:
/// they already know which peer the announce is about (e.g., from
/// the config), so they pass the expected `old_pub`; mismatch is a
/// failure even if the embedded signature would otherwise verify
/// against a different key.
pub fn verify_against(announce: &RotationAnnounce, expected_old_pub: &[u8; 32]) -> Result<()> {
    if &announce.old_pub != expected_old_pub {
        // The announce's embedded old_pub doesn't match what
        // the caller expected — same semantic as a signature
        // verification failure: the message isn't from who
        // we wanted to hear from.
        return Err(crate::error::CryptoError::SignatureInvalid.into());
    }
    verify(announce)
}

/// Serialize a `RotationAnnounce` to its 168-byte wire form.
pub fn encode(a: &RotationAnnounce) -> [u8; ROTATION_ANNOUNCE_LEN] {
    let mut out = [0u8; ROTATION_ANNOUNCE_LEN];
    out[0..32].copy_from_slice(&a.old_pub);
    out[32..64].copy_from_slice(&a.new_pub);
    out[64..72].copy_from_slice(&a.issued_at_ms.to_be_bytes());
    out[72..104].copy_from_slice(&a.nonce);
    out[104..168].copy_from_slice(&a.sig);
    out
}

/// Parse a 168-byte wire form into a `RotationAnnounce`. Does NOT
/// verify the signature — call [`verify`] or [`verify_against`]
/// afterwards.
pub fn decode(bytes: &[u8]) -> std::result::Result<RotationAnnounce, crate::error::CodecError> {
    if bytes.len() != ROTATION_ANNOUNCE_LEN {
        return Err(crate::error::CodecError::Malformed);
    }
    let mut old_pub = [0u8; 32];
    old_pub.copy_from_slice(&bytes[0..32]);
    let mut new_pub = [0u8; 32];
    new_pub.copy_from_slice(&bytes[32..64]);
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&bytes[64..72]);
    let issued_at_ms = u64::from_be_bytes(ts_bytes);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&bytes[72..104]);
    let mut sig = [0u8; XEDDSA_SIG_LEN];
    sig.copy_from_slice(&bytes[104..168]);
    Ok(RotationAnnounce {
        old_pub,
        new_pub,
        issued_at_ms,
        nonce,
        sig,
    })
}

/// Derive the Curve25519 (Montgomery u-coordinate) public bytes
/// from a 32-byte X25519 secret. Identical to what
/// `Identity::from_secret_bytes(secret).public_bytes()` produces.
/// Delegated to x25519-dalek (which is already a drift-core dep)
/// so the clamping + scalar-mult lives in one audited place.
fn derive_montgomery_pub(secret: &[u8; 32]) -> [u8; 32] {
    let s = x25519_dalek::StaticSecret::from(*secret);
    let p = x25519_dalek::PublicKey::from(&s);
    *p.as_bytes()
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_secret(seed: u8) -> [u8; 32] {
        let mut s = [seed; 32];
        // Make sure the seed isn't all-zeros after clamping.
        s[0] |= 1;
        s
    }

    fn fixture_nonce(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn fixture_xn(seed: u8) -> [u8; 64] {
        [seed; 64]
    }

    #[test]
    fn round_trips_through_encode_decode() {
        let old_secret = fixture_secret(0x11);
        let new_pub = derive_montgomery_pub(&fixture_secret(0x22));
        let nonce = fixture_nonce(0x33);
        let xn = fixture_xn(0x44);

        let a = build(&old_secret, &new_pub, 1_700_000_000_000, &nonce, &xn);
        let bytes = encode(&a);
        assert_eq!(bytes.len(), ROTATION_ANNOUNCE_LEN);

        let b = decode(&bytes).expect("decode");
        assert_eq!(b.old_pub, a.old_pub);
        assert_eq!(b.new_pub, a.new_pub);
        assert_eq!(b.issued_at_ms, a.issued_at_ms);
        assert_eq!(b.nonce, a.nonce);
        assert_eq!(b.sig, a.sig);
    }

    #[test]
    fn signature_verifies_with_self_declared_pub() {
        let old_secret = fixture_secret(0x55);
        let new_pub = derive_montgomery_pub(&fixture_secret(0x66));
        let a = build(
            &old_secret,
            &new_pub,
            1_700_000_000_000,
            &fixture_nonce(0x77),
            &fixture_xn(0x88),
        );
        verify(&a).expect("signature should verify");
    }

    #[test]
    fn signature_verifies_with_expected_old_pub() {
        let old_secret = fixture_secret(0x99);
        let old_pub = derive_montgomery_pub(&old_secret);
        let new_pub = derive_montgomery_pub(&fixture_secret(0xaa));
        let a = build(
            &old_secret,
            &new_pub,
            1_700_000_000_000,
            &fixture_nonce(0xbb),
            &fixture_xn(0xcc),
        );
        verify_against(&a, &old_pub).expect("verify_against same key");
    }

    #[test]
    fn rejects_wrong_expected_old_pub() {
        let old_secret = fixture_secret(0x01);
        let new_pub = derive_montgomery_pub(&fixture_secret(0x02));
        let a = build(
            &old_secret,
            &new_pub,
            1_700_000_000_000,
            &fixture_nonce(0x03),
            &fixture_xn(0x04),
        );
        let bogus_pub = derive_montgomery_pub(&fixture_secret(0x05));
        let res = verify_against(&a, &bogus_pub);
        assert!(res.is_err(), "expected mismatch, got Ok");
    }

    #[test]
    fn rejects_tampered_new_pub() {
        let old_secret = fixture_secret(0x10);
        let new_pub = derive_montgomery_pub(&fixture_secret(0x20));
        let mut a = build(
            &old_secret,
            &new_pub,
            1_700_000_000_000,
            &fixture_nonce(0x30),
            &fixture_xn(0x40),
        );
        // Tamper one byte of new_pub. Signature must reject.
        a.new_pub[0] ^= 1;
        assert!(verify(&a).is_err(), "tampered new_pub must fail");
    }

    #[test]
    fn rejects_tampered_issued_at() {
        let old_secret = fixture_secret(0x12);
        let new_pub = derive_montgomery_pub(&fixture_secret(0x21));
        let mut a = build(
            &old_secret,
            &new_pub,
            1_700_000_000_000,
            &fixture_nonce(0x31),
            &fixture_xn(0x41),
        );
        a.issued_at_ms += 1;
        assert!(verify(&a).is_err(), "tampered issued_at must fail");
    }

    #[test]
    fn rejects_short_wire_form() {
        let bytes = [0u8; ROTATION_ANNOUNCE_LEN - 1];
        assert!(decode(&bytes).is_err());
    }
}
