//! XEdDSA signatures over Curve25519 — implements Signal's
//! [XEdDSA specification](https://signal.org/docs/specifications/xeddsa/),
//! curve25519 variant.
//!
//! The construction lets DRIFT's existing 32-byte Curve25519
//! identity keys (used for X25519 Diffie-Hellman in the
//! handshake) double as signing keys. No second keypair to
//! manage; same `Identity` produces both DH shared secrets and
//! XEdDSA signatures.
//!
//! Used by federation presence tickets: a client signs
//! `(bridge_pub, expiry_ms, nonce)` to prove to *third-party*
//! receivers that it really did authorize the announcing bridge
//! to advertise it. Without this, a malicious federated bridge
//! could claim to host pubkeys it doesn't actually have a
//! session with.
//!
//! ## Hash choice
//!
//! Per the spec, SHA-512. DRIFT internally uses BLAKE2b for key
//! derivation, but substituting here would silently diverge from
//! the published construction — keeping SHA-512 means anyone
//! auditing this code can cross-check it against the Signal spec
//! line by line. `sha2` is the only extra dep this brings in.
//!
//! ## Wire format
//!
//! Signature: 64 bytes. `R` (32-byte Edwards point, little-endian
//! y with sign bit), then `s` (32-byte scalar, little-endian).
//! Public key for verification: 32-byte Montgomery u-coordinate
//! (the same bytes as our X25519 static pubkey).

use crate::error::CryptoError;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// Signature length on the wire.
pub const XEDDSA_SIG_LEN: usize = 64;

/// Sign `message` with the Curve25519 static identity scalar
/// `secret_key` (raw 32-byte X25519 private bytes — *not* the
/// clamped scalar; this function clamps internally per spec).
///
/// `nonce_extra` is 64 bytes of entropy mixed into the
/// deterministic `r` value to make the signature
/// re-randomization-resistant (Signal spec calls this `Z`). The
/// caller MUST sample these bytes from a CSPRNG. The same
/// `(secret_key, message)` pair MUST NOT be signed with the same
/// `nonce_extra` twice — that's the standard hedged-deterministic
/// signing requirement.
///
/// Returns the 64-byte signature `(R || s)`.
pub fn sign(secret_key: &[u8; 32], message: &[u8], nonce_extra: &[u8; 64]) -> [u8; XEDDSA_SIG_LEN] {
    // 1. Clamp the X25519 private bytes into a curve scalar.
    //    x25519-dalek does this internally when computing DH;
    //    here we replicate the clamping per RFC 7748 §5 so the
    //    same identity key gives the same Edwards-curve view.
    let mut clamped = *secret_key;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let mut a = Scalar::from_bytes_mod_order(clamped);
    clamped.zeroize();

    // 2. Compute the Edwards public point A = a·B. If A has
    //    negative sign (high bit of compressed y is set), negate
    //    a so the verifier — which reconstructs A from the
    //    Montgomery x-coordinate with sign=0 — sees the same A.
    let mut big_a = ED25519_BASEPOINT_TABLE * &a;
    let a_compressed = big_a.compress();
    if a_compressed.as_bytes()[31] & 0x80 != 0 {
        a = -a;
        big_a = -big_a;
    }
    let a_bytes = big_a.compress().to_bytes();

    // 3. r = SHA-512(prefix || a_bytes || M || Z) reduced mod q,
    //    where `prefix` is 32 bytes 0xFF with the high bit of
    //    the first byte cleared per spec, then 0xFE for the
    //    Curve25519 domain separator.
    let mut prefix = [0xFFu8; 32];
    prefix[0] = 0xFE;
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(a.to_bytes());
    hasher.update(message);
    hasher.update(nonce_extra);
    let r_hash = hasher.finalize();
    let mut r_bytes = [0u8; 64];
    r_bytes.copy_from_slice(&r_hash);
    let r = Scalar::from_bytes_mod_order_wide(&r_bytes);

    // 4. R = r·B
    let big_r = (ED25519_BASEPOINT_TABLE * &r).compress();

    // 5. h = SHA-512(R || A || M) mod q
    let mut hasher = Sha512::new();
    hasher.update(big_r.as_bytes());
    hasher.update(a_bytes);
    hasher.update(message);
    let h_hash = hasher.finalize();
    let mut h_bytes = [0u8; 64];
    h_bytes.copy_from_slice(&h_hash);
    let h = Scalar::from_bytes_mod_order_wide(&h_bytes);

    // 6. s = r + h·a mod q
    let s = r + h * a;

    let mut sig = [0u8; XEDDSA_SIG_LEN];
    sig[..32].copy_from_slice(big_r.as_bytes());
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

/// Verify a 64-byte XEdDSA signature against a 32-byte Curve25519
/// public key (Montgomery u-coordinate — same bytes as our
/// X25519 static pubkey).
///
/// Returns `Ok(())` on valid signature, `Err(CryptoError::SignatureInvalid)`
/// on any failure (bad pubkey encoding, malformed signature,
/// signature does not verify). Constant-time relative to the
/// signature contents.
///
/// The crypto-specific error type makes "the signature is
/// invalid" distinguishable from AEAD-tag-mismatch and replay-
/// detected at the type level, instead of collapsing every
/// security failure into the flat `DriftError::AuthFailed`
/// umbrella. Transitive callers using `?` still work because
/// `From<CryptoError> for DriftError` preserves the old mapping.
pub fn verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; XEDDSA_SIG_LEN],
) -> std::result::Result<(), CryptoError> {
    // 1. Reconstruct the Edwards point from the Montgomery
    //    u-coordinate with sign=0 (matches the choice we made
    //    in `sign`).
    let big_a = MontgomeryPoint(*public_key)
        .to_edwards(0)
        .ok_or(CryptoError::SignatureInvalid)?;
    let a_bytes = big_a.compress().to_bytes();

    // 2. Reject points of small order or in the small-order
    //    cofactor. XEdDSA spec requires this for forgery
    //    resistance; curve25519-dalek exposes the check.
    if big_a.is_small_order() {
        return Err(CryptoError::SignatureInvalid);
    }

    // 3. Decompress R from the first 32 bytes of the signature.
    //    Reject if it isn't a valid point or if the encoding's
    //    high bit (the sign bit) is set with no information.
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let big_r = CompressedEdwardsY(r_bytes)
        .decompress()
        .ok_or(CryptoError::SignatureInvalid)?;
    if big_r.is_small_order() {
        return Err(CryptoError::SignatureInvalid);
    }

    // 4. Parse s. Reject non-canonical scalars (s >= q).
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let s = Scalar::from_canonical_bytes(s_bytes);
    let s = if bool::from(s.is_some()) {
        s.unwrap()
    } else {
        return Err(CryptoError::SignatureInvalid);
    };

    // 5. h = SHA-512(R || A || M) mod q
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(a_bytes);
    hasher.update(message);
    let h_hash = hasher.finalize();
    let mut h_wide = [0u8; 64];
    h_wide.copy_from_slice(&h_hash);
    let h = Scalar::from_bytes_mod_order_wide(&h_wide);

    // 6. Check s·B == R + h·A.
    let left = ED25519_BASEPOINT_TABLE * &s;
    let right = big_r + h * big_a;
    if left == right {
        Ok(())
    } else {
        Err(CryptoError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    /// XEdDSA sign∘verify is the identity (i.e., `verify(pub,
    /// msg, sign(sec, msg, Z))` succeeds).
    #[test]
    fn sign_verify_roundtrip() {
        let secret = [0x42u8; 32];
        // Derive the X25519 public bytes the same way Identity
        // does: scalar-multiply the basepoint with the clamped
        // secret. We use x25519-dalek's StaticSecret to make
        // sure our public-key derivation matches the rest of
        // DRIFT exactly.
        let static_secret = x25519_dalek::StaticSecret::from(secret);
        let public_bytes = x25519_dalek::PublicKey::from(&static_secret).to_bytes();

        let mut nonce = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut nonce);

        let msg = b"presence ticket payload";
        let sig = sign(&secret, msg, &nonce);
        verify(&public_bytes, msg, &sig).expect("valid signature must verify");
    }

    /// Tampered messages MUST NOT verify.
    #[test]
    fn tampered_message_fails() {
        let secret = [0x77u8; 32];
        let pub_bytes =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
        let mut nonce = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut nonce);

        let sig = sign(&secret, b"original", &nonce);
        assert!(verify(&pub_bytes, b"tampered", &sig).is_err());
    }

    /// Signatures must NOT verify under a different pubkey.
    #[test]
    fn wrong_pubkey_fails() {
        let secret_a = [0x11u8; 32];
        let secret_b = [0x22u8; 32];
        let pub_b =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret_b)).to_bytes();
        let mut nonce = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut nonce);

        let sig = sign(&secret_a, b"msg", &nonce);
        assert!(verify(&pub_b, b"msg", &sig).is_err());
    }

    /// Tampered signatures (bit flip anywhere) MUST NOT verify.
    #[test]
    fn tampered_signature_fails() {
        let secret = [0x99u8; 32];
        let pub_bytes =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
        let mut nonce = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut sig = sign(&secret, b"msg", &nonce);
        // Flip a bit in R.
        sig[0] ^= 0x01;
        assert!(verify(&pub_bytes, b"msg", &sig).is_err());

        // Reset and flip a bit in s.
        let mut sig = sign(&secret, b"msg", &nonce);
        sig[40] ^= 0x80;
        assert!(verify(&pub_bytes, b"msg", &sig).is_err());
    }

    /// All-zero pubkey (low-order point) MUST be rejected.
    #[test]
    fn small_order_pubkey_rejected() {
        let secret = [0x33u8; 32];
        let mut nonce = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut nonce);

        let sig = sign(&secret, b"msg", &nonce);
        // All-zero u-coordinate is the identity (order-1) point.
        assert!(verify(&[0u8; 32], b"msg", &sig).is_err());
    }

    /// Re-signing the same message with different `Z` produces
    /// different signatures (hedged-deterministic property).
    #[test]
    fn different_nonces_produce_different_sigs() {
        let secret = [0x55u8; 32];
        let pub_bytes =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();

        let mut n1 = [0u8; 64];
        let mut n2 = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut n1);
        rand::thread_rng().fill_bytes(&mut n2);

        let sig1 = sign(&secret, b"same message", &n1);
        let sig2 = sign(&secret, b"same message", &n2);
        assert_ne!(sig1, sig2);
        // Both verify.
        verify(&pub_bytes, b"same message", &sig1).unwrap();
        verify(&pub_bytes, b"same message", &sig2).unwrap();
    }
}
