//! Post-quantum hybrid key agreement for DRIFT.
//!
//! Implements the `X25519 + ML-KEM-768` hybrid scheme that
//! TLS 1.3, SSH, and most modern transports are rolling out
//! in 2024-2025. The handshake combines two independent
//! key-encapsulation mechanisms:
//!
//!   1. **X25519** (classical): fast, well-understood, broken
//!      by a sufficiently large quantum computer.
//!   2. **ML-KEM-768** (post-quantum): NIST-standardized
//!      lattice-based KEM from FIPS 203, believed secure
//!      against quantum attack.
//!
//! Either half alone gives a shared secret. The final
//! session key is derived from `KDF(x25519_ss ‖ mlkem_ss
//! ‖ nonces)`, so an attacker has to break **both** to
//! recover the session. That protects traffic against
//! "harvest now, decrypt later" — traffic captured today
//! stays private even if X25519 falls to a future quantum
//! computer, because the attacker would also have to break
//! ML-KEM on the same session.
//!
//! This module is standalone: it exposes a small set of
//! helpers (`client_encap`, `server_decap`, `derive_hybrid_key`)
//! that layer cleanly on top of DRIFT's existing X25519
//! handshake. Wire format extensions to HELLO/HELLO_ACK are
//! out of scope for this module — the helpers are invoked
//! by the transport layer when `TransportConfig::hybrid_pq`
//! is enabled, and the wire format carries the extra
//! Kyber public key (1184 bytes) and ciphertext (1088
//! bytes) in auxiliary fields.

use blake2::{digest::consts::U32, Blake2b, Digest};
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;

/// ML-KEM-768 encapsulation-key size (what the client sends
/// to the server). Pinned here so callers don't need to
/// depend on `ml-kem` directly for sizing.
pub const ML_KEM_EK_LEN: usize = 1184;

/// ML-KEM-768 ciphertext size (what the server returns).
pub const ML_KEM_CT_LEN: usize = 1088;

/// Shared secret length produced by ML-KEM-768 decapsulation.
/// Always 32 bytes regardless of parameter set.
pub const ML_KEM_SS_LEN: usize = 32;

/// Client side: generate a fresh ML-KEM keypair. Returns
/// the (encapsulation_key, decapsulation_key) pair. The
/// decapsulation key must be kept secret and dropped after
/// the handshake — it's the PQ equivalent of an ephemeral
/// X25519 private key.
pub fn client_generate_keypair() -> (Vec<u8>, MlKemDecapKey) {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    let ek_bytes = ek.as_bytes().to_vec();
    (ek_bytes, MlKemDecapKey { inner: dk })
}

/// Wrapper around the decapsulation key so callers don't
/// need to import `ml-kem` types directly.
pub struct MlKemDecapKey {
    inner: <MlKem768 as KemCore>::DecapsulationKey,
}

impl MlKemDecapKey {
    /// Given a server ciphertext, recover the 32-byte
    /// shared secret. Returns `None` on any decapsulation
    /// failure (malformed ciphertext or decap error).
    pub fn decapsulate(&self, ct_bytes: &[u8]) -> Option<[u8; ML_KEM_SS_LEN]> {
        if ct_bytes.len() != ML_KEM_CT_LEN {
            return None;
        }
        let ct = Array::<u8, _>::try_from(ct_bytes).ok()?;
        let ss = self.inner.decapsulate(&ct).ok()?;
        let mut out = [0u8; ML_KEM_SS_LEN];
        out.copy_from_slice(ss.as_slice());
        Some(out)
    }
}

/// Server side: given the client's encapsulation key,
/// generate a random shared secret, encapsulate it, and
/// return `(ciphertext, shared_secret)`. The ciphertext
/// goes back to the client; the shared secret feeds the
/// hybrid KDF locally.
pub fn server_encapsulate(ek_bytes: &[u8]) -> Option<(Vec<u8>, [u8; ML_KEM_SS_LEN])> {
    if ek_bytes.len() != ML_KEM_EK_LEN {
        return None;
    }
    let arr = Array::<u8, _>::try_from(ek_bytes).ok()?;
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&arr);
    let mut rng = OsRng;
    let (ct, ss) = ek.encapsulate(&mut rng).ok()?;
    let mut ss_bytes = [0u8; ML_KEM_SS_LEN];
    ss_bytes.copy_from_slice(ss.as_slice());
    Some((ct.as_slice().to_vec(), ss_bytes))
}

/// Combine a classical X25519 shared secret and an ML-KEM
/// shared secret into one 32-byte session key using the
/// DRIFT hybrid KDF:
///
///   `session_key = BLAKE2b("drift-hybrid-pq-v1"
///                          ‖ x25519_ss ‖ mlkem_ss
///                          ‖ client_nonce ‖ server_nonce)`
///
/// Both KEMs feed in; an attacker who breaks one still
/// faces a 32-byte uniform shared secret from the other.
pub fn derive_hybrid_key(
    x25519_ss: &[u8; 32],
    mlkem_ss: &[u8; ML_KEM_SS_LEN],
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(b"drift-hybrid-pq-v1");
    h.update(x25519_ss);
    h.update(mlkem_ss);
    h.update(client_nonce);
    h.update(server_nonce);
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_roundtrip() {
        // Client generates a keypair, ships ek to server;
        // server encapsulates, ships ct back; client
        // decapsulates and recovers the same shared secret.
        let (ek, dk) = client_generate_keypair();
        assert_eq!(ek.len(), ML_KEM_EK_LEN);

        let (ct, server_ss) = server_encapsulate(&ek).expect("server encap");
        assert_eq!(ct.len(), ML_KEM_CT_LEN);

        let client_ss = dk.decapsulate(&ct).expect("client decap");
        assert_eq!(client_ss, server_ss, "hybrid KEM shared secrets must match");
    }

    #[test]
    fn hybrid_kdf_combines_both_kems() {
        let x25519_ss = [0x11u8; 32];
        let mlkem_ss = [0x22u8; 32];
        let cnonce = [0x33u8; 16];
        let snonce = [0x44u8; 16];

        let k1 = derive_hybrid_key(&x25519_ss, &mlkem_ss, &cnonce, &snonce);
        let k2 = derive_hybrid_key(&x25519_ss, &mlkem_ss, &cnonce, &snonce);
        assert_eq!(k1, k2, "derivation is deterministic");

        // Changing either input half produces a different
        // session key.
        let mlkem_ss2 = [0x77u8; 32];
        let k3 = derive_hybrid_key(&x25519_ss, &mlkem_ss2, &cnonce, &snonce);
        assert_ne!(k1, k3, "mlkem_ss change must propagate");

        let x25519_ss2 = [0x88u8; 32];
        let k4 = derive_hybrid_key(&x25519_ss2, &mlkem_ss, &cnonce, &snonce);
        assert_ne!(k1, k4, "x25519_ss change must propagate");
    }

    #[test]
    fn ml_kem_rejects_bad_ciphertext() {
        let (_ek, dk) = client_generate_keypair();
        // Wrong length.
        assert!(dk.decapsulate(&[0u8; 16]).is_none());
    }

    #[test]
    fn ml_kem_rejects_bad_ek_length() {
        assert!(server_encapsulate(&[0u8; 64]).is_none());
    }
}
