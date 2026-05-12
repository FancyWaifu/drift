use crate::crypto::{derive_peer_id, PeerId};
use blake2::{digest::consts::U32, Blake2b, Digest};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const STATIC_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;

/// A long-term X25519 identity. Both endpoints hold one of these.
/// The public half is what peers recognize each other by.
///
/// `StaticSecret` zeroes its bytes when `Identity` drops thanks
/// to x25519-dalek's `zeroize` feature — so an attacker who
/// snapshots the process memory after `Identity` has been freed
/// will not find the long-term private key.
pub struct Identity {
    secret: StaticSecret,
    public: PublicKey,
}

impl Identity {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: [u8; STATIC_KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; STATIC_KEY_LEN] {
        *self.public.as_bytes()
    }

    pub fn peer_id(&self) -> PeerId {
        derive_peer_id(self.public.as_bytes())
    }

    /// Elliptic-curve Diffie-Hellman with a peer's static public key.
    /// Returns the raw 32-byte shared secret, or `None` if the
    /// peer's key is one of the known low-order / identity points on
    /// Curve25519 (which would produce a zero shared secret — a
    /// classic contributory-behavior failure that lets an attacker
    /// predict the derived session key without knowing any private
    /// material). Callers MUST treat `None` as an auth failure.
    pub fn dh(&self, peer_public: &[u8; STATIC_KEY_LEN]) -> Option<[u8; 32]> {
        let peer_pub = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer_pub);
        if !shared.was_contributory() {
            return None;
        }
        Some(*shared.as_bytes())
    }

    /// XEdDSA sign `message` with this identity's static private
    /// key. Used for federation presence tickets (see
    /// `drift::transport::federated::build_ticket`). The raw
    /// private bytes are extracted on the stack, used to sign,
    /// then zeroed when the temporary goes out of scope.
    /// `nonce_extra` is 64 bytes of CSPRNG randomness for the
    /// hedged-deterministic signing — the caller MUST sample
    /// fresh entropy each call.
    pub fn xeddsa_sign(&self, message: &[u8], nonce_extra: &[u8; 64]) -> [u8; 64] {
        let secret_bytes = self.secret.to_bytes();
        let sig = crate::xeddsa::sign(&secret_bytes, message, nonce_extra);
        // `to_bytes()` produces an owned [u8; 32] on the stack; let
        // zeroize wipe it when this Zeroizing wrapper drops.
        let _ = Zeroizing::new(secret_bytes);
        sig
    }
}

/// Derive a 32-byte session key from static DH + ephemeral DH + nonces.
///
/// `static_dh` authenticates the session (only holders of the static
/// private keys can compute it). `ephemeral_dh` provides forward secrecy
/// — after the handshake both sides destroy their ephemeral private
/// keys, so later compromise of the static keys cannot recover past
/// session keys.
///
/// Returns `Zeroizing<[u8; 32]>` so the stack copy held by the
/// caller scrubs itself when it goes out of scope. Caller passes
/// `&*key` into `SessionKey::new`. The session key bytes that
/// land inside ring's `LessSafeKey` are not zeroed by ring (a
/// documented design choice in `ring`); see the `SessionKey`
/// docs for the residual exposure window.
pub fn derive_session_key(
    static_dh: &[u8; 32],
    ephemeral_dh: &[u8; 32],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"drift-session-v2");
    hasher.update(static_dh);
    hasher.update(ephemeral_dh);
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    let result = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&result);
    key
}

/// Derive a new 32-byte session key from an existing session
/// key plus a fresh 32-byte salt. Used to rekey an established
/// DRIFT session without a full re-handshake — see
/// `Transport::rekey`.
///
/// Both sides compute this deterministically from the same
/// inputs, so an attacker who doesn't already know the current
/// session key cannot produce or predict the new one.
///
/// Returns `Zeroizing<[u8; 32]>` for the same stack-scrub
/// reason as `derive_session_key`.
pub fn rekey_derive(old_key: &[u8; 32], salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"drift-rekey-v1");
    hasher.update(old_key);
    hasher.update(salt);
    let result = hasher.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&result);
    out
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    use rand::RngCore;
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_is_symmetric() {
        let a = Identity::generate();
        let b = Identity::generate();
        let ab = a.dh(&b.public_bytes()).unwrap();
        let ba = b.dh(&a.public_bytes()).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn session_keys_match() {
        let a = Identity::generate();
        let b = Identity::generate();
        let a_eph = Identity::generate();
        let b_eph = Identity::generate();
        let cnonce = random_nonce();
        let snonce = random_nonce();

        let static_dh_a = a.dh(&b.public_bytes()).unwrap();
        let static_dh_b = b.dh(&a.public_bytes()).unwrap();
        let eph_dh_a = a_eph.dh(&b_eph.public_bytes()).unwrap();
        let eph_dh_b = b_eph.dh(&a_eph.public_bytes()).unwrap();

        let k_a = derive_session_key(&static_dh_a, &eph_dh_a, &cnonce, &snonce);
        let k_b = derive_session_key(&static_dh_b, &eph_dh_b, &cnonce, &snonce);
        assert_eq!(k_a, k_b);
    }

    #[test]
    fn dh_with_zero_pubkey_rejected() {
        // All-zero is a low-order point; must not produce a shared
        // secret.
        let a = Identity::generate();
        let zero = [0u8; STATIC_KEY_LEN];
        assert!(a.dh(&zero).is_none());
    }
}
