use crate::crypto::{derive_peer_id, PeerId};
use blake2::{digest::consts::U32, Blake2b, Digest};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub const STATIC_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;

/// A long-term X25519 identity. Both endpoints hold one of these.
/// The public half is what peers recognize each other by.
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
}

/// Derive a 32-byte session key from static DH + ephemeral DH + nonces.
///
/// `static_dh` authenticates the session (only holders of the static
/// private keys can compute it). `ephemeral_dh` provides forward secrecy
/// — after the handshake both sides destroy their ephemeral private
/// keys, so later compromise of the static keys cannot recover past
/// session keys.
pub fn derive_session_key(
    static_dh: &[u8; 32],
    ephemeral_dh: &[u8; 32],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"drift-session-v2");
    hasher.update(static_dh);
    hasher.update(ephemeral_dh);
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
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
pub fn rekey_derive(old_key: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"drift-rekey-v1");
    hasher.update(old_key);
    hasher.update(salt);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
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
