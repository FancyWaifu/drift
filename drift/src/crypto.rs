use crate::error::{DriftError, Result};
use crate::header::AUTH_TAG_LEN;
use blake2::{digest::consts::U8, Blake2b, Digest};
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use siphasher::sip128::{Hasher128, SipHasher13};
use std::hash::Hasher as _;

pub const KEY_LEN: usize = 32;
pub const PEER_ID_LEN: usize = 8;

pub type PeerId = [u8; PEER_ID_LEN];

pub fn derive_peer_id(pubkey_material: &[u8]) -> PeerId {
    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"drift-peer-id-v1");
    hasher.update(pubkey_material);
    let result = hasher.finalize();
    let mut id = [0u8; PEER_ID_LEN];
    id.copy_from_slice(&result);
    id
}

pub const COOKIE_MAC_LEN: usize = 16;

/// Produce a 16-byte server-side DoS cookie MAC over arbitrary
/// input. Uses SipHash-1-3 (128-bit output) keyed with the first
/// 16 bytes of the rotating server secret. SipHash is ~3-5× faster
/// than Blake2b on the short inputs the cookie path handles, and
/// 128 bits of output is plenty for a 30-second rotation window
/// — finding a collision takes ~2^64 probes, infeasible even at
/// billions of guesses per second.
///
/// The domain tag "drift-dos-cookie-v1" is mixed in as a prefix
/// so that a cookie MAC never collides with any other keyed
/// SipHash usage that might be added later.
pub fn cookie_mac(secret: &[u8; 32], input: &[u8]) -> [u8; COOKIE_MAC_LEN] {
    let k0 = u64::from_le_bytes(secret[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(secret[8..16].try_into().unwrap());
    let mut hasher = SipHasher13::new_with_keys(k0, k1);
    hasher.write(b"drift-dos-cookie-v1");
    hasher.write(input);
    let out = hasher.finish128();
    let mut mac = [0u8; COOKIE_MAC_LEN];
    mac[..8].copy_from_slice(&out.h1.to_le_bytes());
    mac[8..].copy_from_slice(&out.h2.to_le_bytes());
    mac
}

#[derive(Clone)]
pub struct SessionKey {
    cipher: ChaCha20Poly1305,
    direction: Direction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Initiator = 0,
    Responder = 1,
}

impl SessionKey {
    pub fn new(key: &[u8; KEY_LEN], direction: Direction) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Self { cipher, direction }
    }

    fn nonce_for(&self, seq: u32, packet_type: u8) -> Nonce {
        let mut n = [0u8; 12];
        n[0] = self.direction as u8;
        n[4] = packet_type;
        n[8..12].copy_from_slice(&seq.to_be_bytes());
        *Nonce::from_slice(&n)
    }

    /// Seal `plaintext` with arbitrary AAD, returning a freshly
    /// allocated `Vec<u8>` containing ciphertext + tag.
    pub fn seal(&self, seq: u32, packet_type: u8, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce_for(seq, packet_type);
        self.cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| DriftError::AuthFailed)
    }

    /// Seal `plaintext` into an already-allocated buffer, appending
    /// ciphertext and the 16-byte Poly1305 tag. Saves one Vec
    /// allocation per outgoing packet versus `seal` — hot-path
    /// optimization used by `build_*_packet` helpers.
    pub fn seal_into(
        &self,
        seq: u32,
        packet_type: u8,
        aad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let nonce = self.nonce_for(seq, packet_type);
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, aad, &mut out[start..])
            .map_err(|_| DriftError::AuthFailed)?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Open ciphertext (payload || tag) with arbitrary AAD.
    pub fn open(
        &self,
        seq: u32,
        packet_type: u8,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < AUTH_TAG_LEN {
            return Err(DriftError::PacketTooShort {
                got: ciphertext.len(),
                need: AUTH_TAG_LEN,
            });
        }
        let nonce = self.nonce_for(seq, packet_type);
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| DriftError::AuthFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Header, PacketType, HEADER_LEN};

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_aead_roundtrip(
            key in any::<[u8; 32]>(),
            seq in any::<u32>(),
            plaintext in prop::collection::vec(any::<u8>(), 0..1200),
            aad in prop::collection::vec(any::<u8>(), 0..80),
        ) {
            let sender = SessionKey::new(&key, Direction::Initiator);
            let receiver = SessionKey::new(&key, Direction::Initiator);
            let ct = sender.seal(seq, 3, &aad, &plaintext).unwrap();
            let pt = receiver.open(seq, 3, &aad, &ct).unwrap();
            prop_assert_eq!(pt, plaintext);
        }

        #[test]
        fn prop_aead_tampered_aad_fails(
            key in any::<[u8; 32]>(),
            seq in any::<u32>(),
            plaintext in prop::collection::vec(any::<u8>(), 1..500),
            aad in prop::collection::vec(any::<u8>(), 1..40),
            flip_byte in any::<u8>(),
        ) {
            let k = SessionKey::new(&key, Direction::Initiator);
            let ct = k.seal(seq, 3, &aad, &plaintext).unwrap();
            let mut bad_aad = aad.clone();
            let idx = (flip_byte as usize) % bad_aad.len();
            bad_aad[idx] ^= 0xFF;
            prop_assert!(k.open(seq, 3, &bad_aad, &ct).is_err());
        }

        #[test]
        fn prop_aead_wrong_direction_fails(
            key in any::<[u8; 32]>(),
            seq in any::<u32>(),
            plaintext in prop::collection::vec(any::<u8>(), 0..500),
        ) {
            let initiator = SessionKey::new(&key, Direction::Initiator);
            let responder = SessionKey::new(&key, Direction::Responder);
            let ct = initiator.seal(seq, 3, &[], &plaintext).unwrap();
            prop_assert!(responder.open(seq, 3, &[], &ct).is_err());
        }
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let key = [7u8; KEY_LEN];
        let sender = SessionKey::new(&key, Direction::Initiator);
        let receiver = SessionKey::new(&key, Direction::Initiator);

        let h = Header::new(PacketType::Data, 1, [0; 8], [0; 8]);
        let mut hbuf = [0u8; HEADER_LEN];
        h.encode(&mut hbuf);

        let ct = sender
            .seal(1, PacketType::Data as u8, &hbuf, b"hello drift")
            .unwrap();
        let pt = receiver
            .open(1, PacketType::Data as u8, &hbuf, &ct)
            .unwrap();
        assert_eq!(pt, b"hello drift");
    }

    #[test]
    fn tampered_aad_fails() {
        let key = [7u8; KEY_LEN];
        let k = SessionKey::new(&key, Direction::Initiator);
        let h = Header::new(PacketType::Data, 1, [0; 8], [0; 8]);
        let mut hbuf = [0u8; HEADER_LEN];
        h.encode(&mut hbuf);
        let ct = k
            .seal(1, PacketType::Data as u8, &hbuf, b"payload")
            .unwrap();
        hbuf[4] ^= 0xFF;
        assert!(k.open(1, PacketType::Data as u8, &hbuf, &ct).is_err());
    }
}
