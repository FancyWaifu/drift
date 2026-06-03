use crate::error::{CodecError, CryptoError, Result};
use crate::header::AUTH_TAG_LEN;
use blake2::{digest::consts::U8, Blake2b, Digest};
use siphasher::sip128::{Hasher128, SipHasher24};
use std::hash::Hasher as _;

// AEAD backend selection: `ring` on native (2× faster
// ChaCha20-Poly1305), `chacha20poly1305` crate on wasm32
// (ring doesn't support wasm32-unknown-unknown).
#[cfg(not(target_arch = "wasm32"))]
use ring::aead::{Aad as RingAad, LessSafeKey, Nonce as RingNonce, UnboundKey, CHACHA20_POLY1305};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
#[cfg(target_arch = "wasm32")]
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

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
/// input. Uses SipHash-2-4 (128-bit output) keyed with the first
/// 16 bytes of the rotating server secret.
///
/// ## Security property
///
/// What this MAC needs is **forgery resistance** — given any
/// number of observed (input, cookie) pairs, an off-path
/// attacker should not be able to produce a valid cookie for a
/// fresh input without knowing the secret. (Collision resistance
/// is the wrong frame: attackers don't gain anything by finding
/// two inputs that hash to the same cookie; they need to forge
/// a cookie for a chosen input.)
///
/// SipHash-2-4 is the conservatively-analyzed variant of
/// SipHash. For an attacker that hasn't seen the secret, the
/// best published distinguishers against SipHash-2-4 require
/// query budgets far in excess of what a 30-second rotation
/// window admits — and even those distinguishers don't yield
/// forgery, only statistical bias.
///
/// ## Why not HMAC-SHA-256
///
/// HMAC-SHA-256 would also be defensible. SipHash-2-4 is
/// cheaper on the short (≤64 B) inputs the cookie path handles,
/// which matters because the *whole point* of the cookie is to
/// be the cheap front-line defense against amplification floods
/// — every CPU cycle saved in `cookie_mac` is one less cycle a
/// flood can consume.
///
/// ## Defense in depth
///
/// The rotating secret (replaced every 30s) is not the primary
/// argument; the primary argument is that SipHash-2-4 keyed
/// with 128 bits of secret is forgery-resistant. The rotation
/// limits the *blast radius* of any future cryptanalytic
/// improvement — even a hypothetical break that lowered forgery
/// cost to 2^60 would let an attacker forge ≤30s worth of
/// cookies before the secret rolls.
///
/// The domain tag "drift-dos-cookie-v1" is mixed in as a prefix
/// so a cookie MAC never collides with any other keyed SipHash
/// usage that might be added later (cross-protocol oracle).
pub fn cookie_mac(secret: &[u8; 32], input: &[u8]) -> [u8; COOKIE_MAC_LEN] {
    let k0 = u64::from_le_bytes(secret[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(secret[8..16].try_into().unwrap());
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(b"drift-dos-cookie-v1");
    hasher.write(input);
    let out = hasher.finish128();
    let mut mac = [0u8; COOKIE_MAC_LEN];
    mac[..8].copy_from_slice(&out.h1.to_le_bytes());
    mac[8..].copy_from_slice(&out.h2.to_le_bytes());
    mac
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Initiator = 0,
    Responder = 1,
}

/// Our ChaCha20-Poly1305 nonce construction: 12 bytes laid out as
/// `[dir, 0, 0, 0, packet_type, 0, 0, 0, seq_be...]`. The
/// direction tag guarantees initiator and responder never reuse
/// a nonce even if their seq counters overlap; the packet-type
/// byte namespaces nonces across control vs data packets within
/// one direction.
fn nonce_bytes(direction: Direction, seq: u32, packet_type: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = direction as u8;
    n[4] = packet_type;
    n[8..12].copy_from_slice(&seq.to_be_bytes());
    n
}

/// AEAD session key wrapping a ring `LessSafeKey` (native) or a
/// RustCrypto `ChaCha20Poly1305` (wasm).
///
/// ## Known zeroization gap (native build only)
///
/// `ring::aead::LessSafeKey` does **not** zero its internal key
/// material on drop — that's a documented design choice in
/// `ring`. So when a `SessionKey` is dropped, the 32-byte
/// session key bytes inside `LessSafeKey` linger in the
/// allocator until that memory is reused.
///
/// The bytes the *caller* holds are scrubbed: `derive_session_key`
/// returns `Zeroizing<[u8; 32]>`, so the input to `SessionKey::new`
/// is zeroed when its scope ends. This bounds the exposure to
/// "anything still alive inside ring's internal allocation."
///
/// Removing the ring residual would mean switching all
/// non-wasm callers to RustCrypto's `chacha20poly1305` (which
/// zeroes via the `Zeroize` impls on its types). That switch
/// loses ring's ~2× perf advantage on the ARM/x86 native paths
/// — the `aead_head_to_head` bench shows the gap. A future
/// release may take that trade if the threat model demands it;
/// for now the long-term keys (`Identity::secret`) and stack
/// copies (`Zeroizing<[u8;32]>` from `derive_session_key`) are
/// scrubbed, and the residual ring window is acknowledged
/// explicitly rather than hidden.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub struct SessionKey {
    key: Arc<LessSafeKey>,
    direction: Direction,
}

#[cfg(not(target_arch = "wasm32"))]
impl SessionKey {
    pub fn new(key: &[u8; KEY_LEN], direction: Direction) -> Self {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
            .expect("CHACHA20_POLY1305 key length matches KEY_LEN (32)");
        Self {
            key: Arc::new(LessSafeKey::new(unbound)),
            direction,
        }
    }

    /// Seal `plaintext` with arbitrary AAD, returning a freshly
    /// allocated `Vec<u8>` containing ciphertext + tag.
    pub fn seal(&self, seq: u32, packet_type: u8, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + AUTH_TAG_LEN);
        out.extend_from_slice(plaintext);
        let nonce = RingNonce::assume_unique_for_key(nonce_bytes(self.direction, seq, packet_type));
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, RingAad::from(aad), &mut out)
            .map_err(|_| CryptoError::AeadAuthFailed)?;
        out.extend_from_slice(tag.as_ref());
        Ok(out)
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
        let start = out.len();
        out.extend_from_slice(plaintext);
        let nonce = RingNonce::assume_unique_for_key(nonce_bytes(self.direction, seq, packet_type));
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, RingAad::from(aad), &mut out[start..])
            .map_err(|_| CryptoError::AeadAuthFailed)?;
        out.extend_from_slice(tag.as_ref());
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
            return Err(CodecError::PacketTooShort {
                got: ciphertext.len(),
                need: AUTH_TAG_LEN,
            }
            .into());
        }
        // Ring opens in-place and returns a slice of the plaintext
        // portion of the buffer. Copy in, open, truncate to the
        // plaintext length.
        let mut buf = ciphertext.to_vec();
        let nonce = RingNonce::assume_unique_for_key(nonce_bytes(self.direction, seq, packet_type));
        let pt_len = self
            .key
            .open_in_place(nonce, RingAad::from(aad), &mut buf)
            .map_err(|_| CryptoError::AeadAuthFailed)?
            .len();
        buf.truncate(pt_len);
        Ok(buf)
    }
}

// ──────────── wasm32 fallback: RustCrypto chacha20poly1305 ────────────

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub struct SessionKey {
    cipher: ChaCha20Poly1305,
    direction: Direction,
}

#[cfg(target_arch = "wasm32")]
impl SessionKey {
    pub fn new(key: &[u8; KEY_LEN], direction: Direction) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Self { cipher, direction }
    }

    fn nonce_for(&self, seq: u32, packet_type: u8) -> Nonce {
        *Nonce::from_slice(&nonce_bytes(self.direction, seq, packet_type))
    }

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
            .map_err(|_| CryptoError::AeadAuthFailed.into())
    }

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
            .map_err(|_| CryptoError::AeadAuthFailed)?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    pub fn open(
        &self,
        seq: u32,
        packet_type: u8,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < AUTH_TAG_LEN {
            return Err(CodecError::PacketTooShort {
                got: ciphertext.len(),
                need: AUTH_TAG_LEN,
            }
            .into());
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
            .map_err(|_| CryptoError::AeadAuthFailed.into())
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
