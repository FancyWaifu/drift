//! Bloom filter with asymmetric differential-privacy noise.
//!
//! Used by `FederationDirectory v4` (Phase F): bridges announce
//! a noisy bloom filter of their local clients so federation
//! peers can locally test "could this bridge host pubkey X?"
//! Originators only fan out reactive `FindPeer` queries to
//! bridges whose filter says "maybe", reducing the per-lookup
//! query exposure from "every federation peer" to "only those
//! peers whose filter passed for this target".
//!
//! ## Wire-relevant constants
//!
//! Defaults chosen for ~150 local clients per bridge at ~5%
//! false-positive rate:
//!
//! - `BLOOM_DEFAULT_BITS  = 1024` (128 bytes)
//! - `BLOOM_DEFAULT_K     = 4`
//! - `BLOOM_DEFAULT_NOISE = 0.05` (5% asymmetric noise)
//!
//! For a Bloom filter of m bits with k hash functions over n
//! inserted items, the natural false-positive rate is
//! `(1 - e^(-kn/m))^k`. For (m=1024, k=4, n=150) that gives
//! ~3.2%. Asymmetric DP noise at rate p adds approximately
//! `1 - (1-p)^k = 1 - 0.95^4 ≈ 18.5%` of additional false
//! positives on top.
//!
//! ## Privacy property
//!
//! Plain bloom filters leak set membership: an attacker who
//! reads the filter can test any candidate pubkey and learn
//! whether it's in the bridge's client roster. With asymmetric
//! one-sided noise (we only flip 0 → 1, never 1 → 0), the
//! preserved property is:
//!
//!   - **No false negatives**: if `contains(x)` returns false,
//!     `x` is definitely not in the set. The bloom's classical
//!     property survives — we only ever ADD bits, never clear.
//!   - **Increased false positives**: a fraction of non-members
//!     now test as "maybe in". This is the privacy cost paid by
//!     the originator (more decoy queries) for the bridge's
//!     membership obfuscation gain.
//!
//! The asymmetric scheme does NOT give the strong epsilon-DP
//! guarantee of symmetric flips (which would also flip 1 → 0
//! and introduce false negatives). We accept the weaker
//! guarantee to keep the discovery layer's "no false negatives"
//! invariant intact — otherwise a noisy 1 → 0 flip could
//! permanently hide a real peer from discovery.
//!
//! Operators who want stronger DP can run with `noise_rate`
//! pushed higher (more decoys, less informative filter); a
//! future variant could expose symmetric mode with explicit
//! fallback-to-unconditional-FindPeer.

use sha2::{Digest, Sha256};

/// Per-query salt length. Different from the per-announce salt
/// used in `FindPeerHashed` — both 16 bytes, both fresh-random.
pub const BLOOM_SALT_LEN: usize = 16;

/// Sensible default bloom-filter bit count (128 bytes). Sized
/// for ~150 local clients at ~5% FP rate with k=4 hashes.
pub const BLOOM_DEFAULT_BITS: u16 = 1024;

/// Sensible default k. The product m*ln(2)/n gives the
/// theoretical optimum; 4 hashes is the optimum for the
/// 1024-bit/150-client target.
pub const BLOOM_DEFAULT_K: u8 = 4;

/// Sensible default DP noise rate. 5% means each currently-0
/// bit has a 5% probability of being flipped to 1 before
/// publishing.
pub const BLOOM_DEFAULT_NOISE: f64 = 0.05;

/// Bloom filter with asymmetric one-sided differential-privacy
/// noise. Plain inserts set bits; `add_dp_noise` flips additional
/// bits with calibrated probability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpBloomFilter {
    /// Filter bits packed little-endian. `bits.len() * 8 >= m`.
    pub bits: Vec<u8>,
    /// Logical bit count. Always equal to `bits.len() * 8`
    /// after construction.
    pub m: u16,
    /// Number of hash functions.
    pub k: u8,
    /// Per-announce salt; mixes into the hash so filters from
    /// the same announcer are non-correlatable across rounds.
    pub salt: [u8; BLOOM_SALT_LEN],
}

impl DpBloomFilter {
    /// Construct an empty filter with the given parameters.
    /// `m` MUST be a multiple of 8.
    pub fn new(m: u16, k: u8, salt: [u8; BLOOM_SALT_LEN]) -> Self {
        let bytes = (m as usize).div_ceil(8);
        Self {
            bits: vec![0u8; bytes],
            m,
            k,
            salt,
        }
    }

    /// Empty filter with the sensible defaults (1024 bits, k=4).
    pub fn default_for_size(salt: [u8; BLOOM_SALT_LEN]) -> Self {
        Self::new(BLOOM_DEFAULT_BITS, BLOOM_DEFAULT_K, salt)
    }

    /// Insert a pubkey. Sets `k` bits derived from
    /// `SHA-256(salt || pubkey || j)` for j in 0..k.
    pub fn insert(&mut self, pubkey: &[u8; 32]) {
        for j in 0..self.k {
            let idx = self.bit_index(pubkey, j);
            self.set_bit(idx);
        }
    }

    /// Test membership. Returns true if all `k` bits are set
    /// (member OR false-positive); false guarantees non-member.
    pub fn contains(&self, pubkey: &[u8; 32]) -> bool {
        for j in 0..self.k {
            let idx = self.bit_index(pubkey, j);
            if !self.get_bit(idx) {
                return false;
            }
        }
        true
    }

    /// Apply one-sided DP noise. For each currently-0 bit, set
    /// it to 1 with probability `p`. Preserves "no false
    /// negatives": existing 1-bits stay 1, so any actually-
    /// inserted pubkey still tests positive. Only adds extra
    /// false-positives.
    pub fn add_dp_noise(&mut self, p: f64) {
        if p <= 0.0 {
            return;
        }
        if p >= 1.0 {
            for b in self.bits.iter_mut() {
                *b = 0xFF;
            }
            return;
        }
        // Per-bit Bernoulli sampling. We avoid `rand`'s
        // `gen_bool` because we want explicit f64 control.
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for byte_idx in 0..self.bits.len() {
            let byte = self.bits[byte_idx];
            let mut new_byte = byte;
            for bit in 0..8 {
                let mask = 1u8 << bit;
                if byte & mask != 0 {
                    continue; // already 1
                }
                let r: f64 = rng.gen();
                if r < p {
                    new_byte |= mask;
                }
            }
            self.bits[byte_idx] = new_byte;
        }
    }

    /// Compute the j-th hash position for `pubkey`.
    fn bit_index(&self, pubkey: &[u8; 32], j: u8) -> usize {
        let mut h = Sha256::new();
        h.update(&self.salt);
        h.update(pubkey);
        h.update([j]);
        let out = h.finalize();
        // Take the first 8 bytes as a u64 and reduce mod m.
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&out[..8]);
        let raw = u64::from_be_bytes(buf);
        (raw % self.m as u64) as usize
    }

    fn set_bit(&mut self, idx: usize) {
        self.bits[idx / 8] |= 1u8 << (idx % 8);
    }

    fn get_bit(&self, idx: usize) -> bool {
        (self.bits[idx / 8] >> (idx % 8)) & 1 == 1
    }
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_salt(seed: u8) -> [u8; BLOOM_SALT_LEN] {
        [seed; BLOOM_SALT_LEN]
    }

    fn fake_pubkey(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn empty_filter_contains_nothing() {
        let f = DpBloomFilter::new(1024, 4, fresh_salt(0));
        for s in 0..10 {
            assert!(!f.contains(&fake_pubkey(s)));
        }
    }

    #[test]
    fn insert_then_contains() {
        let mut f = DpBloomFilter::new(1024, 4, fresh_salt(1));
        let pk = fake_pubkey(0x42);
        assert!(!f.contains(&pk));
        f.insert(&pk);
        assert!(f.contains(&pk));
    }

    #[test]
    fn many_inserts_all_present() {
        let mut f = DpBloomFilter::new(2048, 4, fresh_salt(2));
        let pks: Vec<_> = (0..50).map(fake_pubkey).collect();
        for pk in &pks {
            f.insert(pk);
        }
        for pk in &pks {
            assert!(f.contains(pk), "missing inserted pubkey");
        }
    }

    #[test]
    fn different_salts_give_different_layouts() {
        let mut f1 = DpBloomFilter::new(1024, 4, fresh_salt(3));
        let mut f2 = DpBloomFilter::new(1024, 4, fresh_salt(4));
        let pk = fake_pubkey(0x99);
        f1.insert(&pk);
        f2.insert(&pk);
        // Both contain it (definitionally) but the bit patterns
        // differ — non-correlatable across announces.
        assert!(f1.contains(&pk));
        assert!(f2.contains(&pk));
        assert_ne!(f1.bits, f2.bits, "salts didn't randomize layout");
    }

    #[test]
    fn fp_rate_within_theoretical_bound() {
        // (m=1024, k=4, n=100). Theoretical FP ≈ (1 - e^(-400/1024))^4 ≈ 0.024.
        // We allow a generous bound (10x) to keep this test
        // non-flaky.
        let mut f = DpBloomFilter::new(1024, 4, fresh_salt(5));
        for s in 0..100u8 {
            f.insert(&fake_pubkey(s));
        }
        let mut fp = 0;
        let trials = 1000;
        for s in 100u16..(100 + trials) {
            let mut pk = [0u8; 32];
            pk[0] = (s >> 8) as u8;
            pk[1] = s as u8;
            if f.contains(&pk) {
                fp += 1;
            }
        }
        let rate = fp as f64 / trials as f64;
        assert!(rate < 0.25, "FP rate suspiciously high: {}", rate);
    }

    #[test]
    fn dp_noise_preserves_no_false_negatives() {
        let mut f = DpBloomFilter::new(1024, 4, fresh_salt(6));
        let pks: Vec<_> = (0..50u8).map(fake_pubkey).collect();
        for pk in &pks {
            f.insert(pk);
        }
        // 30% noise — aggressive
        f.add_dp_noise(0.30);
        // Every inserted pubkey STILL tests positive — the
        // load-bearing property.
        for pk in &pks {
            assert!(
                f.contains(pk),
                "DP noise broke no-false-negative invariant"
            );
        }
    }

    #[test]
    fn dp_noise_increases_false_positives() {
        let make = |noise: f64| -> f64 {
            let mut f = DpBloomFilter::new(1024, 4, fresh_salt(7));
            for s in 0..50u8 {
                f.insert(&fake_pubkey(s));
            }
            f.add_dp_noise(noise);
            let mut fp = 0;
            let trials = 1000;
            for s in 50u16..(50 + trials) {
                let mut pk = [0u8; 32];
                pk[0] = (s >> 8) as u8;
                pk[1] = s as u8;
                if f.contains(&pk) {
                    fp += 1;
                }
            }
            fp as f64 / trials as f64
        };
        let baseline = make(0.0);
        let noisy = make(0.10);
        assert!(
            noisy >= baseline,
            "noise=0.10 did not increase FP rate: baseline={}, noisy={}",
            baseline,
            noisy
        );
    }

    #[test]
    fn defaults_constants_match_size() {
        let f = DpBloomFilter::default_for_size(fresh_salt(0));
        assert_eq!(f.m, BLOOM_DEFAULT_BITS);
        assert_eq!(f.k, BLOOM_DEFAULT_K);
        assert_eq!(f.bits.len(), 128); // 1024 / 8
    }
}
