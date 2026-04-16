//! Directory module fuzz + flood.
//!
//! (a) Random-byte fuzz: throw a lot of garbage at
//!     `DirMessage::decode` and verify it never panics.
//! (b) Bounded allocation: the `MAX_LISTING_ENTRIES` clamp rejects
//!     huge counts without allocating big Vecs. Already covered in
//!     attack_surface_sweep; here we test a LISTING with a large
//!     but under-cap count that truncates against the buffer.
//! (c) Many REGISTERs in a row — verify decoding is linear-ish
//!     and the struct shape is preserved across many roundtrips.

use drift::directory::{DirMessage, MAX_LISTING_ENTRIES, PeerEntry};
use rand::{Rng, SeedableRng};

#[test]
fn fuzz_random_bytes_never_panic() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xD1F5);
    for _ in 0..10_000 {
        let len = rng.gen_range(0..256);
        let mut buf = vec![0u8; len];
        rng.fill(buf.as_mut_slice());
        // Must not panic — None on malformed input is fine.
        let _ = DirMessage::decode(&buf);
    }
}

#[test]
fn fuzz_prefixed_by_tag() {
    // More targeted: force the first byte to be a valid tag so
    // we actually exercise each branch of the decoder.
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEADBEEF);
    for tag in [0x01u8, 0x02, 0x03] {
        for _ in 0..5_000 {
            let len = rng.gen_range(0..512);
            let mut buf = vec![0u8; len + 1];
            buf[0] = tag;
            for b in &mut buf[1..] {
                *b = rng.gen();
            }
            let _ = DirMessage::decode(&buf);
        }
    }
}

#[test]
fn listing_at_exact_cap_roundtrips() {
    // A LISTING exactly at MAX_LISTING_ENTRIES must encode and
    // decode cleanly — enforces that the cap is inclusive and
    // the allocation pre-sizing still works at the boundary.
    let entry = PeerEntry {
        pubkey: [0xEE; 32],
        addr: "10.0.0.1:9000".to_string(),
        nickname: "x".to_string(),
    };
    let entries = vec![entry.clone(); MAX_LISTING_ENTRIES];
    let msg = DirMessage::Listing(entries.clone());
    let bytes = msg.encode();
    let decoded = DirMessage::decode(&bytes).expect("should decode at cap");
    match decoded {
        DirMessage::Listing(v) => assert_eq!(v.len(), MAX_LISTING_ENTRIES),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn register_churn_many_peers() {
    // Encode/decode many REGISTER messages with varying addr and
    // nickname lengths to exercise the length-prefix path.
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xABCDEF);
    for _ in 0..2_000 {
        let addr_len = rng.gen_range(0..64);
        let nick_len = rng.gen_range(0..32);
        let addr: String = (0..addr_len)
            .map(|_| (b'a' + rng.gen_range(0..26)) as char)
            .collect();
        let nickname: String = (0..nick_len)
            .map(|_| (b'A' + rng.gen_range(0..26)) as char)
            .collect();
        let entry = PeerEntry {
            pubkey: rng.gen(),
            addr,
            nickname,
        };
        let msg = DirMessage::Register(entry.clone());
        let bytes = msg.encode();
        let decoded = DirMessage::decode(&bytes).unwrap();
        assert_eq!(decoded, DirMessage::Register(entry));
    }
}
