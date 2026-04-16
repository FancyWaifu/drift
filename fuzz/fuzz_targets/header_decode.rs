#![no_main]
//! Fuzz target: DRIFT header decoding.
//!
//! Throws arbitrary bytes at `Header::decode`. The decoder must
//! never panic, and any successfully-decoded header must
//! roundtrip through `encode`/`decode` to itself.

use drift::header::{Header, HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input.
    if let Ok(h) = Header::decode(data) {
        // If it decoded, it must roundtrip.
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        let h2 = Header::decode(&buf).expect("encoded header must decode");
        assert_eq!(h.seq, h2.seq);
        assert_eq!(h.supersedes, h2.supersedes);
        assert_eq!(h.src_id, h2.src_id);
        assert_eq!(h.dst_id, h2.dst_id);
        assert_eq!(h.payload_len, h2.payload_len);
        assert_eq!(h.send_time_ms, h2.send_time_ms);
    }
});
