#![no_main]
//! Fuzz target: DRIFT header decoding.
//!
//! Throws arbitrary bytes at `Header::decode`. The decoder must
//! never panic, and any successfully-decoded header must
//! roundtrip through `encode`/`decode` to itself with every
//! field preserved. Successfully-decoded headers must also
//! advertise the current PROTOCOL_VERSION (the decoder rejects
//! everything else — this is a regression guard).

use drift::header::{Header, HEADER_LEN, PROTOCOL_VERSION};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input.
    if let Ok(h) = Header::decode(data) {
        // Decoder gate at drift-core/src/header.rs:246 guarantees
        // this — if it ever regresses, fuzzing will surface it.
        assert_eq!(h.version, PROTOCOL_VERSION);

        // If it decoded, it must roundtrip — every field.
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        let h2 = Header::decode(&buf).expect("encoded header must decode");
        assert_eq!(h.version, h2.version);
        assert_eq!(h.flags, h2.flags);
        assert_eq!(h.packet_type as u8, h2.packet_type as u8);
        assert_eq!(h.deadline_ms, h2.deadline_ms);
        assert_eq!(h.seq, h2.seq);
        assert_eq!(h.supersedes, h2.supersedes);
        assert_eq!(h.src_id, h2.src_id);
        assert_eq!(h.dst_id, h2.dst_id);
        assert_eq!(h.hop_ttl, h2.hop_ttl);
        assert_eq!(h.payload_len, h2.payload_len);
        assert_eq!(h.send_time_ms, h2.send_time_ms);
    }
});
