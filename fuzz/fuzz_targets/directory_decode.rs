#![no_main]
//! Fuzz target: `DirMessage::decode`. Must never panic or
//! allocate unbounded memory regardless of input.
//!
//! Asserts the allocation bound the decoder already enforces
//! at drift-core/src/directory.rs:143 — peak `entries.capacity()`
//! is clamped to `min(MAX_LISTING_ENTRIES, buf.len()/34 + 1)`.
//! A regression that drops the clamp would let a short packet
//! with a huge `count` blow up memory.

use drift::directory::DirMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(msg) = DirMessage::decode(data) {
        if let DirMessage::Listing(entries) = &msg {
            // Each entry is at least 34 bytes on the wire
            // (32-byte pubkey + 1-byte addr_len + 1-byte
            // nick_len). The buffer can't possibly hold more
            // than buf.len()/34 entries — the decoder's clamp
            // is what enforces this invariant. If it's ever
            // removed, capacity here will exceed the ceiling.
            let ceiling = data.len() / 34 + 1;
            assert!(
                entries.capacity() <= ceiling.max(1),
                "Listing capacity {} exceeds bound {} for input len {}",
                entries.capacity(),
                ceiling,
                data.len()
            );
        }
    }
});
