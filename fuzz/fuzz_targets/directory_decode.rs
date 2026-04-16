#![no_main]
//! Fuzz target: `DirMessage::decode`. Must never panic or
//! allocate unbounded memory regardless of input.

use drift::directory::DirMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = DirMessage::decode(data);
});
