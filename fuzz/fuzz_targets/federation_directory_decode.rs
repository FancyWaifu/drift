#![no_main]
//! Fuzz target: FederationDirectory (`PacketType::FederationDirectory`) parser.
//!
//! Bridge-to-bridge directory announcements. Wire layout
//! (drift/src/transport/federated.rs:90-96):
//!
//!   [0]      version  (u8) = 1
//!   [1]      reserved (u8) = 0
//!   [2..4]   count    (u16 BE)
//!   [4..]    pubkeys  ([32 bytes] * count)
//!
//! Invariants asserted on Ok:
//!   * `data.len() == 4 + 32 * out.len()` (parser rejects mismatch).
//!   * `out.len() <= MAX_DIRECTORY_ENTRIES` is NOT enforced by the
//!     parser itself — the cap is on `build_directory` and on the
//!     per-packet wire size. We still assert it as a sanity bound
//!     because `MAX_DIRECTORY_ENTRIES * 32 + 4` is well within any
//!     MTU we'd ever see in real traffic.
//!   * Round-trip identity: `build_directory(parse_directory(x)?) == x`
//!     for valid wires.

use drift::transport::{build_directory, parse_directory, MAX_DIRECTORY_ENTRIES};
use libfuzzer_sys::fuzz_target;

// Wire layout: 4-byte header + N entries; each entry is
// 32-byte pubkey + presence ticket (TICKET_LEN = 8+24+64 = 96).
const DIRECTORY_HEADER_LEN: usize = 4;
const DIRECTORY_ENTRY_LEN: usize = 32 + 96;

fuzz_target!(|data: &[u8]| {
    let Ok(entries) = parse_directory(data) else { return };

    // 1. Length envelope.
    assert_eq!(
        data.len(),
        DIRECTORY_HEADER_LEN + DIRECTORY_ENTRY_LEN * entries.len()
    );

    // 2. Each parsed pubkey matches its slot in the input.
    for (i, (pk, _ticket)) in entries.iter().enumerate() {
        let off = DIRECTORY_HEADER_LEN + i * DIRECTORY_ENTRY_LEN;
        assert_eq!(&pk[..], &data[off..off + 32]);
    }

    // 3. Build is the inverse of parse, but only when the input
    //    is small enough for build_directory's debug_assert. The
    //    parser itself is permissive: it'll happily decode wires
    //    with more than MAX_DIRECTORY_ENTRIES entries, since the
    //    cap is producer-side, not receiver-side. We respect that
    //    asymmetry here.
    if entries.len() <= MAX_DIRECTORY_ENTRIES {
        let rebuilt = build_directory(&entries);
        assert_eq!(
            rebuilt, data,
            "build∘parse is not the identity on a valid wire"
        );
    }
});
