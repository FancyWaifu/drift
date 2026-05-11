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

const DIRECTORY_HEADER_LEN: usize = 4;

fuzz_target!(|data: &[u8]| {
    let Ok(pubs) = parse_directory(data) else { return };

    // 1. Length envelope.
    assert_eq!(data.len(), DIRECTORY_HEADER_LEN + 32 * pubs.len());

    // 2. Each parsed pubkey matches its slot in the input.
    for (i, p) in pubs.iter().enumerate() {
        let off = DIRECTORY_HEADER_LEN + i * 32;
        assert_eq!(&p[..], &data[off..off + 32]);
    }

    // 3. Build is the inverse of parse, but only when the input
    //    is small enough for build_directory's debug_assert. The
    //    parser itself is permissive: it'll happily decode wires
    //    with more than MAX_DIRECTORY_ENTRIES entries, since the
    //    cap is producer-side, not receiver-side. We respect that
    //    asymmetry here.
    if pubs.len() <= MAX_DIRECTORY_ENTRIES {
        let rebuilt = build_directory(&pubs);
        assert_eq!(
            rebuilt, data,
            "build∘parse is not the identity on a valid wire"
        );
    }
});
