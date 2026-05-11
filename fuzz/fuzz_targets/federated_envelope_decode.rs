#![no_main]
//! Fuzz target: federation-envelope (`PacketType::Federated`) parser.
//!
//! The federated envelope is the bridge-routing wire format —
//! 130-byte fixed header (four 32-byte pubkeys + 2-byte
//! payload_len) plus a variable-length payload. The parser
//! runs on every cross-bridge packet, before the source-auth
//! check and dispatch in `handle_federated`.
//!
//! Invariants asserted on Ok:
//!   * Input length equals `FED_HEADER_LEN + payload.len()`.
//!   * All four pubkeys round-trip exactly from `data[0..128]`.
//!   * The borrowed payload is a sub-slice of the input (no copy).
//!
//! And the inverse: `build(parse(x)?) == x` for valid wires.
//! That guards against asymmetric encode/decode drift.

use drift::transport::{build_federated, parse_federated, FED_HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(env) = parse_federated(data) else { return };

    // 1. Length envelope.
    assert_eq!(data.len(), FED_HEADER_LEN + env.payload.len());

    // 2. Pubkeys round-trip from the input bytes.
    assert_eq!(&env.target_bridge_pub[..], &data[0..32]);
    assert_eq!(&env.target_client_pub[..], &data[32..64]);
    assert_eq!(&env.source_bridge_pub[..], &data[64..96]);
    assert_eq!(&env.source_client_pub[..], &data[96..128]);

    // 3. Payload borrows from the input (zero-copy parser).
    if !env.payload.is_empty() {
        assert_eq!(env.payload.as_ptr(), data[FED_HEADER_LEN..].as_ptr());
    }

    // 4. Encode → decode → re-encode is idempotent.
    let rebuilt = build_federated(
        &env.target_bridge_pub,
        &env.target_client_pub,
        &env.source_bridge_pub,
        &env.source_client_pub,
        env.payload,
    );
    assert_eq!(
        rebuilt, data,
        "build∘parse is not the identity on valid wires"
    );
});
