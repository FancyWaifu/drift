//! ECN (RFC 3168) socket-option tests.
//!
//! Verifies that `enable_ecn = true` actually causes the kernel
//! to mark outbound packets as ECT(0). We don't try to test
//! end-to-end CE-mark feedback here because that requires
//! injecting a marked packet from a different process — that's
//! Docker / loopback-with-tc territory, not unit-test territory.
//!
//! What we DO test:
//!   - `enable_ecn = true` makes `is_ecn_enabled()` return true
//!     on Unix, and the kernel actually applied IP_TOS=0x02.
//!   - `enable_ecn = false` (default) leaves the socket at
//!     IP_TOS=0 — no accidental ECN.
//!   - End-to-end traffic still works with ECN enabled, so the
//!     setsockopt didn't break anything.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn ecn_disabled_by_default() {
    let id = Identity::from_secret_bytes([0xE0; 32]);
    let t = Transport::bind("127.0.0.1:0".parse().unwrap(), id)
        .await
        .unwrap();
    assert!(
        !t.is_ecn_enabled(),
        "ECN should be off unless explicitly enabled"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn ecn_enabled_when_configured() {
    let cfg = TransportConfig {
        enable_ecn: true,
        ..TransportConfig::default()
    };
    let id = Identity::from_secret_bytes([0xE1; 32]);
    let t = Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), id, cfg)
        .await
        .unwrap();
    assert!(
        t.is_ecn_enabled(),
        "kernel should have accepted IP_TOS=ECT(0) on a freshly bound v4 socket"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn ecn_session_round_trips_normally() {
    // Sanity: turning ECN on doesn't break ordinary traffic. We
    // can't force a CE mark on loopback without raw sockets, so
    // we just verify a clean handshake + DATA round-trip with
    // ECN enabled on both ends.
    let cfg_a = TransportConfig {
        enable_ecn: true,
        ..TransportConfig::default()
    };
    let cfg_b = TransportConfig {
        enable_ecn: true,
        ..TransportConfig::default()
    };

    let alice_id = Identity::from_secret_bytes([0xE2; 32]);
    let bob_id = Identity::from_secret_bytes([0xE3; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob_id, cfg_b)
            .await
            .unwrap(),
    );
    bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    let alice = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice_id, cfg_a)
            .await
            .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    alice.send_data(&bob_peer, b"ecn-on", 0, 0).await.unwrap();
    let p = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.payload, b"ecn-on");

    // No CE marks on a localhost path (loopback doesn't mark).
    assert_eq!(bob.metrics().ecn_ce_received, 0);
    assert_eq!(alice.metrics().ecn_ce_received, 0);
}
