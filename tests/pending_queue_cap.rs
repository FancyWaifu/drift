//! `peer.pending` bounded-queue tests.
//!
//! Previously, if a peer's handshake couldn't complete, every
//! subsequent `send_data` call would silently push another payload
//! onto `peer.pending` — unbounded. These tests lock that down.

use drift::error::DriftError;
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::time::Duration;

/// Peer registered at an unreachable address (no one listens there):
/// the handshake will retry and eventually give up. Once the per-peer
/// `pending_queue_cap` is hit, `send_data` must return `QueueFull`
/// instead of buffering more payloads.
#[tokio::test]
async fn pending_queue_full_stops_memory_growth() {
    let cfg = TransportConfig {
        pending_queue_cap: 8,
        // Long enough that we hit the queue cap before we hit
        // HandshakeExhausted during this test.
        handshake_max_attempts: 255,
        handshake_retry_base_ms: 10_000,
        ..TransportConfig::default()
    };
    let client = Transport::bind_with_config(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes([0x01; 32]),
        cfg,
    )
    .await
    .unwrap();

    // Some random pubkey pointing at a port nothing is listening on.
    let dead_pub = Identity::from_secret_bytes([0x02; 32]).public_bytes();
    let dead_addr = "127.0.0.1:1"; // privileged / unreachable
    let peer_id = client
        .add_peer(dead_pub, dead_addr.parse().unwrap(), Direction::Initiator)
        .await.unwrap();

    // First 8 sends should queue; the 9th must be QueueFull.
    let mut last_err = None;
    for i in 0..20 {
        match client.send_data(&peer_id, b"x", 0, 0).await {
            Ok(()) => {}
            Err(e) => {
                last_err = Some((i, e));
                break;
            }
        }
    }
    let (attempt, err) = last_err.expect("expected an error eventually");
    assert!(
        matches!(err, DriftError::QueueFull),
        "expected QueueFull, got {:?} at attempt {}",
        err,
        attempt
    );
    assert!(
        attempt >= 8,
        "expected at least 8 successful queues before full, got error at attempt {}",
        attempt
    );
}

/// Peer whose handshake exhausts all retries: subsequent `send_data`
/// calls must return `HandshakeExhausted` so the app stops trying
/// against a dead session.
#[tokio::test]
async fn handshake_exhausted_returns_fast_error() {
    let cfg = TransportConfig {
        // Tight retry schedule so the test runs quickly.
        handshake_max_attempts: 2,
        handshake_retry_base_ms: 20,
        handshake_scan_ms: 10,
        pending_queue_cap: 1024,
        ..TransportConfig::default()
    };
    let client = Transport::bind_with_config(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes([0x11; 32]),
        cfg,
    )
    .await
    .unwrap();

    let dead_pub = Identity::from_secret_bytes([0x12; 32]).public_bytes();
    let peer_id = client
        .add_peer(dead_pub, "127.0.0.1:1".parse().unwrap(), Direction::Initiator)
        .await.unwrap();

    // First send triggers the initial HELLO (attempt 1 of 2).
    client.send_data(&peer_id, b"kick", 0, 0).await.unwrap();

    // Wait long enough for the retry loop to burn through both
    // attempts. Retry delays are 20ms and 40ms, so 300ms is plenty.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Now the peer should be in AwaitingAck with attempts == max.
    // Further sends must fail fast with HandshakeExhausted.
    let err = client
        .send_data(&peer_id, b"late", 0, 0)
        .await
        .expect_err("expected error");
    assert!(
        matches!(err, DriftError::HandshakeExhausted),
        "expected HandshakeExhausted, got {:?}",
        err
    );
}
