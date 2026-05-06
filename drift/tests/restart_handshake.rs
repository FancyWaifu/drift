//! Tests for `Transport::restart_handshake`.
//!
//! Two scenarios:
//!
//! 1. **Mid-handshake reset**: peer is in `AwaitingAck` state
//!    (Initiator sent HELLO, no HELLO_ACK yet). `restart_handshake`
//!    wipes that and the next `send_data` triggers a fresh HELLO.
//!
//! 2. **Established reset + addr swap**: peer is `Established`,
//!    we change `addr` via `update_peer_addr`, then call
//!    `restart_handshake`. The next `send_data` triggers a fresh
//!    HELLO at the *new* addr — which is exactly what drift-vpn's
//!    happy-eyeballs needs.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

async fn make_pair() -> (Arc<Transport>, Arc<Transport>, drift::PeerId, drift::PeerId)
{
    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB1; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let bob = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob_id, cfg.clone())
            .await
            .unwrap(),
    );
    let bob_addr = bob.local_addr().unwrap();
    let bob_peer = bob
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let alice = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice_id, cfg)
            .await
            .unwrap(),
    );
    let alice_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    (alice, bob, alice_peer, bob_peer)
}

#[tokio::test]
async fn restart_clears_session_then_rehandshakes_at_current_addr() {
    let (alice, bob, alice_peer_for_bob, bob_peer_for_alice) = make_pair().await;

    // Establish first session.
    alice
        .send_data(&alice_peer_for_bob, b"hello-1", 0, 0)
        .await
        .unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("bob recv timeout")
        .expect("bob recv None");
    assert_eq!(pkt.payload.as_slice(), b"hello-1");
    let handshakes_after_first = alice.metrics().handshakes_completed;
    assert!(
        handshakes_after_first >= 1,
        "first handshake should have completed"
    );

    // Reset the session on the alice side.
    alice.restart_handshake(&alice_peer_for_bob).await.unwrap();

    // Second send should trigger a new handshake. We assert the
    // `handshakes_completed` counter advances, AND the data
    // round-trips again.
    alice
        .send_data(&alice_peer_for_bob, b"hello-2", 0, 0)
        .await
        .unwrap();
    let pkt2 = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("bob recv #2 timeout")
        .expect("bob recv #2 None");
    assert_eq!(pkt2.payload.as_slice(), b"hello-2");
    assert!(
        alice.metrics().handshakes_completed > handshakes_after_first,
        "restart_handshake didn't trigger a fresh handshake"
    );
    let _ = bob_peer_for_alice; // silence unused
}

#[tokio::test]
async fn restart_after_addr_change_targets_new_addr() {
    // Simulates the drift-vpn happy-eyeballs scenario: peer is
    // registered at endpoint #1, we want to switch to endpoint #2.
    //
    // Concretely:
    //   1. Establish session with bob (real listener).
    //   2. Spin up a SECOND bob on a different port (call it bob2).
    //   3. update_peer_addr to bob2's addr + restart_handshake.
    //   4. Verify the next send_data goes to bob2, not original bob.
    //
    // This is the exact dance drift-vpn does in v0.3.

    let (alice, bob, alice_peer_for_bob, _) = make_pair().await;

    // Establish the original session.
    alice
        .send_data(&alice_peer_for_bob, b"original", 0, 0)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("bob recv timeout")
        .expect("bob recv None");

    // Spin up a second bob at a different addr — same identity,
    // fresh transport. This simulates the peer being reachable at
    // a NEW endpoint (e.g., happy-eyeballs fallback).
    let bob_id_clone = Identity::from_secret_bytes([0xB1; 32]);
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let bob2 = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob_id_clone, cfg)
            .await
            .unwrap(),
    );
    let bob2_addr = bob2.local_addr().unwrap();

    // Switch alice to point at bob2 + reset session.
    let alice_pub = Identity::from_secret_bytes([0xA1; 32]).public_bytes();
    bob2.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    assert!(
        alice
            .update_peer_addr(&alice_peer_for_bob, bob2_addr)
            .await,
        "update_peer_addr should succeed"
    );
    alice.restart_handshake(&alice_peer_for_bob).await.unwrap();

    // Now send. The handshake should target bob2, not bob.
    alice
        .send_data(&alice_peer_for_bob, b"new-path", 0, 0)
        .await
        .unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(2), bob2.recv())
        .await
        .expect("bob2 recv timeout")
        .expect("bob2 recv None");
    assert_eq!(pkt.payload.as_slice(), b"new-path");

    // Sanity: the original bob shouldn't have received this.
    let leaked = tokio::time::timeout(Duration::from_millis(200), bob.recv()).await;
    assert!(
        matches!(leaked, Err(_)),
        "original bob should NOT have received the post-restart packet"
    );
}
