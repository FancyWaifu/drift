//! Graceful Close behavior.
//!
//! * `close_peer` sends an AEAD-authenticated Close packet and
//!   clears local session state.
//! * The receiver removes (or resets) the peer and stops
//!   delivering DATA until a fresh handshake happens.
//! * A subsequent `send_data` re-triggers the handshake and
//!   succeeds.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn close_peer_clears_state_and_peer_can_reconnect() {
    let alice_id = Identity::from_secret_bytes([0x01; 32]);
    let bob_id = Identity::from_secret_bytes([0x02; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    let alice = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Handshake + first packet.
    alice.send_data(&bob_peer, b"hello", 0, 0).await.unwrap();
    let p = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.payload, b"hello");

    // Gracefully close the Alice → Bob session. Alice's local
    // state is cleared and Bob receives the Close packet.
    alice.close_peer(&bob_peer).await.unwrap();

    // Give Bob a beat to process.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A subsequent send re-drives the handshake. Bob receives the
    // payload on the newly re-established session.
    alice.send_data(&bob_peer, b"again", 0, 0).await.unwrap();
    let p2 = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p2.payload, b"again");

    // Bob's state after the reconnect: there are two valid
    // outcomes because the server issues a ResumptionTicket
    // after the first handshake and whether Alice received
    // that ticket before she called close_peer is a race:
    //
    //   A) Ticket arrived first → Alice has it → her next
    //      send_data uses the 1-RTT resumption path
    //      (handshakes=1, resumptions=1 on Bob).
    //   B) Ticket arrived after close → Alice has no
    //      ticket → her next send_data does a full HELLO
    //      (handshakes=2, resumptions=0 on Bob).
    //
    // Both mean "the session was torn down and re-established"
    // which is what this test is actually about. Accept both.
    let m = bob.metrics();
    let total_reconnects = m.handshakes_completed + m.resumptions_completed;
    assert!(
        total_reconnects >= 2,
        "expected ≥2 reconnects (handshakes+resumptions), got handshakes={} resumptions={}",
        m.handshakes_completed,
        m.resumptions_completed
    );
    // No auth failures or replays either way.
    assert_eq!(m.auth_failures, 0);
    assert_eq!(m.replays_caught, 0);
}
