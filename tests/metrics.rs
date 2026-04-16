//! Verify that `Transport::metrics()` reports sensible counts after a
//! real send/recv session.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn metrics_count_real_traffic() {
    let bob = Identity::from_secret_bytes([0x90; 32]);
    let alice = Identity::from_secret_bytes([0x91; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await.unwrap();

    // Send 10 packets; each carries a coalesce group so we can also
    // check coalesce behavior.
    for i in 0..10u32 {
        alice_t.send_data(&bob_peer, &i.to_be_bytes(), 0, 1).await.unwrap();
    }

    // Drain receiver.
    for _ in 0..10 {
        let _ = tokio::time::timeout(Duration::from_millis(500), bob_t.recv())
            .await
            .ok()
            .flatten();
    }

    let am = alice_t.metrics();
    let bm = bob_t.metrics();

    // Alice should have sent at least 10 packets (+ HELLO, possibly beacons).
    assert!(
        am.packets_sent >= 10,
        "alice packets_sent={} < 10",
        am.packets_sent
    );
    // Alice should have completed exactly one handshake.
    assert_eq!(am.handshakes_completed, 1);
    // Bob should have received some packets and completed one handshake.
    assert!(
        bm.packets_received >= 10,
        "bob packets_received={}",
        bm.packets_received
    );
    assert_eq!(bm.handshakes_completed, 1);
    // Byte counts should be non-zero.
    assert!(am.bytes_sent > 0);
    assert!(bm.bytes_received > 0);
    // No authentication failures during a clean session.
    assert_eq!(am.auth_failures, 0);
    assert_eq!(bm.auth_failures, 0);

    println!("alice metrics: {:?}", am);
    println!("bob metrics:   {:?}", bm);
}
