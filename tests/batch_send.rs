//! Integration test for `Transport::send_data_batch`.
//!
//! Warms up a 2-peer session, then ships 100 DATA packets
//! in a single batched call. Verifies every payload arrives
//! on the receiver and that `batched_sends` increments
//! appropriately.

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn batch_send_delivers_every_packet() {
    let alice_id = Identity::from_secret_bytes([0x81; 32]);
    let bob_id = Identity::from_secret_bytes([0x82; 32]);
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

    // Warmup to get the session Established. Batched
    // send skips non-Established peers.
    alice.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();

    // Build a batch of 100 tagged packets.
    let items: Vec<_> = (0u32..100)
        .map(|i| (derive_peer_id(&bob_pub), i.to_be_bytes().to_vec()))
        .collect();
    let sent = alice.send_data_batch(&items).await.unwrap();
    assert_eq!(sent, 100, "all 100 should be accepted by the kernel");

    // Drain them all.
    let mut got = std::collections::HashSet::new();
    while got.len() < 100 {
        let pkt = tokio::time::timeout(Duration::from_secs(5), bob.recv())
            .await
            .expect("drain timeout")
            .unwrap();
        if pkt.payload.len() == 4 {
            let n = u32::from_be_bytes([
                pkt.payload[0],
                pkt.payload[1],
                pkt.payload[2],
                pkt.payload[3],
            ]);
            got.insert(n);
        }
    }
    assert_eq!(got.len(), 100);
    for i in 0..100u32 {
        assert!(got.contains(&i), "missing packet {}", i);
    }

    // Metric sanity: batched_sends should have bumped.
    assert!(alice.metrics().batched_sends >= 1);
    assert_eq!(alice.metrics().auth_failures, 0);
}
