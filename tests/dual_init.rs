//! Dual-init handshake tiebreaker.
//!
//! If two peers simultaneously decide to initiate a handshake
//! with each other (both call `add_peer(.., Direction::Initiator)`
//! and both call `send_data`), they'll each fire a HELLO and
//! each receive the other's HELLO while in `AwaitingAck`.
//! The protocol has a tiebreaker: the side with the
//! LEXICOGRAPHICALLY SMALLER static pubkey "wins" the responder
//! role and accepts the incoming HELLO; the other side ignores
//! the incoming HELLO and waits for its own HELLO_ACK.
//!
//! This test exercises that code path directly — both sides
//! kick off concurrently, both send_data fires a HELLO, the
//! tiebreaker resolves, and exactly ONE session is established
//! end-to-end with both queued payloads delivered.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_mutual_dial_resolves_to_one_session() {
    let alice_id = Identity::from_secret_bytes([0x40; 32]);
    let bob_id = Identity::from_secret_bytes([0x41; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    // Bring both sides up, but each one configures the OTHER
    // as `Initiator` — the classic "we both want to dial"
    // pattern.
    let alice = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    let alice_addr = alice.local_addr().unwrap();
    let bob_addr = bob.local_addr().unwrap();

    let bob_peer_on_alice = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    let alice_peer_on_bob = bob
        .add_peer(alice_pub, alice_addr, Direction::Initiator)
        .await
        .unwrap();

    // Spawn two concurrent send_data tasks — both sides
    // race to fire the first HELLO.
    let alice_c = alice.clone();
    let bob_c = bob.clone();
    let send_a = tokio::spawn(async move {
        alice_c.send_data(&bob_peer_on_alice, b"alice-says-hi", 0, 0)
            .await
            .unwrap();
    });
    let send_b = tokio::spawn(async move {
        bob_c.send_data(&alice_peer_on_bob, b"bob-says-hi", 0, 0)
            .await
            .unwrap();
    });
    send_a.await.unwrap();
    send_b.await.unwrap();

    // Both sides should receive the OTHER's payload exactly
    // once, even though they both tried to dial.
    let pkt_at_alice = tokio::time::timeout(Duration::from_secs(3), alice.recv())
        .await
        .expect("alice never received")
        .unwrap();
    assert_eq!(pkt_at_alice.payload, b"bob-says-hi");

    let pkt_at_bob = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .expect("bob never received")
        .unwrap();
    assert_eq!(pkt_at_bob.payload, b"alice-says-hi");

    // Sanity: the tiebreaker should have produced exactly one
    // completed handshake on each side, NOT two (which would
    // indicate both HELLOs got honored and session keys got
    // overwritten). Some handshake retries are expected
    // during the race, so we don't assert retry counts.
    let am = alice.metrics();
    let bm = bob.metrics();
    assert_eq!(
        am.handshakes_completed, 1,
        "alice should have completed exactly one handshake, got {}",
        am.handshakes_completed
    );
    assert_eq!(
        bm.handshakes_completed, 1,
        "bob should have completed exactly one handshake, got {}",
        bm.handshakes_completed
    );
    assert_eq!(am.auth_failures, 0);
    assert_eq!(bm.auth_failures, 0);

    // Follow-up traffic should work too — proves the
    // post-tiebreaker session is stable.
    let bob_peer_on_alice2 = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice
        .send_data(&bob_peer_on_alice2, b"follow-up", 0, 0)
        .await
        .unwrap();
    let p = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.payload, b"follow-up");
}
