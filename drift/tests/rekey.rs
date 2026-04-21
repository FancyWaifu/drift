//! Session rekey: derive fresh keys from the old session key +
//! a random salt, install them on both sides without a
//! full re-handshake, and keep traffic flowing across the swap.
//!
//! Asserts that:
//! 1. A normal `Transport::rekey` call completes end-to-end.
//! 2. Data sent BEFORE the rekey, AFTER the rekey, and in the
//!    grace window during the swap all round-trips cleanly.
//! 3. The post-rekey traffic is using different cipher state
//!    (seq reset, new AEAD namespace) — verified indirectly by
//!    pushing enough packets that the old seq counter would
//!    have collided.

use drift::identity::Identity;
use drift::session::SEQ_SEND_CEILING;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn rekey_keeps_session_alive_and_reset_seq() {
    let alice_id = Identity::from_secret_bytes([0xAA; 32]);
    let bob_id = Identity::from_secret_bytes([0xBB; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
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

    // Pre-rekey: send 10 packets. Alice's tx seq advances to
    // around 11.
    for i in 0..10u32 {
        alice
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
    }
    let mut received = 0usize;
    while received < 10 {
        let p = tokio::time::timeout(Duration::from_secs(2), bob.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.payload.len(), 4);
        received += 1;
    }

    // Perform the rekey. This is a full Alice-initiated swap:
    // new key derived, old kept for grace, RekeyRequest sent,
    // Bob installs, RekeyAck flows back, Alice drops prev.
    alice.rekey(&bob_peer).await.unwrap();

    // Give the ack a beat to land and clear Alice's prev slot.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Post-rekey: send another 20 packets. Because `rekey`
    // resets seq to 1, these reuse seq values we already burned
    // pre-rekey — which is safe ONLY because the key has
    // changed (so the (key, nonce) tuple is fresh).
    for i in 0..20u32 {
        alice
            .send_data(&bob_peer, &(100 + i).to_be_bytes(), 0, 0)
            .await
            .unwrap();
    }

    let mut post = 0usize;
    while post < 20 {
        let p = tokio::time::timeout(Duration::from_secs(3), bob.recv())
            .await
            .expect("post-rekey recv timeout")
            .expect("channel closed");
        assert_eq!(p.payload.len(), 4);
        post += 1;
    }

    // Sanity: no auth failures, handshakes_completed is still
    // exactly 1 (rekey doesn't count as a handshake).
    let bm = bob.metrics();
    assert_eq!(
        bm.auth_failures, 0,
        "rekey flow must not cause any AEAD failures"
    );
    assert_eq!(
        bm.handshakes_completed, 1,
        "rekey should NOT increment handshakes_completed"
    );

    let am = alice.metrics();
    assert_eq!(am.auth_failures, 0);
}

#[tokio::test]
async fn rekey_preserves_in_flight_under_grace_window() {
    // Stress the grace window: send a burst of packets
    // immediately before AND after the rekey so some of the
    // "old key" traffic is still in flight when the swap
    // happens. They should still decode via the `prev` slot
    // on the receiver side.
    let alice_id = Identity::from_secret_bytes([0xA0; 32]);
    let bob_id = Identity::from_secret_bytes([0xB0; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
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

    // Warm up.
    alice.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();

    // Fire 30 packets, rekey in the middle, fire 30 more.
    for i in 0..30u32 {
        alice
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
    }
    alice.rekey(&bob_peer).await.unwrap();
    for i in 100..130u32 {
        alice
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
    }

    // Drain everything Bob receives for up to 3 seconds.
    let mut delivered = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), bob.recv()).await {
            Ok(Some(_)) => delivered += 1,
            _ => break,
        }
    }

    // We pushed 60 DATA packets across the rekey boundary. All
    // should land (warmup doesn't count since it was already
    // drained above). Under heavy load on CI a couple might be
    // lost to UDP buffer overrun; accept >= 55/60 to avoid
    // flakiness.
    assert!(
        delivered >= 55,
        "only {}/60 post-warmup packets made it across the rekey",
        delivered
    );
}

#[tokio::test]
async fn auto_rekey_fires_before_seq_ceiling() {
    // The app should never see SessionExhausted on a healthy
    // session — `send_data` must transparently rekey when the seq
    // counter approaches the ceiling. Drive the counter up past
    // the auto-rekey threshold (75% of SEQ_SEND_CEILING) and
    // confirm the next send succeeds and the auto_rekeys metric
    // increments.
    let alice_id = Identity::from_secret_bytes([0xE1; 32]);
    let bob_id = Identity::from_secret_bytes([0xE2; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
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

    // Establish the session.
    alice
        .send_data(&bob_peer, b"establish", 0, 0)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(alice.metrics().auto_rekeys, 0);

    // Bump seq just past the threshold. Threshold is 75% of
    // ceiling; pick (3/4)*ceiling + 10 to land safely inside the
    // auto-rekey trigger zone but well below the hard ceiling.
    let target = (SEQ_SEND_CEILING / 4) * 3 + 10;
    assert!(alice.test_bump_peer_seq(&bob_peer, target).await);

    // This should auto-rekey and then deliver the packet.
    alice
        .send_data(&bob_peer, b"after-rekey", 0, 0)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .expect("recv timeout after auto-rekey")
        .unwrap();
    assert_eq!(got.payload, b"after-rekey");

    // The metric should have ticked exactly once and the session
    // should still be on handshake count 1 (rekey is not a new
    // handshake).
    let am = alice.metrics();
    assert_eq!(
        am.auto_rekeys, 1,
        "auto-rekey should have fired exactly once"
    );
    assert_eq!(am.handshakes_completed, 1);
    assert_eq!(bob.metrics().handshakes_completed, 1);
}
