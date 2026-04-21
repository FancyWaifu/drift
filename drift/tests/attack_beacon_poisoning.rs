//! BEACON route-poisoning attack and defense.
//!
//! An authenticated neighbor (Mallory) who has a DRIFT session with
//! Alice can inject a forged BEACON claiming "I can reach Bob at
//! metric 0". Without any defense, Alice's routing table installs
//! `Bob → Mallory` and every subsequent packet Alice sends to Bob
//! gets siphoned through Mallory — traffic analysis and selective
//! drops at Mallory's discretion, even though Alice has a perfectly
//! good direct session with Bob.
//!
//! The fix: `send_data` prefers `peer.addr` whenever the destination
//! peer is in `Established` state, so a learned mesh route can never
//! override a direct session. This test installs a *static* route
//! Bob → Mallory in Alice's table (same effect as BEACON poisoning
//! without the ciphertext gymnastics) and then asserts that Alice's
//! data to Bob still lands at Bob and NOT at Mallory.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn learned_route_cannot_hijack_direct_established_session() {
    // --- Bob: legitimate destination ---
    let bob_id = Identity::from_secret_bytes([0xB0; 32]);
    let bob_pub = bob_id.public_bytes();
    let bob = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    let bob_addr = bob.local_addr().unwrap();

    // --- Alice: sender, will be targeted by the poisoning ---
    let alice_id = Identity::from_secret_bytes([0xA0; 32]);
    let alice_pub = alice_id.public_bytes();
    let alice = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );

    // --- Mallory: attacker who will impersonate being a mesh hop ---
    let mallory_id = Identity::from_secret_bytes([0xC0; 32]);
    let mallory = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), mallory_id)
            .await
            .unwrap(),
    );
    let mallory_addr = mallory.local_addr().unwrap();

    // Bob expects Alice.
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
    .await
    .unwrap();
    // Alice sets up a direct session with Bob.
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Do one packet to establish the session with Bob.
    alice
        .send_data(&bob_peer, b"hello-bob", 0, 0)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.payload, b"hello-bob");

    // --- poisoning ---
    // Install a static mesh route Bob -> Mallory in Alice's table.
    // This simulates the effect of an authenticated BEACON from
    // Mallory advertising "I can reach Bob" — the routing table
    // ends up in the same state either way. The property under test
    // is: does `send_data` honor this learned route and redirect
    // Alice's traffic to Mallory, even though Alice has an
    // Established direct session with Bob?
    alice.add_route(bob_peer, mallory_addr).await;

    // Send another packet. Pre-fix, this would land at mallory and
    // Bob would never see it. Post-fix, Bob still receives.
    alice
        .send_data(&bob_peer, b"still-bob", 0, 0)
        .await
        .unwrap();

    let got = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("Bob never received — route poisoning succeeded")
        .expect("Bob's recv channel closed");
    assert_eq!(
        got.payload, b"still-bob",
        "Alice's traffic must stay on the direct session despite the learned route"
    );

    // Sanity: Mallory should NOT have received the packet. (Mallory
    // isn't set up as a real DRIFT peer of Alice, so even if the
    // bytes reached Mallory's socket they'd be dropped as unknown.)
    let mallory_got = tokio::time::timeout(Duration::from_millis(200), mallory.recv()).await;
    assert!(
        mallory_got.is_err(),
        "Mallory should not have received any traffic"
    );
}
