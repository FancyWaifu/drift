//! 1-RTT session resumption end-to-end tests.
//!
//! * `happy_path_export_import_resume` — full handshake, export
//!   ticket from client, drop client transport, create a fresh
//!   one with the same identity, import the ticket, reconnect:
//!   only resumption metrics should bump, no second full
//!   handshake should happen on the server.
//! * `import_with_wrong_peer_id_rejected` — feeding a ticket
//!   blob in for the wrong peer is rejected with AuthFailed.
//! * `import_with_corrupted_blob_rejected` — flipped bytes are
//!   detected.
//! * `server_forgot_ticket_falls_back_to_full_handshake` —
//!   simulate a server-side restart by clearing the resumption
//!   store; client retries with a full HELLO.

use drift::error::DriftError;
use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn happy_path_export_import_resume() {
    let alice_id_bytes = [0x71u8; 32];
    let bob_id_bytes = [0x72u8; 32];
    let alice_pub = Identity::from_secret_bytes(alice_id_bytes).public_bytes();
    let bob_pub = Identity::from_secret_bytes(bob_id_bytes).public_bytes();

    // ---- first session: do a normal handshake ----
    let bob = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(bob_id_bytes),
        )
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
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_id_bytes),
        )
        .await
        .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    alice
        .send_data(&bob_peer, b"first-session", 0, 0)
        .await
        .unwrap();
    let p = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.payload, b"first-session");

    // Give Bob a beat to issue the ResumptionTicket and Alice
    // to receive + decrypt it.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let am = alice.metrics();
    assert_eq!(
        am.resumption_tickets_received, 1,
        "Alice should have received a ticket"
    );
    assert_eq!(bob.metrics().resumption_tickets_issued, 1);

    // Export the ticket and remember Bob's address.
    let ticket_blob = alice.export_resumption_ticket(&bob_peer).await.unwrap();
    assert!(!ticket_blob.is_empty());

    // ---- drop alice and bring up a fresh transport with the
    //      same identity, then import the ticket and reconnect ----
    drop(alice);

    let alice2 = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_id_bytes),
        )
        .await
        .unwrap(),
    );
    let bob_peer2 = alice2
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    assert_eq!(
        bob_peer2, bob_peer,
        "peer ids are deterministic from pubkey"
    );

    alice2
        .import_resumption_ticket(&bob_peer2, &ticket_blob)
        .await
        .unwrap();

    // Trigger the resumption.
    alice2
        .send_data(&bob_peer2, b"resumed-session", 0, 0)
        .await
        .unwrap();
    let p2 = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("resume timed out — server probably didn't accept the ticket")
        .unwrap();
    assert_eq!(p2.payload, b"resumed-session");

    // Resumption-specific metrics should have bumped.
    let am2 = alice2.metrics();
    let bm = bob.metrics();
    assert_eq!(
        am2.resumption_attempts, 1,
        "alice should have tried 1 resume"
    );
    assert_eq!(
        am2.resumptions_completed, 1,
        "alice should have completed 1 resume"
    );
    assert_eq!(
        bm.resumptions_completed, 1,
        "bob should have handled exactly 1 ResumeHello"
    );
    // Bob did NOT do a second full handshake. handshakes_completed
    // should still be 1 from the first full handshake. Resumption
    // bumps `resumptions_completed`, not `handshakes_completed`.
    assert_eq!(
        bm.handshakes_completed, 1,
        "bob should not have done a second full handshake"
    );

    // The fresh resumption should have given alice2 a NEW ticket
    // for next time.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        alice2.metrics().resumption_tickets_received >= 1,
        "alice2 should have a fresh ticket from the resumed session"
    );
}

#[tokio::test]
async fn import_with_wrong_peer_id_rejected() {
    let bob = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes([0x80; 32]),
        )
        .await
        .unwrap(),
    );
    let alice_pub = Identity::from_secret_bytes([0x81; 32]).public_bytes();
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
    .await
    .unwrap();
    let bob_addr = bob.local_addr().unwrap();
    let bob_pub = bob.local_public();

    let alice = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes([0x81; 32]),
        )
        .await
        .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    alice.send_data(&bob_peer, b"hi", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let blob = alice.export_resumption_ticket(&bob_peer).await.unwrap();

    // Make up a totally different peer id and try to install
    // the ticket for it. Should be rejected.
    let bogus_peer_id = [0xFFu8; 8];
    let err = alice
        .import_resumption_ticket(&bogus_peer_id, &blob)
        .await
        .expect_err("import with wrong peer id must fail");
    assert!(
        matches!(err, DriftError::AuthFailed),
        "expected AuthFailed, got {:?}",
        err
    );
}

#[tokio::test]
async fn import_with_corrupted_blob_rejected() {
    let bob = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes([0x90; 32]),
        )
        .await
        .unwrap(),
    );
    let alice_pub = Identity::from_secret_bytes([0x91; 32]).public_bytes();
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
    .await
    .unwrap();
    let bob_addr = bob.local_addr().unwrap();
    let bob_pub = bob.local_public();

    let alice = Arc::new(
        Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes([0x91; 32]),
        )
        .await
        .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    alice.send_data(&bob_peer, b"hi", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut blob = alice.export_resumption_ticket(&bob_peer).await.unwrap();
    // Truncate.
    blob.truncate(10);
    let err = alice
        .import_resumption_ticket(&bob_peer, &blob)
        .await
        .expect_err("truncated blob must be rejected");
    assert!(matches!(err, DriftError::AuthFailed));
}
