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
//!   liveness regression: a server restart (fresh transport, same
//!   identity, empty resumption store) makes the client's stored
//!   ticket stale; the client must give up the resume quickly and
//!   fall back to a full HELLO instead of parking forever.

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

    let unval = Transport::parse_resumption_ticket(&ticket_blob).unwrap();
    let val = unval.validate(&bob_peer2, &alice2).await.unwrap();
    alice2.import_resumption_ticket(val).await;

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
    // the ticket for it. Should be rejected at the `validate`
    // step — the blob parses fine but the embedded server_id
    // doesn't match `bogus_peer_id`.
    let bogus_peer_id = [0xFFu8; 8];
    let unval =
        Transport::parse_resumption_ticket(&blob).expect("blob is well-formed; parse must succeed");
    let err = unval
        .validate(&bogus_peer_id, &alice)
        .await
        .expect_err("validate with wrong peer id must fail");
    // Phase 2 of the type-state arc moved the wrong-server-id
    // check from `import_resumption_ticket` into
    // `UnvalidatedTicket::validate`. The error variant stays
    // the same (`PeerError::ResumptionTicketNotFound`).
    assert!(
        matches!(
            err,
            DriftError::Peer(drift::error::PeerError::ResumptionTicketNotFound)
        ),
        "expected Peer(ResumptionTicketNotFound), got {:?}",
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
    // Phase 2 of the type-state arc moved blob-parse failure
    // into `Transport::parse_resumption_ticket` (the entry to
    // the typed ticket lifecycle). The error variant is
    // unchanged — `CodecError::Malformed` → `DriftError::Codec(_)`.
    let err =
        Transport::parse_resumption_ticket(&blob).expect_err("truncated blob must be rejected");
    assert!(matches!(
        err,
        DriftError::Codec(drift::error::CodecError::Malformed)
    ));
}

/// Liveness regression: a client holding a resumption ticket the
/// server has FORGOTTEN (restart / lost store / consumed it) must
/// still be able to connect. Before the fix, the client emitted
/// `ResumeHello`, got no reply (the server rejects an unknown
/// ticket silently), retransmitted `ResumeHello` until the
/// handshake-retry budget ran out, and then parked forever WITHOUT
/// dropping the dead ticket — so every later send re-picked
/// resumption and hit the same dead end. The session never
/// recovered. The fix makes a give-up on a resumption attempt fall
/// back to a fresh full HELLO (and burn the stale ticket).
#[tokio::test]
async fn server_forgot_ticket_falls_back_to_full_handshake() {
    let alice_id_bytes = [0x91u8; 32];
    let bob_id_bytes = [0x92u8; 32];
    let alice_pub = Identity::from_secret_bytes(alice_id_bytes).public_bytes();
    let bob_pub = Identity::from_secret_bytes(bob_id_bytes).public_bytes();

    // ---- session 1: full handshake so Alice earns a ticket ----
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
        .send_data(&bob_peer, b"session-1", 0, 0)
        .await
        .unwrap();
    let p = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.payload, b"session-1");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let ticket_blob = alice.export_resumption_ticket(&bob_peer).await.unwrap();

    // ---- the server "restarts": fresh Bob, same identity + addr,
    //      empty resumption store. Bind to Bob's old port so the
    //      ticket's stored route still points at a live server. ----
    drop(bob);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let bob2 = Arc::new(
        Transport::bind(bob_addr, Identity::from_secret_bytes(bob_id_bytes))
            .await
            .unwrap(),
    );
    bob2.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
    .await
    .unwrap();

    // ---- fresh Alice, same identity, imports the now-stale ticket.
    //      Fast handshake retry base so the resume give-up + fallback
    //      completes quickly and deterministically (default backoff
    //      would take ~14s before the fallback fires). ----
    drop(alice);
    let fast_retry = drift::TransportConfig {
        handshake_retry_base_ms: 150,
        ..Default::default()
    };
    let alice2 = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_id_bytes),
            fast_retry,
        )
        .await
        .unwrap(),
    );
    let bob_peer2 = alice2
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    let unval = Transport::parse_resumption_ticket(&ticket_blob).unwrap();
    let val = unval.validate(&bob_peer2, &alice2).await.unwrap();
    alice2.import_resumption_ticket(val).await;

    // This send picks the resumption path (ticket on file). Bob2
    // has no record of the ticket → silent reject. The client must
    // recover by falling back to a full HELLO and deliver the
    // payload. Generous timeout: the fallback only fires after the
    // resume-retry budget is exhausted.
    alice2
        .send_data(&bob_peer2, b"after-fallback", 0, 0)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(20), bob2.recv())
        .await
        .expect("client never recovered — resumption fallback to full HELLO is broken")
        .unwrap();
    assert_eq!(got.payload, b"after-fallback");

    // Bob2 completed a real handshake (the fallback), not a resume.
    let bm = bob2.metrics();
    assert_eq!(
        bm.handshakes_completed, 1,
        "fallback should be a full handshake"
    );
    assert_eq!(
        bm.resumptions_completed, 0,
        "no resume could have succeeded"
    );
    // Alice2 recorded exactly one resume→full-HELLO fallback.
    let am = alice2.metrics();
    assert_eq!(am.resumption_fallbacks, 1, "exactly one fallback expected");
}
