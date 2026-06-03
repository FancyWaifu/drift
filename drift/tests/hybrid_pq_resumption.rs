//! Hybrid PQ + session resumption.
//!
//! Scenario: a session that ESTABLISHED via the X25519+ML-KEM
//! hybrid handshake is later resumed via `ResumeHello`. The
//! current implementation deliberately runs ResumeHello WITHOUT
//! the PQ extension (see drift/src/transport/resumption.rs:486
//! `pq: None`) on the theory that the resumed session inherits
//! its key material from the original PQ-derived session via the
//! ticket's PSK — so the security guarantee carries over without
//! a second ML-KEM round trip.
//!
//! What this test verifies:
//!   - A PQ session can be exported (`export_resumption_ticket`)
//!     and re-imported on a fresh client transport.
//!   - The resumed handshake succeeds (`resumptions_completed`
//!     bumps on both sides).
//!   - The resumption did NOT trigger a fresh hybrid handshake
//!     (i.e. `hybrid_pq_handshakes_completed` stays at 1 from
//!     the original session, NOT 2). This is the documented
//!     contract: ResumeHello is the cheap path.
//!
//! If anyone later flips that behavior (e.g. always do a fresh
//! PQ encap on Resume for stronger forward secrecy), this test
//! will need its expected `hybrid_pq_handshakes_completed` value
//! updated.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

fn pq_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn pq_session_can_be_resumed() {
    let alice_id_bytes = [0xD1u8; 32];
    let bob_id_bytes = [0xD2u8; 32];
    let alice_pub = Identity::from_secret_bytes(alice_id_bytes).public_bytes();
    let bob_pub = Identity::from_secret_bytes(bob_id_bytes).public_bytes();

    // First session: PQ on both sides, full hybrid handshake.
    let bob = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(bob_id_bytes),
            pq_cfg(),
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
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_id_bytes),
            pq_cfg(),
        )
        .await
        .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    alice
        .send_data(&bob_peer, b"first-pq-session", 0, 0)
        .await
        .unwrap();
    let p = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("first PQ handshake timed out")
        .unwrap();
    assert_eq!(p.payload, b"first-pq-session");

    // Confirm the first round was hybrid.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let am1 = alice.metrics();
    let bm1 = bob.metrics();
    assert_eq!(am1.hybrid_pq_handshakes_completed, 1);
    assert_eq!(bm1.hybrid_pq_handshakes_completed, 1);

    // Export the ticket and tear alice down.
    let ticket_blob = alice.export_resumption_ticket(&bob_peer).await.unwrap();
    drop(alice);

    // Fresh alice with the same identity, PQ enabled, imports
    // the ticket and resumes.
    let alice2 = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            Identity::from_secret_bytes(alice_id_bytes),
            pq_cfg(),
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

    alice2
        .send_data(&bob_peer2, b"resumed-pq-session", 0, 0)
        .await
        .unwrap();
    let p2 = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("PQ resumption timed out")
        .unwrap();
    assert_eq!(p2.payload, b"resumed-pq-session");

    let am2 = alice2.metrics();
    let bm2 = bob.metrics();

    // Resumption-specific counters should have bumped.
    assert_eq!(
        am2.resumptions_completed, 1,
        "alice2 should have completed exactly one resumption"
    );
    assert_eq!(
        bm2.resumptions_completed, 1,
        "bob should have accepted exactly one resumption"
    );
    // And critically: NO second full PQ handshake happened.
    // Bob's hybrid counter stays at 1 from the original.
    assert_eq!(
        bm2.hybrid_pq_handshakes_completed, 1,
        "ResumeHello should NOT trigger a second PQ handshake; \
         hybrid_pq_handshakes_completed went from 1 to {}",
        bm2.hybrid_pq_handshakes_completed
    );
    // No second full classical handshake either.
    assert_eq!(
        bm2.handshakes_completed, 1,
        "bob should not have done a second full handshake"
    );
}
