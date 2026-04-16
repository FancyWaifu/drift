//! Seq-ceiling test.
//!
//! DRIFT's AEAD nonce structure embeds `seq` as a 32-bit integer.
//! Allowing that counter to wrap would reuse a nonce with the same
//! session key, which breaks ChaCha20-Poly1305's security guarantee.
//! `Peer::next_seq_checked` returns None once the counter crosses
//! `SEQ_SEND_CEILING` (2^31), and `send_data` then fails with
//! `SessionExhausted`. The app is expected to tear the session down
//! and re-handshake.
//!
//! This test drives the counter up to the ceiling by reaching inside
//! the peer table directly rather than actually sending 2^31 packets.

use drift::error::DriftError;
use drift::identity::Identity;
use drift::session::SEQ_SEND_CEILING;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn seq_ceiling_refuses_send_before_wraparound() {
    let alice_id = Identity::from_secret_bytes([0xAA; 32]);
    let bob_id = Identity::from_secret_bytes([0xBB; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await.unwrap();

    // Drive one real packet through to complete the handshake so the
    // peer enters Established state. That packet ends up with seq=1.
    alice_t
        .send_data(&bob_peer, b"establish", 0, 0)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.payload, b"establish");

    // Fast-forward Alice's seq counter to the ceiling so the *next*
    // send_data must refuse. We can't actually send 2^31 packets in
    // a test, so poke the field directly via the debug accessor.
    assert!(
        alice_t
            .test_bump_peer_seq(&bob_peer, SEQ_SEND_CEILING)
            .await,
        "peer must exist"
    );

    // The next send should fail fast with SessionExhausted rather
    // than attempting a packet that could induce nonce reuse.
    let err = alice_t
        .send_data(&bob_peer, b"past-ceiling", 0, 0)
        .await
        .expect_err("should refuse to send past seq ceiling");
    assert!(
        matches!(err, DriftError::SessionExhausted),
        "expected SessionExhausted, got {:?}",
        err
    );
}
