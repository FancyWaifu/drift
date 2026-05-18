//! SEC.PEN.1 — KCI / unknown-key-share resistance.
//!
//! Threat model: Mallory knows Bob's *public* identity key (it's
//! public — any party who's ever announced it knows it) but not
//! Bob's secret. Mallory takes Bob's network address (DNS
//! hijack, ARP spoof, BGP shenanigans). Alice initiates a DRIFT
//! handshake to that address believing she's talking to Bob.
//!
//! Without KCI resistance, Mallory could complete a handshake
//! that Alice believes is with Bob. Alice would then send
//! confidential traffic to Mallory.
//!
//! DRIFT's defense: `derive_session_key` mixes in `static_dh =
//! my_secret × your_static_pub`. Alice computes this as `alice_sec
//! × bob_pub`; Mallory, lacking Bob's secret, computes `mallory_sec
//! × alice_pub` instead. The two static_dh values are different,
//! so the derived session keys differ, so Mallory cannot produce
//! a HELLO_ACK whose AEAD tag Alice accepts.
//!
//! This test asserts the handshake fails (Alice never reaches
//! `is_ready_for_data`) when Alice connects to Mallory while
//! claiming `dst_pub = bob_pub`. Run alongside the wire-matrix
//! attack tests in `attack_open_relay.rs`.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

fn open_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        // Short retry budget so the test resolves quickly. Default
        // retries 10× at 1 s = 10 s wait; we want failure to
        // surface in a couple of seconds.
        handshake_max_attempts: 3,
        handshake_retry_base_ms: 200,
        ..TransportConfig::default()
    }
}

#[tokio::test]
async fn mallory_cannot_substitute_for_bob_at_handshake() {
    // Bob exists but is not contacted in this test — Mallory has
    // his address and is impersonating him. We bring Bob up only
    // to obtain his pubkey honestly (rather than synthesizing
    // one out-of-band).
    let bob_id = Identity::from_secret_bytes([0xB0; 32]);
    let bob_pub = bob_id.public_bytes();

    // Mallory runs a real DRIFT transport with `accept_any_peer`
    // — that's the open-bridge mode that, by design, says "I'll
    // talk to anyone." She knows bob_pub publicly but not Bob's
    // secret.
    let mallory_id = Identity::from_secret_bytes([0xCC; 32]);
    let mallory = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            mallory_id,
            open_cfg(),
        )
        .await
        .unwrap(),
    );
    let mallory_addr = mallory.local_addr().unwrap();

    // Alice initiates to Mallory's network address but tells her
    // own transport "the peer at that addr has pubkey = bob_pub."
    // This is the exact moment the impersonation succeeds OR
    // fails: Alice's session-key derivation uses bob_pub, but the
    // responder (Mallory) is using mallory_sec — the static_dh
    // term won't match.
    let alice_id = Identity::from_secret_bytes([0xA0; 32]);
    let alice = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            alice_id,
            open_cfg(),
        )
        .await
        .unwrap(),
    );
    let bob_handle = alice
        .add_peer(bob_pub, mallory_addr, Direction::Initiator)
        .await
        .unwrap();

    // Drive the handshake: send_data is what triggers HELLO in
    // DRIFT's lazy-handshake model. We don't actually care if the
    // payload arrives; we care that the SESSION never becomes
    // established.
    let _ = alice.send_data(&bob_handle, b"trigger", 1000, 0).await;

    // Give the handshake plenty of wall-clock to either succeed
    // or fail. With 3 retries × 200 ms base = ~1.4 s budget; pad
    // generously for parallel-test pressure.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // The contract: Alice's peer entry for what-she-thinks-is-bob
    // must NOT be in the Established state. We assert this two
    // ways for robustness:
    //   1. Alice's metrics report at least one auth_failure
    //      (Mallory's HELLO_ACK fails AEAD verification on Alice's
    //      side because the keys don't match), OR
    //   2. Alice's handshakes_completed counter shows zero for this
    //      attempt — handshake never finished.
    //
    // We also assert Alice does NOT think the peer is ready for
    // data, via the public `peer_metrics` query.
    let alice_m = alice.metrics();
    let mallory_m = mallory.metrics();

    let peer_ready = alice
        .peer_metrics(&bob_handle)
        .await
        .map(|m| m.is_established)
        .unwrap_or(false);

    assert!(
        !peer_ready,
        "KCI broken: Alice's session to 'Bob' (actually Mallory) is established. \
         alice metrics: auth_failures={}, handshakes_completed={}; \
         mallory metrics: handshakes_completed={}",
        alice_m.auth_failures, alice_m.handshakes_completed, mallory_m.handshakes_completed
    );

    // Also: at least one side must register an auth failure or
    // handshake retry. If neither does, something silent is
    // happening that we should know about.
    assert!(
        alice_m.auth_failures + alice_m.handshake_retries
            + mallory_m.auth_failures + mallory_m.handshake_retries
            >= 1,
        "expected at least one auth_failure or handshake_retry across \
         alice + mallory, saw zero — handshake may be silently failing \
         in a way that masks the test"
    );
}

#[tokio::test]
async fn mallory_cannot_substitute_when_alice_knows_bob_directly() {
    // Positive-control variant: Alice talks to a REAL Bob and
    // session DOES complete. Catches false-positives in the
    // negative test above (e.g. if `accept_any_peer` were broken
    // and no handshake ever worked, the negative test would
    // pass for the wrong reason).
    let bob_id = Identity::from_secret_bytes([0xB0; 32]);
    let bob_pub = bob_id.public_bytes();
    let bob = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            bob_id,
            open_cfg(),
        )
        .await
        .unwrap(),
    );
    let bob_addr = bob.local_addr().unwrap();

    let alice_id = Identity::from_secret_bytes([0xA0; 32]);
    let alice = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            alice_id,
            open_cfg(),
        )
        .await
        .unwrap(),
    );
    let bob_handle = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice
        .send_data(&bob_handle, b"hello-real-bob", 1000, 0)
        .await
        .unwrap();

    // Bob should actually receive the payload (proves handshake
    // really completes when identities match).
    let pkt = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .expect("bob recv timed out — positive control broken")
        .expect("bob recv returned None");
    assert_eq!(pkt.payload, b"hello-real-bob");
}
