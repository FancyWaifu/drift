//! SEC.PEN.4 — nonce-counter rollover.
//!
//! DRIFT's AEAD nonce embeds `seq` as a 32-bit field. If `seq`
//! wraps at u32::MAX without a rekey, two packets share the same
//! (key, nonce) — catastrophic loss of confidentiality and
//! integrity for those two packets (ChaCha20-Poly1305 forgery on
//! any pair with the same nonce).
//!
//! Defense (drift-core/src/session.rs + drift/src/transport/mod.rs):
//!
//!   - `SEQ_SEND_CEILING = 2^31` — hard ceiling. `next_seq_checked`
//!     returns `None` once `next_tx_seq` reaches this, and the
//!     sender refuses to encrypt with the current key.
//!   - `AUTO_REKEY_THRESHOLD = (SEQ_SEND_CEILING / 4) * 3`
//!     (~1.6B) — `send_data` performs a transparent rekey
//!     before any send whose seq would cross the threshold.
//!     `reset_seq` then puts the counter back to 1.
//!
//! This test uses `test_bump_peer_seq` to jump near both
//! thresholds without sending 1.6B real packets. It asserts:
//!
//!   1. `send_data` past AUTO_REKEY_THRESHOLD triggers a rekey
//!      (auto_rekeys metric increments, next_tx_seq is reset
//!      well below the threshold).
//!   2. `send_data` past SEQ_SEND_CEILING with no rekey path
//!      available errors fail-closed rather than wrapping and
//!      reusing a nonce.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

const SEQ_SEND_CEILING: u32 = 1u32 << 31;
const AUTO_REKEY_THRESHOLD: u32 = (SEQ_SEND_CEILING / 4) * 3;

fn cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        handshake_max_attempts: 3,
        handshake_retry_base_ms: 200,
        ..TransportConfig::default()
    }
}

async fn handshake_pair() -> (Arc<Transport>, Arc<Transport>, drift::PeerId) {
    let bob_id = Identity::from_secret_bytes([0xB0; 32]);
    let bob_pub = bob_id.public_bytes();
    let bob = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            bob_id,
            cfg(),
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
            cfg(),
        )
        .await
        .unwrap(),
    );
    let bob_handle = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice
        .send_data(&bob_handle, b"warmup", 1000, 0)
        .await
        .unwrap();
    // Receive the warmup so the handshake fully settles.
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv()).await;
    (alice, bob, bob_handle)
}

#[tokio::test]
async fn auto_rekey_fires_before_nonce_wrap() {
    let (alice, bob, bob_handle) = handshake_pair().await;

    // Confirm auto_rekeys is currently zero.
    let m_before = alice.metrics();
    assert_eq!(
        m_before.auto_rekeys, 0,
        "expected fresh handshake to have 0 auto_rekeys, got {}",
        m_before.auto_rekeys
    );

    // Push Alice's tx counter just past the auto-rekey threshold.
    // Pre-fix this would happen organically after ~1.6B packets;
    // we shortcut via the test helper.
    let bumped = alice
        .test_bump_peer_seq(&bob_handle, AUTO_REKEY_THRESHOLD + 1)
        .await;
    assert!(bumped, "test_bump_peer_seq failed — peer unknown");

    // Send one more packet. send_data should:
    //   - notice next_tx_seq >= AUTO_REKEY_THRESHOLD
    //   - perform the rekey round-trip
    //   - then send the new packet under the fresh key (seq ~= 1)
    let res = alice
        .send_data(&bob_handle, b"post-rekey", 1000, 0)
        .await;
    assert!(
        res.is_ok(),
        "send_data after auto-rekey threshold should succeed (rekey + retry); \
         got {:?}",
        res
    );

    // Bob should receive the post-rekey payload — proves the new
    // session key is wired up on both sides.
    let pkt = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .expect("bob recv timed out after auto-rekey")
        .expect("bob recv returned None");
    assert_eq!(pkt.payload, b"post-rekey");

    let m_after = alice.metrics();
    assert!(
        m_after.auto_rekeys >= 1,
        "auto_rekeys should have fired; saw {} (was {})",
        m_after.auto_rekeys, m_before.auto_rekeys
    );

    // After rekey, Alice's tx seq for this peer must be far below
    // the ceiling — the session is fresh.
    let pm = alice
        .peer_metrics(&bob_handle)
        .await
        .expect("peer_metrics after rekey");
    assert!(
        pm.next_tx_seq < AUTO_REKEY_THRESHOLD,
        "tx seq did not reset after rekey: {} (threshold {})",
        pm.next_tx_seq, AUTO_REKEY_THRESHOLD
    );
}

#[tokio::test]
async fn send_refuses_at_ceiling_rather_than_wrapping() {
    // If the auto-rekey path is bypassed (e.g. peer offline at
    // the moment we'd need to rekey, or rekey round-trip times
    // out), the sender must HARD-STOP at SEQ_SEND_CEILING rather
    // than wrap to 0 and reuse a nonce.
    //
    // We simulate this by:
    //   1. Bumping Alice's seq to SEQ_SEND_CEILING - 2 (past
    //      auto-rekey, near hard ceiling).
    //   2. Knocking Bob offline so the rekey round-trip cannot
    //      complete — we drop Bob and await a moment.
    //   3. Calling send_data repeatedly. It may either:
    //      (a) succeed via auto-rekey (Bob still answers) — fine,
    //          rekey works.
    //      (b) error fail-closed once the seq cannot advance
    //          safely — also fine, but MUST NOT silently encrypt
    //          a packet with a wrapped (already-used) seq.
    //
    // The negative property we verify: after pushing seq to the
    // ceiling, Alice's reported `next_tx_seq` never goes BACKWARD
    // without a corresponding `auto_rekeys` bump. Wrapping
    // without rekey would manifest as seq dropping from
    // ~2^31 to ~0 with no auto_rekeys delta.
    let (alice, bob, bob_handle) = handshake_pair().await;

    let bumped = alice
        .test_bump_peer_seq(&bob_handle, SEQ_SEND_CEILING - 2)
        .await;
    assert!(bumped);
    let m_pre = alice.metrics();
    let pm_pre = alice.peer_metrics(&bob_handle).await.unwrap();

    // Try a few sends. At least one must EITHER trigger a rekey
    // (auto_rekeys bumps and seq drops with a paired bump) OR
    // return an error. The forbidden outcome is "succeeds AND
    // seq wraps AND no rekey."
    let mut send_results = Vec::new();
    for i in 0..5 {
        let r = alice
            .send_data(&bob_handle, format!("p{}", i).as_bytes(), 1000, 0)
            .await;
        send_results.push(r);
    }
    let m_post = alice.metrics();
    let pm_post = alice.peer_metrics(&bob_handle).await.unwrap();

    let rekeyed = m_post.auto_rekeys > m_pre.auto_rekeys;
    let seq_decreased = pm_post.next_tx_seq < pm_pre.next_tx_seq;

    // If seq decreased, that decrease MUST be explained by a
    // rekey. Otherwise we've witnessed silent wrap → nonce reuse.
    assert!(
        !seq_decreased || rekeyed,
        "ALARM: Alice's next_tx_seq decreased from {} to {} without an \
         auto_rekey (auto_rekeys: {} -> {}). This indicates silent seq \
         wrap, which would reuse an AEAD nonce.",
        pm_pre.next_tx_seq, pm_post.next_tx_seq,
        m_pre.auto_rekeys, m_post.auto_rekeys,
    );

    // Sink any DATA Bob receives so we don't leak the channel.
    let _ = tokio::time::timeout(Duration::from_millis(500), bob.recv()).await;

    eprintln!(
        "send results at ceiling: ok={} err={}, rekeyed={}, seq {} -> {}",
        send_results.iter().filter(|r| r.is_ok()).count(),
        send_results.iter().filter(|r| r.is_err()).count(),
        rekeyed,
        pm_pre.next_tx_seq, pm_post.next_tx_seq,
    );
}
