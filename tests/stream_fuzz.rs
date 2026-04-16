//! Random-byte fuzz for the stream layer.
//!
//! Drives `Transport::send_data` with randomized stream-frame-like
//! bytes on a live session and asserts the victim's StreamManager
//! neither panics nor allocates unbounded state. The victim's
//! `total_buffered_segments` and `live_streams_for` metrics provide
//! the bounding signal.

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{derive_peer_id, Direction, Transport};
use rand::{Rng, RngCore, SeedableRng};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn random_stream_frames_no_panic_bounded_state() {
    let victim_id = Identity::from_secret_bytes([0x50; 32]);
    let attacker_id = Identity::from_secret_bytes([0x51; 32]);
    let victim_pub = victim_id.public_bytes();
    let attacker_pub = attacker_id.public_bytes();
    let attacker_peer_id = derive_peer_id(&attacker_pub);

    let victim_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), victim_id)
            .await
            .unwrap(),
    );
    victim_t
        .add_peer(
            attacker_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await.unwrap();
    let victim_addr = victim_t.local_addr().unwrap();

    let attacker_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), attacker_id)
            .await
            .unwrap(),
    );
    let victim_peer = attacker_t
        .add_peer(victim_pub, victim_addr, Direction::Initiator)
        .await.unwrap();

    let victim_mgr = StreamManager::bind(victim_t.clone()).await;

    // Warm up the handshake with a benign first packet so later
    // fuzzed sends don't hit the pre-handshake pending cap.
    let mut buf = vec![0u8; 9];
    buf[0] = 0x10; // TAG_OPEN
    buf[1..5].copy_from_slice(&1u32.to_be_bytes());
    attacker_t.send_data(&victim_peer, &buf, 0, 0).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now fire 2000 random frames at the victim's stream layer.
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xFACE);
    for _ in 0..2_000 {
        let len = rng.gen_range(1..64);
        let mut frame = vec![0u8; len];
        rng.fill_bytes(&mut frame);
        // Occasionally force a known tag to hit the dispatch
        // branches more deterministically.
        if rng.gen_bool(0.6) {
            frame[0] = [0x10u8, 0x11, 0x12, 0x13][rng.gen_range(0..4)];
        }
        // send_data enforces its own size cap; ignore failures.
        let _ = attacker_t.send_data(&victim_peer, &frame, 0, 0).await;
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Bounds must hold: recv buffer capped, per-peer stream count
    // capped. No panic implied by simply still running.
    let buffered = victim_mgr.total_buffered_segments().await;
    assert!(
        buffered <= 1024,
        "fuzz caused unbounded recv_buf growth: {}",
        buffered
    );
    let live = victim_mgr.live_streams_for(&attacker_peer_id).await;
    assert!(
        live <= 1024,
        "fuzz caused unbounded stream table growth: {}",
        live
    );
}
