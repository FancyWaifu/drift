//! Attack: stream OPEN flood.
//!
//! Any authenticated peer can push raw TAG_OPEN frames through the
//! DRIFT transport directly, and each unique `stream_id` the victim
//! sees turns into a fresh `StreamState` entry plus an mpsc channel.
//! Without a per-peer cap, the victim's stream table grows without
//! bound — a memory DoS against an otherwise-trusted peer.
//!
//! This test plays the attacker from a real Transport: drives the
//! handshake, then fires 5_000 raw TAG_OPEN frames with unique
//! stream ids. The victim's `live_streams_for(attacker)` must stay
//! at or below `MAX_STREAMS_PER_PEER` (1024).

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{derive_peer_id, Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

/// Wire format of a stream OPEN frame: [0x10][stream_id:u32 BE].
fn stream_open_frame(stream_id: u32) -> Vec<u8> {
    let mut wire = Vec::with_capacity(5);
    wire.push(0x10); // TAG_OPEN
    wire.extend_from_slice(&stream_id.to_be_bytes());
    wire
}

#[tokio::test]
async fn open_flood_cannot_exhaust_victim_stream_table() {
    let victim_id = Identity::from_secret_bytes([0x10; 32]);
    let victim_pub = victim_id.public_bytes();
    let victim_transport = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), victim_id)
            .await
            .unwrap(),
    );
    let victim_addr = victim_transport.local_addr().unwrap();

    let attacker_id = Identity::from_secret_bytes([0x20; 32]);
    let attacker_pub = attacker_id.public_bytes();
    let attacker_peer_id = derive_peer_id(&attacker_pub);
    let attacker_transport = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), attacker_id)
            .await
            .unwrap(),
    );

    victim_transport
        .add_peer(
            attacker_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let victim_peer = attacker_transport
        .add_peer(victim_pub, victim_addr, Direction::Initiator)
        .await
        .unwrap();

    let victim_mgr = StreamManager::bind(victim_transport.clone()).await;

    // Warm up the session with one legitimate DATA packet so the
    // handshake completes before the flood. (The flood itself is
    // shipped via send_data, which also triggers the handshake on
    // first call — but doing it explicitly first makes the timing
    // easier to reason about.)
    attacker_transport
        .send_data(&victim_peer, &stream_open_frame(2), 0, 0)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // --- the attack ---
    const FLOOD: u32 = 5_000;
    for i in 0..FLOOD {
        // Use ids that won't collide with the warm-up id=2.
        let wire = stream_open_frame(1_000 + i);
        attacker_transport
            .send_data(&victim_peer, &wire, 0, 0)
            .await
            .unwrap();
    }

    // Let the victim drain the flood.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let live = victim_mgr.live_streams_for(&attacker_peer_id).await;
    assert!(
        live <= 1024,
        "victim allocated {} stream entries for attacker — cap should be 1024",
        live
    );
    // Sanity: at least *some* streams should have been created, so
    // the test is actually exercising the OPEN path rather than
    // silently dropping every frame.
    assert!(
        live >= 100,
        "expected victim to allocate many streams up to the cap, got {}",
        live
    );
}
