//! Attack: out-of-order stream DATA flood.
//!
//! Any peer holding a valid DRIFT session can open a stream to a
//! victim and then bypass the normal `Stream::send` path to inject
//! raw TAG_DATA frames directly into the victim's stream layer. If
//! those frames have skipping sequence numbers, the victim will
//! buffer every one of them in `recv_buf` waiting for the gap to
//! fill in. Without a bound, that buffer grows without limit — a
//! memory DoS by an authenticated peer.
//!
//! This test plays the attacker from a real Transport: it opens a
//! stream via the normal StreamManager path (so the victim
//! accept()s and allocates state), then fires 5_000 raw DATA
//! frames at seqs 10_000 .. 15_000 via `Transport::send_data`. The
//! victim's `total_buffered_segments()` must stay bounded by
//! `MAX_REORDER_WINDOW` (1024).

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

/// Wire format of a stream DATA frame inside a DRIFT DATA payload:
///   [0x11][stream_id:u32 BE][seq:u32 BE][bytes...]
fn stream_data_frame(stream_id: u32, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(9 + body.len());
    wire.push(0x11); // TAG_DATA
    wire.extend_from_slice(&stream_id.to_be_bytes());
    wire.extend_from_slice(&seq.to_be_bytes());
    wire.extend_from_slice(body);
    wire
}

#[tokio::test]
async fn out_of_order_flood_cannot_exhaust_victim_memory() {
    // --- set up victim ---
    let victim_id = Identity::from_secret_bytes([0x01; 32]);
    let victim_pub = victim_id.public_bytes();
    let victim_transport = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), victim_id)
            .await
            .unwrap(),
    );
    let victim_addr = victim_transport.local_addr().unwrap();

    // --- set up attacker ---
    let attacker_id = Identity::from_secret_bytes([0x02; 32]);
    let attacker_pub = attacker_id.public_bytes();
    let attacker_transport = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), attacker_id)
            .await
            .unwrap(),
    );

    // Pre-register each side so the handshake completes.
    victim_transport
        .add_peer(attacker_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let victim_peer = attacker_transport
        .add_peer(victim_pub, victim_addr, Direction::Initiator)
        .await.unwrap();

    // Wrap victim with a StreamManager so it will accept() the stream.
    let victim_mgr = StreamManager::bind(victim_transport.clone()).await;
    // Attacker also uses its own StreamManager for the initial OPEN.
    let attacker_mgr = StreamManager::bind(attacker_transport.clone()).await;

    // Open a stream attacker → victim. This drives the DRIFT
    // handshake and hands the victim a real StreamState to target.
    let stream = attacker_mgr
        .open(victim_peer)
        .await
        .expect("open stream");
    let stream_id = {
        // Force the victim to actually accept the stream, which
        // allocates the recv_buf we're about to attack.
        let accepted = tokio::time::timeout(Duration::from_secs(3), victim_mgr.accept())
            .await
            .expect("victim never accepted")
            .expect("accept returned None");
        // sanity
        assert_eq!(
            accepted.id(),
            stream.id(),
            "stream id mismatch between peers"
        );
        accepted.id()
    };

    // --- the attack ---
    // Fire 5_000 out-of-order DATA frames at seqs well beyond the
    // legitimate start of the stream. Each frame is shipped via the
    // underlying DRIFT transport so it bypasses the StreamManager's
    // own send_pending accounting on the attacker side.
    const FLOOD: u32 = 5_000;
    for i in 0..FLOOD {
        let seq = 10_000 + i; // never send seq 0, so recv_next stays 0
        let payload = stream_data_frame(stream_id, seq, b"x");
        attacker_transport
            .send_data(&victim_peer, &payload, 0, 0)
            .await
            .unwrap();
    }

    // Give the victim time to process the flood.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let buffered = victim_mgr.total_buffered_segments().await;
    assert!(
        buffered <= 1024,
        "victim buffered {} out-of-order segments — cap should be 1024",
        buffered
    );
}
