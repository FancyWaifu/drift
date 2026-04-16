//! Datagrams and streams share the same authenticated session
//! but follow different code paths: streams go through the
//! cwnd / retransmit machinery, datagrams bypass it entirely.
//! This test verifies that a high-rate datagram sender does not
//! starve a parallel stream (or vice versa) on the same peer.
//!
//! The assertion is coarse — we just check that both channels
//! deliver the expected payloads under concurrent load within
//! a reasonable time budget. A starvation bug would manifest as
//! one side deadlocking or running out of budget.

use drift::identity::Identity;
use drift::streams::StreamManager;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn heavy_datagrams_do_not_starve_stream() {
    let alice_id = Identity::from_secret_bytes([0xD1; 32]);
    let bob_id = Identity::from_secret_bytes([0xD2; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob_id)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice_id)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Warmup.
    alice_t.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    let alice_mgr = StreamManager::bind(alice_t.clone()).await;
    let bob_mgr = StreamManager::bind(bob_t.clone()).await;

    let stream_a = alice_mgr.open(bob_peer).await.unwrap();
    let stream_b = tokio::time::timeout(Duration::from_secs(2), bob_mgr.accept())
        .await
        .unwrap()
        .unwrap();

    // Stream payload: 32 KB in 32 chunks.
    const STREAM_BYTES: usize = 32 * 1024;
    const CHUNK: usize = 1024;
    const DATAGRAM_COUNT: usize = 500;

    let stream_payload: Vec<u8> = (0..STREAM_BYTES).map(|i| (i & 0xFF) as u8).collect();
    let stream_payload_c = stream_payload.clone();

    let alice_mgr_for_dgram = alice_mgr.clone();

    // Spawn the stream sender.
    let stream_sender = tokio::spawn(async move {
        for chunk in stream_payload_c.chunks(CHUNK) {
            stream_a.send(chunk).await.unwrap();
        }
    });

    // Spawn the datagram sender — fires 500 small datagrams
    // concurrently with the stream push.
    let datagram_sender = tokio::spawn(async move {
        for i in 0..DATAGRAM_COUNT {
            let body = [(i >> 8) as u8, (i & 0xFF) as u8];
            alice_mgr_for_dgram
                .send_datagram(bob_peer, &body)
                .await
                .unwrap();
            // Tiny yield so the stream task gets a turn.
            if i % 16 == 0 {
                tokio::task::yield_now().await;
            }
        }
    });

    // Drain the stream on Bob.
    let stream_drainer = tokio::spawn(async move {
        let mut out = Vec::with_capacity(STREAM_BYTES);
        while out.len() < STREAM_BYTES {
            match tokio::time::timeout(Duration::from_secs(10), stream_b.recv()).await {
                Ok(Some(chunk)) => out.extend_from_slice(&chunk),
                _ => break,
            }
        }
        out
    });

    // Drain datagrams on Bob.
    let bob_mgr_drainer = bob_mgr.clone();
    let datagram_drainer = tokio::spawn(async move {
        let mut seen = 0usize;
        while seen < DATAGRAM_COUNT {
            match tokio::time::timeout(
                Duration::from_secs(10),
                bob_mgr_drainer.recv_datagram(),
            )
            .await
            {
                Ok(Some(_)) => seen += 1,
                _ => break,
            }
        }
        seen
    });

    // Time-bounded join.
    tokio::time::timeout(Duration::from_secs(20), async {
        stream_sender.await.unwrap();
        datagram_sender.await.unwrap();
    })
    .await
    .expect("sender tasks did not complete — possible starvation");

    let stream_bytes = tokio::time::timeout(Duration::from_secs(10), stream_drainer)
        .await
        .expect("stream drain timed out")
        .unwrap();
    let datagram_count =
        tokio::time::timeout(Duration::from_secs(10), datagram_drainer)
            .await
            .expect("datagram drain timed out")
            .unwrap();

    // Stream must be byte-for-byte intact.
    assert_eq!(
        stream_bytes, stream_payload,
        "stream bytes diverged under concurrent datagram load"
    );

    // Datagrams are unreliable, so we accept a small loss
    // budget to tolerate UDP-buffer overruns on the kernel side.
    // On a clean loopback path virtually all should make it.
    assert!(
        datagram_count >= DATAGRAM_COUNT * 9 / 10,
        "expected ≥90% datagram delivery, got {}/{}",
        datagram_count,
        DATAGRAM_COUNT
    );
}
