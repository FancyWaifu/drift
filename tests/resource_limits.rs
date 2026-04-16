//! Resource exhaustion tests — document scaling limits and identify
//! unbounded-growth gaps.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Add many peers and verify add_peer / lookups stay responsive.
#[tokio::test]
async fn peer_table_add_10k() {
    let server = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes([0x01; 32]),
    )
    .await
    .unwrap();

    let start = Instant::now();
    for i in 0..10_000u32 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&i.to_be_bytes());
        seed[4] = 0xAA;
        let pub_key = Identity::from_secret_bytes(seed).public_bytes();
        server
            .add_peer(pub_key, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
            .await.unwrap();
    }
    let elapsed = start.elapsed();
    println!("peer_table_add_10k: {:?}", elapsed);
    assert!(
        elapsed < Duration::from_secs(10),
        "adding 10k peers took {:?}",
        elapsed
    );
}

/// Routing table scales to many static routes.
#[tokio::test]
async fn routing_table_add_5k() {
    let t = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes([0x02; 32]),
    )
    .await
    .unwrap();

    let start = Instant::now();
    for i in 0..5_000u32 {
        let mut id = [0u8; 8];
        id[..4].copy_from_slice(&i.to_be_bytes());
        t.add_route(id, "127.0.0.1:9000".parse().unwrap()).await;
    }
    let elapsed = start.elapsed();
    println!("routing_table_add_5k: {:?}", elapsed);
    assert!(elapsed < Duration::from_secs(5));
}

/// When a peer is stuck in AwaitingAck (because the server never replies),
/// send_data queues into peer.pending — but the queue is bounded. Past
/// the cap, send_data must fail fast with `QueueFull` (or, if retries
/// are exhausted first, `HandshakeExhausted`). Either way, memory is
/// bounded. Detailed coverage of both errors lives in
/// `tests/pending_queue_cap.rs`; this test just hammers the default
/// config and asserts bounded behavior.
#[tokio::test]
async fn pending_queue_flood_bounded() {
    use drift::error::DriftError;
    // Bob is never started; Alice's handshake will never complete.
    let alice = Identity::from_secret_bytes([0x03; 32]);
    let bob_pub = Identity::from_secret_bytes([0x04; 32]).public_bytes();

    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
        .await
        .unwrap();
    let dead_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, dead_addr, Direction::Initiator)
        .await.unwrap();

    // Blast 10,000 sends. We expect an error well before 10,000.
    let mut successes = 0;
    let mut terminal_err = None;
    for i in 0..10_000u32 {
        match alice_t.send_data(&bob_peer, &i.to_be_bytes(), 0, 0).await {
            Ok(()) => successes += 1,
            Err(e) => {
                terminal_err = Some(e);
                break;
            }
        }
    }

    let err = terminal_err.expect("expected send_data to error out eventually");
    assert!(
        matches!(err, DriftError::QueueFull | DriftError::HandshakeExhausted),
        "expected QueueFull or HandshakeExhausted, got {:?}",
        err
    );
    assert!(
        successes < 10_000,
        "queue must be bounded — got {} successful sends before erroring",
        successes
    );
    println!(
        "pending_queue_flood: {} queued before {:?}",
        successes, err
    );
}

/// Send many different coalesce groups and verify the coalesce_state map
/// doesn't cause delivery failures even at scale.
#[tokio::test]
async fn coalesce_map_10k_groups() {
    let bob = Identity::from_secret_bytes([0x05; 32]);
    let alice = Identity::from_secret_bytes([0x06; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await.unwrap();

    // Spawn receiver in the background.
    let bob_recv = bob_t.clone();
    let rx = tokio::spawn(async move {
        let mut count = 0;
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline && count < 10_000 {
            if tokio::time::timeout(Duration::from_millis(200), bob_recv.recv())
                .await
                .ok()
                .flatten()
                .is_some()
            {
                count += 1;
            }
        }
        count
    });

    // Send 10k unique-group packets with light pacing.
    for group in 1..=10_000u32 {
        alice_t
            .send_data(&bob_peer, &group.to_be_bytes(), 0, group)
            .await
            .unwrap();
        if group % 100 == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    let delivered = rx.await.unwrap();
    println!("coalesce_map_10k_groups: delivered {}/10k", delivered);
    assert!(
        delivered >= 9500,
        "expected ≥95% delivery, got {}",
        delivered
    );
    // Note: the peer's `coalesce_state` map is bounded at
    // `COALESCE_STATE_CAPACITY` (256) with FIFO eviction, so
    // a 10k unique-group run does NOT grow memory without
    // bound — the oldest 9744 entries get aged out. This
    // test used to warn about unbounded growth; that's been
    // addressed. The assertion here just checks that
    // delivery works under that eviction pressure.
}

/// Send with a receiver that never drains its recv channel, verify that
/// back-pressure engages (via tx.send().await in the recv loop) and the
/// sender doesn't spin-loop into an OOM.
#[tokio::test]
async fn recv_channel_backpressure() {
    let bob = Identity::from_secret_bytes([0x07; 32]);
    let alice = Identity::from_secret_bytes([0x08; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await.unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await.unwrap();

    // Warm up.
    alice_t.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _first = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    // Blast 5000 packets without draining. Channel capacity is 1024, so
    // once that fills, the recv loop blocks on tx.send().await, which
    // means incoming UDP packets accumulate in the kernel buffer until
    // it drops them.
    for i in 0..5000u32 {
        alice_t
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
    }

    // Give the system a moment to settle, then drain what we can.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut drained = 0;
    while tokio::time::timeout(Duration::from_millis(50), bob_t.recv())
        .await
        .ok()
        .flatten()
        .is_some()
    {
        drained += 1;
    }
    println!(
        "recv_channel_backpressure: drained {} after 5k sends (cap 1024)",
        drained
    );
    // We expect somewhere around the channel capacity. The exact number
    // depends on kernel buffer and scheduling. The point is: we drained
    // SOMETHING and nothing panicked.
    assert!(drained > 0, "nothing drained — backpressure deadlock?");
}

/// Mesh routing table lookup stays O(1) with many entries.
#[tokio::test]
async fn routing_lookup_constant_time() {
    let t = Transport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Identity::from_secret_bytes([0x09; 32]),
    )
    .await
    .unwrap();
    // Populate 5k routes.
    for i in 0..5_000u32 {
        let mut id = [0u8; 8];
        id[..4].copy_from_slice(&i.to_be_bytes());
        t.add_route(id, "127.0.0.1:9000".parse().unwrap()).await;
    }
    // Force a lookup by starting a handshake (send_data looks up the
    // route for the destination). Use any registered dst id.
    let mut lookup_id = [0u8; 8];
    lookup_id[..4].copy_from_slice(&4999u32.to_be_bytes());
    // No peer registered, so send_data fails — but the lookup itself
    // must have happened. We're measuring that sendtime doesn't explode.
    let start = Instant::now();
    for _ in 0..100 {
        let _ = t.send_data(&lookup_id, &[], 0, 0).await;
    }
    let elapsed = start.elapsed();
    println!("100 send_data attempts with 5k routes: {:?}", elapsed);
    assert!(elapsed < Duration::from_millis(500));
}
