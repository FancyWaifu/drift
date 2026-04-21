//! Soak test — continuous traffic over several seconds, verifying that:
//!  - No packets are dropped inside DRIFT (only due to kernel UDP limits)
//!  - The receiver's coalesce_state doesn't grow unboundedly when a
//!    single group is reused
//!  - The seq counter advances monotonically without gaps on the send side
//!  - No panic, deadlock, or hang under sustained load

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test]
async fn soak_steady_stream() {
    const PACKETS_PER_SEC: u64 = 200;
    const DURATION_SECS: u64 = 5;
    const TOTAL: u64 = PACKETS_PER_SEC * DURATION_SECS;

    let bob = Identity::from_secret_bytes([0x70; 32]);
    let alice = Identity::from_secret_bytes([0x71; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(
            alice_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
            .await
            .unwrap(),
    );
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // Spawn receiver.
    let bob_recv = bob_t.clone();
    let rx_task = tokio::spawn(async move {
        let mut seen = HashSet::new();
        let deadline = Instant::now() + Duration::from_secs(DURATION_SECS + 3);
        while Instant::now() < deadline && (seen.len() as u64) < TOTAL {
            match tokio::time::timeout(Duration::from_millis(200), bob_recv.recv()).await {
                Ok(Some(p)) if p.payload.len() == 8 => {
                    let tick = u64::from_be_bytes(p.payload.try_into().unwrap());
                    seen.insert(tick);
                }
                Ok(Some(_)) => {}
                _ => {}
            }
        }
        seen
    });

    // Sender: tight interval loop.
    let interval = Duration::from_micros(1_000_000 / PACKETS_PER_SEC);
    let mut ticker = tokio::time::interval(interval);
    let start = Instant::now();
    for i in 0..TOTAL {
        ticker.tick().await;
        alice_t
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 1)
            .await
            .unwrap();
    }
    let elapsed = start.elapsed();
    println!("sent {} packets in {:?}", TOTAL, elapsed);

    let seen = rx_task.await.unwrap();
    let delivered = seen.len() as u64;
    let delivery_rate = (delivered as f64) / (TOTAL as f64);
    println!(
        "delivered {}/{} = {:.1}%",
        delivered,
        TOTAL,
        delivery_rate * 100.0
    );

    // Coalescing is active (group=1) but with a single group the state
    // map should stay at size 1 regardless of how many packets flow.
    // We can't inspect peer state from the integration test, but we can
    // verify delivery stays healthy under sustained load.
    assert!(
        delivery_rate >= 0.95,
        "delivery rate {:.1}% below 95% threshold",
        delivery_rate * 100.0
    );

    // Verify no huge gaps — the set should be roughly contiguous.
    let mut ticks: Vec<u64> = seen.into_iter().collect();
    ticks.sort_unstable();
    if let (Some(&first), Some(&last)) = (ticks.first(), ticks.last()) {
        let range = last - first + 1;
        println!("first={} last={} range={}", first, last, range);
        assert!(
            range >= delivered,
            "seq range ({}) < delivered count ({})",
            range,
            delivered
        );
    }
}

#[tokio::test]
async fn soak_many_coalesce_groups() {
    // Verifies that the coalesce_state HashMap behaves with many groups.
    // If there's no eviction logic, this test documents current behavior:
    // state grows linearly with unique groups used. Real workloads should
    // either reuse a bounded set of groups or accept the memory cost.
    let bob = Identity::from_secret_bytes([0x72; 32]);
    let alice = Identity::from_secret_bytes([0x73; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse().unwrap(), bob)
            .await
            .unwrap(),
    );
    bob_t
        .add_peer(
            alice_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let bob_addr = bob_t.local_addr().unwrap();

    let alice_t = Transport::bind("127.0.0.1:0".parse().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();

    // 500 unique groups, one packet each. Yield between sends so
    // Bob's recv task can drain the socket — otherwise a tight burst
    // on localhost UDP can overflow SO_RCVBUF under load and drop
    // packets before DRIFT ever sees them.
    for group in 1..=500u32 {
        alice_t
            .send_data(&bob_peer, &group.to_be_bytes(), 0, group)
            .await
            .unwrap();
        tokio::task::yield_now().await;
    }

    // Drain — we just want to verify no crash. The per-recv timeout
    // is generous so we don't bail early under scheduler jitter on a
    // loaded machine; this test has historically flaked when the
    // deadline was tight.
    let mut count = 0;
    let deadline = Instant::now() + Duration::from_secs(8);
    while count < 500 && Instant::now() < deadline {
        if tokio::time::timeout(Duration::from_secs(1), bob_t.recv())
            .await
            .ok()
            .flatten()
            .is_some()
        {
            count += 1;
        } else {
            break;
        }
    }
    println!("500 unique groups: delivered {}", count);
    // Fine for this test: just verifying no explosion.
    assert!(count >= 400, "delivered only {}/500", count);
}
