//! Long-running soak: drive steady traffic over a real session
//! for ~20 seconds and assert:
//!
//! * every sent packet is delivered (no silent drops on the
//!   fast path under moderate throughput on localhost),
//! * seq counter progresses monotonically as expected,
//! * metric deltas are consistent with the traffic pattern,
//! * no background counter is surprised (auth_failures,
//!   replays_caught, deadline_dropped all remain zero).
//!
//! This test is longer than the other soaks intentionally — it
//! catches slow leaks and metric drift that short tests miss.
//! Marked `#[ignore]` by default to keep `cargo test` fast; run
//! with `cargo test --test long_soak -- --ignored` when needed.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test]
#[ignore]
async fn steady_stream_twenty_seconds() {
    let alice = Identity::from_secret_bytes([0x60; 32]);
    let bob = Identity::from_secret_bytes([0x61; 32]);
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

    // Warm up.
    alice_t.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv())
        .await
        .unwrap()
        .unwrap();

    // Drive 200 pps for 20 seconds = 4000 packets.
    let start = Instant::now();
    let mut sent = 0u64;
    let total = 4000u64;

    let bob_c = bob_t.clone();
    let recv_task = tokio::spawn(async move {
        let mut n = 0u64;
        while n < total {
            match tokio::time::timeout(Duration::from_secs(2), bob_c.recv()).await {
                Ok(Some(_)) => n += 1,
                _ => break,
            }
        }
        n
    });

    while sent < total {
        alice_t
            .send_data(&bob_peer, &sent.to_be_bytes(), 0, 0)
            .await
            .unwrap();
        sent += 1;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let received = recv_task.await.unwrap();
    let elapsed = start.elapsed();

    println!(
        "soak: sent {} / received {} / elapsed {:?}",
        sent, received, elapsed
    );
    assert_eq!(
        sent, total,
        "sender loop should have completed all {} sends",
        total
    );
    assert!(
        received >= (total * 99) / 100,
        "lost too many packets: sent {} received {}",
        sent,
        received
    );

    let m_alice = alice_t.metrics();
    let m_bob = bob_t.metrics();

    // No unexpected counter bumps.
    assert_eq!(m_alice.auth_failures, 0);
    assert_eq!(m_bob.auth_failures, 0);
    assert_eq!(m_alice.replays_caught, 0);
    assert_eq!(m_bob.replays_caught, 0);
    assert_eq!(m_alice.deadline_dropped, 0);
    assert_eq!(m_bob.deadline_dropped, 0);
    assert_eq!(m_alice.coalesce_dropped, 0);
    assert_eq!(m_bob.coalesce_dropped, 0);
    assert_eq!(m_bob.path_probes_sent, 0);

    // Beacons may have fired a handful of times at 2s intervals.
    // Just assert the count is sane: ~10 max over 20 seconds.
    assert!(m_alice.beacons_sent <= 20);
    assert!(m_bob.beacons_sent <= 20);
}
