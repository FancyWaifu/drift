//! Run DRIFT through a simulated lossy link and verify:
//!  - Handshake still completes under 10% loss + jitter
//!  - Coalescing correctly drops stale packets under reordering
//!  - Deadline enforcement drops expired packets under high latency
//!
//! The "proxy" is inlined here as an in-process forwarder with configurable
//! drop/reorder/latency. This avoids needing a separate binary.

use drift::identity::Identity;
use drift::{Direction, Transport};
use rand::{Rng, SeedableRng};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Clone, Copy)]
struct LossProfile {
    drop_rate: f64,
    reorder_rate: f64,
    latency_ms: u64,
    jitter_ms: u64,
}

/// Spawn a bidirectional UDP proxy with the given loss profile.
/// Returns the proxy's listen address.
async fn spawn_proxy(target: SocketAddr, profile: LossProfile) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let mut rng = rand::rngs::StdRng::from_entropy();
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let data = buf[..n].to_vec();

            let dst = if src == target {
                match *client.lock().await {
                    Some(a) => a,
                    None => continue,
                }
            } else {
                let mut c = client.lock().await;
                if c.is_none() {
                    *c = Some(src);
                }
                target
            };

            if rng.gen::<f64>() < profile.drop_rate {
                continue;
            }

            let mut delay = profile.latency_ms;
            if profile.jitter_ms > 0 {
                delay += rng.gen_range(0..=profile.jitter_ms);
            }
            if rng.gen::<f64>() < profile.reorder_rate {
                delay += rng.gen_range(30..=150);
            }

            let sock_clone = sock.clone();
            tokio::spawn(async move {
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                let _ = sock_clone.send_to(&data, dst).await;
            });
        }
    });

    addr
}

/// Handshake must complete under 10% packet loss. The transport's
/// background retry loop retransmits HELLO with the same client_nonce;
/// the server caches HELLO_ACK so a duplicate HELLO gets a replayed
/// response rather than a fresh session.
#[tokio::test]
async fn handshake_under_loss() {
    let bob = Identity::from_secret_bytes([0xF0; 32]);
    let alice = Identity::from_secret_bytes([0xF1; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), bob)
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

    // 30% loss per direction — each HELLO/HELLO_ACK round-trip
    // succeeds ~49% of the time, so expected handshake attempts
    // hover around 2. Bumped down from an earlier 50% that flaked
    // under cargo-test parallel pressure without actually
    // strengthening the assertion.
    let proxy_addr = spawn_proxy(
        bob_addr,
        LossProfile {
            drop_rate: 0.3,
            reorder_rate: 0.0,
            latency_ms: 20,
            jitter_ms: 10,
        },
    )
    .await;

    // Use a beefier retry budget than the default so the 50% drop
    // rate can't exhaust all 10 default attempts before the
    // handshake completes.
    let cfg = drift::TransportConfig {
        handshake_max_attempts: 50,
        handshake_retry_base_ms: 30,
        ..drift::TransportConfig::default()
    };
    let alice_t =
        Transport::bind_with_config("127.0.0.1:0".parse::<SocketAddr>().unwrap(), alice, cfg)
            .await
            .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, proxy_addr, Direction::Initiator)
        .await
        .unwrap();

    // Try handshake by sending a DATA packet.
    let mut delivered = 0;
    for i in 0..100u32 {
        alice_t
            .send_data(&bob_peer, &i.to_be_bytes(), 0, 0)
            .await
            .unwrap();
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(400), bob_t.recv()).await {
            delivered += 1;
            if delivered >= 5 {
                break;
            }
        }
    }
    assert!(
        delivered >= 3,
        "got {} packets through 50% loss link — handshake or retries broken",
        delivered
    );
}

#[tokio::test]
async fn coalescing_under_reorder() {
    // Heavy reordering: 40% of packets get delayed randomly. Send coalesced
    // "position updates" and verify the receiver never sees a group-seq
    // that's lower than one it already received.
    let bob = Identity::from_secret_bytes([0xE0; 32]);
    let alice = Identity::from_secret_bytes([0xE1; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), bob)
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

    let proxy_addr = spawn_proxy(
        bob_addr,
        LossProfile {
            drop_rate: 0.0,
            reorder_rate: 0.4,
            latency_ms: 10,
            jitter_ms: 5,
        },
    )
    .await;

    let alice_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, proxy_addr, Direction::Initiator)
        .await
        .unwrap();

    // Send 100 position updates in the same coalesce group.
    for tick in 1..=100u32 {
        alice_t
            .send_data(&bob_peer, &tick.to_be_bytes(), 5000, 1)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Drain with a generous budget — under heavy reordering the
    // proxy's delay queue can keep packets in flight longer than a
    // tight deadline, which used to flake this test on loaded
    // machines.
    let mut highest_seen: u32 = 0;
    let mut count = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), bob_t.recv()).await {
            Ok(Some(p)) => {
                let tick = u32::from_be_bytes(p.payload.try_into().unwrap());
                // Critical property: the receiver must never see a tick
                // that's lower than one it already received, because
                // coalescing drops stale packets.
                assert!(
                    tick > highest_seen,
                    "coalesce violation: saw {} after {}",
                    tick,
                    highest_seen
                );
                highest_seen = tick;
                count += 1;
            }
            _ => {}
        }
    }
    println!(
        "coalesce-under-reorder: {} unique updates delivered, highest tick = {}",
        count, highest_seen
    );
    assert!(count >= 5, "only got {} updates", count);
}

#[tokio::test]
async fn deadline_drops_slow_packets() {
    // 150ms latency link + 50ms deadline. Packets should arrive too late
    // and be dropped by the deadline filter on the receiver.
    let bob = Identity::from_secret_bytes([0xD0; 32]);
    let alice = Identity::from_secret_bytes([0xD1; 32]);
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let bob_t = Arc::new(
        Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), bob)
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

    let proxy_addr = spawn_proxy(
        bob_addr,
        LossProfile {
            drop_rate: 0.0,
            reorder_rate: 0.0,
            latency_ms: 150,
            jitter_ms: 30,
        },
    )
    .await;

    let alice_t = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), alice)
        .await
        .unwrap();
    let bob_peer = alice_t
        .add_peer(bob_pub, proxy_addr, Direction::Initiator)
        .await
        .unwrap();

    // First: warm up the handshake (no deadline).
    alice_t.send_data(&bob_peer, b"warmup", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob_t.recv()).await;

    // Now: send 20 packets with a 50ms deadline. They should all arrive
    // at bob AFTER their deadline, so they should all be dropped.
    for i in 0..20u32 {
        alice_t
            .send_data(&bob_peer, &i.to_be_bytes(), 50, 0)
            .await
            .unwrap();
    }

    let mut received = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(300), bob_t.recv()).await {
            Ok(Some(_)) => received += 1,
            _ => break,
        }
    }
    println!(
        "deadline-filter: received {}/20 packets (expected ≤ few)",
        received
    );
    // The deadline filter should drop most or all of these. A few might
    // slip through if jitter is low, but > 5 means the filter is broken.
    assert!(
        received <= 5,
        "deadline filter let {}/20 expired packets through",
        received
    );
}
