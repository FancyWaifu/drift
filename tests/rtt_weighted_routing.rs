//! Tier 2 payoff test: the RTT-weighted mesh router should
//! pick a LOW-LATENCY 2-hop path over a HIGH-LATENCY 1-hop
//! path among mesh-forwarded routes.
//!
//! Topology:
//!
//! ```text
//!                ┌─── B1 ───┐       (fast path)
//!                │          │
//!     A ─────────┤          ├──── C
//!                │          │
//!                └─── B2 ───┘       (slow path via proxy)
//! ```
//!
//! A has direct sessions with B1 and B2 but NOT with C (C's
//! direct address is unreachable from A). B1 and B2 both
//! have direct sessions with C. B1's network path to A is
//! fast (direct loopback). B2's network path to A goes
//! through a latency-injecting proxy that adds 50 ms of
//! delay in each direction.
//!
//! After beacons flow:
//!   - A hears from B1: "I can reach C at cost ~0 µs."
//!   - A hears from B2: "I can reach C at cost ~0 µs."
//!   - A composes: "C via B1" cost ≈ neighbor_rtt_to_B1 (fast)
//!                 "C via B2" cost ≈ neighbor_rtt_to_B2 (slow)
//!   - RTT-weighted `update_if_better` picks B1.
//!
//! We verify this by watching A's routing table and asserting
//! the next_hop for C is B1's address (or the address A
//! resolved for reaching B1, which on this setup is B1's
//! actual socket).

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Bidirectional UDP proxy that delays every packet by
/// `delay_ms`. Used to simulate a high-latency link between
/// two transports that are actually on loopback.
async fn spawn_delay_proxy(target: SocketAddr, delay_ms: u64) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
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
            let sock2 = sock.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let _ = sock2.send_to(&data, dst).await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rtt_weighted_picks_fast_two_hop_over_slow_one_hop() {
    // Fast beacons + fast RTT probes so routes converge in
    // the test's time budget. Also bump max_peers just in
    // case.
    let fast_cfg = || TransportConfig {
        beacon_interval_ms: 200,
        rtt_probe_interval_ms: 200,
        accept_any_peer: true,
        ..TransportConfig::default()
    };

    // ---- Identities ----
    let a_id = Identity::from_secret_bytes([0xA0; 32]);
    let b1_id = Identity::from_secret_bytes([0xB1; 32]);
    let b2_id = Identity::from_secret_bytes([0xB2; 32]);
    let c_id = Identity::from_secret_bytes([0xC0; 32]);
    let a_pub = a_id.public_bytes();
    let b1_pub = b1_id.public_bytes();
    let b2_pub = b2_id.public_bytes();
    let c_pub = c_id.public_bytes();

    // ---- Transports ----
    let a_t = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), a_id, fast_cfg())
            .await
            .unwrap(),
    );
    let b1_t = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), b1_id, fast_cfg())
            .await
            .unwrap(),
    );
    let b2_t = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), b2_id, fast_cfg())
            .await
            .unwrap(),
    );
    let c_t = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), c_id, fast_cfg())
            .await
            .unwrap(),
    );

    let a_addr = a_t.local_addr().unwrap();
    let b1_addr = b1_t.local_addr().unwrap();
    let b2_addr = b2_t.local_addr().unwrap();
    let c_addr = c_t.local_addr().unwrap();

    // ---- Latency-injecting proxy in front of B2 as seen by A ----
    // A talks to B2 through this proxy → 50ms round-trip.
    let b2_via_proxy = spawn_delay_proxy(b2_addr, 50).await;

    // ---- Peering ----
    // A knows B1 directly, B2 via the proxy, and C at an
    // unreachable placeholder address (we never handshake
    // directly to C).
    let b1_peer_on_a = a_t
        .add_peer(b1_pub, b1_addr, Direction::Initiator)
        .await
        .unwrap();
    let b2_peer_on_a = a_t
        .add_peer(b2_pub, b2_via_proxy, Direction::Initiator)
        .await
        .unwrap();
    let c_peer_on_a = a_t
        .add_peer(c_pub, "127.0.0.1:1".parse().unwrap(), Direction::Initiator)
        .await
        .unwrap();

    // B1 and B2 know C directly and know A as a responder.
    b1_t.add_peer(a_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    b1_t.add_peer(c_pub, c_addr, Direction::Initiator)
        .await
        .unwrap();
    b2_t.add_peer(a_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    b2_t.add_peer(c_pub, c_addr, Direction::Initiator)
        .await
        .unwrap();

    // C knows B1 and B2 as responders.
    c_t.add_peer(b1_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();
    c_t.add_peer(b2_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await
        .unwrap();

    // Drive the handshakes: A ↔ B1, A ↔ B2, B1 ↔ C, B2 ↔ C.
    a_t.send_data(&b1_peer_on_a, b"hi", 0, 0).await.unwrap();
    a_t.send_data(&b2_peer_on_a, b"hi", 0, 0).await.unwrap();
    let b1_c_peer: [u8; 8] = drift::crypto::derive_peer_id(&c_pub);
    let b2_c_peer: [u8; 8] = drift::crypto::derive_peer_id(&c_pub);
    b1_t.send_data(&b1_c_peer, b"hi", 0, 0).await.unwrap();
    b2_t.send_data(&b2_c_peer, b"hi", 0, 0).await.unwrap();

    // Drain the bootstrap traffic.
    for _ in 0..4 {
        let _ = tokio::time::timeout(Duration::from_secs(2), b1_t.recv()).await;
    }
    for _ in 0..4 {
        let _ = tokio::time::timeout(Duration::from_secs(2), b2_t.recv()).await;
    }
    for _ in 0..4 {
        let _ = tokio::time::timeout(Duration::from_secs(2), c_t.recv()).await;
    }

    // Give the routing layer enough beacon + ping rounds
    // to converge: two beacon intervals past the probe
    // settling time.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Verify: A's routing table for C should point at B1's
    // address (the fast path), not B2's (the slow path via
    // the proxy). We use the test-only accessor
    // `test_lookup_route` to peek.
    let route_for_c = a_t.test_lookup_route(&c_peer_on_a).await;
    assert!(
        route_for_c.is_some(),
        "A should have learned a route to C via beacons"
    );
    let (next_hop, cost_us) = route_for_c.unwrap();
    println!(
        "A's route to C: next_hop={} cost_us={}",
        next_hop, cost_us
    );

    // The next hop must be B1's direct address — NOT the
    // proxy in front of B2. A hears beacons from both B1
    // and B2, but B1's composed cost is neighbor_rtt_to_B1
    // (sub-ms loopback) and B2's is neighbor_rtt_to_B2
    // (~50ms proxy), so B1 wins.
    assert_eq!(
        next_hop, b1_addr,
        "A should route to C via B1 (fast), got {}",
        next_hop
    );

    // Suppress unused warnings for _a_addr which we keep for
    // debugging but don't assert against.
    let _ = (a_addr, b2_peer_on_a);
}
