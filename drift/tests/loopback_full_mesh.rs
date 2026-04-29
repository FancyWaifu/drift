//! 127.0.0.1–127.0.0.4 full-mesh end-to-end test.
//!
//! For each registered URL transport (UDP, TCP, WebSocket) plus
//! a mixed-protocol final case, four peers register each other
//! and every peer sends a unique payload to every other peer.
//! Verifying all 12 messages arrive at their intended recipient
//! exercises:
//!
//!   1. Full handshake / session-key derivation per peer pair
//!   2. End-to-end AEAD over each transport in turn
//!   3. Mesh forwarding through a bridge for transports that
//!      can't do peer-to-peer directly (TCP / WS / WebRTC are
//!      point-to-point per stream)
//!   4. Cross-protocol bridging when the four peers each pick
//!      a different wire
//!
//! UDP gets the direct-mesh treatment since it's connectionless;
//! everything else uses a bridge node, which is the same
//! topology `four_medium_bridge.rs` proves works.

use drift::identity::Identity;
use drift::{Direction, PeerId, Transport, TransportConfig};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const N: usize = 4;

struct PeerState {
    transport: Arc<Transport>,
    pubkey: [u8; 32],
    peer_id: PeerId,
    /// UDP-direct case: each peer is bound to a real ip:port
    /// the others can route to. Bridge case: this is None
    /// because dial-out uses an ephemeral local port.
    udp_addr: Option<SocketAddr>,
}

fn fast_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        beacon_interval_ms: 200,
        rtt_probe_interval_ms: 0,
        ..TransportConfig::default()
    }
}

fn parse_bound_url(url: &str) -> SocketAddr {
    url.splitn(2, "://")
        .nth(1)
        .expect("bound URL must have scheme")
        .parse()
        .expect("bound URL ends in valid socketaddr")
}

/// Read up to N-1 packets from `t` and return the set of payload
/// strings observed. Bounded by `deadline` so a stuck peer
/// doesn't hang the whole test.
async fn collect_n_minus_one(
    t: &Arc<Transport>,
    expected: usize,
    deadline: Instant,
) -> HashSet<String> {
    let mut got = HashSet::new();
    while got.len() < expected && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, t.recv()).await {
            Ok(Some(pkt)) => {
                if let Ok(s) = String::from_utf8(pkt.payload.clone()) {
                    got.insert(s);
                }
            }
            _ => break,
        }
    }
    got
}

/// Asserts that every peer received exactly the 3 messages
/// addressed to it (one from each other peer).
fn assert_full_mesh_delivered(received: &[HashSet<String>], label: &str) {
    for (recv_idx, got) in received.iter().enumerate() {
        let expected: HashSet<String> = (0..N)
            .filter(|&i| i != recv_idx)
            .map(|i| format!("from-{}-to-{}", i + 1, recv_idx + 1))
            .collect();
        assert_eq!(
            got, &expected,
            "{}: peer {} got {:?} but expected {:?}",
            label,
            recv_idx + 1,
            got,
            expected
        );
    }
}

// ─── 1. UDP direct mesh on 127.0.0.1–.4 ───────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_all_udp_direct_loopback_1_to_4() {
    // UDP is connectionless, so we don't need a bridge — each
    // peer can `add_peer` the other three by their bound UDP
    // addr and start sending immediately.
    let cfg = fast_cfg();
    let mut peers: Vec<PeerState> = Vec::with_capacity(N);
    for i in 1..=N {
        let url = format!("udp://127.0.0.{}:0", i);
        let id = Identity::generate();
        let pubkey = id.public_bytes();
        let peer_id = drift::crypto::derive_peer_id(&pubkey);
        let (transport, bound_url) = Transport::bind_url(&url, id, cfg.clone()).await.unwrap();
        let udp_addr = parse_bound_url(&bound_url);
        peers.push(PeerState {
            transport: Arc::new(transport),
            pubkey,
            peer_id,
            udp_addr: Some(udp_addr),
        });
    }

    // Full mesh of (peer_pubkey, peer_addr) registrations.
    for i in 0..N {
        for j in 0..N {
            if i == j {
                continue;
            }
            peers[i]
                .transport
                .add_peer(
                    peers[j].pubkey,
                    peers[j].udp_addr.unwrap(),
                    Direction::Initiator,
                )
                .await
                .unwrap();
        }
    }

    // 12 directed sends.
    for sender in 0..N {
        for recv in 0..N {
            if sender == recv {
                continue;
            }
            let payload = format!("from-{}-to-{}", sender + 1, recv + 1);
            peers[sender]
                .transport
                .send_data(&peers[recv].peer_id, payload.as_bytes(), 0, 0)
                .await
                .unwrap();
        }
    }

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut received: Vec<HashSet<String>> = Vec::with_capacity(N);
    for p in &peers {
        received.push(collect_n_minus_one(&p.transport, N - 1, deadline).await);
    }
    assert_full_mesh_delivered(&received, "udp-direct");
}

// ─── 2. TCP all-4-peers via bridge ────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_all_tcp_via_bridge_loopback_1_to_4() {
    full_mesh_via_bridge(&["tcp", "tcp", "tcp", "tcp"], "tcp-mesh").await;
}

// ─── 3. WebSocket all-4-peers via bridge ──────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_all_ws_via_bridge_loopback_1_to_4() {
    full_mesh_via_bridge(&["ws", "ws", "ws", "ws"], "ws-mesh").await;
}

// ─── 4. Mixed protocols via bridge ────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_mixed_protocols_via_bridge_loopback_1_to_4() {
    // Each of the four peers picks a different wire to reach
    // the bridge, exercising cross-medium routing: a UDP peer
    // sends to a WS peer through the bridge, etc.
    full_mesh_via_bridge(&["udp", "tcp", "ws", "udp"], "mixed-mesh").await;
}

/// Bridge-topology helper. The bridge listens on every transport
/// the four peers might use; each peer dials the bridge over its
/// chosen wire; mesh routing forwards traffic between peers.
async fn full_mesh_via_bridge(per_peer_scheme: &[&str; N], label: &str) {
    let cfg = fast_cfg();

    // Bridge listens on every transport mentioned across all
    // peers, so each peer's chosen wire has a matching listener.
    let mut wanted_schemes: HashSet<&str> = HashSet::new();
    for s in per_peer_scheme {
        wanted_schemes.insert(*s);
    }
    let primary_scheme = wanted_schemes.iter().next().copied().unwrap();
    let primary_url = format!("{}://127.0.0.1:0", primary_scheme);
    let bridge_id = Identity::generate();
    let bridge_pub = bridge_id.public_bytes();
    let bridge_pid = drift::crypto::derive_peer_id(&bridge_pub);
    let (bridge, primary_bound_url) =
        Transport::bind_url(&primary_url, bridge_id, cfg.clone()).await.unwrap();
    let bridge = Arc::new(bridge);

    // Capture the bound URL of every transport the bridge
    // listens on, keyed by scheme, so peers know where to dial.
    let mut bridge_urls: std::collections::HashMap<&str, String> =
        std::collections::HashMap::new();
    bridge_urls.insert(primary_scheme, primary_bound_url);
    for scheme in wanted_schemes.iter().copied() {
        if scheme == primary_scheme {
            continue;
        }
        let extra_url = format!("{}://127.0.0.1:0", scheme);
        let bound = bridge.add_listener(&extra_url).await.unwrap();
        bridge_urls.insert(scheme, bound);
    }

    // Each of the 4 peers dials the bridge over its chosen wire.
    let mut peers: Vec<PeerState> = Vec::with_capacity(N);
    for (i, scheme) in per_peer_scheme.iter().copied().enumerate() {
        let bridge_url = bridge_urls
            .get(scheme)
            .unwrap_or_else(|| panic!("no bridge listener for scheme {}", scheme));
        let id = Identity::generate();
        let pubkey = id.public_bytes();
        let peer_id = drift::crypto::derive_peer_id(&pubkey);
        let (transport, peer_addr) =
            Transport::connect_url(bridge_url, id, cfg.clone()).await.unwrap();
        let transport = Arc::new(transport);
        // Peer registers the bridge as its first hop.
        transport
            .add_peer(bridge_pub, peer_addr, Direction::Initiator)
            .await
            .unwrap();
        peers.push(PeerState {
            transport,
            pubkey,
            peer_id,
            udp_addr: None,
        });
        let _ = i;
    }

    // Warm up the four bridge sessions so the bridge has each
    // peer in its routing table (and knows which interface they
    // arrived on) before mesh-handshake forwarding kicks in.
    for p in &peers {
        p.transport
            .send_data(&bridge_pid, b"warmup", 0, 0)
            .await
            .unwrap();
    }
    for _ in 0..N {
        let _ = tokio::time::timeout(Duration::from_secs(3), bridge.recv()).await;
    }

    // Wait for beacons to converge so each peer learns routes
    // to every other peer through the bridge.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Each peer adds the others as known peers (placeholder
    // addr — mesh routing finds the path).
    let placeholder: SocketAddr = "127.0.0.99:60000".parse().unwrap();
    for i in 0..N {
        for j in 0..N {
            if i == j {
                continue;
            }
            let _ = peers[i]
                .transport
                .add_peer(peers[j].pubkey, placeholder, Direction::Initiator)
                .await;
        }
    }

    // 12 directed sends.
    for sender in 0..N {
        for recv in 0..N {
            if sender == recv {
                continue;
            }
            let payload = format!("from-{}-to-{}", sender + 1, recv + 1);
            peers[sender]
                .transport
                .send_data(&peers[recv].peer_id, payload.as_bytes(), 0, 0)
                .await
                .unwrap();
        }
    }

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut received: Vec<HashSet<String>> = Vec::with_capacity(N);
    for p in &peers {
        received.push(collect_n_minus_one(&p.transport, N - 1, deadline).await);
    }
    assert_full_mesh_delivered(&received, label);
}
