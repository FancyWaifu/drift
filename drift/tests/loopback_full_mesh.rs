//! 127.0.0.1–127.0.0.4 full-mesh end-to-end test.
//!
//! For every adapter DRIFT ships, four peers register each
//! other and every peer sends a unique payload to every other
//! peer. Verifying all 12 messages arrive at the right
//! recipient exercises:
//!
//!   1. Full handshake / session-key derivation per peer pair
//!   2. End-to-end AEAD over each transport in turn
//!   3. Mesh forwarding through a bridge for transports that
//!      can't do peer-to-peer directly (TCP / WS / WebRTC /
//!      WebTransport are point-to-point per stream)
//!   4. Cross-protocol bridging when the four peers each pick
//!      a different wire
//!
//! UDP gets the direct-mesh treatment since it's connectionless;
//! everything else uses a bridge node, identical to the topology
//! `four_medium_bridge.rs` already proves works.

use drift::identity::Identity;
use drift::io::{PacketIO, WebRTCPacketIO, WebTransportPacketIO};
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
    /// Only the UDP-direct case populates this — for bridge-
    /// mediated transports the peer's "address" is meaningless
    /// at the network layer because routing is by pubkey.
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

// ─── Shared mesh-verification core ────────────────────────────────
//
// Given a bridge + 4 already-handshaked peers, pumps 12 directed
// messages through and asserts they all land. Each transport-
// specific test sets up the topology, then calls this.

async fn run_full_mesh_via_bridge(
    bridge: &Arc<Transport>,
    bridge_pid: PeerId,
    peers: &[PeerState],
    label: &str,
) {
    // Warm up: every peer sends a byte to the bridge so the
    // bridge's peer table records each peer + its interface.
    // The bridge's recvs are drained so the channel stays
    // healthy.
    for p in peers {
        p.transport
            .send_data(&bridge_pid, b"warmup", 0, 0)
            .await
            .unwrap();
    }
    for _ in 0..N {
        let _ = tokio::time::timeout(Duration::from_secs(5), bridge.recv()).await;
    }

    // Wait for beacons so each peer learns the routes to the
    // other three through the bridge.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Each peer adds the others as known peers (placeholder
    // address — mesh routing finds the path through the
    // bridge).
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
    for p in peers {
        received.push(collect_n_minus_one(&p.transport, N - 1, deadline).await);
    }
    assert_full_mesh_delivered(&received, label);
}

// ─── 1. UDP direct mesh on 127.0.0.1–.4 ───────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing-fragile under loaded CI (4-peer mesh sharing one process under cargo-test parallelism); passes reliably in isolation, runs in nightly. See HANDOFF flaky-test note."]
async fn mesh_all_udp_direct_loopback_1_to_4() {
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

// ─── 2. URL-dispatchable transports via bridge ───────────────────

async fn build_url_bridge_and_peers(
    per_peer_scheme: &[&str; N],
) -> (Arc<Transport>, PeerId, Vec<PeerState>) {
    let cfg = fast_cfg();
    let mut wanted: HashSet<&str> = HashSet::new();
    for s in per_peer_scheme {
        wanted.insert(*s);
    }
    let primary = wanted.iter().next().copied().unwrap();
    let primary_url = format!("{}://127.0.0.1:0", primary);
    let bridge_id = Identity::generate();
    let bridge_pub = bridge_id.public_bytes();
    let bridge_pid = drift::crypto::derive_peer_id(&bridge_pub);
    let (bridge, primary_bound_url) =
        Transport::bind_url(&primary_url, bridge_id, cfg.clone()).await.unwrap();
    let bridge = Arc::new(bridge);
    let mut bridge_urls: std::collections::HashMap<&str, String> =
        std::collections::HashMap::new();
    bridge_urls.insert(primary, primary_bound_url);
    for scheme in wanted.iter().copied() {
        if scheme == primary {
            continue;
        }
        let extra = format!("{}://127.0.0.1:0", scheme);
        let bound = bridge.add_listener(&extra).await.unwrap();
        bridge_urls.insert(scheme, bound);
    }

    let mut peers: Vec<PeerState> = Vec::with_capacity(N);
    for scheme in per_peer_scheme.iter().copied() {
        let bridge_url = bridge_urls.get(scheme).expect("scheme has no bridge listener");
        let id = Identity::generate();
        let pubkey = id.public_bytes();
        let peer_id = drift::crypto::derive_peer_id(&pubkey);
        let (transport, peer_addr) =
            Transport::connect_url(bridge_url, id, cfg.clone()).await.unwrap();
        let transport = Arc::new(transport);
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
    }
    (bridge, bridge_pid, peers)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing-fragile under loaded CI (4-peer mesh sharing one process under cargo-test parallelism); passes reliably in isolation, runs in nightly. See HANDOFF flaky-test note."]
async fn mesh_all_tcp_via_bridge_loopback_1_to_4() {
    let (bridge, bridge_pid, peers) = build_url_bridge_and_peers(&["tcp"; N]).await;
    run_full_mesh_via_bridge(&bridge, bridge_pid, &peers, "tcp-mesh").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing-fragile under loaded CI (4-peer mesh sharing one process under cargo-test parallelism); passes reliably in isolation, runs in nightly. See HANDOFF flaky-test note."]
async fn mesh_all_ws_via_bridge_loopback_1_to_4() {
    let (bridge, bridge_pid, peers) = build_url_bridge_and_peers(&["ws"; N]).await;
    run_full_mesh_via_bridge(&bridge, bridge_pid, &peers, "ws-mesh").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing-fragile under loaded CI (4-peer mesh sharing one process under cargo-test parallelism); passes reliably in isolation, runs in nightly. See HANDOFF flaky-test note."]
async fn mesh_mixed_protocols_via_bridge_loopback_1_to_4() {
    let (bridge, bridge_pid, peers) =
        build_url_bridge_and_peers(&["udp", "tcp", "ws", "udp"]).await;
    run_full_mesh_via_bridge(&bridge, bridge_pid, &peers, "mixed-mesh").await;
}

// ─── 3. WebTransport bridge mesh ──────────────────────────────────

async fn build_wt_bridge_and_peers() -> (Arc<Transport>, PeerId, Vec<PeerState>) {
    use wtransport::{ClientConfig, Endpoint, Identity as WtIdentity, ServerConfig};

    let cfg = fast_cfg();

    // Bridge: wtransport server endpoint with self-signed cert.
    let server_identity = WtIdentity::self_signed(["localhost", "127.0.0.1"]).unwrap();
    let server_config = ServerConfig::builder()
        .with_bind_default(0)
        .with_identity(server_identity)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();
    let server = Endpoint::server(server_config).unwrap();
    let server_addr: SocketAddr = server.local_addr().unwrap();

    // Bridge transport: MemPacketIO placeholder primary; each
    // accepted WT session becomes a new add_interface entry.
    let bridge_id = Identity::generate();
    let bridge_pub = bridge_id.public_bytes();
    let bridge_pid = drift::crypto::derive_peer_id(&bridge_pub);
    let (mem_primary, _mem_dead) = drift::io::MemPacketIO::pair();
    let primary: Arc<dyn PacketIO> = Arc::new(mem_primary);
    let bridge = Arc::new(
        Transport::bind_with_io(primary, bridge_id, cfg.clone())
            .await
            .unwrap(),
    );

    // Spawn a task that acts as the wtransport accept loop
    // *for the duration of building the peers*. We collect the
    // join handle so we can cancel it after setup.
    let bridge_for_accept = bridge.clone();
    let accept_handle = tokio::spawn(async move {
        loop {
            let incoming = server.accept().await;
            match incoming.await {
                Ok(req) => match req.accept().await {
                    Ok(conn) => {
                        let remote = conn.remote_address();
                        let io: Arc<dyn PacketIO> =
                            Arc::new(WebTransportPacketIO::new(conn, remote));
                        bridge_for_accept.add_interface("wt", io);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "wt accept failed");
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "wt session-request failed");
                    break;
                }
            }
        }
    });

    let mut peers: Vec<PeerState> = Vec::with_capacity(N);
    for _ in 0..N {
        // Test-only: skip cert validation. Production deployments
        // pass `with_server_certificate_hashes` / `with_native_certs`.
        let client_config = ClientConfig::builder()
            .with_bind_default()
            .with_no_cert_validation()
            .build();
        let client = Endpoint::client(client_config).unwrap();
        let url = format!("https://localhost:{}/", server_addr.port());
        let conn = client.connect(url).await.unwrap();
        let remote = conn.remote_address();

        let io: Arc<dyn PacketIO> = Arc::new(WebTransportPacketIO::new(conn, remote));
        let id = Identity::generate();
        let pubkey = id.public_bytes();
        let peer_id = drift::crypto::derive_peer_id(&pubkey);
        let transport = Arc::new(Transport::bind_with_io(io, id, cfg.clone()).await.unwrap());
        transport
            .add_peer(bridge_pub, remote, Direction::Initiator)
            .await
            .unwrap();

        peers.push(PeerState {
            transport,
            pubkey,
            peer_id,
            udp_addr: None,
        });
    }

    // Give the accept loop time to attach all 4 peers as
    // interfaces before we shut it down. (Keeping the handle
    // alive for the test would also work; we just don't need
    // additional accepts.)
    tokio::time::sleep(Duration::from_millis(300)).await;
    accept_handle.abort();

    (bridge, bridge_pid, peers)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing-fragile under loaded CI (4-peer mesh sharing one process under cargo-test parallelism); passes reliably in isolation, runs in nightly. See HANDOFF flaky-test note."]
async fn mesh_all_webtransport_via_bridge_loopback_1_to_4() {
    let (bridge, bridge_pid, peers) = build_wt_bridge_and_peers().await;
    run_full_mesh_via_bridge(&bridge, bridge_pid, &peers, "webtransport-mesh").await;
}

// ─── 4. WebRTC bridge mesh ────────────────────────────────────────

async fn build_webrtc_bridge_and_peers() -> (Arc<Transport>, PeerId, Vec<PeerState>) {
    use webrtc::api::APIBuilder;
    use webrtc::data_channel::RTCDataChannel;
    use webrtc::peer_connection::configuration::RTCConfiguration;
    use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
    use webrtc::peer_connection::RTCPeerConnection;

    let cfg = fast_cfg();

    let bridge_id = Identity::generate();
    let bridge_pub = bridge_id.public_bytes();
    let bridge_pid = drift::crypto::derive_peer_id(&bridge_pub);
    let (mem_primary, _mem_dead) = drift::io::MemPacketIO::pair();
    let primary: Arc<dyn PacketIO> = Arc::new(mem_primary);
    let bridge = Arc::new(
        Transport::bind_with_io(primary, bridge_id, cfg.clone())
            .await
            .unwrap(),
    );

    async fn new_pc(
    ) -> Result<Arc<RTCPeerConnection>, Box<dyn std::error::Error + Send + Sync>> {
        let api = APIBuilder::new().build();
        let cfg = RTCConfiguration {
            ice_servers: vec![],
            ..Default::default()
        };
        Ok(Arc::new(api.new_peer_connection(cfg).await?))
    }

    async fn ice_complete(pc: Arc<RTCPeerConnection>) {
        let mut g = pc.gathering_complete_promise().await;
        let _ = g.recv().await;
    }

    /// Build one bridge↔peer pair, exchange SDP in-process,
    /// return the two ready-to-use DataChannels. Bridge is the
    /// offerer (creates the DC), peer is the answerer.
    async fn rtc_pair(
    ) -> (
        Arc<RTCDataChannel>,
        Arc<RTCDataChannel>,
    ) {
        let pc_b = new_pc().await.unwrap();
        let pc_p = new_pc().await.unwrap();

        let dc_bridge = pc_b.create_data_channel("drift", None).await.unwrap();

        let (tx_b, rx_b) = tokio::sync::oneshot::channel();
        let tx_b = Arc::new(tokio::sync::Mutex::new(Some(tx_b)));
        let dc_for_b = dc_bridge.clone();
        let tx_for_b = tx_b.clone();
        dc_bridge.on_open(Box::new(move || {
            let tx = tx_for_b.clone();
            let dc = dc_for_b.clone();
            Box::pin(async move {
                if let Some(s) = tx.lock().await.take() {
                    let _ = s.send(dc);
                }
            })
        }));

        let (tx_p, rx_p) = tokio::sync::oneshot::channel();
        let tx_p = Arc::new(tokio::sync::Mutex::new(Some(tx_p)));
        pc_p.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let tx = tx_p.clone();
            Box::pin(async move {
                let dc_clone = dc.clone();
                let tx_inner = tx.clone();
                dc.on_open(Box::new(move || {
                    let tx = tx_inner.clone();
                    let dc = dc_clone.clone();
                    Box::pin(async move {
                        if let Some(s) = tx.lock().await.take() {
                            let _ = s.send(dc);
                        }
                    })
                }));
            })
        }));

        // SDP exchange.
        let offer = pc_b.create_offer(None).await.unwrap();
        pc_b.set_local_description(offer).await.unwrap();
        ice_complete(pc_b.clone()).await;
        let b_local = pc_b.local_description().await.unwrap();

        pc_p.set_remote_description(RTCSessionDescription::offer(b_local.sdp).unwrap())
            .await
            .unwrap();
        let answer = pc_p.create_answer(None).await.unwrap();
        pc_p.set_local_description(answer).await.unwrap();
        ice_complete(pc_p.clone()).await;
        let p_local = pc_p.local_description().await.unwrap();
        pc_b
            .set_remote_description(RTCSessionDescription::answer(p_local.sdp).unwrap())
            .await
            .unwrap();

        let dc_b = tokio::time::timeout(Duration::from_secs(60), rx_b)
            .await
            .expect("bridge DC open timeout")
            .expect("bridge DC oneshot dropped");
        let dc_p = tokio::time::timeout(Duration::from_secs(60), rx_p)
            .await
            .expect("peer DC open timeout")
            .expect("peer DC oneshot dropped");
        // Leak the peer connections so the data channels stay
        // alive for the rest of the test (Arc keeps them alive,
        // but if the PC drops everything tears down).
        std::mem::forget(pc_b);
        std::mem::forget(pc_p);
        (dc_b, dc_p)
    }

    let mut peers: Vec<PeerState> = Vec::with_capacity(N);
    for i in 0..N {
        let (dc_bridge_side, dc_peer_side) = rtc_pair().await;
        let placeholder_b: SocketAddr = format!("127.0.0.1:6500{}", i).parse().unwrap();
        let placeholder_p: SocketAddr = format!("127.0.0.{}:0", i + 1).parse().unwrap();

        // Bridge-side data channel becomes a new interface.
        let bridge_io: Arc<dyn PacketIO> =
            Arc::new(WebRTCPacketIO::new(dc_bridge_side, placeholder_b));
        bridge.add_interface(format!("rtc-{}", i), bridge_io);

        // Peer-side data channel becomes the peer's transport's
        // primary interface.
        let peer_io: Arc<dyn PacketIO> =
            Arc::new(WebRTCPacketIO::new(dc_peer_side, placeholder_p));
        let id = Identity::generate();
        let pubkey = id.public_bytes();
        let peer_id = drift::crypto::derive_peer_id(&pubkey);
        let transport =
            Arc::new(Transport::bind_with_io(peer_io, id, cfg.clone()).await.unwrap());
        transport
            .add_peer(bridge_pub, placeholder_b, Direction::Initiator)
            .await
            .unwrap();

        peers.push(PeerState {
            transport,
            pubkey,
            peer_id,
            udp_addr: None,
        });
    }

    (bridge, bridge_pid, peers)
}

// macOS: the webrtc-rs crate's ICE gathering doesn't reliably
// emit host candidates fast enough for the in-process loopback
// DataChannel to open within the test deadline. Bisected — fails
// on the original commit that introduced this test, so it's an
// environment / dependency-drift issue, not a regression. Adding
// a STUN server doesn't help. The webrtc *adapter* itself is fine
// (used by drift-wasm in browsers); only this test setup is
// flaky on macOS.
//
// Gate so `cargo test --all-targets` is green on macOS while we
// chase a real fix. Linux/Windows hosts run the test normally.
#[cfg_attr(
    target_os = "macos",
    ignore = "webrtc-rs in-process loopback stalls on macOS; \
              the adapter works in browsers, only the test setup is flaky. \
              Run with `cargo test -- --ignored` once the upstream issue is resolved."
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_all_webrtc_via_bridge_loopback_1_to_4() {
    let (bridge, bridge_pid, peers) = build_webrtc_bridge_and_peers().await;
    run_full_mesh_via_bridge(&bridge, bridge_pid, &peers, "webrtc-mesh").await;
}
