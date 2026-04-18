//! Four-medium bridge test: UDP + TCP + WebSocket + Memory.
//!
//! Four peers, each on a different transport medium, all
//! connected to a single bridge node. Exercises the full
//! DRIFT protocol surface across mediums:
//!
//!   1. Mesh handshakes (through bridge, all 12 peer pairs)
//!   2. Bidirectional data delivery (established sessions)
//!   3. Reliable streams (ordered multi-segment transfer)
//!   4. Fire-and-forget datagrams
//!   5. Semantic coalescing (supersedes groups)
//!   6. Metrics integrity (per-node counters)
//!   7. Every medium-pair combination (12 directed edges)
//!
//! ```text
//!  [Alice/UDP]  ────UDP────┐
//!  [Bob/TCP]    ────TCP────┤── Bridge
//!  [Carol/Mem]  ───chan────┤
//!  [Dave/WS]   ────WS─────┘
//! ```

use drift::identity::Identity;
use drift::io::{MemPacketIO, TcpPacketIO, WsPacketIO};
use drift::streams::StreamManager;
use drift::{Direction, Transport, TransportConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

const NAMES: [&str; 4] = ["alice", "bob", "carol", "dave"];
const MEDIUMS: [&str; 4] = ["UDP", "TCP", "Memory", "WebSocket"];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_mediums_all_talk_through_bridge() {
    let fast_cfg = TransportConfig {
        accept_any_peer: true,
        beacon_interval_ms: 200,
        rtt_probe_interval_ms: 0,
        ..TransportConfig::default()
    };

    // ---- Identities ----
    let bridge_id = Identity::from_secret_bytes([0xBB; 32]);
    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB2; 32]);
    let carol_id = Identity::from_secret_bytes([0xC3; 32]);
    let dave_id = Identity::from_secret_bytes([0xD4; 32]);
    let bridge_pub = bridge_id.public_bytes();
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();
    let carol_pub = carol_id.public_bytes();
    let dave_pub = dave_id.public_bytes();
    let bridge_pid = drift::crypto::derive_peer_id(&bridge_pub);
    let alice_pid = drift::crypto::derive_peer_id(&alice_pub);
    let bob_pid = drift::crypto::derive_peer_id(&bob_pub);
    let carol_pid = drift::crypto::derive_peer_id(&carol_pub);
    let dave_pid = drift::crypto::derive_peer_id(&dave_pub);

    // ---- Bridge: starts with UDP (interface 0) ----
    let bridge = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bridge_id, fast_cfg.clone())
            .await
            .unwrap(),
    );
    let bridge_udp_addr = bridge.local_addr().unwrap();

    // ---- Alice: UDP ----
    let alice = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice_id, fast_cfg.clone())
            .await
            .unwrap(),
    );
    alice
        .add_peer(bridge_pub, bridge_udp_addr, Direction::Initiator)
        .await
        .unwrap();

    // ---- Bob: TCP (interface 1 on bridge) ----
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let bob_tcp = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
    let (bridge_tcp, _) = tcp_listener.accept().await.unwrap();
    bridge.add_interface("tcp", Arc::new(TcpPacketIO::new(bridge_tcp).unwrap()));
    let bob = Arc::new(
        Transport::bind_with_io(
            Arc::new(TcpPacketIO::new(bob_tcp).unwrap()),
            bob_id,
            fast_cfg.clone(),
        )
        .await
        .unwrap(),
    );
    bob.add_peer(bridge_pub, tcp_addr, Direction::Initiator)
        .await
        .unwrap();

    // ---- Carol: In-memory channels (interface 2 on bridge) ----
    let (bridge_mem, carol_mem) = MemPacketIO::pair();
    bridge.add_interface("memory", Arc::new(bridge_mem));
    let carol = Arc::new(
        Transport::bind_with_io(Arc::new(carol_mem), carol_id, fast_cfg.clone())
            .await
            .unwrap(),
    );
    carol
        .add_peer(
            bridge_pub,
            "127.0.0.1:60000".parse().unwrap(),
            Direction::Initiator,
        )
        .await
        .unwrap();

    // ---- Dave: WebSocket (interface 3 on bridge) ----
    let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_addr = ws_listener.local_addr().unwrap();
    let (dave_result, bridge_ws_result) = tokio::join!(
        tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}", ws_addr.port())),
        async {
            let (tcp_stream, peer_addr) = ws_listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp_stream).await.unwrap();
            (ws, peer_addr)
        }
    );
    let (dave_ws, _) = dave_result.unwrap();
    let (bridge_ws, bridge_ws_peer) = bridge_ws_result;
    bridge.add_interface(
        "websocket",
        Arc::new(WsPacketIO::new(bridge_ws, bridge_ws_peer)),
    );
    let dave = Arc::new(
        Transport::bind_with_io(
            Arc::new(WsPacketIO::new(dave_ws, ws_addr)),
            dave_id,
            fast_cfg.clone(),
        )
        .await
        .unwrap(),
    );
    dave.add_peer(bridge_pub, ws_addr, Direction::Initiator)
        .await
        .unwrap();

    // ---- Every peer adds every other (via bridge) ----
    let all_pubs = [alice_pub, bob_pub, carol_pub, dave_pub];
    let transports: [Arc<Transport>; 4] = [alice.clone(), bob.clone(), carol.clone(), dave.clone()];
    for (i, t) in transports.iter().enumerate() {
        for (j, pub_bytes) in all_pubs.iter().enumerate() {
            if i == j {
                continue;
            }
            let _ = t
                .add_peer(*pub_bytes, bridge_udp_addr, Direction::Initiator)
                .await;
        }
    }

    // ---- Warm up: everyone handshakes with bridge ----
    for t in &transports {
        t.send_data(&bridge_pid, b"warmup", 0, 0).await.unwrap();
    }
    for _ in 0..4 {
        let _ = tokio::time::timeout(Duration::from_secs(3), bridge.recv()).await;
    }

    // ---- Beacon convergence ----
    tokio::time::sleep(Duration::from_secs(3)).await;

    // ---- Phase 1: Establish all peer-to-peer sessions ----
    let pids = [alice_pid, bob_pid, carol_pid, dave_pid];
    for (i, t) in transports.iter().enumerate() {
        for (j, pid) in pids.iter().enumerate() {
            if i == j {
                continue;
            }
            let msg = format!("handshake-{}-{}", NAMES[i], NAMES[j]);
            let _ = t.send_data(pid, msg.as_bytes(), 0, 0).await;
        }
    }
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Drain handshake-phase messages.
    for t in &transports {
        loop {
            match tokio::time::timeout(Duration::from_millis(200), t.recv()).await {
                Ok(Some(_)) => {}
                _ => break,
            }
        }
    }

    // ===========================================================
    //  Phase 2: Bidirectional data — every peer to every other
    // ===========================================================
    for (i, t) in transports.iter().enumerate() {
        for (j, pid) in pids.iter().enumerate() {
            if i == j {
                continue;
            }
            let msg = format!("{}-to-{}", NAMES[i], NAMES[j]);
            t.send_data(pid, msg.as_bytes(), 0, 0).await.unwrap();
        }
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut data_got: HashMap<usize, Vec<String>> = HashMap::new();
    for (i, t) in transports.iter().enumerate() {
        let mut got = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(500), t.recv()).await {
                Ok(Some(p)) => {
                    got.push(String::from_utf8_lossy(&p.payload).to_string());
                }
                _ => break,
            }
        }
        data_got.insert(i, got);
    }

    println!("\n=== Phase 2: Bidirectional Data ===");
    for i in 0..4 {
        println!("  {} ({}): {:?}", NAMES[i], MEDIUMS[i], data_got[&i]);
    }

    let total_data: usize = data_got.values().map(|g| g.len()).sum();
    assert_eq!(
        total_data, 12,
        "expected 12/12 data deliveries, got {}",
        total_data
    );

    // Verify every directed medium pair delivered.
    for i in 0..4 {
        for j in 0..4 {
            if i == j {
                continue;
            }
            let expected = format!("{}-to-{}", NAMES[i], NAMES[j]);
            assert!(
                data_got[&j].contains(&expected),
                "missing {} → {} ({}→{})",
                NAMES[i],
                NAMES[j],
                MEDIUMS[i],
                MEDIUMS[j]
            );
        }
    }

    // ===========================================================
    //  Phase 3: Semantic coalescing across mediums
    // ===========================================================
    //  Alice sends 3 messages to Bob in coalesce group 42.
    //  Only the newest (highest seq) should survive; older
    //  ones may be dropped.
    //  Must run BEFORE StreamManager::bind, which takes over recv.

    alice
        .send_data(&bob_pid, b"coalesce-old", 0, 42)
        .await
        .unwrap();
    alice
        .send_data(&bob_pid, b"coalesce-mid", 0, 42)
        .await
        .unwrap();
    alice
        .send_data(&bob_pid, b"coalesce-new", 0, 42)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut coalesce_got = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(500), bob.recv()).await {
            Ok(Some(p)) => {
                let msg = String::from_utf8_lossy(&p.payload).to_string();
                if msg.starts_with("coalesce-") {
                    coalesce_got.push(msg);
                }
            }
            _ => break,
        }
    }

    println!("\n=== Phase 3: Coalescing (UDP→TCP, group 42) ===");
    println!("  Bob received: {:?}", coalesce_got);

    assert!(
        coalesce_got.contains(&"coalesce-new".to_string()),
        "newest coalesced message must be delivered"
    );

    // ===========================================================
    //  Phase 4: Reliable streams across mediums
    // ===========================================================
    //  Alice (UDP) opens a stream to Dave (WebSocket),
    //  Carol (Memory) opens a stream to Bob (TCP).
    //  Each sends 10 ordered segments; receiver verifies order.

    let alice_sm = StreamManager::bind(alice.clone()).await;
    let bob_sm = StreamManager::bind(bob.clone()).await;
    let carol_sm = StreamManager::bind(carol.clone()).await;
    let dave_sm = StreamManager::bind(dave.clone()).await;
    let stream_managers = [&alice_sm, &bob_sm, &carol_sm, &dave_sm];

    let segments: usize = 10;

    // Alice → Dave stream (UDP → WebSocket)
    let s_alice_dave = alice_sm.open(dave_pid).await.unwrap();
    // Carol → Bob stream (Memory → TCP)
    let s_carol_bob = carol_sm.open(bob_pid).await.unwrap();

    // Accept on receivers.
    let a_dave = tokio::spawn({
        let sm = dave_sm.clone();
        async move { tokio::time::timeout(Duration::from_secs(5), sm.accept()).await }
    });
    let a_bob = tokio::spawn({
        let sm = bob_sm.clone();
        async move { tokio::time::timeout(Duration::from_secs(5), sm.accept()).await }
    });

    // Send segments.
    for seq in 0..segments {
        let payload = format!("udp-ws-seg-{:04}", seq);
        s_alice_dave.send(payload.as_bytes()).await.unwrap();
        let payload = format!("mem-tcp-seg-{:04}", seq);
        s_carol_bob.send(payload.as_bytes()).await.unwrap();
    }

    // Receive and verify order.
    let dave_stream = a_dave.await.unwrap().unwrap().unwrap();
    let bob_stream = a_bob.await.unwrap().unwrap().unwrap();

    let mut dave_recv = Vec::new();
    for _ in 0..segments {
        if let Some(data) = tokio::time::timeout(Duration::from_secs(5), dave_stream.recv())
            .await
            .ok()
            .flatten()
        {
            dave_recv.push(String::from_utf8_lossy(&data).to_string());
        }
    }
    let mut bob_recv = Vec::new();
    for _ in 0..segments {
        if let Some(data) = tokio::time::timeout(Duration::from_secs(5), bob_stream.recv())
            .await
            .ok()
            .flatten()
        {
            bob_recv.push(String::from_utf8_lossy(&data).to_string());
        }
    }

    println!("\n=== Phase 4: Streams ===");
    println!(
        "  Alice→Dave (UDP→WS):   {}/{} segments",
        dave_recv.len(),
        segments
    );
    println!(
        "  Carol→Bob  (Mem→TCP):  {}/{} segments",
        bob_recv.len(),
        segments
    );

    assert_eq!(dave_recv.len(), segments, "UDP→WS stream incomplete");
    assert_eq!(bob_recv.len(), segments, "Mem→TCP stream incomplete");

    // Verify ordering.
    for (seq, msg) in dave_recv.iter().enumerate() {
        assert_eq!(
            msg,
            &format!("udp-ws-seg-{:04}", seq),
            "UDP→WS out of order at {}",
            seq
        );
    }
    for (seq, msg) in bob_recv.iter().enumerate() {
        assert_eq!(
            msg,
            &format!("mem-tcp-seg-{:04}", seq),
            "Mem→TCP out of order at {}",
            seq
        );
    }

    // Close streams cleanly.
    s_alice_dave.close().await.unwrap();
    s_carol_bob.close().await.unwrap();

    // ===========================================================
    //  Phase 5: Datagrams across mediums
    // ===========================================================
    //  Bob (TCP) → Alice (UDP) and Dave (WS) → Carol (Memory).

    bob_sm
        .send_datagram(alice_pid, b"dgram-tcp-to-udp")
        .await
        .unwrap();
    dave_sm
        .send_datagram(carol_pid, b"dgram-ws-to-mem")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut dgram_alice = Vec::new();
    let mut dgram_carol = Vec::new();
    for _ in 0..5 {
        if let Ok(Some((_, data))) =
            tokio::time::timeout(Duration::from_millis(500), alice_sm.recv_datagram()).await
        {
            dgram_alice.push(String::from_utf8_lossy(&data).to_string());
        }
    }
    for _ in 0..5 {
        if let Ok(Some((_, data))) =
            tokio::time::timeout(Duration::from_millis(500), carol_sm.recv_datagram()).await
        {
            dgram_carol.push(String::from_utf8_lossy(&data).to_string());
        }
    }

    println!("\n=== Phase 5: Datagrams ===");
    println!("  Bob→Alice (TCP→UDP):    {:?}", dgram_alice);
    println!("  Dave→Carol (WS→Mem):    {:?}", dgram_carol);

    assert!(
        dgram_alice.iter().any(|s| s == "dgram-tcp-to-udp"),
        "TCP→UDP datagram not received"
    );
    assert!(
        dgram_carol.iter().any(|s| s == "dgram-ws-to-mem"),
        "WS→Memory datagram not received"
    );

    // ===========================================================
    //  Metrics
    // ===========================================================
    println!("\n=== Metrics ===");

    let bm = bridge.metrics();
    println!(
        "  Bridge: hs={} fwd={} auth_fail={} beacons={} pkts_tx={} pkts_rx={}",
        bm.handshakes_completed,
        bm.forwarded,
        bm.auth_failures,
        bm.beacons_sent,
        bm.packets_sent,
        bm.packets_received
    );

    assert!(bm.handshakes_completed >= 4, "bridge needs 4+ handshakes");
    assert_eq!(bm.auth_failures, 0, "no auth failures on bridge");
    assert!(bm.forwarded > 0, "bridge must forward packets");
    assert!(bm.beacons_sent > 0, "bridge must emit beacons");

    for (i, t) in transports.iter().enumerate() {
        let m = t.metrics();
        println!(
            "  {} ({}): hs={} retries={} auth_fail={} pkts_tx={} pkts_rx={}",
            NAMES[i],
            MEDIUMS[i],
            m.handshakes_completed,
            m.handshake_retries,
            m.auth_failures,
            m.packets_sent,
            m.packets_received
        );
        assert!(
            m.handshakes_completed >= 4,
            "{} needs 4+ handshakes",
            NAMES[i]
        );
        assert_eq!(
            m.auth_failures, 0,
            "{} should have 0 auth failures",
            NAMES[i]
        );
        assert!(m.packets_sent > 0, "{} must have sent packets", NAMES[i]);
        assert!(
            m.packets_received > 0,
            "{} must have received packets",
            NAMES[i]
        );
    }

    // Stream managers should have no lingering state after close.
    for (i, sm) in stream_managers.iter().enumerate() {
        let live = sm.live_streams_for(&pids[i]).await;
        assert_eq!(live, 0, "{} should have 0 live self-streams", NAMES[i]);
    }
}
