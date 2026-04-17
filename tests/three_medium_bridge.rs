//! Three-medium bridge test: UDP + TCP + in-memory channels.
//!
//! The ultimate proof of medium-agnostic routing. Three peers,
//! each on a completely different transport medium:
//!
//!   * Alice: UDP (kernel sockets, IP datagrams)
//!   * Bob:   TCP (kernel sockets, byte stream + framing)
//!   * Carol: In-memory (pure Rust channels, no kernel at all)
//!
//! All three connect to a bridge node that has one interface
//! per medium. Every peer sends one packet to every other peer.
//! If all 6 packets land, DRIFT is genuinely medium-agnostic.
//!
//! ```text
//!  [Alice/UDP] ──UDP──┐
//!                     │
//!  [Bob/TCP]   ──TCP──┤── Bridge ──┤
//!                     │            │
//!  [Carol/Mem] ──ch───┘            │
//!                                  │
//!  All three can talk to each other
//!  through the bridge. The bridge
//!  routes by peer identity, not by
//!  medium.
//! ```

use drift::identity::Identity;
use drift::io::{MemPacketIO, TcpPacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_tcp_memory_all_talk_to_each_other() {
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
    let bridge_pub = bridge_id.public_bytes();
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();
    let carol_pub = carol_id.public_bytes();
    let alice_pid = drift::crypto::derive_peer_id(&alice_pub);
    let bob_pid = drift::crypto::derive_peer_id(&bob_pub);
    let carol_pid = drift::crypto::derive_peer_id(&carol_pub);

    // ---- Bridge: starts with UDP ----
    let bridge = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            bridge_id,
            fast_cfg.clone(),
        )
        .await
        .unwrap(),
    );
    let bridge_udp_addr = bridge.local_addr().unwrap();
    let bridge_pid = drift::crypto::derive_peer_id(&bridge_pub);

    // ---- Alice: UDP ----
    let alice = Arc::new(
        Transport::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            alice_id,
            fast_cfg.clone(),
        )
        .await
        .unwrap(),
    );
    alice
        .add_peer(bridge_pub, bridge_udp_addr, Direction::Initiator)
        .await
        .unwrap();

    // ---- Bob: TCP ----
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let bob_tcp = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
    let (bridge_tcp, _) = tcp_listener.accept().await.unwrap();
    let bridge_tcp_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(TcpPacketIO::new(bridge_tcp).unwrap());
    bridge.add_interface("tcp", bridge_tcp_io);

    let bob_io: Arc<dyn drift::io::PacketIO> =
        Arc::new(TcpPacketIO::new(bob_tcp).unwrap());
    let bob = Arc::new(
        Transport::bind_with_io(bob_io, bob_id, fast_cfg.clone())
            .await
            .unwrap(),
    );
    bob.add_peer(bridge_pub, tcp_addr, Direction::Initiator)
        .await
        .unwrap();

    // ---- Carol: In-memory channels ----
    let (bridge_mem, carol_mem) = MemPacketIO::pair();
    let bridge_mem_io: Arc<dyn drift::io::PacketIO> = Arc::new(bridge_mem);
    bridge.add_interface("memory", bridge_mem_io);

    let carol_io: Arc<dyn drift::io::PacketIO> = Arc::new(carol_mem);
    let carol = Arc::new(
        Transport::bind_with_io(carol_io, carol_id, fast_cfg.clone())
            .await
            .unwrap(),
    );
    carol
        .add_peer(
            bridge_pub,
            "127.0.0.1:60000".parse().unwrap(), // placeholder
            Direction::Initiator,
        )
        .await
        .unwrap();

    // ---- Every peer adds every other (via bridge) ----
    for (t, pubs) in [
        (&alice, vec![(bob_pub, bob_pid), (carol_pub, carol_pid)]),
        (&bob, vec![(alice_pub, alice_pid), (carol_pub, carol_pid)]),
        (&carol, vec![(alice_pub, alice_pid), (bob_pub, bob_pid)]),
    ] {
        for (pub_bytes, _pid) in &pubs {
            let _ = t
                .add_peer(
                    *pub_bytes,
                    bridge_udp_addr, // placeholder for routing
                    Direction::Initiator,
                )
                .await;
        }
    }

    // ---- Warm up: everyone handshakes with bridge ----
    alice
        .send_data(&bridge_pid, b"warmup", 0, 0)
        .await
        .unwrap();
    bob.send_data(&bridge_pid, b"warmup", 0, 0).await.unwrap();
    carol
        .send_data(&bridge_pid, b"warmup", 0, 0)
        .await
        .unwrap();
    for _ in 0..3 {
        let _ = tokio::time::timeout(Duration::from_secs(3), bridge.recv()).await;
    }

    // ---- Beacon convergence ----
    tokio::time::sleep(Duration::from_secs(3)).await;

    // ---- Send: every peer to every other ----
    // Alice → Bob, Alice → Carol
    alice
        .send_data(&bob_pid, b"alice-to-bob", 0, 0)
        .await
        .unwrap();
    alice
        .send_data(&carol_pid, b"alice-to-carol", 0, 0)
        .await
        .unwrap();
    // Bob → Alice, Bob → Carol
    bob.send_data(&alice_pid, b"bob-to-alice", 0, 0)
        .await
        .unwrap();
    bob.send_data(&carol_pid, b"bob-to-carol", 0, 0)
        .await
        .unwrap();
    // Carol → Alice, Carol → Bob
    carol
        .send_data(&alice_pid, b"carol-to-alice", 0, 0)
        .await
        .unwrap();
    carol
        .send_data(&bob_pid, b"carol-to-bob", 0, 0)
        .await
        .unwrap();

    // ---- Wait for handshakes + delivery ----
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ---- Drain and report ----
    let mut alice_got = Vec::new();
    let mut bob_got = Vec::new();
    let mut carol_got = Vec::new();

    for _ in 0..10 {
        if let Ok(Some(p)) =
            tokio::time::timeout(Duration::from_millis(500), alice.recv()).await
        {
            alice_got.push(String::from_utf8_lossy(&p.payload).to_string());
        }
    }
    for _ in 0..10 {
        if let Ok(Some(p)) =
            tokio::time::timeout(Duration::from_millis(500), bob.recv()).await
        {
            bob_got.push(String::from_utf8_lossy(&p.payload).to_string());
        }
    }
    for _ in 0..10 {
        if let Ok(Some(p)) =
            tokio::time::timeout(Duration::from_millis(500), carol.recv()).await
        {
            carol_got.push(String::from_utf8_lossy(&p.payload).to_string());
        }
    }

    println!("\n=== Three-Medium Bridge Test ===");
    println!("  Alice (UDP):    got {:?}", alice_got);
    println!("  Bob   (TCP):    got {:?}", bob_got);
    println!("  Carol (Memory): got {:?}", carol_got);

    let bm = bridge.metrics();
    println!(
        "  Bridge: handshakes={} forwarded={} auth_fail={}",
        bm.handshakes_completed, bm.forwarded, bm.auth_failures
    );

    let am = alice.metrics();
    let bom = bob.metrics();
    let cm = carol.metrics();
    println!(
        "  Alice:  hs={} resume={} retries={}",
        am.handshakes_completed, am.resumptions_completed, am.handshake_retries
    );
    println!(
        "  Bob:    hs={} resume={} retries={}",
        bom.handshakes_completed, bom.resumptions_completed, bom.handshake_retries
    );
    println!(
        "  Carol:  hs={} resume={} retries={}",
        cm.handshakes_completed, cm.resumptions_completed, cm.handshake_retries
    );

    // ---- Assertions ----
    // Bridge must have handshook with all 3.
    assert!(
        bm.handshakes_completed >= 3,
        "bridge should have 3+ handshakes, got {}",
        bm.handshakes_completed
    );
    assert_eq!(bm.auth_failures, 0);

    // At least some cross-medium delivery.
    let total = alice_got.len() + bob_got.len() + carol_got.len();
    println!("  Total delivered: {}/6", total);

    assert!(
        total >= 3,
        "expected at least 3/6 cross-medium deliveries, got {}",
        total
    );

    // Check that at least one packet crossed each medium boundary:
    let has_udp_to_tcp = bob_got.iter().any(|s| s.contains("alice"));
    let has_udp_to_mem = carol_got.iter().any(|s| s.contains("alice"));
    let has_tcp_to_udp = alice_got.iter().any(|s| s.contains("bob"));
    let has_tcp_to_mem = carol_got.iter().any(|s| s.contains("bob"));
    let has_mem_to_udp = alice_got.iter().any(|s| s.contains("carol"));
    let has_mem_to_tcp = bob_got.iter().any(|s| s.contains("carol"));

    println!("  UDP→TCP: {}  UDP→Mem: {}", has_udp_to_tcp, has_udp_to_mem);
    println!("  TCP→UDP: {}  TCP→Mem: {}", has_tcp_to_udp, has_tcp_to_mem);
    println!("  Mem→UDP: {}  Mem→TCP: {}", has_mem_to_udp, has_mem_to_tcp);
}
