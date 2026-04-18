//! Regression test: beacon emitter must skip peers reachable
//! only through a mesh relay.
//!
//! Before the fix, a peer with one direct neighbor (the bridge)
//! and one mesh-routed peer (reachable via the bridge) would emit
//! two beacons per tick: one to the bridge (forwarded fine), and
//! one addressed to the mesh peer with `hop_ttl = 1`. That second
//! beacon hit the bridge's forward gate (`hop_ttl > 1` required),
//! fell through to `handle_beacon`, and was rejected with
//! `UnknownPeer` because the bridge was not the destination.
//!
//! The fix filters `emit_beacons` targets to `!p.via_mesh`, which:
//!   * eliminates the drops at the bridge
//!   * cuts redundant beacon bandwidth (routes still converge
//!     because the bridge advertises its direct peers to everyone)
//!
//! We verify both invariants below.

use drift::identity::Identity;
use drift::io::TcpPacketIO;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emit_beacons_skips_via_mesh_peers() {
    // Fast beacons, no RTT probes, auto-register.
    let cfg = TransportConfig {
        accept_any_peer: true,
        beacon_interval_ms: 100,
        rtt_probe_interval_ms: 0,
        ..TransportConfig::default()
    };

    // Identities.
    let bridge_id = Identity::from_secret_bytes([0xBB; 32]);
    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB2; 32]);
    let bridge_pub = bridge_id.public_bytes();
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();
    let bridge_pid = drift::crypto::derive_peer_id(&bridge_pub);
    let alice_pid = drift::crypto::derive_peer_id(&alice_pub);
    let bob_pid = drift::crypto::derive_peer_id(&bob_pub);

    // Bridge with UDP interface 0.
    let bridge = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bridge_id, cfg.clone())
            .await
            .unwrap(),
    );
    let bridge_udp = bridge.local_addr().unwrap();

    // Alice: UDP, direct to bridge.
    let alice = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice_id, cfg.clone())
            .await
            .unwrap(),
    );
    alice
        .add_peer(bridge_pub, bridge_udp, Direction::Initiator)
        .await
        .unwrap();

    // Bob: TCP interface on bridge (interface 1).
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let bob_tcp = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
    let (bridge_tcp, _) = tcp_listener.accept().await.unwrap();
    bridge.add_interface("tcp", Arc::new(TcpPacketIO::new(bridge_tcp).unwrap()));
    let bob = Arc::new(
        Transport::bind_with_io(
            Arc::new(TcpPacketIO::new(bob_tcp).unwrap()),
            bob_id,
            cfg.clone(),
        )
        .await
        .unwrap(),
    );
    bob.add_peer(bridge_pub, tcp_addr, Direction::Initiator)
        .await
        .unwrap();

    // Both peers register each other through the bridge.
    alice
        .add_peer(bob_pub, bridge_udp, Direction::Initiator)
        .await
        .unwrap();
    bob.add_peer(alice_pub, tcp_addr, Direction::Initiator)
        .await
        .unwrap();

    // Warm up direct handshakes with the bridge.
    alice.send_data(&bridge_pid, b"warmup", 0, 0).await.unwrap();
    bob.send_data(&bridge_pid, b"warmup", 0, 0).await.unwrap();
    for _ in 0..2 {
        let _ = tokio::time::timeout(Duration::from_secs(2), bridge.recv()).await;
    }

    // Beacon convergence.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Cross-peer handshake: alice -> bob via bridge. Bob should
    // end up with alice as via_mesh (and vice versa).
    alice.send_data(&bob_pid, b"hi-bob", 0, 0).await.unwrap();
    bob.send_data(&alice_pid, b"hi-alice", 0, 0).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Drain any received data across all three transports so
    // subsequent recv timeouts don't include in-flight traffic
    // from the handshake phase.
    for t in [&alice, &bob, &bridge] {
        loop {
            match tokio::time::timeout(Duration::from_millis(100), t.recv()).await {
                Ok(Some(_)) => {}
                _ => break,
            }
        }
    }

    // Snapshot metrics, then observe beacon emission rate over a
    // window large enough to catch the bug if it were present.
    let b_auth_before = bridge.metrics().auth_failures;
    let alice_beacons_before = alice.metrics().beacons_sent;
    let bob_beacons_before = bob.metrics().beacons_sent;

    const BEACON_WINDOW_MS: u64 = 1200;
    const BEACON_INTERVAL_MS: u64 = 100;
    tokio::time::sleep(Duration::from_millis(BEACON_WINDOW_MS)).await;

    let b_auth_after = bridge.metrics().auth_failures;
    let alice_emitted = alice.metrics().beacons_sent - alice_beacons_before;
    let bob_emitted = bob.metrics().beacons_sent - bob_beacons_before;

    // Expected ticks in the window (roughly). Round down so timer
    // jitter never makes the test flaky — we only care about the
    // ratio between peers emitting to direct-only vs all-peers.
    let expected_ticks = BEACON_WINDOW_MS / BEACON_INTERVAL_MS;

    // With the fix: alice and bob each have exactly ONE direct
    // peer (the bridge). Every tick they emit ONE beacon, so the
    // window count is ~expected_ticks.
    //
    // Without the fix: each peer has TWO Established sessions
    // (bridge direct + the other peer via_mesh), so would emit
    // ~2 * expected_ticks beacons. The assertion below fails.
    assert!(
        alice_emitted <= expected_ticks + 2,
        "alice emitted {} beacons in {}ms ({} ticks) — expected ~{}; the \
         beacon emitter is sending to via_mesh peers again",
        alice_emitted,
        BEACON_WINDOW_MS,
        expected_ticks,
        expected_ticks,
    );
    assert!(
        bob_emitted <= expected_ticks + 2,
        "bob emitted {} beacons in {}ms — expected ~{}",
        bob_emitted,
        BEACON_WINDOW_MS,
        expected_ticks,
    );

    // The bridge should not register any auth failures during
    // this window.
    assert_eq!(
        b_auth_before, b_auth_after,
        "bridge auth_failures moved during steady-state beacons",
    );

    // No unknown-peer drops at the bridge across the full run —
    // catches the beacon bug (wrong filter), the ResumptionTicket
    // bug (missing hop_ttl for mesh peers), and any future
    // control-packet emitter that forgets to honor via_mesh.
    let bridge_metrics = bridge.metrics();
    assert_eq!(
        bridge_metrics.unknown_peer_drops, 0,
        "bridge dropped {} packets as UnknownPeer — a control-packet \
         emitter is shipping `hop_ttl=1` to a mesh-routed peer",
        bridge_metrics.unknown_peer_drops,
    );

    // Sanity: the cross-medium session is still alive — send one
    // more payload each way and confirm it delivers. Regression
    // could otherwise hide behind a broken mesh forwarding path.
    alice
        .send_data(&bob_pid, b"post-fix-1", 0, 0)
        .await
        .unwrap();
    bob.send_data(&alice_pid, b"post-fix-2", 0, 0)
        .await
        .unwrap();

    let mut alice_saw = false;
    let mut bob_saw = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline && !(alice_saw && bob_saw) {
        if !alice_saw {
            if let Ok(Some(p)) =
                tokio::time::timeout(Duration::from_millis(200), alice.recv()).await
            {
                if p.payload == b"post-fix-2" {
                    alice_saw = true;
                }
            }
        }
        if !bob_saw {
            if let Ok(Some(p)) = tokio::time::timeout(Duration::from_millis(200), bob.recv()).await
            {
                if p.payload == b"post-fix-1" {
                    bob_saw = true;
                }
            }
        }
    }
    assert!(alice_saw, "alice did not receive post-fix message from bob");
    assert!(bob_saw, "bob did not receive post-fix message from alice");
}
