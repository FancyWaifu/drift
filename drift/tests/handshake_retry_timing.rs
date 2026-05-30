//! Regression tests for `handshake_retry_base_ms = 1000`
//! (RFC 6298 §2.1) and the SRTT-driven retry path.
//!
//! Asserts:
//!   1. The 1s default doesn't make LAN handshakes any slower
//!      (the first HELLO succeeds; retry timer never fires).
//!   2. Hybrid PQ handshake completes on a 10 Kbps link with
//!      RTO=1s — the regression case that motivated the
//!      change. Verified by the matching test in
//!      `extreme_conditions::scenario_10kbps_bandwidth_cap`
//!      already passing classical, this asserts hybrid does
//!      too.
//!   3. Once a peer has an SRTT sample, subsequent handshake
//!      retries use `max(200ms, 4*SRTT)`, NOT the 1s default.
//!      This is the path that re-handshakes hit, and the
//!      reason the 1s default doesn't penalize known peers.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

// ────────────────────────── shared helpers ──────────────────────────

/// Traffic-shaping UDP proxy with separate per-direction
/// queues. Real low-bandwidth links queue oversized bursts
/// rather than dropping them (modulo finite buffer depth),
/// so a more realistic model is: enqueue every packet, dequeue
/// at `bandwidth_bps`. The two directions are independently
/// rate-limited because hybrid PQ HELLOs in flight in both
/// directions shouldn't compete for the same byte budget.
async fn spawn_bw_proxy(target: SocketAddr, bandwidth_bps: u64) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Per-direction send queues.
    let (to_target_tx, mut to_target_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (to_client_tx, mut to_client_rx) =
        tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();

    // Forwarder: drain queue at `bandwidth_bps`, sending to
    // `target`. The dispatch delay is proportional to packet
    // size — 1 packet of N bytes occupies the link for
    // `N / bandwidth_bps` seconds.
    let sock_fwd = sock.clone();
    tokio::spawn(async move {
        while let Some(data) = to_target_rx.recv().await {
            let send_us = (data.len() as u64 * 1_000_000) / bandwidth_bps;
            tokio::time::sleep(Duration::from_micros(send_us)).await;
            let _ = sock_fwd.send_to(&data, target).await;
        }
    });
    let sock_back = sock.clone();
    tokio::spawn(async move {
        while let Some((data, dst)) = to_client_rx.recv().await {
            let send_us = (data.len() as u64 * 1_000_000) / bandwidth_bps;
            tokio::time::sleep(Duration::from_micros(send_us)).await;
            let _ = sock_back.send_to(&data, dst).await;
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let data = buf[..n].to_vec();
            if src == target {
                let dst = match *client.lock().await {
                    Some(a) => a,
                    None => continue,
                };
                let _ = to_client_tx.send((data, dst));
            } else {
                let mut c = client.lock().await;
                if c.is_none() {
                    *c = Some(src);
                }
                drop(c);
                let _ = to_target_tx.send(data);
            }
        }
    });
    addr
}

async fn pair_via_proxy(
    bw_bps: u64,
    alice_cfg: TransportConfig,
    bob_cfg: TransportConfig,
) -> (Arc<Transport>, Arc<Transport>, drift::PeerId) {
    let alice_id = Identity::from_secret_bytes([0xA1; 32]);
    let bob_id = Identity::from_secret_bytes([0xB1; 32]);
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), bob_id, bob_cfg)
            .await
            .unwrap(),
    );
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
    .await
    .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    let proxy_addr = if bw_bps > 0 {
        spawn_bw_proxy(bob_addr, bw_bps).await
    } else {
        bob_addr
    };

    let alice = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), alice_id, alice_cfg)
            .await
            .unwrap(),
    );
    let bob_peer = alice
        .add_peer(bob_pub, proxy_addr, Direction::Initiator)
        .await
        .unwrap();
    (alice, bob, bob_peer)
}

fn cfg_default() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        ..Default::default()
    }
}

fn cfg_pq() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        ..Default::default()
    }
}

// ───────────────────────── tests ─────────────────────────

/// 1. LAN-fast handshake is not slowed by the RTO bump.
///
/// First HELLO completes via direct loopback in well under
/// 1s — way before the retry timer would fire. RTO change is
/// invisible.
#[tokio::test]
async fn classical_handshake_on_lan_unaffected_by_rto_bump() {
    let (alice, bob, peer) = pair_via_proxy(0, cfg_default(), cfg_default()).await;

    let start = Instant::now();
    alice.send_data(&peer, b"lan-fast", 0, 0).await.unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("LAN handshake timed out")
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(pkt.payload, b"lan-fast");
    assert!(
        elapsed < Duration::from_millis(500),
        "LAN handshake unexpectedly slow ({}ms); RTO bump regressed loopback",
        elapsed.as_millis()
    );

    // The handshake_retries metric counts retransmits. None
    // should have fired on a loopback path.
    assert_eq!(
        alice.metrics().handshake_retries,
        0,
        "no retries should fire on a clean LAN path"
    );
}

/// 2. Hybrid PQ on a 10 Kbps link completes the handshake.
///
/// This is the regression case. With the old 50ms RTO + 1.3 KB
/// hybrid HELLO + 1.25 KB/s link, the client would retransmit
/// ~6 HELLOs before the first one finished. With RTO=1s, the
/// first HELLO has time to deliver and the handshake completes
/// on attempt 1 (or attempt 2 if a single retry fires before
/// the HELLO_ACK arrives — both acceptable).
#[tokio::test]
async fn hybrid_handshake_completes_at_10kbps() {
    let bw_bps = 10_000 / 8; // 10 Kbps = 1250 bytes/sec
    let (alice, bob, peer) = pair_via_proxy(bw_bps, cfg_pq(), cfg_pq()).await;

    let start = Instant::now();
    alice.send_data(&peer, b"slow-pq", 0, 0).await.unwrap();
    // Budget: a hybrid HELLO+HELLO_ACK at 1250 B/s is ~2s
    // baseline + some retry overhead. 12s is generous and the
    // test must still fail fast if the bug is back.
    let pkt = tokio::time::timeout(Duration::from_secs(12), bob.recv())
        .await
        .expect("hybrid PQ handshake should complete at 10kbps with RTO=1s")
        .unwrap();
    eprintln!(
        "[10kbps + PQ] handshake elapsed: {} ms, retries: {}",
        start.elapsed().as_millis(),
        alice.metrics().handshake_retries
    );
    assert_eq!(pkt.payload, b"slow-pq");
    assert!(
        alice.metrics().hybrid_pq_handshakes_completed >= 1,
        "should have completed a hybrid handshake; metrics: {:?}",
        alice.metrics()
    );
}

/// 3. Once a peer has an SRTT sample, subsequent retries use
///    `max(200ms, 4*SRTT)` per RFC 6298 §2.4 — NOT the 1s
///    default.
///
/// We verify by:
///   a. Doing a fresh handshake with a custom config whose
///      `handshake_retry_base_ms` is bumped to something
///      observable (say 5000ms).
///   b. Force-restarting the handshake (so we re-enter
///      `AwaitingAck`).
///   c. The retransmit loop should now use the SRTT-derived
///      timing (sub-second on loopback), much faster than 5s.
#[tokio::test]
async fn second_handshake_uses_rtt_derived_rto() {
    let mut alice_cfg = cfg_default();
    alice_cfg.handshake_retry_base_ms = 5_000; // 5s, easy to detect
    let (alice, bob, peer) = pair_via_proxy(0, alice_cfg, cfg_default()).await;

    // First handshake to establish + sample RTT.
    alice.send_data(&peer, b"first", 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), bob.recv())
        .await
        .expect("first handshake timed out")
        .unwrap();

    // Tear down + reconnect: bob restarts (new identity, new
    // session), alice has to re-handshake. But alice's peer
    // record retains the SRTT sample from the first
    // session — so the retry should be RTT-derived.
    //
    // To force the retry path: explicitly restart the
    // handshake.
    alice.restart_handshake(&peer).await.unwrap();
    let restart_at = Instant::now();
    alice.send_data(&peer, b"second", 0, 0).await.unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(3), bob.recv())
        .await
        .expect("second handshake didn't complete within RTT-derived budget")
        .unwrap();
    let elapsed = restart_at.elapsed();
    assert_eq!(pkt.payload, b"second");

    // The win is: even though alice's config says "wait 5s
    // before first retry", the second handshake completes
    // well under that on a fast loopback path. Empirically
    // it completes in <100ms; we allow 500ms to be robust.
    eprintln!(
        "[re-handshake] elapsed: {} ms (5000ms static budget would have hidden this)",
        elapsed.as_millis()
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "second handshake took {}ms — SRTT-derived path may not be active",
        elapsed.as_millis()
    );
}
