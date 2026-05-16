//! Thundering-herd scale test for hybrid PQ default-on.
//!
//! This is the inverse of `scale_handshakes::thousand_concurrent_handshakes`:
//! same shape (1000 clients hit one server simultaneously),
//! but with both sides using PQ AND the server tuned for it
//! (SO_RCVBUF=4MB, clients with 334ms first-HELLO jitter).
//!
//! Without the tuning, T.10.4 measured ~68% delivery rate.
//! With the tuning, we expect ≥95% — matching the classical
//! baseline.
//!
//! `#[ignore]` because it spins up 1000 transports (slow);
//! run explicitly with `cargo test --release --ignored`.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

const N: usize = 1000;
const RECV_BUF: usize = 4 * 1024 * 1024; // 4 MiB
const JITTER_MS: u64 = 334;              // WireGuard's value

fn server_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        udp_recv_buffer_bytes: Some(RECV_BUF),
        // Server doesn't initiate HELLOs; jitter unused but
        // harmless if set.
        ..Default::default()
    }
}

fn client_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        handshake_jitter_ms: JITTER_MS,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "spins up 1000 transports; opt-in via --ignored"]
async fn thousand_concurrent_hybrid_pq_handshakes_with_tuning() {
    let server_id = Identity::from_secret_bytes([0xAB; 32]);
    let server_pub = server_id.public_bytes();
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, server_cfg())
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    // Pre-register every client pubkey on the server so we
    // measure handshake throughput, not the cookie path. Same
    // setup as the classical scale test.
    let mut client_secrets = Vec::with_capacity(N);
    for i in 0..N {
        let mut secret = [0u8; 32];
        secret[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        secret[31] = 0xAA;
        client_secrets.push(secret);
        let pub_bytes = Identity::from_secret_bytes(secret).public_bytes();
        server
            .add_peer(
                pub_bytes,
                "0.0.0.0:0".parse().unwrap(),
                Direction::Responder,
            )
            .await
            .unwrap();
    }

    // Fire all N clients concurrently. With jitter=334ms,
    // their HELLOs spread over ~334ms instead of arriving in
    // the same microsecond.
    let mut handles = Vec::with_capacity(N);
    for secret in client_secrets {
        let server_pub = server_pub;
        handles.push(tokio::spawn(async move {
            let client = Transport::bind_with_config(
                "127.0.0.1:0".parse().unwrap(),
                Identity::from_secret_bytes(secret),
                client_cfg(),
            )
            .await
            .unwrap();
            let peer = client
                .add_peer(server_pub, server_addr, Direction::Initiator)
                .await
                .unwrap();
            client.send_data(&peer, b"scale-pq", 0, 0).await.unwrap();
            // Keep client alive long enough for the handshake
            // and DATA to reach the server.
            tokio::time::sleep(Duration::from_secs(8)).await;
        }));
    }

    // Drain server side, counting deliveries. Budget is 20s
    // total — jitter spread (up to 334ms) + hybrid handshake
    // (a few ms each) + drain.
    let mut delivered = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while delivered < N && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), server.recv()).await {
            Ok(Some(_)) => delivered += 1,
            _ => continue,
        }
    }

    // Wait for client tasks to finish cleanly.
    for h in handles {
        let _ = h.await;
    }

    let m = server.metrics();
    eprintln!(
        "[hybrid scale] delivered={}/{}  handshakes={}  hybrid={}  recv_buf={}KB",
        delivered,
        N,
        m.handshakes_completed,
        m.hybrid_pq_handshakes_completed,
        RECV_BUF / 1024
    );

    // The tuning's job is to bring delivery to ≥95% — matching
    // the classical baseline. Without it (T.10.4) we observed
    // ~68%.
    assert!(
        delivered >= (N * 95) / 100,
        "only {}/{} hybrid handshakes delivered with tuning; \
         need ≥95% — recv_buf={} bytes, jitter_ms={}",
        delivered,
        N,
        RECV_BUF,
        JITTER_MS
    );
    assert!(
        m.hybrid_pq_handshakes_completed >= (N as u64 * 95) / 100,
        "server reports only {} completed hybrid handshakes (need ≥{})",
        m.hybrid_pq_handshakes_completed,
        (N * 95) / 100
    );
}
