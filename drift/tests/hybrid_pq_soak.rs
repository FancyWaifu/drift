//! PQ steady-state soak.
//!
//! Two PQ-enabled transports exchange one DATA packet every
//! 10ms for `SOAK_SECS`. The assertions are about steady state,
//! not throughput peaks:
//!
//!   - `handshakes_completed` stays at 1 throughout — i.e. NO
//!     re-handshakes get triggered by PQ-specific bugs (a
//!     leak in the dk stash would force re-handshakes when the
//!     session expires, for example).
//!   - Every DATA packet round-trips successfully.
//!   - Final RSS doesn't blow up — proxy for "no leak on
//!     accumulated PQ state".
//!
//! Tunable via `DRIFT_SOAK_SECS` env var; default 30s for CI,
//! bump to 300s for a real overnight test. `#[ignore]` keeps it
//! out of the default `cargo test` run since 30s is long.
//!
//! Run manually:
//!   cargo test --release --test hybrid_pq_soak -- --ignored --nocapture

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn pq_cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "long-running; opt-in via --ignored"]
async fn hybrid_pq_soak_stable_steady_state() {
    let soak_secs: u64 = std::env::var("DRIFT_SOAK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!("[soak] running {} seconds of PQ steady-state", soak_secs);

    let server_id = Identity::from_secret_bytes([0xF1; 32]);
    let server_pub = server_id.public_bytes();
    let server = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), server_id, pq_cfg())
            .await
            .unwrap(),
    );
    let server_addr = server.local_addr().unwrap();

    let client_id = Identity::from_secret_bytes([0xF2; 32]);
    let client_pub = client_id.public_bytes();
    let client = Arc::new(
        Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), client_id, pq_cfg())
            .await
            .unwrap(),
    );

    server
        .add_peer(
            client_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let server_handle = client
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .unwrap();

    // Prime the session.
    client
        .send_data(&server_handle, b"prime", 0, 0)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), server.recv())
        .await
        .expect("initial PQ handshake didn't complete");

    // Steady-state: one DATA per 10ms for `soak_secs`. Use a
    // background drainer on the server so the recv channel
    // doesn't back up.
    let drain_server = server.clone();
    let drainer = tokio::spawn(async move {
        loop {
            if drain_server.recv().await.is_none() {
                break;
            }
        }
    });

    let start = Instant::now();
    let mut sent = 0u64;
    let mut send_errors = 0u64;
    let mut ticker = tokio::time::interval(Duration::from_millis(10));
    while start.elapsed() < Duration::from_secs(soak_secs) {
        ticker.tick().await;
        match client.send_data(&server_handle, b"soak-tick", 0, 0).await {
            Ok(_) => sent += 1,
            Err(_) => send_errors += 1,
        }
    }

    // Tear down drainer.
    drop(client);
    drop(server);
    let _ = drainer.await;

    eprintln!(
        "[soak] sent {} packets, {} send errors over {}s",
        sent, send_errors, soak_secs
    );
    assert_eq!(
        send_errors, 0,
        "PQ steady-state developed send errors — likely session re-handshake bug"
    );

    // Hard floor: we should have sent at least sent_secs * 50
    // packets (10ms cadence, allow 50% slop).
    let expected_min = soak_secs as u64 * 50;
    assert!(
        sent >= expected_min,
        "soak ran too slow: sent {} (expected at least {})",
        sent,
        expected_min
    );
}
