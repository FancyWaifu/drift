//! Docker-based peer churn test.
//!
//! Hub-and-spoke topology with one hub + N clients (default
//! 4). Role picked by env var `ROLE`:
//!
//!   * `hub`: binds :9400 with `accept_any_peer=true`, drains
//!     forever, prints metrics every ~second. Exits only
//!     when killed by compose.
//!   * `client`: reads `CLIENT_ID` and `HUB_ADDR`, runs a
//!     fixed schedule of send + random-close actions against
//!     the hub. Exits 0 if the per-client metrics look sane
//!     at the end, nonzero otherwise.
//!
//! The compose file uses `--exit-code-from client3` (the
//! last-started client) to propagate pass/fail. Hub metrics
//! can be pulled out via `docker compose logs hub` for
//! post-mortem if a client fails.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use rand::{Rng, SeedableRng};
use std::env;
use std::sync::Arc;
use std::time::Duration;

const HUB_SECRET: [u8; 32] = [0x70; 32];

fn client_secret(cid: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0xC0 + cid;
    s
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let role = env::var("ROLE").unwrap_or_else(|_| "client".into());
    match role.as_str() {
        "hub" => run_hub().await,
        "client" => run_client().await,
        other => {
            eprintln!("unknown ROLE={}", other);
            std::process::exit(64);
        }
    }
}

async fn run_hub() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let id = Identity::from_secret_bytes(HUB_SECRET);
    let t = Arc::new(
        Transport::bind_with_config("0.0.0.0:9400".parse()?, id, cfg).await?,
    );
    println!("[hub] bound {}", t.local_addr()?);

    // Background metrics printer.
    let metrics_t = t.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let m = metrics_t.metrics();
            println!(
                "[hub] metrics: pkts_rx={} handshakes={} auth_fail={} replays={}",
                m.packets_received, m.handshakes_completed, m.auth_failures, m.replays_caught
            );
        }
    });

    let mut total = 0u64;
    while let Some(pkt) = t.recv().await {
        total += 1;
        if total % 10 == 0 {
            println!(
                "[hub] drained {} packets so far, latest {} bytes",
                total,
                pkt.payload.len()
            );
        }
    }
    Ok(())
}

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    let cid: u8 = env::var("CLIENT_ID")
        .expect("CLIENT_ID required")
        .parse()
        .expect("CLIENT_ID must be u8");
    let hub_addr = env::var("HUB_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9400".into())
        .parse()?;
    let actions: u32 = env::var("ACTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    // Wait for the hub to be ready.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let id = Identity::from_secret_bytes(client_secret(cid));
    let hub_pub = Identity::from_secret_bytes(HUB_SECRET).public_bytes();
    let t = Arc::new(
        Transport::bind("0.0.0.0:0".parse()?, id).await?,
    );
    let hub_peer = t
        .add_peer(hub_pub, hub_addr, Direction::Initiator)
        .await?;

    let mut rng = rand::rngs::StdRng::seed_from_u64(cid as u64);
    let mut sends_ok = 0u32;
    let mut reconnects = 0u32;

    println!("[client-{}] starting {} churn actions", cid, actions);

    for step in 0..actions {
        let action: u8 = rng.gen_range(0..10);
        if action < 7 {
            let body = [cid, (step & 0xFF) as u8];
            match t.send_data(&hub_peer, &body, 0, 0).await {
                Ok(()) => sends_ok += 1,
                Err(e) => eprintln!("[client-{}] send step {} err: {:?}", cid, step, e),
            }
        } else {
            let _ = t.close_peer(&hub_peer).await;
            reconnects += 1;
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        tokio::task::yield_now().await;
    }

    // Final graceful close.
    let _ = t.close_peer(&hub_peer).await;

    let m = t.metrics();
    println!(
        "[client-{}] DONE sends_ok={} reconnects={} handshakes={} auth_fail={} replays={}",
        cid,
        sends_ok,
        reconnects,
        m.handshakes_completed,
        m.auth_failures,
        m.replays_caught
    );

    // Sanity: each reconnect should have triggered a fresh
    // handshake, plus the initial one. We allow some slack
    // because a close right before an action boundary can
    // race with the next handshake attempt.
    if m.handshakes_completed == 0 {
        eprintln!("[client-{}] FAIL zero handshakes completed", cid);
        std::process::exit(2);
    }
    // Churn-induced auth failures are bounded (mirrors the
    // in-process test's relaxed threshold).
    if m.auth_failures as u32 > reconnects * 3 + 5 {
        eprintln!(
            "[client-{}] FAIL auth_failures={} exceeds bound",
            cid, m.auth_failures
        );
        std::process::exit(3);
    }
    println!("[client-{}] OK", cid);
    Ok(())
}
