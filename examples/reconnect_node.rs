//! Docker-based reconnect cycle test.
//!
//! Two roles picked by env var `ROLE`:
//!   * `server`: binds :9200, echoes every DATA packet back
//!     to the sender via its own peer table entry for the
//!     client. Prints metrics every few cycles.
//!   * `client`: handshakes with the server, sends one
//!     packet, calls `close_peer`, repeats N times (configured
//!     via `CYCLES` env var, default 20). Exits with code 0
//!     on full success, nonzero on any assertion failure.
//!
//! The compose file runs both containers on the same bridge
//! network. The client's exit code propagates via
//! `--exit-code-from client` so `docker compose up` pass/fail
//! is directly driven by whether the reconnect cycles hold.

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::env;
use std::sync::Arc;
use std::time::Duration;

// Deterministic keys so server knows client's pubkey
// without any dynamic discovery.
const SERVER_SECRET: [u8; 32] = [0x51; 32];
const CLIENT_SECRET: [u8; 32] = [0x52; 32];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let role = env::var("ROLE").unwrap_or_else(|_| "client".into());
    match role.as_str() {
        "server" => run_server().await,
        "client" => run_client().await,
        other => {
            eprintln!("unknown ROLE={}", other);
            std::process::exit(64);
        }
    }
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let server_id = Identity::from_secret_bytes(SERVER_SECRET);
    let client_pub = Identity::from_secret_bytes(CLIENT_SECRET).public_bytes();

    let t = Transport::bind("0.0.0.0:9200".parse()?, server_id).await?;
    println!("[server] bound {}", t.local_addr()?);
    t.add_peer(client_pub, "0.0.0.0:0".parse()?, Direction::Responder)
        .await?;

    let mut seen = 0u32;
    loop {
        match t.recv().await {
            Some(pkt) => {
                seen += 1;
                let m = t.metrics();
                println!(
                    "[server] recv #{} payload={:?} handshakes={} auth_fail={}",
                    seen,
                    String::from_utf8_lossy(&pkt.payload),
                    m.handshakes_completed,
                    m.auth_failures
                );
            }
            None => break,
        }
    }
    Ok(())
}

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve server address from env.
    let server_addr = env::var("SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9200".into())
        .parse()?;
    let cycles: u32 = env::var("CYCLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let client_id = Identity::from_secret_bytes(CLIENT_SECRET);
    let server_pub = Identity::from_secret_bytes(SERVER_SECRET).public_bytes();

    // Wait briefly for the server to be ready — Docker's
    // depends_on only guarantees start order, not readiness.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let t = Arc::new(Transport::bind("0.0.0.0:0".parse()?, client_id).await?);
    let server_peer = t
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await?;

    println!(
        "[client] starting {} close/reconnect cycles against {}",
        cycles, server_addr
    );

    for i in 0..cycles {
        let payload = format!("cycle-{}", i);
        t.send_data(&server_peer, payload.as_bytes(), 0, 0).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        t.close_peer(&server_peer).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        println!("[client] completed cycle {}/{}", i + 1, cycles);
    }

    let m = t.metrics();
    // After the first full handshake + ticket issuance,
    // subsequent cycles reconnect via 1-RTT session
    // resumption (`ResumeHello` → `ResumeAck`) because the
    // client cached the resumption ticket the server gave
    // it. Full handshakes and resumptions are counted
    // separately — total reconnects is the sum.
    let total_reconnects = m.handshakes_completed + m.resumptions_completed;
    println!(
        "[client] DONE cycles={} handshakes={} resumptions={} total={} auth_fail={} replays={}",
        cycles,
        m.handshakes_completed,
        m.resumptions_completed,
        total_reconnects,
        m.auth_failures,
        m.replays_caught
    );

    // Exactly `cycles` reconnects: 1 full handshake + (cycles-1) resumptions.
    if m.handshakes_completed != 1 {
        eprintln!(
            "[client] FAIL handshakes_completed={} expected=1 (first cycle)",
            m.handshakes_completed
        );
        std::process::exit(2);
    }
    if m.resumptions_completed != (cycles - 1) as u64 {
        eprintln!(
            "[client] FAIL resumptions_completed={} expected={}",
            m.resumptions_completed,
            cycles - 1
        );
        std::process::exit(3);
    }
    if m.auth_failures != 0 {
        eprintln!("[client] FAIL auth_failures={}", m.auth_failures);
        std::process::exit(4);
    }
    if m.replays_caught != 0 {
        eprintln!("[client] FAIL replays_caught={}", m.replays_caught);
        std::process::exit(5);
    }
    println!(
        "[client] OK — 1 full handshake + {} 1-RTT resumptions",
        cycles - 1
    );
    Ok(())
}
