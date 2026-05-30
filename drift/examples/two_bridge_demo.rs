//! Two-bridge mesh demo.
//!
//! Topology:
//!
//! ```text
//!   client-1  ──┐                                      ┌──  client-6
//!   client-2  ──┤                                      ├──  client-7
//!   client-3  ──┼──▶ bridge-a ◀──── DRIFT ────▶ bridge-b ──┼──▶ client-8
//!   client-4  ──┤                                      ├──  client-9
//!   client-5  ──┘                                      └──  client-10
//! ```
//!
//! 12 containers: 2 bridges + 10 clients. Each client sends a
//! unique message to each of the other 9 clients (90 directed
//! messages total). Cross-bridge messages (clients 1-5 → 6-10
//! and vice versa) prove that DRIFT's mesh routing forwards
//! between two relay nodes; intra-bridge messages prove that
//! the bridge serves multiple clients independently.
//!
//! Each container picks its role from `NODE_ROLE` and its
//! identity from `NODE_INDEX` (0 = bridge-a, 1 = bridge-b,
//! 2-11 = clients 1-10), so identities are deterministic and
//! every container can compute everyone else's peer_id without
//! any out-of-band exchange.

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::{Direction, PeerId, Transport, TransportConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const N_CLIENTS: usize = 10;

const PORT: u16 = 9000;

/// Deterministic identity per node index. Bridge A = 0,
/// Bridge B = 1, clients 1..=10 = indices 2..=11.
fn identity_for(idx: u8) -> Identity {
    let mut seed = [0u8; 32];
    seed[0] = 0xC0 | idx; // make seeds visibly distinct in logs
    for byte in seed.iter_mut().skip(1) {
        *byte = idx;
    }
    Identity::from_secret_bytes(seed)
}

fn pubkey_for(idx: u8) -> [u8; 32] {
    identity_for(idx).public_bytes()
}

fn peer_id_for(idx: u8) -> PeerId {
    derive_peer_id(&pubkey_for(idx))
}

fn bridge_a_idx() -> u8 {
    0
}
fn bridge_b_idx() -> u8 {
    1
}
fn client_idx(client_num: u8) -> u8 {
    // client 1..=10 → idx 2..=11
    1 + client_num
}

fn role() -> String {
    env::var("NODE_ROLE").unwrap_or_else(|_| "client".into())
}

fn node_index() -> u8 {
    env::var("NODE_INDEX")
        .expect("NODE_INDEX required")
        .parse()
        .expect("NODE_INDEX must be a u8")
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn,two_bridge_demo=info".into()),
        )
        .init();

    match role().as_str() {
        "bridge" => run_bridge().await,
        "client" => run_client().await,
        other => {
            eprintln!("unknown NODE_ROLE: {}", other);
            std::process::exit(64);
        }
    }
}

// ─── Bridge ───────────────────────────────────────────────────────

async fn run_bridge() -> Result<(), Box<dyn std::error::Error>> {
    let idx = node_index();
    let id = identity_for(idx);
    let cfg = TransportConfig {
        accept_any_peer: true,
        beacon_interval_ms: 500,
        ..TransportConfig::default()
    };
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", PORT).parse()?;
    let transport = Arc::new(Transport::bind_with_config(bind_addr, id, cfg).await?);

    eprintln!(
        "[bridge] idx={} pub={} peer_id={}",
        idx,
        hex(&pubkey_for(idx)),
        hex8(&peer_id_for(idx))
    );

    // Add the OTHER bridge as a known peer so mesh beacons
    // propagate across the bridge link. The other bridge's
    // hostname is the docker-compose service name.
    let other_idx = if idx == bridge_a_idx() {
        bridge_b_idx()
    } else {
        bridge_a_idx()
    };
    let other_host = bridge_hostname(other_idx);
    let other_addr: SocketAddr = resolve(&format!("{}:{}", other_host, PORT)).await?;
    transport
        .add_peer(pubkey_for(other_idx), other_addr, Direction::Initiator)
        .await?;
    eprintln!(
        "[bridge] added peer-bridge {} at {}",
        bridge_hostname(other_idx),
        other_addr
    );

    // Kick off the bridge↔bridge handshake by sending a
    // periodic ping. Without this, neither bridge has a
    // reason to handshake with the other (clients only
    // contact their own bridge), and beacons never propagate
    // across the link, so cross-bridge mesh routes never
    // form. Once the handshake completes the periodic ping
    // also keeps the path warm.
    let other_pid = peer_id_for(other_idx);
    let t_for_ping = transport.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(2));
        loop {
            ticker.tick().await;
            let _ = t_for_ping.send_data(&other_pid, b"bridge-ping", 0, 0).await;
        }
    });

    // The bridge just sits here forwarding traffic. We do
    // need to drain `recv()` so the channel doesn't fill up;
    // any message addressed to the bridge itself (the
    // periodic pings) is silently dropped.
    while let Some(_msg) = transport.recv().await {
        // drain
    }
    Ok(())
}

fn bridge_hostname(idx: u8) -> &'static str {
    if idx == bridge_a_idx() {
        "bridge-a"
    } else {
        "bridge-b"
    }
}

// ─── Client ───────────────────────────────────────────────────────

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    let idx = node_index();
    let client_num = idx - 1; // idx 2 → client 1
    let id = identity_for(idx);
    let cfg = TransportConfig {
        accept_any_peer: true,
        beacon_interval_ms: 500,
        ..TransportConfig::default()
    };

    // Which bridge does this client connect to?
    // Clients 1-5 (idx 2-6) → bridge-a (idx 0)
    // Clients 6-10 (idx 7-11) → bridge-b (idx 1)
    let my_bridge_idx = if client_num <= 5 {
        bridge_a_idx()
    } else {
        bridge_b_idx()
    };
    let bridge_host = bridge_hostname(my_bridge_idx);
    let bridge_addr: SocketAddr = resolve(&format!("{}:{}", bridge_host, PORT)).await?;

    let transport = Arc::new(Transport::bind_with_config("0.0.0.0:0".parse()?, id, cfg).await?);
    transport
        .add_peer(pubkey_for(my_bridge_idx), bridge_addr, Direction::Initiator)
        .await?;

    eprintln!(
        "[client-{}] idx={} pub={} bridge={} ({})",
        client_num,
        idx,
        hex(&pubkey_for(idx)),
        bridge_host,
        bridge_addr
    );

    // Add every other client as a peer (mesh-routed). The
    // address is a placeholder; routing learns the path
    // through our bridge once beacons converge.
    let placeholder: SocketAddr = "127.0.0.99:60000".parse()?;
    for other in 1u8..=N_CLIENTS as u8 {
        if other == client_num {
            continue;
        }
        transport
            .add_peer(
                pubkey_for(client_idx(other)),
                placeholder,
                Direction::Initiator,
            )
            .await
            .ok();
    }

    // Warm-up: send a byte to the bridge so it learns our
    // interface, then wait for beacon convergence. Cross-
    // bridge routes need ≥1 round of beacons on each side of
    // the bridge↔bridge link, so 10 s is the floor for
    // reliable convergence with the 500 ms beacon interval.
    transport
        .send_data(&peer_id_for(my_bridge_idx), b"warmup", 0, 0)
        .await?;
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Send one unique message to each of the other 9 clients.
    for other in 1u8..=N_CLIENTS as u8 {
        if other == client_num {
            continue;
        }
        let payload = format!("from-{}-to-{}", client_num, other);
        let other_pid = peer_id_for(client_idx(other));
        transport
            .send_data(&other_pid, payload.as_bytes(), 0, 0)
            .await?;
    }

    // Receive 9 messages (one from each other client) and
    // verify the expected payloads. We give a generous
    // timeout because cross-bridge mesh convergence + 90
    // total in-flight messages takes some seconds.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut got = std::collections::HashSet::new();
    while got.len() < N_CLIENTS - 1 && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, transport.recv()).await {
            Ok(Some(msg)) => {
                if let Ok(s) = String::from_utf8(msg.payload.clone()) {
                    got.insert(s);
                }
            }
            _ => break,
        }
    }

    let expected: std::collections::HashSet<String> = (1u8..=N_CLIENTS as u8)
        .filter(|n| *n != client_num)
        .map(|n| format!("from-{}-to-{}", n, client_num))
        .collect();

    if got == expected {
        eprintln!(
            "[client-{}] PASS: received all {} expected messages",
            client_num,
            expected.len()
        );
        std::process::exit(0);
    } else {
        let missing: Vec<_> = expected.difference(&got).collect();
        let extra: Vec<_> = got.difference(&expected).collect();
        eprintln!(
            "[client-{}] FAIL: missing={:?} extra={:?}",
            client_num, missing, extra
        );
        std::process::exit(1);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────

async fn resolve(host_port: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let mut iter = tokio::net::lookup_host(host_port).await?;
    iter.next()
        .ok_or_else(|| format!("no address for {}", host_port).into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

fn hex8(bytes: &[u8; 8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
