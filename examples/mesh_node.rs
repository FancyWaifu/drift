//! Docker-based five-node full mesh test.
//!
//! Five instances of this binary run as five containers on
//! the same bridge network. Each container:
//!
//!   1. Reads `NODE_ID` (0..=4) and `PEER_ADDRS` (comma-
//!      separated list of the other four containers'
//!      addresses in node-index order) from env.
//!   2. Binds :9300 with a deterministic identity derived
//!      from `NODE_ID`.
//!   3. Adds every other node as a peer. Direction is
//!      decided by peer-id lexicographic order to match
//!      the in-process test's strategy and skip the
//!      dual-init tiebreaker path.
//!   4. Sends one uniquely-tagged DATA packet to each of
//!      the 4 other nodes.
//!   5. Drains its own recv channel until it has seen 4
//!      distinct packets (one from each peer).
//!   6. Verifies the payloads match the expected tags,
//!      then exits with a deterministic code.
//!
//! The compose file uses `depends_on` so nodes come up in
//! order, and picks one node as the "verifier" via
//! `--exit-code-from node0`.

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::{Direction, Transport};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;

const N: usize = 5;

fn secret_for(node_id: u8) -> [u8; 32] {
    [0xA0 + node_id; 32]
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let node_id: u8 = env::var("NODE_ID")
        .expect("NODE_ID required")
        .parse()
        .expect("NODE_ID must be 0..=4");
    if node_id as usize >= N {
        eprintln!("NODE_ID out of range: {}", node_id);
        std::process::exit(64);
    }

    let peer_addrs_raw = env::var("PEER_ADDRS").expect("PEER_ADDRS required");
    let peer_addrs: Vec<_> = peer_addrs_raw
        .split(',')
        .map(|s| s.trim().parse().expect("peer addr parse failed"))
        .collect::<Vec<std::net::SocketAddr>>();
    assert_eq!(
        peer_addrs.len(),
        N,
        "PEER_ADDRS must have exactly {} entries (node's own slot is a placeholder)",
        N
    );

    // Build every node's identity so we can compute peer ids
    // for directional tiebreaking.
    let mut pubs = Vec::with_capacity(N);
    let mut peer_ids = Vec::with_capacity(N);
    for i in 0..N {
        let id = Identity::from_secret_bytes(secret_for(i as u8));
        pubs.push(id.public_bytes());
        peer_ids.push(derive_peer_id(&id.public_bytes()));
    }

    let my_id = Identity::from_secret_bytes(secret_for(node_id));
    let t = Arc::new(
        Transport::bind("0.0.0.0:9300".parse()?, my_id).await?,
    );
    println!("[node-{}] bound {}", node_id, t.local_addr()?);

    // Register every other node as a peer.
    for j in 0..N {
        if j == node_id as usize {
            continue;
        }
        let dir = if peer_ids[node_id as usize] < peer_ids[j] {
            Direction::Initiator
        } else {
            Direction::Responder
        };
        let addr = if dir == Direction::Initiator {
            peer_addrs[j]
        } else {
            "0.0.0.0:0".parse()?
        };
        t.add_peer(pubs[j], addr, dir).await?;
    }

    // Stagger a bit so every container has its peer table
    // populated before traffic starts. Docker's `depends_on`
    // only orders startup, not readiness.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send one tagged packet to each other node.
    for j in 0..N {
        if j == node_id as usize {
            continue;
        }
        let body = [node_id, j as u8];
        let dst_id = peer_ids[j];
        t.send_data(&dst_id, &body, 0, 0).await?;
        println!("[node-{}] sent to node-{}", node_id, j);
    }

    // Drain our own recv until we've seen (N-1) distinct
    // senders.
    let mut seen: HashMap<[u8; 8], Vec<u8>> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while seen.len() < N - 1 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, t.recv()).await {
            Ok(Some(pkt)) => {
                seen.insert(pkt.peer_id, pkt.payload);
            }
            Ok(None) | Err(_) => break,
        }
    }

    let m = t.metrics();
    println!(
        "[node-{}] collected {}/{} senders, handshakes={} auth_fail={}",
        node_id,
        seen.len(),
        N - 1,
        m.handshakes_completed,
        m.auth_failures
    );

    // Verify.
    if seen.len() != N - 1 {
        eprintln!(
            "[node-{}] FAIL received from {} senders, expected {}",
            node_id,
            seen.len(),
            N - 1
        );
        std::process::exit(2);
    }
    for j in 0..N {
        if j == node_id as usize {
            continue;
        }
        let sender_pid = peer_ids[j];
        let expected = vec![j as u8, node_id];
        let got = seen.get(&sender_pid).ok_or_else(|| {
            format!(
                "node-{} never heard from node-{} ({:?})",
                node_id, j, sender_pid
            )
        })?;
        if got != &expected {
            eprintln!(
                "[node-{}] FAIL wrong payload from node-{}: got {:?} expected {:?}",
                node_id, j, got, expected
            );
            std::process::exit(3);
        }
    }
    if m.auth_failures != 0 {
        eprintln!("[node-{}] FAIL auth_failures={}", node_id, m.auth_failures);
        std::process::exit(4);
    }
    if m.handshakes_completed != (N - 1) as u64 {
        eprintln!(
            "[node-{}] FAIL handshakes_completed={} expected={}",
            node_id,
            m.handshakes_completed,
            N - 1
        );
        std::process::exit(5);
    }

    println!("[node-{}] OK", node_id);

    // Give slower peers a moment to also finish so they can
    // read THEIR received packets before we tear down. This
    // node's early exit doesn't harm others because they
    // already have the data queued in their recv buffers.
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}
