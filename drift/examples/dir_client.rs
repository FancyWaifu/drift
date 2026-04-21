//! drift-dir-client: a client that bootstraps via a directory relay.
//!
//! Flow:
//!   1. Generate a unique identity from the provided nickname.
//!   2. Establish a DRIFT session with the relay.
//!   3. Register itself (pubkey + advertised address + nickname).
//!   4. Query the relay for the full directory.
//!   5. For every OTHER peer in the directory, open a DIRECT session
//!      and send a one-shot greeting.
//!   6. Receive greetings from other peers.
//!
//! Usage:
//!   drift-dir-client <nickname> <listen_addr> <advertised_addr> <relay_addr>
//!
//! Example:
//!   drift-dir-client alice 0.0.0.0:9000 10.90.0.20:9000 10.90.0.10:9000

use drift::directory::{DirMessage, PeerEntry};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn identity_from_nickname(nick: &str) -> Identity {
    let mut seed = [0u8; 32];
    let bytes = nick.as_bytes();
    let n = bytes.len().min(31);
    seed[..n].copy_from_slice(&bytes[..n]);
    seed[31] = 0xCC;
    Identity::from_secret_bytes(seed)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn".into()),
        )
        .init();

    let args: Vec<String> = env::args().collect();
    let nickname = args.get(1).cloned().unwrap_or_else(|| "anon".to_string());
    let listen: SocketAddr = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("0.0.0.0:9000")
        .parse()?;
    let advertised: SocketAddr = args
        .get(3)
        .map(|s| s.as_str())
        .unwrap_or("127.0.0.1:9000")
        .parse()?;
    let relay_addr: SocketAddr = args
        .get(4)
        .map(|s| s.as_str())
        .unwrap_or("127.0.0.1:9500")
        .parse()?;

    let identity = identity_from_nickname(&nickname);
    let my_pubkey = identity.public_bytes();
    println!("[{}] pubkey {}", nickname, hex(&my_pubkey[..8]));

    // Enable accept_any_peer so other clients can initiate direct
    // sessions with us after learning our pubkey via the directory.
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let transport = Arc::new(Transport::bind_with_config(listen, identity, cfg).await?);
    println!("[{}] bound on {}", nickname, transport.local_addr()?);

    // Pre-share the relay's pubkey (fixed identity in dir_server).
    let relay_pubkey = Identity::from_secret_bytes([0xAA; 32]).public_bytes();
    let relay_peer = transport
        .add_peer(relay_pubkey, relay_addr, Direction::Initiator)
        .await
        .unwrap();

    // Wait briefly so all clients can start before the registration
    // storm, then register ourselves.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let my_entry = PeerEntry {
        pubkey: my_pubkey,
        addr: advertised.to_string(),
        nickname: nickname.clone(),
    };
    let register_bytes = DirMessage::Register(my_entry).encode();
    transport
        .send_data(&relay_peer, &register_bytes, 0, 0)
        .await?;
    println!("[{}] REGISTER sent", nickname);

    // Let other clients also register.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // Query the directory.
    let lookup_bytes = DirMessage::Lookup.encode();
    transport
        .send_data(&relay_peer, &lookup_bytes, 0, 0)
        .await?;
    println!("[{}] LOOKUP sent", nickname);

    // Wait for the LISTING response.
    let listing = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut result: Option<Vec<PeerEntry>> = None;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(500), transport.recv()).await {
                Ok(Some(pkt)) => {
                    if let Some(DirMessage::Listing(entries)) = DirMessage::decode(&pkt.payload) {
                        result = Some(entries);
                        break;
                    }
                }
                _ => {}
            }
        }
        result
    };

    let Some(listing) = listing else {
        eprintln!("[{}] timed out waiting for LISTING", nickname);
        return Ok(());
    };

    println!(
        "[{}] received directory with {} entries:",
        nickname,
        listing.len()
    );
    for e in &listing {
        println!("  - {} @ {} ({})", e.nickname, e.addr, hex(&e.pubkey[..8]));
    }

    // Establish direct sessions with each non-self peer in the listing
    // and send a greeting.
    let mut direct_peer_ids = Vec::new();
    for entry in &listing {
        if entry.pubkey == my_pubkey {
            continue;
        }
        let addr: SocketAddr = match entry.addr.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let peer = transport
            .add_peer(entry.pubkey, addr, Direction::Initiator)
            .await
            .unwrap();
        direct_peer_ids.push((entry.nickname.clone(), peer));
    }

    // Small pause to let everyone set up their peer tables.
    tokio::time::sleep(Duration::from_millis(500)).await;

    for (other_nick, peer_id) in &direct_peer_ids {
        let msg = format!("hello {} from {}", other_nick, nickname);
        if let Err(e) = transport.send_data(peer_id, msg.as_bytes(), 0, 0).await {
            eprintln!("[{}] failed to greet {}: {}", nickname, other_nick, e);
        } else {
            println!("[{}] → greeted {} directly", nickname, other_nick);
        }
    }

    // Receive greetings from other clients for a few seconds.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    let mut received_greetings = 0;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), transport.recv()).await {
            Ok(Some(pkt)) => {
                if let Ok(text) = std::str::from_utf8(&pkt.payload) {
                    if text.starts_with("hello") {
                        received_greetings += 1;
                        println!("[{}] ← direct: {}", nickname, text);
                    }
                }
            }
            _ => {}
        }
    }

    println!(
        "[{}] DONE — received {} direct greetings, expected {}",
        nickname,
        received_greetings,
        direct_peer_ids.len()
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
