//! drift-dir-server: a directory relay ("librarian peer").
//!
//! Accepts DRIFT connections from any peer (via accept_any_peer), stores
//! RegisterPeer entries in an in-memory table, and responds to Lookup
//! messages with the current directory.
//!
//! The relay is deliberately dumb — it does NOT proxy data traffic.
//! Clients use it to find each other, then connect DIRECTLY.
//!
//! Usage:
//!   drift-dir-server [LISTEN_ADDR]
//!
//! The relay's identity is fixed ([0xAA; 32]) so clients can pre-share
//! the relay's pubkey. In a real deployment you'd configure this from
//! a file or environment variable.

use drift::directory::{DirMessage, PeerEntry};
use drift::identity::Identity;
use drift::{Transport, TransportConfig};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn".into()),
        )
        .init();

    let args: Vec<String> = env::args().collect();
    let listen: SocketAddr = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("0.0.0.0:9000")
        .parse()?;

    // Fixed relay identity: deterministic secret so clients can embed
    // the relay's pubkey at compile time.
    let identity = Identity::from_secret_bytes([0xAA; 32]);
    println!("[relay] pubkey {}", hex(&identity.public_bytes()));

    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let transport = Arc::new(Transport::bind_with_config(listen, identity, cfg).await?);
    println!("[relay] bound on {}", transport.local_addr()?);

    // Directory: pubkey → PeerEntry
    let directory: Arc<Mutex<HashMap<[u8; 32], PeerEntry>>> = Arc::new(Mutex::new(HashMap::new()));

    // Periodic summary printer so we can see the directory grow.
    let dir_snap = directory.clone();
    tokio::spawn(async move {
        let mut tk = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tk.tick().await;
            let dir = dir_snap.lock().await;
            println!("[relay] directory size: {}", dir.len());
        }
    });

    loop {
        let pkt = match transport.recv().await {
            Some(p) => p,
            None => break,
        };

        let msg = match DirMessage::decode(&pkt.payload) {
            Some(m) => m,
            None => {
                eprintln!("[relay] malformed message from {:?}", pkt.peer_id);
                continue;
            }
        };

        match msg {
            DirMessage::Register(entry) => {
                let nick = entry.nickname.clone();
                let addr = entry.addr.clone();
                directory.lock().await.insert(entry.pubkey, entry);
                println!("[relay] REGISTER {} @ {}", nick, addr);
            }
            DirMessage::Lookup => {
                let listing: Vec<PeerEntry> = directory.lock().await.values().cloned().collect();
                let count = listing.len();
                let reply = DirMessage::Listing(listing).encode();
                match transport.send_data(&pkt.peer_id, &reply, 0, 0).await {
                    Ok(_) => println!(
                        "[relay] LOOKUP from {} → returned {} entries",
                        hex(&pkt.peer_id),
                        count
                    ),
                    Err(e) => eprintln!("[relay] failed to send listing: {}", e),
                }
            }
            DirMessage::Listing(_) => {
                // Clients send this, not to us. Ignore.
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
