//! drift-peer: a unified peer for the DRIFT directory demo.
//!
//! Every node in a deployment — whether it's "just a client" or
//! "a hub connecting two LANs" — runs this exact binary with
//! different command-line arguments. There is NO special relay role:
//! hubs are just peers that happen to be reachable from more places
//! and that accumulate more contacts in their phonebook.
//!
//! Each peer:
//!   - Runs with accept_any_peer so unknown peers can connect
//!   - Maintains a local phonebook (pubkey → PeerEntry)
//!   - Starts its phonebook with its own entry
//!   - Responds to REGISTER by recording the sender
//!   - Responds to LOOKUP by returning its whole phonebook
//!   - Absorbs received LISTINGs into its phonebook
//!
//! The identity protocol used here is *demo-only*: each peer's secret
//! key is derived from its nickname, so knowing "alice" is sufficient
//! to know alice's pubkey. In a real deployment you'd exchange keys
//! out-of-band.
//!
//! Usage:
//!   drift-peer --name NAME --listen ADDR --advertise ADDR
//!              [--seed NAME@ADDR ...]
//!              [--wait-for N]
//!              [--greet]

use drift::directory::{DirMessage, PeerEntry};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

fn identity_from_name(name: &str) -> Identity {
    let mut seed = [0u8; 32];
    let bytes = name.as_bytes();
    let n = bytes.len().min(31);
    seed[..n].copy_from_slice(&bytes[..n]);
    seed[31] = 0xCC;
    Identity::from_secret_bytes(seed)
}

struct Args {
    name: String,
    listen: SocketAddr,
    advertise: SocketAddr,
    seeds: Vec<(String, SocketAddr)>,
    wait_for: usize,
    greet: bool,
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let argv: Vec<String> = std::env::args().collect();
    let mut name = None;
    let mut listen: Option<SocketAddr> = None;
    let mut advertise: Option<SocketAddr> = None;
    let mut seeds = Vec::new();
    let mut wait_for = 0usize;
    let mut greet = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--name" => {
                name = Some(argv[i + 1].clone());
                i += 2;
            }
            "--listen" => {
                listen = Some(argv[i + 1].parse()?);
                i += 2;
            }
            "--advertise" => {
                advertise = Some(argv[i + 1].parse()?);
                i += 2;
            }
            "--seed" => {
                let val = &argv[i + 1];
                let at = val
                    .find('@')
                    .ok_or("bad --seed format, expected NAME@ADDR")?;
                let seed_name = val[..at].to_string();
                let seed_addr: SocketAddr = val[at + 1..].parse()?;
                seeds.push((seed_name, seed_addr));
                i += 2;
            }
            "--wait-for" => {
                wait_for = argv[i + 1].parse()?;
                i += 2;
            }
            "--greet" => {
                greet = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    Ok(Args {
        name: name.ok_or("--name required")?,
        listen: listen.ok_or("--listen required")?,
        advertise: advertise.ok_or("--advertise required")?,
        seeds,
        wait_for,
        greet,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn".into()),
        )
        .init();

    let args = parse_args()?;
    let identity = identity_from_name(&args.name);
    let my_pubkey = identity.public_bytes();
    let name = args.name.clone();

    println!("[{}] pubkey {}", name, hex(&my_pubkey[..8]));

    // Every peer accepts unknown incoming connections — that's how new
    // contacts can reach us after learning our pubkey from someone
    // else's phonebook.
    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let transport = Arc::new(Transport::bind_with_config(args.listen, identity, cfg).await?);
    println!("[{}] listening on {}", name, transport.local_addr()?);

    // Local phonebook — start with just ourselves.
    let phonebook: Arc<Mutex<HashMap<[u8; 32], PeerEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));
    {
        let mut pb = phonebook.lock().await;
        pb.insert(
            my_pubkey,
            PeerEntry {
                pubkey: my_pubkey,
                addr: args.advertise.to_string(),
                nickname: name.clone(),
            },
        );
    }

    // Background task: receive loop that handles directory messages and
    // greetings. Every peer responds to LOOKUP — there is no separate
    // "server" role.
    let pb_bg = phonebook.clone();
    let transport_bg = transport.clone();
    let name_bg = name.clone();
    tokio::spawn(async move {
        loop {
            let pkt = match transport_bg.recv().await {
                Some(p) => p,
                None => return,
            };

            if let Some(msg) = DirMessage::decode(&pkt.payload) {
                match msg {
                    DirMessage::Register(entry) => {
                        let is_new = {
                            let mut pb = pb_bg.lock().await;
                            let new = !pb.contains_key(&entry.pubkey);
                            pb.insert(entry.pubkey, entry.clone());
                            new
                        };
                        if is_new {
                            println!(
                                "[{}] learned about {} @ {}",
                                name_bg, entry.nickname, entry.addr
                            );
                        }
                    }
                    DirMessage::Lookup => {
                        let entries: Vec<_> =
                            pb_bg.lock().await.values().cloned().collect();
                        let count = entries.len();
                        let reply = DirMessage::Listing(entries).encode();
                        match transport_bg.send_data(&pkt.peer_id, &reply, 0, 0).await {
                            Ok(_) => println!(
                                "[{}] served LOOKUP → returned {} entries",
                                name_bg, count
                            ),
                            Err(e) => {
                                eprintln!("[{}] LOOKUP reply failed: {}", name_bg, e)
                            }
                        }
                    }
                    DirMessage::Listing(entries) => {
                        let mut learned = 0;
                        {
                            let mut pb = pb_bg.lock().await;
                            for e in entries {
                                if !pb.contains_key(&e.pubkey) {
                                    learned += 1;
                                }
                                pb.insert(e.pubkey, e);
                            }
                        }
                        if learned > 0 {
                            let sz = pb_bg.lock().await.len();
                            println!(
                                "[{}] absorbed {} new entries from LISTING (total {})",
                                name_bg, learned, sz
                            );
                        }
                    }
                }
            } else if let Ok(text) = std::str::from_utf8(&pkt.payload) {
                if text.starts_with("hello ") {
                    println!("[{}] ← direct: {}", name_bg, text);
                }
            }
        }
    });

    // If we have seeds, reach out to them and bootstrap our phonebook.
    if !args.seeds.is_empty() {
        // Register every seed in our own phonebook and as a DRIFT peer.
        let mut seed_peer_ids = Vec::new();
        for (seed_name, seed_addr) in &args.seeds {
            let seed_pubkey = identity_from_name(seed_name).public_bytes();
            let peer_id = transport
                .add_peer(seed_pubkey, *seed_addr, Direction::Initiator)
                .await.unwrap();
            seed_peer_ids.push(peer_id);
            phonebook.lock().await.insert(
                seed_pubkey,
                PeerEntry {
                    pubkey: seed_pubkey,
                    addr: seed_addr.to_string(),
                    nickname: seed_name.clone(),
                },
            );
        }

        // Small pause so every peer finishes binding before the
        // registration storm.
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Register ourselves with every seed.
        let my_entry = phonebook.lock().await.get(&my_pubkey).cloned().unwrap();
        let register_bytes = DirMessage::Register(my_entry).encode();
        for peer_id in &seed_peer_ids {
            transport.send_data(peer_id, &register_bytes, 0, 0).await?;
        }
        println!(
            "[{}] REGISTER sent to {} seed(s)",
            name,
            seed_peer_ids.len()
        );

        // Poll-and-absorb loop: keep asking seeds for their phonebook
        // until ours reaches the target size (or timeout).
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut last_printed = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let sz = phonebook.lock().await.len();
            if sz != last_printed {
                println!("[{}] phonebook size: {}", name, sz);
                last_printed = sz;
            }
            if args.wait_for > 0 && sz >= args.wait_for {
                break;
            }
            if Instant::now() >= deadline {
                println!("[{}] bootstrap deadline reached", name);
                break;
            }
            // Ask each seed for its current phonebook.
            let lookup_bytes = DirMessage::Lookup.encode();
            for peer_id in &seed_peer_ids {
                let _ = transport.send_data(peer_id, &lookup_bytes, 0, 0).await;
            }
        }

        println!(
            "[{}] final phonebook size: {}",
            name,
            phonebook.lock().await.len()
        );
    }

    // Greet mode: connect directly to everyone in the phonebook and
    // send a hello, then linger to receive incoming greetings.
    if args.greet {
        let entries: Vec<_> = phonebook.lock().await.values().cloned().collect();
        let mut greeted = 0;
        for entry in &entries {
            if entry.pubkey == my_pubkey {
                continue;
            }
            let addr: SocketAddr = match entry.addr.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let peer_id = transport
                .add_peer(entry.pubkey, addr, Direction::Initiator)
                .await.unwrap();
            let msg = format!("hello {} from {}", entry.nickname, name);
            match transport.send_data(&peer_id, msg.as_bytes(), 0, 0).await {
                Ok(_) => {
                    greeted += 1;
                    println!("[{}] → greeted {} directly", name, entry.nickname);
                }
                Err(e) => eprintln!("[{}] greet {} failed: {}", name, entry.nickname, e),
            }
        }
        println!("[{}] sent {} direct greetings", name, greeted);

        // Linger so greetings from other peers have time to arrive.
        tokio::time::sleep(Duration::from_secs(8)).await;
        println!("[{}] DONE", name);
        return Ok(());
    }

    // No greet mode: run forever as a discovery node.
    std::future::pending::<()>().await;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
