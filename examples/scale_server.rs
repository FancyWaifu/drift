//! scale-server: a DRIFT receiver that accepts N clients with seeds 0..N.
//! Counts unique client seeds seen, prints a summary on ctrl-c or exit.
//!
//! Usage:
//!   scale-server <listen_addr> <num_clients>

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::collections::HashSet;
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

    let args: Vec<String> = std::env::args().collect();
    let listen: std::net::SocketAddr = args[1].parse()?;
    let n_clients: u32 = args[2].parse()?;

    let server_id = Identity::from_secret_bytes([0xEE; 32]);
    let transport = Transport::bind(listen, server_id).await?;
    println!("scale-server bound on {}", transport.local_addr()?);

    // Register every client's pubkey.
    for seed in 0..n_clients {
        let mut secret = [0u8; 32];
        secret[..4].copy_from_slice(&seed.to_be_bytes());
        secret[4] = 0xCC;
        let pubkey = Identity::from_secret_bytes(secret).public_bytes();
        transport
            .add_peer(pubkey, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
            .await.unwrap();
    }
    println!("registered {} client identities", n_clients);

    let clients_seen: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));
    let packets_seen = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Print summary every second.
    let cs = clients_seen.clone();
    let ps = packets_seen.clone();
    tokio::spawn(async move {
        let mut tk = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tk.tick().await;
            let clients = cs.lock().await.len();
            let packets = ps.load(std::sync::atomic::Ordering::Relaxed);
            println!("summary: clients={}, packets={}", clients, packets);
        }
    });

    loop {
        let pkt = match transport.recv().await {
            Some(p) => p,
            None => break,
        };
        if pkt.payload.len() >= 4 {
            let seed = u32::from_be_bytes(pkt.payload[..4].try_into().unwrap());
            clients_seen.lock().await.insert(seed);
            packets_seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    Ok(())
}
