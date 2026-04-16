//! drift-ring: a single node of an N-node DRIFT ring.
//!
//! Each node identifies itself by an integer `index` in `0..total`.
//! Identities are deterministic: the secret key is derived from the
//! index so every container in the compose file can compute every
//! other node's public key without out-of-band exchange.
//!
//! Data flow:
//!   - Node 0 injects K tokens, each a payload of the form
//!     `[u32 token_id][u8 path_len][path_len bytes of node indices]`.
//!   - Every receiving node appends its own index to the path and
//!     forwards to its "next" peer.
//!   - When the token returns to node 0 with a path containing all
//!     nodes, it's logged as completed.
//!
//! Usage:
//!   drift-ring --index N --total T --listen ADDR --next-addr ADDR
//!              [--tokens K] [--interval-ms MS]

use drift::identity::Identity;
use drift::{Direction, Transport};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn node_identity(index: u32) -> Identity {
    let mut seed = [0u8; 32];
    seed[0] = 0xD1;
    seed[1..5].copy_from_slice(&index.to_be_bytes());
    seed[5] = 0x1F;
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
    let mut index: u32 = 0;
    let mut total: u32 = 15;
    let mut listen: SocketAddr = "0.0.0.0:9000".parse()?;
    let mut next_addr: SocketAddr = "127.0.0.1:9001".parse()?;
    let mut tokens: u32 = 20;
    let mut interval_ms: u64 = 100;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--index" => { index = args[i + 1].parse()?; i += 2; }
            "--total" => { total = args[i + 1].parse()?; i += 2; }
            "--listen" => { listen = args[i + 1].parse()?; i += 2; }
            "--next-addr" => { next_addr = args[i + 1].parse()?; i += 2; }
            "--tokens" => { tokens = args[i + 1].parse()?; i += 2; }
            "--interval-ms" => { interval_ms = args[i + 1].parse()?; i += 2; }
            _ => i += 1,
        }
    }

    let my_id = node_identity(index);
    let next_index = (index + 1) % total;
    let prev_index = (index + total - 1) % total;
    let next_pub = node_identity(next_index).public_bytes();
    let prev_pub = node_identity(prev_index).public_bytes();

    let transport = Arc::new(Transport::bind(listen, my_id).await?);
    println!(
        "node {}/{} listen={} next={}({})",
        index, total, transport.local_addr()?, next_index, next_addr
    );

    // Register next as Initiator (we send HELLO to them).
    let next_peer = transport
        .add_peer(next_pub, next_addr, Direction::Initiator)
        .await.unwrap();
    // Register prev as Responder (they send HELLO to us).
    transport
        .add_peer(prev_pub, "0.0.0.0:0".parse()?, Direction::Responder)
        .await.unwrap();

    // Node 0 injects tokens after a warmup delay.
    if index == 0 {
        let tx = transport.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(4)).await;
            println!("node 0 injecting {} tokens", tokens);
            for token_id in 0..tokens {
                let mut payload = Vec::with_capacity(8);
                payload.extend_from_slice(&token_id.to_be_bytes());
                payload.push(1u8); // path_len = 1
                payload.push(0u8); // index 0
                if let Err(e) = tx.send_data(&next_peer, &payload, 0, 0).await {
                    eprintln!("node 0 send error: {}", e);
                }
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
        });
    }

    // Process incoming tokens.
    let mut completed: u32 = 0;
    loop {
        let pkt = match transport.recv().await {
            Some(p) => p,
            None => break,
        };
        if pkt.payload.len() < 5 {
            continue;
        }
        let token_id = u32::from_be_bytes(pkt.payload[..4].try_into().unwrap());
        let path_len = pkt.payload[4] as usize;
        if pkt.payload.len() < 5 + path_len {
            continue;
        }
        let path = &pkt.payload[5..5 + path_len];

        // Node 0 logs completions when the path contains all nodes.
        if index == 0 && path_len >= total as usize {
            completed += 1;
            println!(
                "node 0 COMPLETED token {} after {} hops ({}/{} done)",
                token_id, path_len, completed, tokens
            );
            if completed >= tokens {
                println!("node 0: all {} tokens completed the ring", tokens);
                tokio::time::sleep(Duration::from_secs(1)).await;
                break;
            }
            continue;
        }

        // Append our index and forward.
        let mut new_payload = Vec::with_capacity(pkt.payload.len() + 1);
        new_payload.extend_from_slice(&token_id.to_be_bytes());
        new_payload.push((path_len + 1) as u8);
        new_payload.extend_from_slice(path);
        new_payload.push(index as u8);

        if let Err(e) = transport.send_data(&next_peer, &new_payload, 0, 0).await {
            eprintln!("node {} forward error: {}", index, e);
        } else if index != 0 {
            println!(
                "node {} forwarded token {} (path_len={})",
                index,
                token_id,
                path_len + 1
            );
        }
    }
    Ok(())
}
