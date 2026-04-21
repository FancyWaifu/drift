//! mesh: spawns three Transport instances in one process to demonstrate
//! mesh forwarding. Topology:
//!
//!   Alice (client)  →  Relay  →  Bob (server)
//!
//! Alice has a route `bob_id → relay_addr`. She sends DATA to Bob; the
//! packets physically go to the relay first, get forwarded, and land at
//! Bob with their crypto intact.
//!
//! Run: cargo run --example mesh

use drift::identity::Identity;
use drift::{derive_peer_id, Direction, Transport};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("drift=debug,mesh=info")
        .init();

    // Identities.
    let alice_id = Identity::from_secret_bytes([0x11; 32]);
    let bob_id = Identity::from_secret_bytes([0x22; 32]);
    let relay_id = Identity::from_secret_bytes([0x33; 32]);

    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let alice_peer_id = derive_peer_id(&alice_pub);
    let bob_peer_id = derive_peer_id(&bob_pub);

    let bob_addr: std::net::SocketAddr = "127.0.0.1:9010".parse()?;
    let relay_addr: std::net::SocketAddr = "127.0.0.1:9011".parse()?;
    let alice_addr: std::net::SocketAddr = "127.0.0.1:9012".parse()?;

    // Bob listens on 9010 as the real destination.
    let bob = Transport::bind(bob_addr, bob_id).await?;
    bob.add_peer(alice_pub, "0.0.0.0:0".parse()?, Direction::Responder)
        .await
        .unwrap();
    println!("bob bound on {}", bob.local_addr()?);

    // Relay listens on 9011. It has no peer entries — it just forwards.
    // Routes: alice_peer_id → alice_addr, bob_peer_id → bob_addr.
    let relay = Transport::bind(relay_addr, relay_id).await?;
    relay.add_route(alice_peer_id, alice_addr).await;
    relay.add_route(bob_peer_id, bob_addr).await;
    println!("relay bound on {}", relay.local_addr()?);

    // Alice binds 9012 (fixed port so the relay can route back to her).
    let alice = Transport::bind(alice_addr, alice_id).await?;
    // Give bob a placeholder addr; the mesh route overrides it.
    alice
        .add_peer(bob_pub, "0.0.0.0:0".parse()?, Direction::Initiator)
        .await
        .unwrap();
    alice.add_route(bob_peer_id, relay_addr).await;
    println!("alice bound on {}", alice.local_addr()?);

    // Bob's receive loop (in a task).
    tokio::spawn(async move {
        loop {
            match bob.recv().await {
                Some(p) => {
                    let s = String::from_utf8_lossy(&p.payload).to_string();
                    println!("BOB recv seq={} from mesh: {:?}", p.seq, s);
                }
                None => break,
            }
        }
    });

    // Relay has no application-level recv to drain; the background task
    // handles forwarding automatically. But we still need to keep the
    // transport alive, so hold it.
    let _relay = relay;

    // Alice sends.
    for i in 1..=5 {
        let msg = format!("mesh hello #{i}");
        alice
            .send_data(&bob_peer_id, msg.as_bytes(), 500, 0)
            .await?;
        println!("ALICE sent #{i}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Wait a moment for the final packets to traverse the relay.
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}
