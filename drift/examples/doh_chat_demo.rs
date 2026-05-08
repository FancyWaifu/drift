//! Self-driving demo: two DRIFT peers chatting through a deployed
//! `drift-doh-relay` Cloudflare Worker. Same protocol path as
//! `doh-chat`, but both sides run in this one binary so the
//! handshake + message exchange happen automatically and we can
//! verify byte-for-byte delivery.
//!
//! Run:
//!
//! ```sh
//! cargo run --example doh-chat-demo -- \
//!     https://drift-doh-relay.<your-subdomain>.workers.dev
//! ```
//!
//! What you'll see: Alice's pubkey, Bob's pubkey, a few messages
//! flying both ways with timestamps, then a verification summary
//! confirming every message round-tripped.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let worker_url = std::env::args()
        .nth(1)
        .ok_or("usage: doh-chat-demo <worker-url>")?;
    let host = worker_url
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string();

    // Two random identities — fresh per run, so the Worker's
    // per-pubkey inboxes are guaranteed empty on first contact.
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();
    let alice_hex = hex::encode(alice_pub);
    let bob_hex = hex::encode(bob_pub);

    println!();
    println!("┌─ DRIFT-over-DoH live demo ──────────────────────────────");
    println!("│ Worker:  https://{}", host);
    println!("│ Alice:   {}", alice_hex);
    println!("│ Bob:     {}", bob_hex);
    println!("└─────────────────────────────────────────────────────────");
    println!();

    // Each side's URL has THEIR pubkey first (the inbox the
    // Worker drains for them) and the PEER's pubkey second
    // (the inbox the Worker pushes their fragments into).
    let alice_url = format!("doh://{}/v1/{}/{}/dns-query", host, alice_hex, bob_hex);
    let bob_url = format!("doh://{}/v1/{}/{}/dns-query", host, bob_hex, alice_hex);

    let t0 = Instant::now();

    // Bring both transports up. Each runs its own background poll
    // loop against the Worker — no listener, no bound socket on
    // either side, both are HTTPS clients of Cloudflare's edge.
    let (alice_t, alice_addr) =
        Transport::connect_url(&alice_url, alice, TransportConfig::default()).await?;
    let alice_t = Arc::new(alice_t);
    let (bob_t, bob_addr) =
        Transport::connect_url(&bob_url, bob, TransportConfig::default()).await?;
    let bob_t = Arc::new(bob_t);

    println!("[{:>5}ms] both transports connected to Worker", t0.elapsed().as_millis());

    // Both sides register the other as Initiator. DRIFT's
    // dual-init tiebreaker picks one side as the responder
    // automatically (lex-smaller pubkey wins responder role).
    let bob_handle = alice_t
        .add_peer(bob_pub, alice_addr, Direction::Initiator)
        .await?;
    let alice_handle = bob_t
        .add_peer(alice_pub, bob_addr, Direction::Initiator)
        .await?;

    // Spawn receivers on both sides — print every incoming
    // message with the side and a timestamp. We also collect
    // them in a channel so the main task can verify counts at
    // the end.
    let (alice_rx_tx, mut alice_rx_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (bob_rx_tx, mut bob_rx_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let at = alice_t.clone();
    let t_for_alice = t0;
    tokio::spawn(async move {
        while let Some(pkt) = at.recv().await {
            let text = String::from_utf8_lossy(&pkt.payload).to_string();
            println!(
                "[{:>5}ms]   alice ◀ {:?}",
                t_for_alice.elapsed().as_millis(),
                text
            );
            let _ = alice_rx_tx.send(pkt.payload);
        }
    });

    let bt = bob_t.clone();
    let t_for_bob = t0;
    tokio::spawn(async move {
        while let Some(pkt) = bt.recv().await {
            let text = String::from_utf8_lossy(&pkt.payload).to_string();
            println!(
                "[{:>5}ms]     bob ◀ {:?}",
                t_for_bob.elapsed().as_millis(),
                text
            );
            let _ = bob_rx_tx.send(pkt.payload);
        }
    });

    // Conversation script. Alice sends N messages, Bob sends M
    // back, interleaved with small sleeps so the wire activity
    // is visible. Total exchange should complete in ~5-10s
    // depending on the Worker's edge latency.
    let alice_says: Vec<&str> = vec![
        "hello bob",
        "this is alice — going through cloudflare",
        "no vps, no domain, no public ip",
        "every byte AEAD-sealed end-to-end",
    ];
    let bob_says: Vec<&str> = vec![
        "hi alice — i hear you",
        "the worker only sees ciphertext + pubkey routing",
        "this is the universal-firewall-piercer wire",
    ];

    // Alice sends; the first send_data triggers the HELLO →
    // HELLO_ACK handshake inline (rides as the first DRIFT
    // packet through DoH).
    let alice_send_t = alice_t.clone();
    let alice_lines = alice_says.clone();
    tokio::spawn(async move {
        for (i, line) in alice_lines.iter().enumerate() {
            tokio::time::sleep(Duration::from_millis(if i == 0 { 0 } else { 1500 })).await;
            println!(
                "[{:>5}ms]   alice ▶ {:?}",
                t0.elapsed().as_millis(),
                line
            );
            if let Err(e) = alice_send_t.send_data(&bob_handle, line.as_bytes(), 0, 0).await
            {
                eprintln!("alice send error: {}", e);
            }
        }
    });

    let bob_send_t = bob_t.clone();
    let bob_lines = bob_says.clone();
    tokio::spawn(async move {
        // Slight stagger so Alice's HELLO lands at the Worker
        // before Bob's — keeps the log output easy to follow.
        // The dual-init tiebreaker handles either order safely.
        tokio::time::sleep(Duration::from_millis(800)).await;
        for line in bob_lines.iter() {
            println!(
                "[{:>5}ms]     bob ▶ {:?}",
                t0.elapsed().as_millis(),
                line
            );
            if let Err(e) = bob_send_t.send_data(&alice_handle, line.as_bytes(), 0, 0).await
            {
                eprintln!("bob send error: {}", e);
            }
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
    });

    // Wait for everything to round-trip. We expect Alice to
    // receive `bob_says.len()` messages and Bob to receive
    // `alice_says.len()`. Bail with a timeout if anything
    // hangs.
    let want_alice = bob_says.len();
    let want_bob = alice_says.len();
    let deadline = Duration::from_secs(60);

    let mut got_alice: Vec<Vec<u8>> = Vec::new();
    let mut got_bob: Vec<Vec<u8>> = Vec::new();

    let collect = async {
        while got_alice.len() < want_alice || got_bob.len() < want_bob {
            tokio::select! {
                Some(p) = alice_rx_rx.recv() => got_alice.push(p),
                Some(p) = bob_rx_rx.recv() => got_bob.push(p),
                else => break,
            }
        }
    };

    if tokio::time::timeout(deadline, collect).await.is_err() {
        eprintln!();
        eprintln!("⏱️  timed out after {} s", deadline.as_secs());
        eprintln!("   alice received {}/{}, bob received {}/{}",
            got_alice.len(), want_alice, got_bob.len(), want_bob);
        std::process::exit(2);
    }

    println!();
    println!("┌─ result ────────────────────────────────────────────────");
    println!(
        "│ alice received {}/{} messages",
        got_alice.len(),
        want_alice
    );
    println!("│ bob   received {}/{} messages", got_bob.len(), want_bob);

    // Spot-check that the bytes match what was sent (order is
    // FIFO per direction since DRIFT preserves stream order).
    let alice_strs: Vec<String> = got_alice
        .iter()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .collect();
    let bob_strs: Vec<String> = got_bob
        .iter()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .collect();
    let alice_ok: bool = alice_strs.iter().zip(bob_says.iter()).all(|(a, b)| a == b);
    let bob_ok: bool = bob_strs.iter().zip(alice_says.iter()).all(|(a, b)| a == b);
    println!("│ alice bytes match expected: {}", if alice_ok { "✅" } else { "❌" });
    println!("│ bob   bytes match expected: {}", if bob_ok { "✅" } else { "❌" });

    let am = alice_t.metrics();
    let bm = bob_t.metrics();
    println!(
        "│ alice metrics: handshakes={} sent={} recv={} auth_fail={}",
        am.handshakes_completed, am.packets_sent, am.packets_received, am.auth_failures
    );
    println!(
        "│ bob   metrics: handshakes={} sent={} recv={} auth_fail={}",
        bm.handshakes_completed, bm.packets_sent, bm.packets_received, bm.auth_failures
    );
    println!(
        "│ total wall-clock: {} ms",
        t0.elapsed().as_millis()
    );
    println!("└─────────────────────────────────────────────────────────");

    if alice_ok && bob_ok && got_alice.len() == want_alice && got_bob.len() == want_bob {
        println!();
        println!("✅ DRIFT chat through Cloudflare Worker — fully verified.");
        Ok(())
    } else {
        std::process::exit(1)
    }
}
