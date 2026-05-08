//! Two-peer chat over a deployed `drift-doh-relay` Cloudflare Worker.
//!
//! Each peer runs this binary on their own machine. Identities are
//! random per run (stored only in memory) — print yours, paste the
//! other side's, and you're talking. Every byte rides DRIFT's
//! AEAD-sealed wire over the DoH adapter; the Worker only ever
//! sees ciphertext.
//!
//! ## Usage
//!
//! ```sh
//! # Terminal 1 (Alice)
//! cargo run --example doh-chat -- https://drift-doh-relay.<your-subdomain>.workers.dev
//! # → prints Alice's pubkey, then waits at "peer pubkey:"
//!
//! # Terminal 2 (Bob), after copying Alice's pubkey:
//! cargo run --example doh-chat -- \
//!     https://drift-doh-relay.<your-subdomain>.workers.dev \
//!     <alice-pubkey-hex>
//! # → Bob's pubkey prints; copy it back to Alice's terminal
//! ```
//!
//! Once both sides have entered the other's pubkey, the DRIFT
//! handshake completes through the Worker and stdin lines start
//! flowing.

use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let worker_url = args
        .next()
        .ok_or("usage: doh-chat <worker-url> [peer-pubkey-hex]")?;
    let worker_url = worker_url.trim_end_matches('/').to_string();
    let peer_arg = args.next();

    // Random identity per run — same convention as drift-shell's
    // ephemeral mode. For persistence, you'd swap this for
    // `Identity::load_or_create("~/.config/drift/identity.key")`
    // (the same file every other DRIFT tool uses).
    let identity = Identity::generate();
    let my_pub = identity.public_bytes();
    let my_hex = hex::encode(my_pub);

    println!();
    println!("┌─────────────────────────────────────────────────────────");
    println!("│ MY PUBKEY (share with peer):");
    println!("│   {}", my_hex);
    println!("└─────────────────────────────────────────────────────────");
    println!();

    // Either pubkey came from argv (one-shot mode) or we prompt
    // for it now.
    let peer_hex = match peer_arg {
        Some(h) => h.trim().to_string(),
        None => {
            print!("paste peer's pubkey: ");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim().to_string()
        }
    };
    if peer_hex.len() != 64 {
        return Err(format!("expected 64-hex-char pubkey, got {} chars", peer_hex.len()).into());
    }
    let peer_pub: [u8; 32] = hex::decode(&peer_hex)?
        .try_into()
        .map_err(|_| "pubkey must decode to 32 bytes")?;

    let url = format!("doh://{}/v1/{}/{}/dns-query", strip_scheme(&worker_url), my_hex, peer_hex);
    println!("[doh-chat] connecting via {}", url);

    let (transport, addr) =
        Transport::connect_url(&url, identity, TransportConfig::default()).await?;
    let transport = Arc::new(transport);

    // Both sides register as Initiator — the protocol's
    // dual-init tiebreaker picks one side as the responder
    // automatically based on which pubkey is lexicographically
    // smaller. Symmetric, no flags needed.
    let peer_handle = transport
        .add_peer(peer_pub, addr, Direction::Initiator)
        .await?;
    println!("[doh-chat] handshake will complete on first message — type something to start");
    println!("[doh-chat] (ctrl-c to exit)");

    // ─── Receiver: print incoming messages ───────────────────────
    let recv_t = transport.clone();
    tokio::spawn(async move {
        loop {
            match recv_t.recv().await {
                Some(pkt) => {
                    let text = String::from_utf8_lossy(&pkt.payload);
                    // \r so a partially-typed prompt gets overwritten.
                    println!("\r◀ {}", text);
                    print!("▶ ");
                    let _ = std::io::stdout().flush();
                }
                None => {
                    eprintln!("[doh-chat] transport closed — exiting");
                    std::process::exit(1);
                }
            }
        }
    });

    // ─── Sender: read stdin lines, transport.send_data ───────────
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    print!("▶ ");
    std::io::stdout().flush()?;
    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            print!("▶ ");
            std::io::stdout().flush()?;
            continue;
        }
        // send_data(peer, payload, stream_id=0, deadline_ms=0)
        // — non-streamed, no coalescing deadline. For chat, the
        // first send_data also triggers the HELLO handshake
        // through the Worker.
        if let Err(e) = transport.send_data(&peer_handle, line.as_bytes(), 0, 0).await {
            eprintln!("[doh-chat] send error: {}", e);
        }
        print!("▶ ");
        std::io::stdout().flush()?;
    }

    // Stdin closed (Ctrl-D). Give in-flight packets a chance to
    // round-trip before we exit.
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}

/// `Transport::connect_url` parses `<scheme>://<addr>`. We accept
/// `worker_url` either as `https://host` (what wrangler prints) or
/// as `host` directly; the DoH adapter's own URL builder turns
/// `127.0.0.x` into `http://` and everything else into `https://`,
/// which is the right thing for both production and local-mock
/// tests.
fn strip_scheme(s: &str) -> &str {
    s.trim_start_matches("https://")
        .trim_start_matches("http://")
}
