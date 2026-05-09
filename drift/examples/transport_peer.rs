//! Generic 2-peer DRIFT test driver — works on any transport
//! scheme registered with the URL dispatcher (`udp://`, `tcp://`,
//! `ws://`, `tls://`, `dns://`, `doh://`).
//!
//! Two roles:
//!
//! ```sh
//! # Side A (listener / responder):
//! transport-peer listen <bind-url>
//! # → prints pubkey hex on stdout, then waits for inbound
//! #   DATA packets and prints each one.
//!
//! # Side B (initiator):
//! transport-peer send <peer-url> <peer-pub-hex> [--count N]
//! # → connects, completes handshake, sends N messages, exits.
//! # → prints metrics (handshakes_completed, packets_sent,
//! #   packets_received, auth_failures) on stdout.
//! ```
//!
//! For schemes without a listener (`doh://`), use `chat` mode on
//! both ends instead — both peers `connect_url`, both exchange
//! messages, the relay routes between them:
//!
//! ```sh
//! transport-peer chat <my-url> <peer-pub-hex> --count 3 --send-text "hello"
//! ```
//!
//! Output is parseable: each event is one line, prefixed with
//! `[evt]`. Final line is `[done] <key=value>...` so test
//! harnesses can grep + assert.

use clap::Parser;
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(version)]
enum Mode {
    /// Bind a listener on URL. Prints pubkey hex, then waits for
    /// inbound DATA. Each received message is printed as one
    /// line; Ctrl-C to exit.
    Listen {
        /// e.g. udp://0.0.0.0:9000, tcp://0.0.0.0:9000,
        /// ws://0.0.0.0:9000, tls://0.0.0.0:9000,
        /// dns://0.0.0.0:5354
        url: String,
        /// Exit after receiving this many DATA packets.
        #[arg(short, long, default_value = "0")]
        recv_count: usize,
        /// Exit after this many seconds even if recv_count not met.
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },
    /// Connect to URL with a known peer pubkey, send N
    /// fire-and-forget DATA messages, exit. Used for one-way
    /// throughput / handshake tests.
    Send {
        url: String,
        peer_pub_hex: String,
        #[arg(short, long, default_value = "5")]
        count: usize,
        #[arg(short = 's', long, default_value = "16")]
        size: usize,
    },
    /// Connect + exchange messages with a peer that's also in
    /// chat mode. Both sides send and receive. Required for
    /// schemes without a listener (doh://).
    Chat {
        url: String,
        peer_pub_hex: String,
        #[arg(short, long, default_value = "3")]
        count: usize,
        #[arg(long, default_value = "alice-msg")]
        send_text: String,
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let mode = Mode::parse();
    match mode {
        Mode::Listen {
            url,
            recv_count,
            timeout,
        } => listen(&url, recv_count, timeout).await,
        Mode::Send {
            url,
            peer_pub_hex,
            count,
            size,
        } => send(&url, &peer_pub_hex, count, size).await,
        Mode::Chat {
            url,
            peer_pub_hex,
            count,
            send_text,
            timeout,
        } => chat(&url, &peer_pub_hex, count, &send_text, timeout).await,
    }
}

// ─── listen ───────────────────────────────────────────────────────

async fn listen(url: &str, recv_count: usize, timeout_s: u64) -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::generate();
    let my_pub = identity.public_bytes();
    let my_hex = hex::encode(my_pub);

    let (transport, bound_url) =
        Transport::bind_url(url, identity, default_config()).await?;
    let transport = Arc::new(transport);
    println!("[evt] role=listen pubkey={} bound={}", my_hex, bound_url);

    let mut got: usize = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_s);
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            println!("[evt] timeout reached after {}s", timeout_s);
            break;
        }
        if recv_count > 0 && got >= recv_count {
            println!("[evt] target recv_count={} reached", recv_count);
            break;
        }
        let recv_fut = transport.recv();
        let pkt = tokio::select! {
            p = recv_fut => p,
            _ = tokio::time::sleep_until(deadline) => {
                println!("[evt] timeout reached after {}s", timeout_s);
                break;
            }
        };
        match pkt {
            Some(p) => {
                got += 1;
                let text = String::from_utf8_lossy(&p.payload);
                println!("[evt] recv #{} bytes={} text={:?}", got, p.payload.len(), text);
            }
            None => {
                println!("[evt] transport closed");
                break;
            }
        }
    }

    let m = transport.metrics();
    println!(
        "[done] role=listen pubkey={} recv={} sent={} handshakes={} auth_fail={}",
        my_hex, m.packets_received, m.packets_sent, m.handshakes_completed, m.auth_failures
    );
    Ok(())
}

// ─── send (one-way) ───────────────────────────────────────────────

async fn send(
    url: &str,
    peer_pub_hex: &str,
    count: usize,
    size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::generate();
    let my_pub = identity.public_bytes();
    let my_hex = hex::encode(my_pub);
    let peer_pub: [u8; 32] = parse_hex32(peer_pub_hex)?;

    let (transport, addr) =
        Transport::connect_url(url, identity, default_config()).await?;
    let transport = Arc::new(transport);
    let peer_handle = transport
        .add_peer(peer_pub, addr, Direction::Initiator)
        .await?;
    println!("[evt] role=send my_pub={} peer={} url={}", my_hex, peer_pub_hex, url);

    let payload: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
    let t0 = std::time::Instant::now();
    for i in 0..count {
        transport.send_data(&peer_handle, &payload, 0, 0).await?;
        if i % 10 == 0 {
            println!("[evt] sent #{} bytes={}", i + 1, payload.len());
        }
    }
    // Give in-flight packets a chance to round-trip before we
    // exit and tear down the transport.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let elapsed = t0.elapsed();

    let m = transport.metrics();
    println!(
        "[done] role=send my_pub={} count={} size={} elapsed_ms={} sent={} recv={} handshakes={} auth_fail={}",
        my_hex,
        count,
        size,
        elapsed.as_millis(),
        m.packets_sent,
        m.packets_received,
        m.handshakes_completed,
        m.auth_failures
    );
    Ok(())
}

// ─── chat (bi-directional) ────────────────────────────────────────

async fn chat(
    url: &str,
    peer_pub_hex: &str,
    count: usize,
    send_text: &str,
    timeout_s: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::generate();
    let my_pub = identity.public_bytes();
    let my_hex = hex::encode(my_pub);
    let peer_pub: [u8; 32] = parse_hex32(peer_pub_hex)?;

    let (transport, addr) =
        Transport::connect_url(url, identity, default_config()).await?;
    let transport = Arc::new(transport);
    let peer_handle = transport
        .add_peer(peer_pub, addr, Direction::Initiator)
        .await?;
    println!("[evt] role=chat my_pub={} peer={} url={}", my_hex, peer_pub_hex, url);

    // Receiver task — print every incoming message.
    let recv_t = transport.clone();
    let (got_tx, mut got_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    tokio::spawn(async move {
        let mut got: usize = 0;
        while let Some(p) = recv_t.recv().await {
            got += 1;
            let text = String::from_utf8_lossy(&p.payload);
            println!("[evt] recv #{} bytes={} text={:?}", got, p.payload.len(), text);
            let _ = got_tx.send(());
        }
    });

    // Sender — fire `count` messages with a stagger.
    for i in 0..count {
        let msg = format!("{}#{}", send_text, i);
        transport.send_data(&peer_handle, msg.as_bytes(), 0, 0).await?;
        println!("[evt] sent #{} bytes={}", i + 1, msg.len());
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Wait until we've received `count` messages or the timeout
    // hits.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_s);
    let mut got: usize = 0;
    while got < count {
        tokio::select! {
            r = got_rx.recv() => match r {
                Some(()) => got += 1,
                None => break,
            },
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }

    let m = transport.metrics();
    println!(
        "[done] role=chat my_pub={} sent={} recv_msgs={} handshakes={} auth_fail={} packets_sent={} packets_recv={}",
        my_hex,
        count,
        got,
        m.handshakes_completed,
        m.auth_failures,
        m.packets_sent,
        m.packets_received,
    );
    Ok(())
}

// ─── helpers ──────────────────────────────────────────────────────

fn default_config() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    }
}

fn parse_hex32(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
