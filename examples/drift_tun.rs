//! drift-tun: tunnel arbitrary TCP traffic over DRIFT.
//!
//! Two modes:
//!
//!   listen: accept DRIFT sessions and for each inbound stream, open a
//!           TCP connection to --forward and pipe bytes both ways.
//!
//!   dial:   connect to a DRIFT peer, then accept local TCP connections
//!           on --listen-port; for each, open a new DRIFT stream and
//!           pipe bytes both ways.
//!
//! Every tunneled connection becomes one DRIFT stream. Multiple local
//! connections are multiplexed on the same DRIFT session without
//! head-of-line blocking.
//!
//! Usage:
//!   drift-tun listen --name NAME --drift-port PORT --forward HOST:PORT
//!   drift-tun dial   --name NAME --peer NAME@HOST:PORT --listen-port PORT
//!
//! Identities are derived from --name for demo purposes. In real
//! deployment you'd load a keypair from a file.

use drift::identity::Identity;
use drift::streams::{Stream, StreamManager};
use drift::{Direction, Transport, TransportConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn identity_from_name(name: &str) -> Identity {
    let mut seed = [0u8; 32];
    let bytes = name.as_bytes();
    let n = bytes.len().min(31);
    seed[..n].copy_from_slice(&bytes[..n]);
    seed[31] = 0xCC;
    Identity::from_secret_bytes(seed)
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  drift-tun listen --name NAME --drift-port PORT --forward HOST:PORT");
    eprintln!("  drift-tun dial   --name NAME --peer NAME@HOST:PORT --listen-port PORT");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn,drift_tun=info".into()),
        )
        .init();

    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        usage();
        std::process::exit(2);
    }

    match argv[1].as_str() {
        "listen" => run_listen(&argv[2..]).await?,
        "dial" => run_dial(&argv[2..]).await?,
        other => {
            eprintln!("unknown mode: {}", other);
            usage();
            std::process::exit(2);
        }
    }
    Ok(())
}

// --- listen mode ---

struct ListenArgs {
    name: String,
    drift_port: u16,
    forward: SocketAddr,
}

fn parse_listen(args: &[String]) -> Result<ListenArgs, Box<dyn std::error::Error>> {
    let mut name = None;
    let mut drift_port = None;
    let mut forward = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                name = Some(args[i + 1].clone());
                i += 2;
            }
            "--drift-port" => {
                drift_port = Some(args[i + 1].parse()?);
                i += 2;
            }
            "--forward" => {
                forward = Some(args[i + 1].parse()?);
                i += 2;
            }
            _ => i += 1,
        }
    }
    Ok(ListenArgs {
        name: name.ok_or("--name required")?,
        drift_port: drift_port.ok_or("--drift-port required")?,
        forward: forward.ok_or("--forward required")?,
    })
}

async fn run_listen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_listen(args)?;
    let identity = identity_from_name(&args.name);
    let listen: SocketAddr = format!("0.0.0.0:{}", args.drift_port).parse()?;

    println!(
        "[listen] name={} drift={} forward-to={}",
        args.name, listen, args.forward
    );

    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let transport = Arc::new(Transport::bind_with_config(listen, identity, cfg).await?);
    let mgr = StreamManager::bind(transport).await;

    loop {
        let stream = match mgr.accept().await {
            Some(s) => s,
            None => break,
        };
        let forward = args.forward;
        tokio::spawn(async move {
            println!(
                "[listen] stream {} from peer {:02x?} → dialing {}",
                stream.id(),
                &stream.peer()[..4],
                forward
            );
            match TcpStream::connect(forward).await {
                Ok(tcp) => {
                    let _ = tcp.set_nodelay(true);
                    pipe(stream, tcp).await;
                }
                Err(e) => {
                    eprintln!("[listen] TCP connect to {} failed: {}", forward, e);
                    let _ = stream.close().await;
                }
            }
        });
    }
    Ok(())
}

// --- dial mode ---

struct DialArgs {
    name: String,
    peer_name: String,
    peer_addr: SocketAddr,
    listen_port: u16,
}

fn parse_dial(args: &[String]) -> Result<DialArgs, Box<dyn std::error::Error>> {
    let mut name = None;
    let mut peer = None;
    let mut listen_port = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                name = Some(args[i + 1].clone());
                i += 2;
            }
            "--peer" => {
                peer = Some(args[i + 1].clone());
                i += 2;
            }
            "--listen-port" => {
                listen_port = Some(args[i + 1].parse()?);
                i += 2;
            }
            _ => i += 1,
        }
    }
    let peer = peer.ok_or("--peer required")?;
    let at = peer
        .find('@')
        .ok_or("bad --peer format, expected NAME@HOST:PORT")?;
    let peer_name = peer[..at].to_string();
    let peer_addr: SocketAddr = peer[at + 1..].parse()?;
    Ok(DialArgs {
        name: name.ok_or("--name required")?,
        peer_name,
        peer_addr,
        listen_port: listen_port.ok_or("--listen-port required")?,
    })
}

async fn run_dial(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_dial(args)?;
    let identity = identity_from_name(&args.name);
    let local_listen: SocketAddr = format!("0.0.0.0:{}", args.listen_port).parse()?;

    println!(
        "[dial] name={} peer={}@{} local-listen={}",
        args.name, args.peer_name, args.peer_addr, local_listen
    );

    let cfg = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let transport = Arc::new(
        Transport::bind_with_config("0.0.0.0:0".parse()?, identity, cfg).await?,
    );

    let peer_pub = identity_from_name(&args.peer_name).public_bytes();
    let peer_id = transport
        .add_peer(peer_pub, args.peer_addr, Direction::Initiator)
        .await.unwrap();

    let mgr = StreamManager::bind(transport).await;
    let tcp_listener = TcpListener::bind(local_listen).await?;

    println!("[dial] TCP listener ready");

    loop {
        let (tcp, from) = tcp_listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        println!("[dial] local TCP connection from {}", from);
        let mgr = mgr.clone();
        tokio::spawn(async move {
            match mgr.open(peer_id).await {
                Ok(stream) => {
                    println!("[dial] opened stream {} for {}", stream.id(), from);
                    pipe(stream, tcp).await;
                }
                Err(e) => {
                    eprintln!("[dial] open stream failed: {}", e);
                }
            }
        });
    }
}

// --- shared pipe ---

/// Bidirectionally shuttle bytes between a DRIFT stream and a TCP
/// socket. Either end closing terminates both directions.
async fn pipe(stream: Stream, tcp: TcpStream) {
    let stream = Arc::new(stream);
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    // stream → tcp
    let sr = stream.clone();
    let s_to_t = tokio::spawn(async move {
        loop {
            match sr.recv().await {
                Some(bytes) => {
                    if tcp_w.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
        let _ = tcp_w.shutdown().await;
    });

    // tcp → stream
    let sw = stream.clone();
    let t_to_s = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if sw.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = sw.close().await;
    });

    let _ = tokio::join!(s_to_t, t_to_s);
}
