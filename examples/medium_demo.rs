//! Three-medium loopback demo: one bridge with UDP/TCP/WebSocket
//! ears, three peers each bound to a distinct 127.0.0.x address,
//! each reaching the bridge via its own medium and addressing
//! every other peer by identity through mesh routing.
//!
//! Layout:
//!   bridge:  127.0.0.1 listens UDP:9001, TCP:9002, WS:9003
//!   udp:     source 127.0.0.1  (UDP  -> bridge UDP)
//!   tcp:     source 127.0.0.2  (TCP  -> bridge TCP)
//!   ws:      source 127.0.0.3  (WS   -> bridge WS)
//!
//! Usage:
//!   drift-medium-demo bridge
//!   drift-medium-demo udp-peer
//!   drift-medium-demo tcp-peer
//!   drift-medium-demo ws-peer

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::io::{TcpPacketIO, WsPacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket};

const BRIDGE_UDP: &str = "127.0.0.1:9001";
const BRIDGE_TCP: &str = "127.0.0.1:9002";
const BRIDGE_WS: &str = "127.0.0.1:9003";

const UDP_PEER_IP: &str = "127.0.0.1:0";
const TCP_PEER_IP: &str = "127.0.0.2:0";
const WS_PEER_IP: &str = "127.0.0.3:0";

fn bridge_id() -> Identity {
    Identity::from_secret_bytes([0xBB; 32])
}
fn udp_id() -> Identity {
    Identity::from_secret_bytes([0xA1; 32])
}
fn tcp_id() -> Identity {
    Identity::from_secret_bytes([0xB2; 32])
}
fn ws_id() -> Identity {
    Identity::from_secret_bytes([0xC3; 32])
}

fn cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        beacon_interval_ms: 200,
        rtt_probe_interval_ms: 0,
        ..TransportConfig::default()
    }
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{:02x}", x)).collect()
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
    match args.get(1).map(String::as_str).unwrap_or("") {
        "bridge" => run_bridge().await,
        "udp-peer" => run_peer(Medium::Udp).await,
        "tcp-peer" => run_peer(Medium::Tcp).await,
        "ws-peer" => run_peer(Medium::Ws).await,
        _ => {
            eprintln!("usage: drift-medium-demo <bridge|udp-peer|tcp-peer|ws-peer>");
            std::process::exit(2);
        }
    }
}

#[derive(Copy, Clone)]
enum Medium {
    Udp,
    Tcp,
    Ws,
}

async fn run_bridge() -> Result<(), Box<dyn std::error::Error>> {
    let bridge =
        Arc::new(Transport::bind_with_config(BRIDGE_UDP.parse()?, bridge_id(), cfg()).await?);
    println!("[bridge] UDP  iface 0 on {}", BRIDGE_UDP);

    let tcp_listener = TcpListener::bind(BRIDGE_TCP).await?;
    println!("[bridge] TCP  listening on {}", BRIDGE_TCP);
    let ws_listener = TcpListener::bind(BRIDGE_WS).await?;
    println!("[bridge] WS   listening on {}", BRIDGE_WS);

    let b_tcp = bridge.clone();
    tokio::spawn(async move {
        if let Ok((stream, addr)) = tcp_listener.accept().await {
            println!("[bridge] TCP  peer TCP-connected from {}", addr);
            match TcpPacketIO::new(stream) {
                Ok(io) => {
                    let idx = b_tcp.add_interface("tcp", Arc::new(io));
                    println!("[bridge] TCP  iface {} wired", idx);
                }
                Err(e) => eprintln!("[bridge] TCP wrap failed: {}", e),
            }
        }
    });

    let b_ws = bridge.clone();
    tokio::spawn(async move {
        if let Ok((stream, addr)) = ws_listener.accept().await {
            println!("[bridge] WS   peer TCP-connected from {}", addr);
            match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => {
                    let idx = b_ws.add_interface("ws", Arc::new(WsPacketIO::new(ws, addr)));
                    println!("[bridge] WS   iface {} wired (handshake ok)", idx);
                }
                Err(e) => eprintln!("[bridge] WS accept failed: {}", e),
            }
        }
    });

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(25) {
        match tokio::time::timeout(Duration::from_millis(500), bridge.recv()).await {
            Ok(Some(pkt)) => {
                println!(
                    "[bridge] recv from peer={} seq={} {}B: {:?}",
                    hex8(&pkt.peer_id),
                    pkt.seq,
                    pkt.payload.len(),
                    String::from_utf8_lossy(&pkt.payload),
                );
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }

    let m = bridge.metrics();
    println!(
        "[bridge] done: handshakes={} forwarded={} auth_fail={}",
        m.handshakes_completed, m.forwarded, m.auth_failures
    );
    Ok(())
}

async fn run_peer(medium: Medium) -> Result<(), Box<dyn std::error::Error>> {
    let (name, self_id, peer_ids, bridge_addr_for_routing): (
        &str,
        Identity,
        Vec<(&str, [u8; 32])>,
        SocketAddr,
    ) = match medium {
        Medium::Udp => (
            "udp",
            udp_id(),
            vec![
                ("tcp", tcp_id().public_bytes()),
                ("ws", ws_id().public_bytes()),
            ],
            BRIDGE_UDP.parse()?,
        ),
        Medium::Tcp => (
            "tcp",
            tcp_id(),
            vec![
                ("udp", udp_id().public_bytes()),
                ("ws", ws_id().public_bytes()),
            ],
            BRIDGE_TCP.parse()?,
        ),
        Medium::Ws => (
            "ws",
            ws_id(),
            vec![
                ("udp", udp_id().public_bytes()),
                ("tcp", tcp_id().public_bytes()),
            ],
            BRIDGE_WS.parse()?,
        ),
    };
    let bridge_pub = bridge_id().public_bytes();
    let bridge_pid = derive_peer_id(&bridge_pub);

    // Build the transport with the right medium.
    let transport = match medium {
        Medium::Udp => {
            Arc::new(Transport::bind_with_config(UDP_PEER_IP.parse()?, self_id, cfg()).await?)
        }
        Medium::Tcp => {
            let sock = TcpSocket::new_v4()?;
            sock.bind(TCP_PEER_IP.parse()?)?;
            let stream = sock.connect(BRIDGE_TCP.parse()?).await?;
            let local = stream.local_addr()?;
            println!("[{}] TCP source {} -> {}", name, local, BRIDGE_TCP);
            let io = Arc::new(TcpPacketIO::new(stream)?);
            Arc::new(Transport::bind_with_io(io, self_id, cfg()).await?)
        }
        Medium::Ws => {
            let sock = TcpSocket::new_v4()?;
            sock.bind(WS_PEER_IP.parse()?)?;
            let tcp = sock.connect(BRIDGE_WS.parse()?).await?;
            let local = tcp.local_addr()?;
            println!("[{}] WS  source {} -> {}", name, local, BRIDGE_WS);
            let (ws, _) =
                tokio_tungstenite::client_async(format!("ws://{}/", BRIDGE_WS), tcp).await?;
            let io = Arc::new(WsPacketIO::new(ws, BRIDGE_WS.parse()?));
            Arc::new(Transport::bind_with_io(io, self_id, cfg()).await?)
        }
    };

    // Register bridge as an Initiator peer (we open the handshake).
    transport
        .add_peer(bridge_pub, bridge_addr_for_routing, Direction::Initiator)
        .await
        .unwrap();
    // Register the other two peers; their reach address is the bridge
    // (mesh will forward once beacons have converged).
    for (_other_name, other_pub) in &peer_ids {
        let _ = transport
            .add_peer(*other_pub, bridge_addr_for_routing, Direction::Initiator)
            .await;
    }

    // Handshake with bridge.
    transport.send_data(&bridge_pid, b"warmup", 0, 0).await?;
    println!("[{}] warmup sent, waiting for beacon convergence...", name);
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Cross-medium sends.
    for (other_name, other_pub) in &peer_ids {
        let other_pid = derive_peer_id(other_pub);
        let msg = format!("hello-from-{}-to-{}", name, other_name);
        match transport.send_data(&other_pid, msg.as_bytes(), 0, 0).await {
            Ok(_) => println!("[{}] sent -> {} ({:?})", name, other_name, msg),
            Err(e) => println!("[{}] send to {} FAILED: {}", name, other_name, e),
        }
    }

    // Receive window.
    let start = std::time::Instant::now();
    let mut got: Vec<String> = Vec::new();
    while start.elapsed() < Duration::from_secs(6) {
        match tokio::time::timeout(Duration::from_millis(500), transport.recv()).await {
            Ok(Some(pkt)) => {
                let s = String::from_utf8_lossy(&pkt.payload).to_string();
                println!(
                    "[{}] recv from peer={} {}B: {:?}",
                    name,
                    hex8(&pkt.peer_id),
                    pkt.payload.len(),
                    s
                );
                got.push(s);
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }

    let m = transport.metrics();
    println!(
        "[{}] done: got={} handshakes={} retries={}",
        name,
        got.len(),
        m.handshakes_completed,
        m.handshake_retries
    );
    Ok(())
}
