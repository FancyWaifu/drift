//! drift-chat: three-node chat over DRIFT, one medium per IP.
//!
//! Topology:
//!   bridge   — rendezvous with UDP:9200 + TCP:9201 + WS:9202 on 127.0.0.1
//!   chat @1  — UDP       (127.0.0.1)
//!   chat @2  — TCP       (127.0.0.2)
//!   chat @3  — WebSocket (127.0.0.3)
//!
//! Identities are derived from `role_tag + bind_ip` so every node
//! can compute the same peer_id for every other node without a
//! key-exchange step. All messaging is addressed by peer_id through
//! the bridge; the underlying medium is picked solely by the
//! sender's and receiver's bind IP.
//!
//! Usage:
//!   drift-chat bridge
//!   drift-chat <bind_ip>                 # auto: greet each peer, listen 10s
//!   drift-chat <bind_ip> --for <secs>    # auto mode with custom listen window
//!   drift-chat <bind_ip> --interactive   # read stdin, type:
//!                                        #   all <text>        broadcast
//!                                        #   .1 <text> | .2 .. address by last IP octet
//!                                        #   quit              exit

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::io::{TcpPacketIO, WsPacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpSocket};

const BRIDGE_UDP: &str = "127.0.0.1:9200";
const BRIDGE_TCP: &str = "127.0.0.1:9201";
const BRIDGE_WS: &str = "127.0.0.1:9202";

const CHAT_IPS: [&str; 3] = ["127.0.0.1", "127.0.0.2", "127.0.0.3"];

fn bridge_id() -> Identity {
    Identity::from_secret_bytes([0xBB; 32])
}

fn chat_id(ip: &str) -> Identity {
    let mut seed = [0u8; 32];
    seed[0] = 0xCC;
    for (i, b) in ip.as_bytes().iter().take(30).enumerate() {
        seed[i + 1] = *b;
    }
    Identity::from_secret_bytes(seed)
}

fn medium_for(ip: &str) -> &'static str {
    match ip {
        "127.0.0.1" => "UDP",
        "127.0.0.2" => "TCP",
        "127.0.0.3" => "WS",
        _ => "?",
    }
}

fn bridge_addr_for(ip: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    Ok(match ip {
        "127.0.0.1" => BRIDGE_UDP,
        "127.0.0.2" => BRIDGE_TCP,
        "127.0.0.3" => BRIDGE_WS,
        _ => return Err(format!("no bridge addr for {}", ip).into()),
    }
    .parse()?)
}

fn cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        beacon_interval_ms: 150,
        rtt_probe_interval_ms: 0,
        ..TransportConfig::default()
    }
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
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    match cmd {
        "bridge" => run_bridge().await,
        bind_ip if CHAT_IPS.contains(&bind_ip) => {
            let interactive = args.iter().any(|a| a == "--interactive");
            let for_secs = find_flag_u64(&args, "--for").unwrap_or(10);
            run_chat(bind_ip, interactive, for_secs).await
        }
        _ => {
            eprintln!(
                "usage:\n  drift-chat bridge\n  drift-chat <127.0.0.1|127.0.0.2|127.0.0.3> [--for SECS | --interactive]"
            );
            std::process::exit(2);
        }
    }
}

fn find_flag_u64(args: &[String], flag: &str) -> Option<u64> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
}

async fn run_bridge() -> Result<(), Box<dyn std::error::Error>> {
    let bridge = Arc::new(
        Transport::bind_with_config(BRIDGE_UDP.parse()?, bridge_id(), cfg()).await?,
    );
    println!("[bridge] UDP iface 0 on {}", BRIDGE_UDP);

    let tcp_listener = TcpListener::bind(BRIDGE_TCP).await?;
    println!("[bridge] TCP listening on {}", BRIDGE_TCP);
    let b = bridge.clone();
    tokio::spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, addr)) => match TcpPacketIO::new(stream) {
                    Ok(io) => {
                        let idx = b.add_interface("tcp", Arc::new(io));
                        println!("[bridge] TCP iface {} wired (peer {})", idx, addr);
                    }
                    Err(e) => eprintln!("[bridge] TCP wrap: {}", e),
                },
                Err(e) => {
                    eprintln!("[bridge] TCP accept: {}", e);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    });

    let ws_listener = TcpListener::bind(BRIDGE_WS).await?;
    println!("[bridge] WS listening on {}", BRIDGE_WS);
    let b = bridge.clone();
    tokio::spawn(async move {
        loop {
            match ws_listener.accept().await {
                Ok((stream, addr)) => match tokio_tungstenite::accept_async(stream).await {
                    Ok(ws) => {
                        let idx =
                            b.add_interface("ws", Arc::new(WsPacketIO::new(ws, addr)));
                        println!("[bridge] WS iface {} wired (peer {})", idx, addr);
                    }
                    Err(e) => eprintln!("[bridge] WS accept: {}", e),
                },
                Err(e) => {
                    eprintln!("[bridge] WS accept: {}", e);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    });

    // Drain recv so warmups don't back up the channel.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3600) {
        match tokio::time::timeout(Duration::from_millis(500), bridge.recv()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {}
        }
    }
    Ok(())
}

async fn run_chat(
    bind_ip: &str,
    interactive: bool,
    listen_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let my_medium = medium_for(bind_ip);
    let identity = chat_id(bind_ip);
    let me_hex = hex_full(&derive_peer_id(&identity.public_bytes()));
    let bridge_addr = bridge_addr_for(bind_ip)?;

    // Build transport for this node's medium.
    let transport: Arc<Transport> = match bind_ip {
        "127.0.0.1" => Arc::new(
            Transport::bind_with_config(
                format!("{}:0", bind_ip).parse()?,
                identity,
                cfg(),
            )
            .await?,
        ),
        "127.0.0.2" => {
            let sock = TcpSocket::new_v4()?;
            sock.bind(format!("{}:0", bind_ip).parse()?)?;
            let stream = sock.connect(BRIDGE_TCP.parse()?).await?;
            let io = Arc::new(TcpPacketIO::new(stream)?);
            Arc::new(Transport::bind_with_io(io, identity, cfg()).await?)
        }
        "127.0.0.3" => {
            let sock = TcpSocket::new_v4()?;
            sock.bind(format!("{}:0", bind_ip).parse()?)?;
            let tcp = sock.connect(BRIDGE_WS.parse()?).await?;
            let (ws, _) =
                tokio_tungstenite::client_async(format!("ws://{}/", BRIDGE_WS), tcp).await?;
            let io = Arc::new(WsPacketIO::new(ws, BRIDGE_WS.parse()?));
            Arc::new(Transport::bind_with_io(io, identity, cfg()).await?)
        }
        other => return Err(format!("unsupported chat bind IP: {}", other).into()),
    };

    println!(
        "[chat/{} {}] peer_id={}",
        bind_ip,
        my_medium,
        &me_hex[..12]
    );

    // Register the bridge and every other chat peer, all reached
    // via the bridge we're currently connected through.
    let bridge_pub = bridge_id().public_bytes();
    let bridge_pid = derive_peer_id(&bridge_pub);
    transport
        .add_peer(bridge_pub, bridge_addr, Direction::Initiator)
        .await?;
    let mut peers: Vec<(String, [u8; 8])> = Vec::new();
    for ip in CHAT_IPS {
        if ip == bind_ip {
            continue;
        }
        let pub_bytes = chat_id(ip).public_bytes();
        let pid = derive_peer_id(&pub_bytes);
        transport
            .add_peer(pub_bytes, bridge_addr, Direction::Initiator)
            .await?;
        peers.push((ip.to_string(), pid));
    }

    // Warm up with the bridge and let beacons converge.
    transport.send_data(&bridge_pid, b"warmup", 0, 0).await?;
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Spawn a background receiver that prints every incoming
    // message with the source peer's IP + medium tag.
    let recv_deadline = Instant::now() + Duration::from_secs(listen_secs);
    let t_recv = transport.clone();
    let me_bind = bind_ip.to_string();
    let recv_task = tokio::spawn(async move {
        while Instant::now() < recv_deadline {
            match tokio::time::timeout(Duration::from_millis(250), t_recv.recv()).await {
                Ok(Some(pkt)) => {
                    let from = identify_peer(&pkt.peer_id);
                    let msg = String::from_utf8_lossy(&pkt.payload);
                    if msg == "warmup" {
                        continue;
                    }
                    println!("[{}] RECV <- {}: {}", me_bind, from, msg.trim_end());
                }
                Ok(None) => break,
                Err(_) => {}
            }
        }
    });

    if interactive {
        run_interactive(&transport, bind_ip, my_medium, &peers).await?;
    } else {
        // Auto mode: greet every peer once, then let the recv
        // task run until the listen window closes.
        for (ip, pid) in &peers {
            let text = format!("hello from {} ({})", bind_ip, my_medium);
            let _ = transport.send_data(pid, text.as_bytes(), 0, 0).await;
            println!("[{}] SEND -> {} ({}): {}", bind_ip, ip, medium_for(ip), text);
        }
    }

    let _ = recv_task.await;
    let m = transport.metrics();
    println!(
        "[{}] done: handshakes={} retries={} unknown_peer_drops={}",
        bind_ip,
        m.handshakes_completed,
        m.handshake_retries,
        m.unknown_peer_drops
    );
    Ok(())
}

async fn run_interactive(
    transport: &Arc<Transport>,
    bind_ip: &str,
    my_medium: &str,
    peers: &[(String, [u8; 8])],
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "[{}] interactive. commands: `all <text>` | `.1|.2|.3 <text>` | `who` | `quit`",
        bind_ip
    );
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = stdin.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "quit" {
            break;
        }
        if line == "who" {
            for (ip, pid) in peers {
                println!("  {} ({}) peer_id={}", ip, medium_for(ip), hex8(pid));
            }
            continue;
        }
        let (prefix, rest) = line
            .split_once(' ')
            .unwrap_or((line, ""));
        let targets: Vec<&(String, [u8; 8])> = match prefix {
            "all" => peers.iter().collect(),
            ".1" => peers.iter().filter(|(ip, _)| ip == "127.0.0.1").collect(),
            ".2" => peers.iter().filter(|(ip, _)| ip == "127.0.0.2").collect(),
            ".3" => peers.iter().filter(|(ip, _)| ip == "127.0.0.3").collect(),
            _ => {
                println!("  ? unknown command (`all <text>` | `.1|.2|.3 <text>` | `who` | `quit`)");
                continue;
            }
        };
        if rest.is_empty() {
            println!("  ? empty message");
            continue;
        }
        let tagged = format!("[{}/{}] {}", bind_ip, my_medium, rest);
        for (ip, pid) in targets {
            match transport.send_data(pid, tagged.as_bytes(), 0, 0).await {
                Ok(_) => println!("[{}] SEND -> {} ({}): {}", bind_ip, ip, medium_for(ip), rest),
                Err(e) => println!("[{}] FAIL -> {}: {}", bind_ip, ip, e),
            }
        }
    }
    Ok(())
}

fn identify_peer(peer_id: &[u8; 8]) -> String {
    for ip in CHAT_IPS {
        if &derive_peer_id(&chat_id(ip).public_bytes()) == peer_id {
            return format!("{} ({})", ip, medium_for(ip));
        }
    }
    format!("?peer={}", hex8(peer_id))
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{:02x}", x)).collect()
}
fn hex_full(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
