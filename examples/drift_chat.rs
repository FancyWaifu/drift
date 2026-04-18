//! drift-chat: four-node chat over DRIFT, one medium per IP.
//!
//! Topology:
//!   bridge   — rendezvous with
//!               UDP:9200  TCP:9201  WS:9202 on 127.0.0.1,
//!               plus a WebRTC signaling TCP port on :9203
//!   chat @1  — UDP       (127.0.0.1)
//!   chat @2  — TCP       (127.0.0.2)
//!   chat @3  — WebSocket (127.0.0.3)
//!   chat @4  — WebRTC    (127.0.0.4)
//!
//! Identities are derived from `role_tag + bind_ip` so every node
//! can compute the same peer_id for every other node without a
//! key-exchange step. All messaging is addressed by peer_id through
//! the bridge; the underlying medium is picked solely by the
//! sender's and receiver's bind IP.
//!
//! WebRTC uses a tiny SDP-over-TCP signaling step (newline-delimited
//! JSON) to bootstrap the RTCPeerConnection, then all DRIFT traffic
//! rides over the DataChannel. On loopback there's no NAT or STUN
//! dance — ICE gathers host candidates in a few hundred ms.
//!
//! Usage:
//!   drift-chat bridge
//!   drift-chat <bind_ip>                 # auto: greet each peer, listen 10s
//!   drift-chat <bind_ip> --for <secs>    # auto mode with custom listen window
//!   drift-chat <bind_ip> --interactive   # read stdin

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::io::{TcpPacketIO, WebRTCPacketIO, WsPacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

const BRIDGE_UDP: &str = "127.0.0.1:9200";
const BRIDGE_TCP: &str = "127.0.0.1:9201";
const BRIDGE_WS: &str = "127.0.0.1:9202";
const BRIDGE_RTC_SIGNALING: &str = "127.0.0.1:9203";

const CHAT_IPS: [&str; 4] = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"];

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
        "127.0.0.4" => "WebRTC",
        _ => "?",
    }
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
                "usage:\n  drift-chat bridge\n  drift-chat <127.0.0.1|127.0.0.2|127.0.0.3|127.0.0.4> [--for SECS | --interactive]"
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

    // WebRTC signaling: each client connection kicks off a single
    // offer/answer exchange, then we wrap the resulting DataChannel
    // as a PacketIO and add it as a bridge interface.
    let rtc_listener = TcpListener::bind(BRIDGE_RTC_SIGNALING).await?;
    println!(
        "[bridge] WebRTC signaling listening on {}",
        BRIDGE_RTC_SIGNALING
    );
    let b = bridge.clone();
    tokio::spawn(async move {
        loop {
            match rtc_listener.accept().await {
                Ok((stream, addr)) => {
                    let bb = b.clone();
                    tokio::spawn(async move {
                        match accept_webrtc_peer(stream).await {
                            Ok(dc) => {
                                let io = Arc::new(WebRTCPacketIO::new(dc, addr));
                                let idx = bb.add_interface("webrtc", io);
                                println!(
                                    "[bridge] WebRTC iface {} wired (peer {})",
                                    idx, addr
                                );
                            }
                            Err(e) => {
                                eprintln!("[bridge] WebRTC setup failed for {}: {}", addr, e)
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[bridge] WebRTC accept: {}", e);
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

// ─── WebRTC signaling ──────────────────────────────────────
//
// Minimal offer/answer over a single TCP connection, one message
// per line in JSON. Avoids trickle ICE by waiting for ICE
// gathering to complete before sending SDP — loopback gathers in
// a few hundred ms.

#[derive(serde::Serialize, serde::Deserialize)]
struct SignalMsg {
    kind: String, // "offer" | "answer"
    sdp: String,
}

async fn accept_webrtc_peer(
    stream: TcpStream,
) -> Result<Arc<RTCDataChannel>, Box<dyn std::error::Error + Send + Sync>> {
    // Bridge is the offerer: it creates the data channel and
    // emits the SDP offer. The incoming client is the answerer.
    let pc = new_peer_connection().await?;
    let dc_ready = spawn_data_channel_opener(pc.clone()).await?;

    let offer = pc.create_offer(None).await?;
    pc.set_local_description(offer).await?;
    wait_for_ice_complete(pc.clone()).await;
    let local = pc
        .local_description()
        .await
        .ok_or("no local description after ICE")?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader).lines();

    let offer_json = serde_json::to_string(&SignalMsg {
        kind: "offer".into(),
        sdp: local.sdp,
    })?;
    writer.write_all(offer_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    let answer_line = reader
        .next_line()
        .await?
        .ok_or("answerer closed signaling before replying")?;
    let answer: SignalMsg = serde_json::from_str(&answer_line)?;
    if answer.kind != "answer" {
        return Err(format!("expected answer, got {}", answer.kind).into());
    }
    let rtc_answer = RTCSessionDescription::answer(answer.sdp)?;
    pc.set_remote_description(rtc_answer).await?;

    // Wait for the data channel's open event.
    let dc = tokio::time::timeout(Duration::from_secs(20), dc_ready).await??;
    Ok(dc)
}

async fn connect_webrtc_peer(
    signaling_addr: &str,
) -> Result<Arc<RTCDataChannel>, Box<dyn std::error::Error + Send + Sync>> {
    // Client is the answerer: it receives an offer over the
    // signaling TCP connection, then replies with an answer.
    let stream = TcpStream::connect(signaling_addr).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader).lines();

    let pc = new_peer_connection().await?;
    let dc_ready = register_data_channel_opener(pc.clone());

    let offer_line = reader
        .next_line()
        .await?
        .ok_or("offerer closed signaling before sending offer")?;
    let offer: SignalMsg = serde_json::from_str(&offer_line)?;
    if offer.kind != "offer" {
        return Err(format!("expected offer, got {}", offer.kind).into());
    }
    let rtc_offer = RTCSessionDescription::offer(offer.sdp)?;
    pc.set_remote_description(rtc_offer).await?;

    let answer = pc.create_answer(None).await?;
    pc.set_local_description(answer).await?;
    wait_for_ice_complete(pc.clone()).await;
    let local = pc
        .local_description()
        .await
        .ok_or("no local description after ICE")?;

    let answer_json = serde_json::to_string(&SignalMsg {
        kind: "answer".into(),
        sdp: local.sdp,
    })?;
    writer.write_all(answer_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    // Wait for the data channel to open (ondatachannel → on_open).
    let dc = tokio::time::timeout(Duration::from_secs(5), dc_ready).await??;
    Ok(dc)
}

async fn new_peer_connection(
) -> Result<Arc<RTCPeerConnection>, Box<dyn std::error::Error + Send + Sync>> {
    // No STUN servers on loopback — ICE uses host candidates only.
    let api = APIBuilder::new().build();
    let cfg = RTCConfiguration {
        ice_servers: vec![],
        ..Default::default()
    };
    let pc = Arc::new(api.new_peer_connection(cfg).await?);
    // Log state transitions so the rotation/chat demos can see
    // where a setup stalls (e.g. ICE failed vs DTLS stuck vs
    // data channel never opened).
    pc.on_peer_connection_state_change(Box::new(|s| {
        Box::pin(async move {
            eprintln!("[webrtc] pc state -> {:?}", s);
        })
    }));
    pc.on_ice_connection_state_change(Box::new(|s| {
        Box::pin(async move {
            eprintln!("[webrtc] ice state -> {:?}", s);
        })
    }));
    Ok(pc)
}

/// Offerer-side: create a data channel up-front and wait for
/// its `on_open` event. Returns a receiver for the open Arc.
async fn spawn_data_channel_opener(
    pc: Arc<RTCPeerConnection>,
) -> Result<
    tokio::sync::oneshot::Receiver<Arc<RTCDataChannel>>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let dc = pc.create_data_channel("drift", None).await?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
    let dc_for_open = dc.clone();
    let tx_for_open = tx.clone();
    dc.on_open(Box::new(move || {
        let tx = tx_for_open.clone();
        let dc = dc_for_open.clone();
        Box::pin(async move {
            if let Some(sender) = tx.lock().await.take() {
                let _ = sender.send(dc);
            }
        })
    }));
    Ok(rx)
}

/// Answerer-side: wait for the incoming data channel via
/// `on_data_channel`, then wait for it to open.
fn register_data_channel_opener(
    pc: Arc<RTCPeerConnection>,
) -> tokio::sync::oneshot::Receiver<Arc<RTCDataChannel>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
    pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        let tx = tx.clone();
        Box::pin(async move {
            let dc_for_open = dc.clone();
            let tx_for_open = tx.clone();
            dc.on_open(Box::new(move || {
                let tx = tx_for_open.clone();
                let dc = dc_for_open.clone();
                Box::pin(async move {
                    if let Some(sender) = tx.lock().await.take() {
                        let _ = sender.send(dc);
                    }
                })
            }));
        })
    }));
    rx
}

async fn wait_for_ice_complete(pc: Arc<RTCPeerConnection>) {
    let mut gather = pc.gathering_complete_promise().await;
    let _ = gather.recv().await;
}

// ─── Chat node ──────────────────────────────────────────────

async fn run_chat(
    bind_ip: &str,
    interactive: bool,
    listen_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let my_medium = medium_for(bind_ip);
    let identity = chat_id(bind_ip);
    let me_hex = hex_full(&derive_peer_id(&identity.public_bytes()));

    // Build transport + resolve the bridge addr used for
    // initial peer registration (symbolic for mesh routing —
    // actual delivery goes over the configured adapter).
    let (transport, bridge_addr_symbolic): (Arc<Transport>, SocketAddr) = match bind_ip {
        "127.0.0.1" => (
            Arc::new(
                Transport::bind_with_config(
                    format!("{}:0", bind_ip).parse()?,
                    identity,
                    cfg(),
                )
                .await?,
            ),
            BRIDGE_UDP.parse()?,
        ),
        "127.0.0.2" => {
            let sock = TcpSocket::new_v4()?;
            sock.bind(format!("{}:0", bind_ip).parse()?)?;
            let stream = sock.connect(BRIDGE_TCP.parse()?).await?;
            let io = Arc::new(TcpPacketIO::new(stream)?);
            (
                Arc::new(Transport::bind_with_io(io, identity, cfg()).await?),
                BRIDGE_TCP.parse()?,
            )
        }
        "127.0.0.3" => {
            let sock = TcpSocket::new_v4()?;
            sock.bind(format!("{}:0", bind_ip).parse()?)?;
            let tcp = sock.connect(BRIDGE_WS.parse()?).await?;
            let (ws, _) =
                tokio_tungstenite::client_async(format!("ws://{}/", BRIDGE_WS), tcp).await?;
            let io = Arc::new(WsPacketIO::new(ws, BRIDGE_WS.parse()?));
            (
                Arc::new(Transport::bind_with_io(io, identity, cfg()).await?),
                BRIDGE_WS.parse()?,
            )
        }
        "127.0.0.4" => {
            println!("[chat/127.0.0.4 WebRTC] running SDP exchange with bridge...");
            let dc = connect_webrtc_peer(BRIDGE_RTC_SIGNALING)
                .await
                .map_err(|e| format!("WebRTC setup: {}", e))?;
            let io = Arc::new(WebRTCPacketIO::new(dc, BRIDGE_RTC_SIGNALING.parse()?));
            (
                Arc::new(Transport::bind_with_io(io, identity, cfg()).await?),
                BRIDGE_RTC_SIGNALING.parse()?,
            )
        }
        other => return Err(format!("unsupported chat bind IP: {}", other).into()),
    };

    println!(
        "[chat/{} {}] peer_id={}",
        bind_ip,
        my_medium,
        &me_hex[..12]
    );

    let bridge_pub = bridge_id().public_bytes();
    let bridge_pid = derive_peer_id(&bridge_pub);
    transport
        .add_peer(bridge_pub, bridge_addr_symbolic, Direction::Initiator)
        .await?;
    let mut peers: Vec<(String, [u8; 8])> = Vec::new();
    for ip in CHAT_IPS {
        if ip == bind_ip {
            continue;
        }
        let pub_bytes = chat_id(ip).public_bytes();
        let pid = derive_peer_id(&pub_bytes);
        transport
            .add_peer(pub_bytes, bridge_addr_symbolic, Direction::Initiator)
            .await?;
        peers.push((ip.to_string(), pid));
    }

    transport.send_data(&bridge_pid, b"warmup", 0, 0).await?;
    tokio::time::sleep(Duration::from_millis(1000)).await;

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
        bind_ip, m.handshakes_completed, m.handshake_retries, m.unknown_peer_drops
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
        "[{}] interactive. commands: `all <text>` | `.1|.2|.3|.4 <text>` | `who` | `quit`",
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
        let (prefix, rest) = line.split_once(' ').unwrap_or((line, ""));
        let targets: Vec<&(String, [u8; 8])> = match prefix {
            "all" => peers.iter().collect(),
            ".1" => peers.iter().filter(|(ip, _)| ip == "127.0.0.1").collect(),
            ".2" => peers.iter().filter(|(ip, _)| ip == "127.0.0.2").collect(),
            ".3" => peers.iter().filter(|(ip, _)| ip == "127.0.0.3").collect(),
            ".4" => peers.iter().filter(|(ip, _)| ip == "127.0.0.4").collect(),
            _ => {
                println!("  ? unknown command (`all <text>` | `.1|.2|.3|.4 <text>` | `who` | `quit`)");
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
