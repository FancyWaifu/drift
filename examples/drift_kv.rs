//! drift-kv: a Redis-compatible mini-KV store over DRIFT.
//!
//! Port of the Tokio team's mini-redis (MIT, https://github.com/tokio-rs/mini-redis)
//! — specifically its wire protocol (Redis RESP) and command
//! surface (PING / SET / GET / DEL) — swapping its raw-TCP
//! transport for DRIFT. The server doubles as the DRIFT bridge,
//! listening on UDP / TCP / WebSocket / WebRTC so clients from
//! any of the four mediums can hit the same KV state by peer_id.
//!
//! Wire format is verbatim Redis RESP:
//!
//!   *3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n  ← request
//!   +OK\r\n                                        ← response
//!   $3\r\nbar\r\n                                  ← GET hit
//!   $-1\r\n                                        ← GET miss / null
//!   :1\r\n                                         ← DEL count
//!
//! Each request and response rides as one DRIFT DATA payload —
//! no streaming, no framing beyond what RESP already provides.
//!
//! Usage:
//!   drift-kv server               # runs both bridge + KV store
//!   drift-kv client <bind_ip> <CMD> [args...]
//!     PING
//!     SET <key> <value>
//!     GET <key>
//!     DEL <key>

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::io::{TcpPacketIO, WebRTCPacketIO, WsPacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Mutex;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

const SERVER_UDP: &str = "127.0.0.1:9400";
const SERVER_TCP: &str = "127.0.0.1:9401";
const SERVER_WS: &str = "127.0.0.1:9402";
const SERVER_RTC_SIG: &str = "127.0.0.1:9403";

const CLIENT_IPS: [&str; 4] = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"];

fn server_id() -> Identity {
    // 0x4B = 'K' for KV store.
    Identity::from_secret_bytes([0x4B; 32])
}

fn client_id(ip: &str) -> Identity {
    let mut seed = [0u8; 32];
    seed[0] = 0xC1;
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
    match args.get(1).map(String::as_str).unwrap_or("") {
        "server" => run_server().await,
        "client" => {
            let bind_ip = args.get(2).ok_or("client <bind_ip> <cmd>...")?.clone();
            if !CLIENT_IPS.contains(&bind_ip.as_str()) {
                return Err(format!("unsupported bind IP: {}", bind_ip).into());
            }
            if args.len() < 4 {
                return Err("client <bind_ip> <cmd> [args...]".into());
            }
            run_client(&bind_ip, &args[3..]).await
        }
        _ => {
            eprintln!("usage:\n  drift-kv server\n  drift-kv client <127.0.0.{{1,2,3,4}}> <CMD> [args...]");
            std::process::exit(2);
        }
    }
}

// ─── RESP codec ──────────────────────────────────────────────
//
// A faithful-enough subset of Redis Serialization Protocol.
// Enough to parse client commands (always arrays of bulk
// strings) and emit all four response types we need:
// simple string, integer, bulk, null-bulk.

#[derive(Debug, Clone)]
enum Resp {
    Simple(String),
    Bulk(Option<Vec<u8>>),
    Integer(i64),
    Array(Vec<Resp>),
    Error(String),
}

impl Resp {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Resp::Simple(s) => {
                out.push(b'+');
                out.extend_from_slice(s.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            Resp::Error(s) => {
                out.push(b'-');
                out.extend_from_slice(s.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            Resp::Integer(n) => {
                out.push(b':');
                out.extend_from_slice(n.to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            Resp::Bulk(None) => out.extend_from_slice(b"$-1\r\n"),
            Resp::Bulk(Some(b)) => {
                out.push(b'$');
                out.extend_from_slice(b.len().to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(b);
                out.extend_from_slice(b"\r\n");
            }
            Resp::Array(items) => {
                out.push(b'*');
                out.extend_from_slice(items.len().to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
                for item in items {
                    item.encode_into(out);
                }
            }
        }
    }

    fn parse(buf: &[u8]) -> Result<(Resp, usize), String> {
        if buf.is_empty() {
            return Err("empty".into());
        }
        let (body, line_len) = read_line(buf).ok_or("missing CRLF")?;
        match buf[0] {
            b'+' => Ok((Resp::Simple(String::from_utf8_lossy(body).into()), line_len)),
            b'-' => Ok((Resp::Error(String::from_utf8_lossy(body).into()), line_len)),
            b':' => {
                let n: i64 = std::str::from_utf8(body)
                    .map_err(|e| e.to_string())?
                    .parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())?;
                Ok((Resp::Integer(n), line_len))
            }
            b'$' => {
                let n: i64 = std::str::from_utf8(body)
                    .map_err(|e| e.to_string())?
                    .parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())?;
                if n < 0 {
                    return Ok((Resp::Bulk(None), line_len));
                }
                let n = n as usize;
                let start = line_len;
                if buf.len() < start + n + 2 {
                    return Err("short bulk".into());
                }
                let data = buf[start..start + n].to_vec();
                Ok((Resp::Bulk(Some(data)), start + n + 2))
            }
            b'*' => {
                let n: i64 = std::str::from_utf8(body)
                    .map_err(|e| e.to_string())?
                    .parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())?;
                let mut offset = line_len;
                let mut items = Vec::with_capacity(n.max(0) as usize);
                for _ in 0..n.max(0) {
                    let (item, consumed) = Resp::parse(&buf[offset..])?;
                    items.push(item);
                    offset += consumed;
                }
                Ok((Resp::Array(items), offset))
            }
            b => Err(format!("unknown RESP tag: {}", b as char)),
        }
    }
}

fn read_line(buf: &[u8]) -> Option<(&[u8], usize)> {
    // body between [1..end-1], return (body, total_consumed_including_CRLF)
    for i in 1..buf.len().saturating_sub(1) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some((&buf[1..i], i + 2));
        }
    }
    None
}

fn build_command(parts: &[&[u8]]) -> Vec<u8> {
    let items: Vec<Resp> = parts.iter().map(|b| Resp::Bulk(Some(b.to_vec()))).collect();
    Resp::Array(items).encode()
}

// ─── Server ──────────────────────────────────────────────────

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let transport =
        Arc::new(Transport::bind_with_config(SERVER_UDP.parse()?, server_id(), cfg()).await?);
    let pid = hex8(&derive_peer_id(&server_id().public_bytes()));
    println!("[kv] UDP iface 0 on {} peer_id={}", SERVER_UDP, pid);

    let tcp_listener = TcpListener::bind(SERVER_TCP).await?;
    println!("[kv] TCP listening on {}", SERVER_TCP);
    let t = transport.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((s, addr)) = tcp_listener.accept().await {
                if let Ok(io) = TcpPacketIO::new(s) {
                    let idx = t.add_interface("tcp", Arc::new(io));
                    println!("[kv] TCP iface {} wired (peer {})", idx, addr);
                }
            }
        }
    });

    let ws_listener = TcpListener::bind(SERVER_WS).await?;
    println!("[kv] WS listening on {}", SERVER_WS);
    let t = transport.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((s, addr)) = ws_listener.accept().await {
                if let Ok(ws) = tokio_tungstenite::accept_async(s).await {
                    let idx = t.add_interface("ws", Arc::new(WsPacketIO::new(ws, addr)));
                    println!("[kv] WS iface {} wired (peer {})", idx, addr);
                }
            }
        }
    });

    let rtc_listener = TcpListener::bind(SERVER_RTC_SIG).await?;
    println!("[kv] WebRTC signaling listening on {}", SERVER_RTC_SIG);
    let t = transport.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((s, addr)) = rtc_listener.accept().await {
                let t = t.clone();
                tokio::spawn(async move {
                    match accept_webrtc_peer(s).await {
                        Ok(dc) => {
                            let io = Arc::new(WebRTCPacketIO::new(dc, addr));
                            let idx = t.add_interface("webrtc", io);
                            println!("[kv] WebRTC iface {} wired (peer {})", idx, addr);
                        }
                        Err(e) => eprintln!("[kv] WebRTC setup failed for {}: {}", addr, e),
                    }
                });
            }
        }
    });

    // KV state.
    let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    println!("[kv] ready; waiting for commands...");

    let deadline = Instant::now() + Duration::from_secs(3600);
    while Instant::now() < deadline {
        let pkt = match tokio::time::timeout(Duration::from_millis(500), transport.recv()).await {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(_) => continue,
        };
        if pkt.payload == b"warmup" || pkt.payload.is_empty() {
            continue;
        }
        let reply = match Resp::parse(&pkt.payload) {
            Ok((Resp::Array(items), _)) => handle_command(&store, &items).await,
            Ok(_) => Resp::Error("ERR expected command array".into()),
            Err(e) => Resp::Error(format!("ERR parse: {}", e)),
        };
        let summary = summarize_command(&pkt.payload);
        println!(
            "[kv] from peer={} {} -> {}",
            hex8(&pkt.peer_id),
            summary,
            summarize_reply(&reply)
        );
        let wire = reply.encode();
        if let Err(e) = transport.send_data(&pkt.peer_id, &wire, 0, 0).await {
            eprintln!("[kv] send_data failed: {}", e);
        }
    }
    Ok(())
}

async fn handle_command(store: &Arc<Mutex<HashMap<String, Vec<u8>>>>, items: &[Resp]) -> Resp {
    if items.is_empty() {
        return Resp::Error("ERR empty command".into());
    }
    let argv: Vec<&[u8]> = items
        .iter()
        .filter_map(|x| match x {
            Resp::Bulk(Some(b)) => Some(b.as_slice()),
            _ => None,
        })
        .collect();
    if argv.len() != items.len() {
        return Resp::Error("ERR non-bulk argument".into());
    }
    let name = std::str::from_utf8(argv[0])
        .unwrap_or("")
        .to_ascii_uppercase();
    match name.as_str() {
        "PING" => Resp::Simple("PONG".into()),
        "SET" if argv.len() == 3 => {
            let key = String::from_utf8_lossy(argv[1]).into_owned();
            store.lock().await.insert(key, argv[2].to_vec());
            Resp::Simple("OK".into())
        }
        "GET" if argv.len() == 2 => {
            let key = String::from_utf8_lossy(argv[1]).into_owned();
            match store.lock().await.get(&key) {
                Some(v) => Resp::Bulk(Some(v.clone())),
                None => Resp::Bulk(None),
            }
        }
        "DEL" if argv.len() >= 2 => {
            let mut n: i64 = 0;
            let mut s = store.lock().await;
            for arg in &argv[1..] {
                let key = String::from_utf8_lossy(arg).into_owned();
                if s.remove(&key).is_some() {
                    n += 1;
                }
            }
            Resp::Integer(n)
        }
        _ => Resp::Error(format!("ERR unknown or malformed command: {}", name)),
    }
}

fn summarize_command(buf: &[u8]) -> String {
    match Resp::parse(buf) {
        Ok((Resp::Array(items), _)) => {
            let parts: Vec<String> = items
                .iter()
                .map(|x| match x {
                    Resp::Bulk(Some(b)) => String::from_utf8_lossy(b).into_owned(),
                    other => format!("{:?}", other),
                })
                .collect();
            parts.join(" ")
        }
        _ => "?malformed".into(),
    }
}

fn summarize_reply(r: &Resp) -> String {
    match r {
        Resp::Simple(s) => format!("+{}", s),
        Resp::Error(s) => format!("-{}", s),
        Resp::Integer(n) => format!(":{}", n),
        Resp::Bulk(None) => "(nil)".into(),
        Resp::Bulk(Some(b)) => format!("\"{}\"", String::from_utf8_lossy(b)),
        Resp::Array(_) => "(array)".into(),
    }
}

// ─── Client ──────────────────────────────────────────────────

async fn run_client(bind_ip: &str, cmd_argv: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let medium = medium_for(bind_ip);
    let identity = client_id(bind_ip);

    let (transport, server_addr_symbolic): (Arc<Transport>, SocketAddr) = match bind_ip {
        "127.0.0.1" => (
            Arc::new(
                Transport::bind_with_config(format!("{}:0", bind_ip).parse()?, identity, cfg())
                    .await?,
            ),
            SERVER_UDP.parse()?,
        ),
        "127.0.0.2" => {
            let sock = TcpSocket::new_v4()?;
            sock.bind(format!("{}:0", bind_ip).parse()?)?;
            let stream = sock.connect(SERVER_TCP.parse()?).await?;
            let io = Arc::new(TcpPacketIO::new(stream)?);
            (
                Arc::new(Transport::bind_with_io(io, identity, cfg()).await?),
                SERVER_TCP.parse()?,
            )
        }
        "127.0.0.3" => {
            let sock = TcpSocket::new_v4()?;
            sock.bind(format!("{}:0", bind_ip).parse()?)?;
            let tcp = sock.connect(SERVER_WS.parse()?).await?;
            let (ws, _) =
                tokio_tungstenite::client_async(format!("ws://{}/", SERVER_WS), tcp).await?;
            let io = Arc::new(WsPacketIO::new(ws, SERVER_WS.parse()?));
            (
                Arc::new(Transport::bind_with_io(io, identity, cfg()).await?),
                SERVER_WS.parse()?,
            )
        }
        "127.0.0.4" => {
            let dc = connect_webrtc_peer(SERVER_RTC_SIG)
                .await
                .map_err(|e| format!("WebRTC setup: {}", e))?;
            let io = Arc::new(WebRTCPacketIO::new(dc, SERVER_RTC_SIG.parse()?));
            (
                Arc::new(Transport::bind_with_io(io, identity, cfg()).await?),
                SERVER_RTC_SIG.parse()?,
            )
        }
        _ => unreachable!(),
    };

    let server_pub = server_id().public_bytes();
    let server_pid = derive_peer_id(&server_pub);
    transport
        .add_peer(server_pub, server_addr_symbolic, Direction::Initiator)
        .await?;
    transport.send_data(&server_pid, b"warmup", 0, 0).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Build RESP command from argv.
    let byte_parts: Vec<Vec<u8>> = cmd_argv.iter().map(|s| s.as_bytes().to_vec()).collect();
    let part_refs: Vec<&[u8]> = byte_parts.iter().map(|v| v.as_slice()).collect();
    let wire = build_command(&part_refs);
    let human = cmd_argv.join(" ");

    transport.send_data(&server_pid, &wire, 0, 0).await?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), transport.recv()).await {
            Ok(Some(pkt)) => {
                if pkt.peer_id != server_pid {
                    continue;
                }
                match Resp::parse(&pkt.payload) {
                    Ok((r, _)) => {
                        println!(
                            "[client/{} {}] {} -> {}",
                            bind_ip,
                            medium,
                            human,
                            summarize_reply(&r)
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        println!(
                            "[client/{} {}] {} -> (parse error: {})",
                            bind_ip, medium, human, e
                        );
                        return Ok(());
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
    println!("[client/{} {}] {} -> TIMEOUT", bind_ip, medium, human);
    std::process::exit(1);
}

// ─── WebRTC signaling (same as drift-chat) ──────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct SignalMsg {
    kind: String,
    sdp: String,
}

async fn accept_webrtc_peer(
    stream: TcpStream,
) -> Result<Arc<RTCDataChannel>, Box<dyn std::error::Error + Send + Sync>> {
    let pc = new_peer_connection().await?;
    let dc_ready = spawn_data_channel_opener(pc.clone()).await?;
    let offer = pc.create_offer(None).await?;
    pc.set_local_description(offer).await?;
    wait_for_ice_complete(pc.clone()).await;
    let local = pc.local_description().await.ok_or("no local description")?;
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
        .ok_or("answerer closed before replying")?;
    let answer: SignalMsg = serde_json::from_str(&answer_line)?;
    let rtc_answer = RTCSessionDescription::answer(answer.sdp)?;
    pc.set_remote_description(rtc_answer).await?;
    let dc = tokio::time::timeout(Duration::from_secs(20), dc_ready).await??;
    Ok(dc)
}

async fn connect_webrtc_peer(
    signaling_addr: &str,
) -> Result<Arc<RTCDataChannel>, Box<dyn std::error::Error + Send + Sync>> {
    let stream = TcpStream::connect(signaling_addr).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader).lines();
    let pc = new_peer_connection().await?;
    let dc_ready = register_data_channel_opener(pc.clone());
    let offer_line = reader
        .next_line()
        .await?
        .ok_or("offerer closed before sending offer")?;
    let offer: SignalMsg = serde_json::from_str(&offer_line)?;
    let rtc_offer = RTCSessionDescription::offer(offer.sdp)?;
    pc.set_remote_description(rtc_offer).await?;
    let answer = pc.create_answer(None).await?;
    pc.set_local_description(answer).await?;
    wait_for_ice_complete(pc.clone()).await;
    let local = pc.local_description().await.ok_or("no local description")?;
    let answer_json = serde_json::to_string(&SignalMsg {
        kind: "answer".into(),
        sdp: local.sdp,
    })?;
    writer.write_all(answer_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    let dc = tokio::time::timeout(Duration::from_secs(20), dc_ready).await??;
    Ok(dc)
}

async fn new_peer_connection(
) -> Result<Arc<RTCPeerConnection>, Box<dyn std::error::Error + Send + Sync>> {
    let api = APIBuilder::new().build();
    let cfg = RTCConfiguration {
        ice_servers: vec![],
        ..Default::default()
    };
    Ok(Arc::new(api.new_peer_connection(cfg).await?))
}

async fn spawn_data_channel_opener(
    pc: Arc<RTCPeerConnection>,
) -> Result<
    tokio::sync::oneshot::Receiver<Arc<RTCDataChannel>>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let dc = pc.create_data_channel("drift-kv", None).await?;
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

fn hex8(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{:02x}", x)).collect()
}
