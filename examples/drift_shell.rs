//! drift-shell: a tiny command server reachable over DRIFT.
//!
//! Three roles share one binary:
//!
//!   bridge  — stable rendezvous. UDP on 127.0.0.1:9100. Never moves.
//!   server  — handles requests. Identity fixed across rotations;
//!             source IP can be any of 127.0.0.1 / .2 / .3.
//!   client  — opens a DRIFT session, sends one command, prints
//!             the reply, exits. Addresses server by peer_id.
//!
//! The point of the rotation demo: clients NEVER learn the server's
//! current IP. They only know its peer_id (a hash of its pubkey). As
//! long as the bridge can mesh-route to wherever the server currently
//! lives, clients keep working when the server moves.
//!
//! Persistent state:
//!   /tmp/drift-shell-counter  — increments on `count` command,
//!                               survives server rotations.
//!
//! Commands (newline-terminated, one per request):
//!   time         — server wall clock (RFC 3339)
//!   uptime       — seconds since THIS server process started
//!   rotations    — how many times the server has rotated (from --rotation)
//!   count        — increment & return persistent counter
//!   whoami       — server peer_id hex (same across rotations — that's the point)
//!   ip           — server's bind IP this run
//!   echo <rest>  — echo the rest of the line
//!   help         — list commands
//!
//! Usage:
//!   drift-shell bridge
//!   drift-shell server <bind_ip> [--rotation N]
//!   drift-shell client <bind_ip> <cmd...>

use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const BRIDGE_ADDR: &str = "127.0.0.1:9100";
const COUNTER_PATH: &str = "/tmp/drift-shell-counter";
const CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_CONVERGENCE_WAIT: Duration = Duration::from_millis(600);

fn bridge_id() -> Identity {
    Identity::from_secret_bytes([0xBB; 32])
}

// Identity derived from a role tag + IP string. Lets the demo
// give each local IP its own stable server and client identities
// without any runtime key exchange — both sides of a request can
// compute the same peer_id from the same inputs.
fn identity_for(role: u8, ip: &str) -> Identity {
    let mut seed = [0u8; 32];
    seed[0] = role;
    let bytes = ip.as_bytes();
    for (i, b) in bytes.iter().take(30).enumerate() {
        seed[i + 1] = *b;
    }
    Identity::from_secret_bytes(seed)
}

fn server_id_for(ip: &str) -> Identity {
    identity_for(0x55, ip)
}
fn client_id_for(ip: &str) -> Identity {
    identity_for(0xC1, ip)
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
    let role = args.get(1).map(String::as_str).unwrap_or("");
    match role {
        "bridge" => run_bridge().await,
        "server" => {
            let bind = args.get(2).ok_or("server <bind_ip>")?.to_string();
            let rotation = find_flag_u64(&args, "--rotation").unwrap_or(0);
            run_server(&bind, rotation as u32).await
        }
        "client" => {
            // client <bind_ip> --target <ip>  <cmd...>
            // client <bind_ip> --any              <cmd...>   (iterates known server IPs)
            let bind = args
                .get(2)
                .ok_or("client <bind_ip> --target <ip>|--any <cmd...>")?
                .to_string();
            let mode_flag = args.get(3).map(String::as_str).unwrap_or("");
            let (targets, cmd_start) = match mode_flag {
                "--target" => {
                    let t = args.get(4).ok_or("--target <ip>")?.to_string();
                    (vec![t], 5)
                }
                "--any" => (
                    vec!["127.0.0.1".into(), "127.0.0.2".into(), "127.0.0.3".into()],
                    4,
                ),
                _ => return Err("expected --target <ip> or --any".into()),
            };
            if args.len() <= cmd_start {
                return Err("missing command".into());
            }
            let cmd = args[cmd_start..].join(" ");
            run_client(&bind, &targets, &cmd).await
        }
        _ => {
            eprintln!("usage: drift-shell <bridge|server|client> ...");
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
    let bridge =
        Arc::new(Transport::bind_with_config(BRIDGE_ADDR.parse()?, bridge_id(), cfg()).await?);
    let pid = hex8(&derive_peer_id(&bridge_id().public_bytes()));
    println!("[bridge] UDP on {} peer_id={}", BRIDGE_ADDR, pid);

    // Passive — bridge doesn't process requests, it just forwards
    // packets between its peers via the mesh routing table. We
    // drain recv() so warmup packets don't back up the channel.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(600) {
        match tokio::time::timeout(Duration::from_millis(500), bridge.recv()).await {
            Ok(Some(pkt)) => {
                if pkt.payload != b"warmup" {
                    println!(
                        "[bridge] unexpected direct packet from peer={} ({}B)",
                        hex8(&pkt.peer_id),
                        pkt.payload.len()
                    );
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
    let m = bridge.metrics();
    println!(
        "[bridge] exit: handshakes={} forwarded={} unknown_peer_drops={} auth_failures={}",
        m.handshakes_completed, m.forwarded, m.unknown_peer_drops, m.auth_failures
    );
    Ok(())
}

struct ServerState {
    start: Instant,
    rotation: u32,
    bind_ip: String,
}

impl ServerState {
    fn uptime_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
}

async fn run_server(bind_ip: &str, rotation: u32) -> Result<(), Box<dyn std::error::Error>> {
    let identity = server_id_for(bind_ip);
    let my_pid_hex = hex_full(&derive_peer_id(&identity.public_bytes()));
    let bind_addr: SocketAddr = format!("{}:0", bind_ip).parse()?;
    let transport = Arc::new(Transport::bind_with_config(bind_addr, identity, cfg()).await?);
    let local = transport.local_addr()?;
    println!(
        "[server] bind={} rotation={} peer_id={}",
        local,
        rotation,
        &my_pid_hex[..12]
    );

    let bridge_pub = bridge_id().public_bytes();
    let bridge_pid = derive_peer_id(&bridge_pub);
    transport
        .add_peer(bridge_pub, BRIDGE_ADDR.parse()?, Direction::Initiator)
        .await?;

    // Warm up the handshake with the bridge.
    transport.send_data(&bridge_pid, b"warmup", 0, 0).await?;

    let state = Arc::new(Mutex::new(ServerState {
        start: Instant::now(),
        rotation,
        bind_ip: bind_ip.to_string(),
    }));

    println!("[server] ready; waiting for requests...");

    let deadline = Instant::now() + Duration::from_secs(600);
    while Instant::now() < deadline {
        let pkt = match tokio::time::timeout(Duration::from_millis(500), transport.recv()).await {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(_) => continue,
        };
        // Skip our own warmup reply (comes from bridge) and ignore empty.
        if pkt.peer_id == bridge_pid || pkt.payload.is_empty() {
            continue;
        }
        let req = String::from_utf8_lossy(&pkt.payload).to_string();
        let resp = {
            let mut s = state.lock().await;
            process_command(&req, &mut s, &my_pid_hex)
        };
        println!(
            "[server] req from peer={} cmd={:?} -> {:?}",
            hex8(&pkt.peer_id),
            req.trim(),
            resp.trim_end()
        );
        if let Err(e) = transport
            .send_data(&pkt.peer_id, resp.as_bytes(), 0, 0)
            .await
        {
            eprintln!("[server] send_data failed: {}", e);
        }
    }
    Ok(())
}

fn process_command(line: &str, state: &mut ServerState, my_pid_hex: &str) -> String {
    let line = line.trim();
    let mut parts = line.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim();
    match cmd {
        "time" => {
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("unix={}\n", t)
        }
        "uptime" => format!("{}s\n", state.uptime_secs()),
        "rotations" => format!("{}\n", state.rotation),
        "count" => {
            let n = bump_counter();
            format!("{}\n", n)
        }
        "whoami" => format!("{}\n", my_pid_hex),
        "ip" => format!("{}\n", state.bind_ip),
        "echo" => format!("{}\n", rest),
        "help" => "time, uptime, rotations, count, whoami, ip, echo <msg>, help\n".into(),
        "" => "".into(),
        other => format!("unknown command: {}\n", other),
    }
}

fn bump_counter() -> u64 {
    let current: u64 = std::fs::read_to_string(COUNTER_PATH)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let next = current + 1;
    let _ = std::fs::write(COUNTER_PATH, format!("{}\n", next));
    next
}

async fn run_client(
    bind_ip: &str,
    targets: &[String],
    cmd: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = client_id_for(bind_ip);
    let bind_addr: SocketAddr = format!("{}:0", bind_ip).parse()?;
    let transport = Arc::new(Transport::bind_with_config(bind_addr, identity, cfg()).await?);
    let bridge_pub = bridge_id().public_bytes();
    let bridge_pid = derive_peer_id(&bridge_pub);

    transport
        .add_peer(bridge_pub, BRIDGE_ADDR.parse()?, Direction::Initiator)
        .await?;

    // Register every candidate target so we can address each by peer_id.
    let mut target_pids: Vec<(String, [u8; 8])> = Vec::with_capacity(targets.len());
    for ip in targets {
        let pub_bytes = server_id_for(ip).public_bytes();
        let pid = derive_peer_id(&pub_bytes);
        transport
            .add_peer(pub_bytes, BRIDGE_ADDR.parse()?, Direction::Initiator)
            .await?;
        target_pids.push((ip.clone(), pid));
    }

    // Handshake with the bridge and let beacons converge.
    transport.send_data(&bridge_pid, b"warmup", 0, 0).await?;
    tokio::time::sleep(CLIENT_CONVERGENCE_WAIT).await;

    // Fire the command at every candidate target. Only the one
    // whose server is currently running will reply.
    for (_, pid) in &target_pids {
        let _ = transport.send_data(pid, cmd.as_bytes(), 0, 0).await;
    }

    // Collect replies until we've heard from every live server
    // or the deadline fires.
    let deadline = Instant::now() + CLIENT_RESPONSE_TIMEOUT;
    let mut heard: Vec<String> = Vec::new();
    while Instant::now() < deadline && heard.len() < target_pids.len() {
        match tokio::time::timeout(Duration::from_millis(200), transport.recv()).await {
            Ok(Some(pkt)) => {
                if let Some((ip, _)) = target_pids.iter().find(|(_, p)| *p == pkt.peer_id) {
                    let resp = String::from_utf8_lossy(&pkt.payload);
                    let resp = resp.trim_end_matches('\n');
                    println!("[client/{}] target={} -> {}", bind_ip, ip, resp);
                    heard.push(ip.clone());
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
    let silent: Vec<_> = target_pids
        .iter()
        .filter(|(ip, _)| !heard.contains(ip))
        .map(|(ip, _)| ip.as_str())
        .collect();
    if !silent.is_empty() {
        println!("[client/{}] silent: {}", bind_ip, silent.join(", "));
    }
    Ok(())
}

fn hex8(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{:02x}", x)).collect()
}
fn hex_full(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
