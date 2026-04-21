use super::identity::{from_hex, hex, load_identity};
use super::{expand_path, ListenArgs, TransportPreset};
use drift::identity::Identity;
use drift::io::{TcpPacketIO, WsPacketIO};
use drift::streams::{Stream, StreamManager};
use drift::{Direction, Transport, TransportConfig};
use anyhow::{bail, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;

pub async fn run(args: &ListenArgs, identity_path: &str) -> Result<()> {
    let secret = load_identity(&expand_path(identity_path))?;
    let id = Identity::from_secret_bytes(secret);

    let accept_any = args.accept_any || args.peers.is_empty();

    let mut config = match args.preset {
        TransportPreset::Default => TransportConfig::default(),
        TransportPreset::Iot => TransportConfig::iot(),
        TransportPreset::Realtime => TransportConfig::realtime(),
    };
    config.accept_any_peer = accept_any;

    // Bind UDP as the primary interface.
    let transport: Arc<Transport> = Arc::new(
        Transport::bind_with_config(args.bind, id, config).await?,
    );
    let base_port = args.bind.port();

    eprintln!("adapters:");
    eprintln!("  [1] UDP  {}", transport.local_addr()?);

    // Bind TCP on base_port + 1.
    let tcp_addr: std::net::SocketAddr =
        format!("{}:{}", args.bind.ip(), base_port + 1).parse()?;
    let tcp_listener = TcpListener::bind(tcp_addr).await?;
    let tcp_local = tcp_listener.local_addr()?;
    eprintln!("  [2] TCP  {}", tcp_local);

    // Spawn TCP acceptor — each incoming TCP connection becomes
    // a new PacketIO interface on the transport.
    let transport_tcp = transport.clone();
    tokio::spawn(async move {
        let mut tcp_count = 0u32;
        loop {
            let (stream, peer_addr) = match tcp_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("tcp accept error: {}", e);
                    continue;
                }
            };
            tcp_count += 1;
            let name = format!("tcp-{}", tcp_count);
            match TcpPacketIO::new(stream) {
                Ok(io) => {
                    transport_tcp.add_interface(&name, Arc::new(io));
                    eprintln!("  [tcp] accepted connection from {}", peer_addr);
                }
                Err(e) => eprintln!("tcp io error: {}", e),
            }
        }
    });

    // Bind WebSocket on base_port + 2.
    let ws_addr: std::net::SocketAddr =
        format!("{}:{}", args.bind.ip(), base_port + 2).parse()?;
    let ws_listener = TcpListener::bind(ws_addr).await?;
    let ws_local = ws_listener.local_addr()?;
    eprintln!("  [3] WS   {}", ws_local);

    // Spawn WebSocket acceptor.
    let transport_ws = transport.clone();
    tokio::spawn(async move {
        let mut ws_count = 0u32;
        loop {
            let (tcp_stream, peer_addr) = match ws_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ws accept error: {}", e);
                    continue;
                }
            };
            ws_count += 1;
            let name = format!("ws-{}", ws_count);
            match tokio_tungstenite::accept_async(tcp_stream).await {
                Ok(ws) => {
                    transport_ws.add_interface(
                        &name,
                        Arc::new(WsPacketIO::new(ws, peer_addr)),
                    );
                    eprintln!("  [ws] accepted connection from {}", peer_addr);
                }
                Err(e) => eprintln!("ws upgrade error: {}", e),
            }
        }
    });

    eprintln!("");
    eprintln!("peer_id:    {}", hex(&transport.local_peer_id()));
    eprintln!("public_key: {}", hex(&transport.local_public()));

    if accept_any && args.peers.is_empty() {
        eprintln!("accepting connections from any peer (use --peer to restrict)");
    }

    for peer_hex in &args.peers {
        let pub_bytes = from_hex(peer_hex)?;
        if pub_bytes.len() != 32 {
            bail!("--peer must be 64 hex chars (32 bytes)");
        }
        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&pub_bytes);
        transport
            .add_peer(pub_key, "0.0.0.0:0".parse()?, Direction::Responder)
            .await?;
    }

    // StreamManager takes over transport recv. All data flows
    // through it: datagrams for messages, streams for files.
    let sm = StreamManager::bind(transport.clone()).await;

    let sm_accept = sm.clone();
    let output_dir = args.output_dir.clone();

    // Stream acceptor for file receives.
    tokio::spawn(async move {
        loop {
            let stream: Stream = match sm_accept.accept().await {
                Some(s) => s,
                None => break,
            };
            let dir = output_dir.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_stream(stream, dir.as_deref()).await {
                    eprintln!("stream error: {}", e);
                }
            });
        }
    });

    // Datagram + Ctrl-C loop.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            dgram = sm.recv_datagram() => {
                match dgram {
                    Some((peer, data)) => {
                        if let Ok(text) = std::str::from_utf8(&data) {
                            eprintln!("[from {}] {} bytes", hex(&peer), data.len());
                            println!("{}", text);
                        } else {
                            eprintln!("[from {}] {} bytes (binary)", hex(&peer), data.len());
                            println!("{}", hex(&data));
                        }
                    }
                    None => break,
                }
            }
            _ = &mut ctrl_c => {
                eprintln!("\nshutting down...");
                break;
            }
        }
    }

    let m = transport.metrics();
    eprintln!(
        "metrics: pkts_tx={} pkts_rx={} hs={} auth_fail={}",
        m.packets_sent, m.packets_received, m.handshakes_completed, m.auth_failures
    );
    Ok(())
}

async fn handle_stream(stream: Stream, output_dir: Option<&Path>) -> Result<()> {
    let peer = stream.peer();

    let header: Vec<u8> = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.recv(),
    )
    .await
    {
        Ok(Some(data)) => data,
        _ => bail!("stream closed before header"),
    };

    let (filename, has_header) = if header.len() >= 2 {
        let name_len = u16::from_be_bytes([header[0], header[1]]) as usize;
        if header.len() >= 2 + name_len && name_len > 0 {
            let name = String::from_utf8_lossy(&header[2..2 + name_len]).to_string();
            (name, true)
        } else {
            ("stream_data".to_string(), false)
        }
    } else {
        ("stream_data".to_string(), false)
    };

    eprintln!("[stream from {}] receiving '{}'", hex(&peer), filename);

    let mut data = Vec::new();
    if !has_header {
        data.extend_from_slice(&header);
    }

    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.recv()).await {
            Ok(Some(chunk)) => data.extend_from_slice(&chunk),
            _ => break,
        }
    }

    if let Some(dir) = output_dir {
        std::fs::create_dir_all(dir)?;
        let safe_name = Path::new(&filename)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed".to_string());
        let out_path = dir.join(&safe_name);
        std::fs::write(&out_path, &data)?;
        eprintln!("saved {} bytes to {}", data.len(), out_path.display());
    } else if let Ok(text) = std::str::from_utf8(&data) {
        println!("{}", text);
    } else {
        eprintln!("received {} bytes (binary)", data.len());
    }

    Ok(())
}
