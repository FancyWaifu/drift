use super::identity::{from_hex, hex, load_identity};
use super::{expand_path, SendArgs};
use drift::crypto::derive_peer_id;
use drift::identity::Identity;
use drift::io::{TcpPacketIO, WsPacketIO};
use drift::streams::StreamManager;
use drift::{Direction, Transport, TransportConfig};
use anyhow::{bail, Context, Result};
use std::sync::Arc;

pub async fn run(args: &SendArgs, identity_path: &str) -> Result<()> {
    let secret = load_identity(&expand_path(identity_path))?;
    let id = Identity::from_secret_bytes(secret);

    let peer_pub_bytes = from_hex(&args.peer_key)?;
    if peer_pub_bytes.len() != 32 {
        bail!("--peer-key must be 64 hex chars (32 bytes), got {}", peer_pub_bytes.len());
    }
    let mut peer_pub = [0u8; 32];
    peer_pub.copy_from_slice(&peer_pub_bytes);
    let peer_id = derive_peer_id(&peer_pub);

    let config = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };

    let adapter_name = match args.adapter {
        1 => "UDP",
        2 => "TCP",
        3 => "WebSocket",
        n => bail!("unknown adapter {}: use 1=UDP, 2=TCP, 3=WebSocket", n),
    };

    let transport: Arc<Transport> = match args.adapter {
        1 => {
            // UDP (default).
            Arc::new(Transport::bind_with_config(args.bind, id, config).await?)
        }
        2 => {
            // TCP: connect to target, wrap in TcpPacketIO.
            let tcp = tokio::net::TcpStream::connect(args.target)
                .await
                .with_context(|| format!("TCP connect to {}", args.target))?;
            let io = Arc::new(TcpPacketIO::new(tcp)?);
            Arc::new(Transport::bind_with_io(io, id, config).await?)
        }
        3 => {
            // WebSocket: connect_async to target.
            let url = format!("ws://{}:{}", args.target.ip(), args.target.port());
            let (ws, _) = tokio_tungstenite::connect_async(&url)
                .await
                .with_context(|| format!("WebSocket connect to {}", url))?;
            let io = Arc::new(WsPacketIO::new(ws, args.target));
            Arc::new(Transport::bind_with_io(io, id, config).await?)
        }
        _ => unreachable!(),
    };

    eprintln!("connected via {} to {}", adapter_name, args.target);

    // For TCP/WS, the target address is the transport's peer
    // address (point-to-point). For UDP, it's the remote addr.
    let peer_addr = args.target;
    let added_peer_id = if let Some(via) = args.via {
        let pid = transport
            .add_peer(peer_pub, peer_addr, Direction::Initiator)
            .await?;
        transport.add_route(peer_id, via).await;
        pid
    } else {
        transport
            .add_peer(peer_pub, peer_addr, Direction::Initiator)
            .await?
    };

    let sm = StreamManager::bind(transport.clone()).await;

    if let Some(ref msg) = args.message {
        sm.send_datagram(added_peer_id, msg.as_bytes()).await?;
        eprintln!("sent {} bytes to {}", msg.len(), hex(&peer_id));
    } else if let Some(ref file_path) = args.file {
        let data = std::fs::read(file_path)
            .with_context(|| format!("reading {}", file_path.display()))?;
        let filename = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed".to_string());

        let stream = sm.open(added_peer_id).await?;

        let name_bytes = filename.as_bytes();
        let mut header = Vec::with_capacity(2 + name_bytes.len());
        header.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        header.extend_from_slice(name_bytes);
        stream.send(&header).await?;

        for chunk in data.chunks(1024) {
            stream.send(chunk).await?;
        }
        stream.close().await?;
        eprintln!(
            "sent file '{}' ({} bytes) to {}",
            filename,
            data.len(),
            hex(&peer_id)
        );
    } else {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading stdin")?;

        if buf.is_empty() {
            bail!("nothing to send (empty stdin, no --message or --file)");
        }

        if buf.len() <= 1200 {
            sm.send_datagram(added_peer_id, &buf).await?;
        } else {
            let stream = sm.open(added_peer_id).await?;
            for chunk in buf.chunks(1024) {
                stream.send(chunk).await?;
            }
            stream.close().await?;
        }
        eprintln!("sent {} bytes to {}", buf.len(), hex(&peer_id));
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(())
}
