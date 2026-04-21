use super::identity::hex;
use super::RelayArgs;
use anyhow::{bail, Context, Result};
use drift::identity::Identity;
use drift::{Transport, TransportConfig};
use std::net::SocketAddr;

pub async fn run(args: &RelayArgs) -> Result<()> {
    let id = Identity::generate();
    let config = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };

    let transport = Transport::bind_with_config(args.bind, id, config).await?;
    eprintln!("relay bound to {}", transport.local_addr()?);
    eprintln!("peer_id: {}", hex(&transport.local_peer_id()));

    for route_str in &args.routes {
        let (peer_id, addr) = parse_route(route_str)?;
        transport.add_route(peer_id, addr).await;
        eprintln!("  route {} -> {}", hex(&peer_id), addr);
    }

    if args.metrics_interval > 0 {
        let interval = std::time::Duration::from_secs(args.metrics_interval);
        let metrics_task = async {
            loop {
                tokio::time::sleep(interval).await;
                let m = transport.metrics();
                eprintln!(
                    "[metrics] pkts_tx={} pkts_rx={} fwd={} hs={} auth_fail={}",
                    m.packets_sent,
                    m.packets_received,
                    m.forwarded,
                    m.handshakes_completed,
                    m.auth_failures
                );
            }
        };

        tokio::select! {
            _ = metrics_task => {}
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nshutting down...");
            }
        }
    } else {
        tokio::signal::ctrl_c().await?;
        eprintln!("\nshutting down...");
    }

    let m = transport.metrics();
    eprintln!(
        "final: pkts_tx={} pkts_rx={} fwd={} hs={} auth_fail={}",
        m.packets_sent, m.packets_received, m.forwarded, m.handshakes_completed, m.auth_failures
    );
    Ok(())
}

fn parse_route(s: &str) -> Result<([u8; 8], SocketAddr)> {
    let first_colon = s.find(':').context("route format: PEERID_HEX:HOST:PORT")?;
    let id_hex = &s[..first_colon];
    let addr_str = &s[first_colon + 1..];

    if id_hex.len() != 16 {
        bail!(
            "peer ID must be 16 hex chars (8 bytes), got {}",
            id_hex.len()
        );
    }
    let mut id = [0u8; 8];
    for i in 0..8 {
        id[i] =
            u8::from_str_radix(&id_hex[i * 2..i * 2 + 2], 16).context("invalid hex in peer ID")?;
    }
    let addr: SocketAddr = addr_str.parse().context("invalid address in route")?;
    Ok((id, addr))
}
