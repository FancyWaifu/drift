//! Multi-transport server bootstrapping.
//!
//! Given a list of `<scheme>://addr` bind specs, produces a
//! `drift::Transport` listening on all of them simultaneously.
//! UDP is point-to-multipoint (one socket → many peers), so each
//! UDP bind becomes a single interface. TCP is point-to-point
//! per stream — for a server we run an accept loop and call
//! `add_interface()` for each accepted connection so a single
//! drift-http instance can fan out to many TCP clients.
//!
//! Implementation note: `Transport::bind_with_config` requires
//! UDP for its primary interface (it owns the UDP socket). So
//! we always need at least one UDP `--bind`. If the user wants
//! TCP-only, they pass `udp://127.0.0.1:0` as a no-traffic
//! placeholder plus `tcp://0.0.0.0:N` as the real listener.

use anyhow::{anyhow, Context, Result};
use drift::identity::Identity;
use drift::io::{PacketIO, TcpPacketIO};
use drift::{Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};

use crate::transport_url::{AddrSpec, Transport as TpKind};

pub struct ServeBindResult {
    pub transport: Arc<Transport>,
    /// All bound addresses (UDP socketaddrs + TCP listener addrs)
    /// that the server is reachable on. Useful for printing the
    /// startup banner.
    pub addrs: Vec<(TpKind, SocketAddr)>,
}

/// Build a `Transport` and start any necessary accept loops.
/// `binds` MUST contain at least one UDP entry (used as the
/// primary interface for `Transport::bind_with_config`).
pub async fn build_serve_transport(
    binds: &[AddrSpec],
    identity: Identity,
    config: TransportConfig,
) -> Result<ServeBindResult> {
    if binds.is_empty() {
        return Err(anyhow!("at least one --bind is required"));
    }
    // Pull the first UDP bind to use as the transport primary.
    let primary_idx = binds
        .iter()
        .position(|b| b.transport == TpKind::Udp)
        .ok_or_else(|| {
            anyhow!(
                "at least one --bind must be UDP (Transport currently \
                 requires a UDP primary). For TCP-only, pass \
                 udp://127.0.0.1:0 as a placeholder plus your \
                 tcp://... bind."
            )
        })?;
    let primary = &binds[primary_idx];

    let transport = Arc::new(
        Transport::bind_with_config(primary.addr, identity, config)
            .await
            .with_context(|| format!("UDP bind failed on {}", primary.addr))?,
    );
    let primary_addr = transport.local_addr()?;
    let mut addrs = vec![(TpKind::Udp, primary_addr)];

    // Add each non-primary bind. Order is preserved so the
    // banner reports in user-supplied order.
    for (i, bind) in binds.iter().enumerate() {
        if i == primary_idx {
            continue;
        }
        match bind.transport {
            TpKind::Udp => {
                let sock = Arc::new(UdpSocket::bind(bind.addr).await.with_context(|| {
                    format!("UDP bind failed on {}", bind.addr)
                })?);
                let addr = sock.local_addr()?;
                let io: Arc<dyn PacketIO> =
                    Arc::new(drift::io::UdpPacketIO::new(sock));
                let name = format!("udp-{}", addr);
                transport.add_interface(name, io);
                addrs.push((TpKind::Udp, addr));
            }
            TpKind::Tcp => {
                let listener = TcpListener::bind(bind.addr).await.with_context(|| {
                    format!("TCP listen failed on {}", bind.addr)
                })?;
                let addr = listener.local_addr()?;
                addrs.push((TpKind::Tcp, addr));
                spawn_tcp_accept_loop(transport.clone(), listener);
            }
        }
    }

    Ok(ServeBindResult { transport, addrs })
}

/// Accept TCP connections forever and add each accepted stream
/// as a new transport interface. Fire-and-forget — the task
/// runs for the life of the process.
fn spawn_tcp_accept_loop(transport: Arc<Transport>, listener: TcpListener) {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp, peer_addr)) => {
                    tracing::debug!(peer = %peer_addr, "accepted TCP for DRIFT");
                    let io: Arc<dyn PacketIO> = match TcpPacketIO::new(tcp) {
                        Ok(io) => Arc::new(io),
                        Err(e) => {
                            tracing::warn!(error = ?e, "wrapping TCP stream failed");
                            continue;
                        }
                    };
                    transport.add_interface(format!("tcp-{}", peer_addr), io);
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "TCP accept failed; backing off");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });
}

/// Build a client-side `Transport` that knows how to reach a
/// single peer. UDP uses a fresh ephemeral socket; TCP dials the
/// peer's listener and wraps the connected stream.
pub async fn build_connect_transport(
    local_udp_bind: SocketAddr,
    peer_spec: &AddrSpec,
    identity: Identity,
) -> Result<(Arc<Transport>, SocketAddr)> {
    match peer_spec.transport {
        TpKind::Udp => {
            let transport = Arc::new(
                Transport::bind(local_udp_bind, identity)
                    .await
                    .with_context(|| format!("UDP bind failed on {}", local_udp_bind))?,
            );
            Ok((transport, peer_spec.addr))
        }
        TpKind::Tcp => {
            // Dial the remote TCP listener; wrap as PacketIO; use
            // bind_with_io so the Transport's primary interface
            // IS this TCP stream. `--local-bind` is unused for
            // TCP — there's no UDP socket to bind.
            let tcp = tokio::net::TcpStream::connect(peer_spec.addr)
                .await
                .with_context(|| format!("TCP connect failed to {}", peer_spec.addr))?;
            let io: Arc<dyn PacketIO> = Arc::new(TcpPacketIO::new(tcp)?);
            let transport = Arc::new(
                Transport::bind_with_io(io, identity, TransportConfig::default())
                    .await
                    .context("DRIFT TCP transport bind failed")?,
            );
            Ok((transport, peer_spec.addr))
        }
    }
}
