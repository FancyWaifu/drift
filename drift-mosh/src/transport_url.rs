//! Transport selection for drift-mosh.
//!
//! Same shape as drift-http's `transport_url` module — DRIFT
//! decouples identity from transport, so both `--bind` (server)
//! and `--server-addr` (client) accept a small URL-shaped
//! grammar:
//!
//! ```text
//! 0.0.0.0:9100        # bare = UDP (back-compat default)
//! udp://0.0.0.0:9100  # explicit UDP
//! tcp://0.0.0.0:9100  # TCP
//! ```
//!
//! drift-mosh keeps the simpler "one transport per process"
//! shape rather than the multi-bind-simultaneous pattern that
//! drift-http needs — a mosh session is naturally point-to-point.

use anyhow::{anyhow, Context, Result};
use drift::identity::Identity;
use drift::io::{MemPacketIO, PacketIO, TcpPacketIO};
use drift::{Transport, TransportConfig};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransportKind {
    Udp,
    Tcp,
}

impl TransportKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportKind::Udp => "udp",
            TransportKind::Tcp => "tcp",
        }
    }
}

impl FromStr for TransportKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Ok(TransportKind::Udp),
            "tcp" => Ok(TransportKind::Tcp),
            other => Err(anyhow!("unknown transport {:?} (supported: udp, tcp)", other)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AddrSpec {
    pub transport: TransportKind,
    pub addr: SocketAddr,
}

pub fn parse_addr(s: &str) -> Result<AddrSpec> {
    if let Some(idx) = s.find("://") {
        let scheme = &s[..idx];
        let rest = &s[idx + 3..];
        let transport: TransportKind = scheme.parse()?;
        let addr: SocketAddr = rest
            .parse()
            .with_context(|| format!("address {:?} is not host:port", rest))?;
        Ok(AddrSpec { transport, addr })
    } else {
        let addr: SocketAddr = s
            .parse()
            .with_context(|| format!("address {:?} is not host:port", s))?;
        Ok(AddrSpec {
            transport: TransportKind::Udp,
            addr,
        })
    }
}

/// Server-side: bind a `Transport` reachable on the given
/// transport. UDP is a single-call bind; TCP spawns an accept
/// loop adding each accepted connection as an additional
/// interface (since `TcpPacketIO` is point-to-point per stream).
pub async fn build_server_transport(
    spec: &AddrSpec,
    identity: Identity,
    config: TransportConfig,
) -> Result<(Arc<Transport>, SocketAddr)> {
    match spec.transport {
        TransportKind::Udp => {
            let transport = Arc::new(
                Transport::bind_with_config(spec.addr, identity, config)
                    .await
                    .with_context(|| format!("UDP bind failed on {}", spec.addr))?,
            );
            let addr = transport.local_addr()?;
            Ok((transport, addr))
        }
        TransportKind::Tcp => {
            // Bind the TCP listener up front so we can return
            // its addr immediately — callers want to print
            // the banner before any client connects.
            let listener = TcpListener::bind(spec.addr)
                .await
                .with_context(|| format!("TCP listen failed on {}", spec.addr))?;
            let bound = listener.local_addr()?;

            // The Transport API requires a non-null primary
            // PacketIO. We satisfy that with a MemPacketIO
            // whose other half we immediately drop — no traffic
            // will ever flow through it. Real client traffic
            // arrives on the TCP interfaces we attach via the
            // accept loop below.
            let (mem_primary, _mem_dead) = MemPacketIO::pair();
            let primary_io: Arc<dyn PacketIO> = Arc::new(mem_primary);
            let transport = Arc::new(
                Transport::bind_with_io(primary_io, identity, config)
                    .await
                    .context("DRIFT TCP transport bind failed")?,
            );

            // Accept-loop: each accepted TCP stream becomes a
            // new interface. Point-to-point per stream is the
            // TcpPacketIO contract, so a many-clients server
            // builds up many interfaces over its lifetime.
            let t = transport.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((tcp, peer_addr)) => {
                            let io: Arc<dyn PacketIO> = match TcpPacketIO::new(tcp) {
                                Ok(io) => Arc::new(io),
                                Err(e) => {
                                    tracing::warn!(error = ?e, "wrapping TCP stream failed");
                                    continue;
                                }
                            };
                            t.add_interface(format!("tcp-{}", peer_addr), io);
                        }
                        Err(e) => {
                            tracing::warn!(error = ?e, "TCP accept failed; backing off");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
            Ok((transport, bound))
        }
    }
}

/// Client-side: build a `Transport` reachable to a single peer.
/// UDP uses a fresh ephemeral socket; TCP dials and wraps the
/// connected stream.
pub async fn build_client_transport(
    local_udp_bind: SocketAddr,
    spec: &AddrSpec,
    identity: Identity,
) -> Result<(Arc<Transport>, SocketAddr)> {
    match spec.transport {
        TransportKind::Udp => {
            let transport = Arc::new(
                Transport::bind(local_udp_bind, identity)
                    .await
                    .with_context(|| format!("UDP bind failed on {}", local_udp_bind))?,
            );
            Ok((transport, spec.addr))
        }
        TransportKind::Tcp => {
            let tcp = TcpStream::connect(spec.addr)
                .await
                .with_context(|| format!("TCP connect failed to {}", spec.addr))?;
            let io: Arc<dyn PacketIO> = Arc::new(TcpPacketIO::new(tcp)?);
            let transport = Arc::new(
                Transport::bind_with_io(io, identity, TransportConfig::default())
                    .await
                    .context("DRIFT TCP transport bind failed")?,
            );
            Ok((transport, spec.addr))
        }
    }
}
