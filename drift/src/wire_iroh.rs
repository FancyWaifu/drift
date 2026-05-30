//! `iroh://` — DRIFT over Iroh (n0-computer's pubkey-addressed
//! QUIC overlay). Behind `--features iroh`.
//!
//! Yes, this is putting a wire-agnostic identity-based transport
//! on top of a single-wire identity-based transport. The pubkey-
//! on-pubkey layering is intentional: DRIFT identity inside Iroh
//! identity, with both sides pretending the other doesn't exist.
//! In practice the user-facing benefit is Iroh's NAT punching +
//! relay infrastructure as another wire option in DRIFT's
//! adapter inventory — pick `iroh://` when you want
//! through-NAT P2P without setting up a federation bridge.
//!
//! Wire shape:
//!
//!   1. Listener binds an `iroh::Endpoint` with ALPN
//!      `drift/iroh/1`. Each incoming `iroh::Connection` becomes
//!      one DRIFT peer.
//!   2. Connector parses `iroh://<endpoint_id_hex>@<host:port>`,
//!      constructs an `EndpointAddr`, and dials it.
//!   3. DRIFT packets ride as **QUIC datagrams** (RFC 9221):
//!      one DRIFT packet per QUIC datagram, no framing, no
//!      head-of-line blocking. Iroh wraps quinn's datagram
//!      extension and negotiates support during the TLS
//!      handshake.
//!   4. Unreliable + unordered, matching DRIFT's packet model
//!      and the `udp://` wire's semantics. DRIFT's own session
//!      layer handles drops and reordering at the protocol
//!      level (it already does for `udp://`).
//!   5. DRIFT's AEAD authenticates each packet; iroh's QUIC
//!      encryption is hop-to-hop confidentiality.
//!
//! Why datagrams instead of bidi streams: each DRIFT packet is
//! independent. Riding a single QUIC stream made every packet
//! pay per-frame stream overhead AND introduced head-of-line
//! blocking — one slow frame stalled every subsequent packet
//! in the link. Datagrams are how QUIC says "low-overhead
//! independent messages."
//!
//! URL format:
//!
//!   - Listener: `iroh://0.0.0.0:51820` (or any sockaddr — the
//!     port is informational; iroh picks its own UDP socket).
//!     The endpoint's id is logged at bind time.
//!   - Connector: `iroh://<endpoint_id_hex>@<host:port>` — the
//!     `<endpoint_id_hex>` is the 64-char hex of the target
//!     iroh `EndpointId`, the `<host:port>` is the direct iroh
//!     listening address (no PKARR / relay lookup; we want
//!     deterministic LAN/docker dispatch).

use crate::io::{Listener, PacketIO, SchemeRegistration};
use async_trait::async_trait;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};

use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointAddr, EndpointId};

/// Process-wide singleton iroh `Endpoint`. Iroh's own docs
/// recommend "It is recommended to only create a single instance
/// per application. This ensures all the connections made share
/// the same peer-to-peer connections to other iroh endpoints."
///
/// Without this, a bridge that both listens (via `--listen iroh://`)
/// and federates outbound (via `--federate iroh://`) ends up with
/// two separate Endpoints — incoming + outgoing — and iroh's
/// connection-per-peer dedup can't fire across them. That triggers
/// the K=3 mutual-init asymmetry bug documented in
/// `drift-bench/FEDERATION-IROH-VS-H2S.md`: bridge2 dials bridge3
/// AND bridge3 dials bridge2 simultaneously, both succeed because
/// each Endpoint is unaware of the other, DRIFT's dual-init handler
/// merges the sessions but the mesh-routing table only records
/// one direction.
///
/// With the shared Endpoint, iroh's built-in connection dedup
/// fires before DRIFT ever sees the dual-init: only ONE
/// Connection per peer ever exists per process.
static SHARED_ENDPOINT: OnceCell<Endpoint> = OnceCell::const_new();

/// Gets or initializes the process-wide iroh `Endpoint`. The
/// first caller's `bind_hint` (if Some and port != 0) determines
/// the bound UDP port; subsequent calls ignore the hint and
/// reuse the existing endpoint. Listeners pass the URL's port
/// hint; connectors pass None.
async fn shared_endpoint(bind_hint: Option<SocketAddr>) -> io::Result<Endpoint> {
    SHARED_ENDPOINT
        .get_or_try_init(|| async {
            let mut builder = Endpoint::builder(presets::Minimal).alpns(vec![ALPN.to_vec()]);
            if let Some(sk) = iroh_secret_from_env() {
                builder = builder.secret_key(sk);
            }
            if let Some(hint) = bind_hint {
                if hint.port() != 0 {
                    builder = builder
                        .bind_addr(hint)
                        .map_err(|e| io::Error::other(format!("iroh bind_addr {}: {}", hint, e)))?;
                }
            }
            builder
                .bind()
                .await
                .map_err(|e| io::Error::other(format!("iroh shared endpoint bind: {}", e)))
        })
        .await
        .cloned()
}

const ALPN: &[u8] = b"drift/iroh/1";
/// Defensive upper bound on a single datagram we'll accept from
/// the recv path. QUIC datagram size is capped by path MTU minus
/// QUIC overhead — typically ~1200 B on the public internet,
/// larger on LAN/loopback. The actual per-connection ceiling is
/// `Connection::max_datagram_size()`; we use this constant only
/// to bound the in-buffer copy on receive so a malformed peer
/// can't trick us into a giant allocation.
const MAX_DATAGRAM: usize = 64 * 1024;

/// SocketAddr for the iroh peer, derived deterministically
/// from its `EndpointId`. The post-handshake `Connection` API
/// doesn't expose the underlying socket addr (relay/direct/
/// custom transport abstraction), so we synthesize a stable
/// per-peer addr from the iroh endpoint id.
///
/// **Why this matters for DRIFT federation**: other multi-
/// shot wires (h2, ws, webtransport) return the real connecting
/// peer's IP. DRIFT correlates sessions by src_addr; an earlier
/// iroh build that returned `127.0.0.1:60000` from a process-
/// wide counter made the federation handshake AEAD-auth-fail
/// because session lookup picked the wrong peer. Deterministic
/// per-id synthesis avoids that: same peer → same addr →
/// session table correlates correctly.
///
/// Uses the 192.0.2.0/24 documentation range (RFC 5737) so the
/// synthesized addrs are outside loopback and outside any
/// real subnet anyone is likely to use.
fn peer_addr_for_connection(conn: &Connection) -> SocketAddr {
    use std::hash::Hasher;
    let id = conn.remote_id();
    let mut h = siphasher::sip::SipHasher24::new();
    h.write(id.as_bytes());
    let hash = h.finish();
    let octet = ((hash >> 16) & 0xff) as u8;
    let port = (hash as u16).max(1024);
    SocketAddr::from(([192, 0, 2, octet], port))
}

// ─── Per-connection PacketIO ─────────────────────────────────────

pub struct IrohPacketIO {
    conn: Connection,
    peer_addr: SocketAddr,
    // iroh::Endpoint owns the underlying QUIC state. If it
    // drops, every connection it owns dies. Keep it alive
    // for the lifetime of the PacketIO.
    _endpoint: Endpoint,
    // Serializes read_datagram() calls — quinn's datagram
    // receive queue allows one reader at a time per Connection.
    // send_datagram() is non-blocking + queues internally, so
    // it doesn't need a lock.
    recv_lock: Mutex<()>,
}

impl IrohPacketIO {
    fn new(conn: Connection, peer_addr: SocketAddr, endpoint: Endpoint) -> Self {
        Self {
            conn,
            peer_addr,
            _endpoint: endpoint,
            recv_lock: Mutex::new(()),
        }
    }
}

#[async_trait]
impl PacketIO for IrohPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        // QUIC datagrams are bounded by the path MTU minus QUIC
        // overhead. iroh exposes the negotiated ceiling via
        // `Connection::max_datagram_size()`. If a DRIFT packet is
        // larger we error out — the upstream IO layer treats this
        // like a UDP MTU rejection, same shape as the udp:// wire.
        let max = self
            .conn
            .max_datagram_size()
            .ok_or_else(|| io::Error::other("iroh peer didn't negotiate QUIC datagram support"))?;
        if buf.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("iroh datagram too large: {} bytes > {} max", buf.len(), max),
            ));
        }
        self.conn
            .send_datagram(bytes::Bytes::copy_from_slice(buf))
            .map_err(|e| io::Error::other(format!("iroh send_datagram: {}", e)))?;
        Ok(buf.len())
    }

    async fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // One reader at a time per Connection. The send side is
        // lock-free so this doesn't block outbound packets.
        let _g = self.recv_lock.lock().await;
        let datagram = self
            .conn
            .read_datagram()
            .await
            .map_err(|e| io::Error::other(format!("iroh read_datagram: {}", e)))?;
        let n = datagram.len();
        if n > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "iroh datagram exceeds defensive cap: {} > {}",
                    n, MAX_DATAGRAM
                ),
            ));
        }
        if n > out.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "iroh datagram too large for caller buffer: {} > {}",
                    n,
                    out.len()
                ),
            ));
        }
        out[..n].copy_from_slice(&datagram);
        Ok((n, self.peer_addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
}

// ─── Listener ────────────────────────────────────────────────────

pub struct IrohListenerIO {
    local_addr: SocketAddr,
    ready_rx: Mutex<tokio::sync::mpsc::Receiver<Arc<dyn PacketIO>>>,
    _accept_task: tokio::task::JoinHandle<()>,
}

/// Reads `DRIFT_IROH_SECRET_HEX` env var (64 hex chars = 32
/// bytes). If set, returns a deterministic iroh `SecretKey` so
/// the endpoint id stays stable across bridge restarts. If
/// unset, returns None and iroh generates a fresh ephemeral
/// key (fine for short-lived bench connections, broken for
/// long-lived federation links that embed the id in operator
/// config).
fn iroh_secret_from_env() -> Option<iroh::SecretKey> {
    let hex_str = std::env::var("DRIFT_IROH_SECRET_HEX").ok()?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    if bytes.len() != 32 {
        tracing::warn!(
            "DRIFT_IROH_SECRET_HEX must be exactly 64 hex chars (32 bytes); got {}",
            bytes.len()
        );
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(iroh::SecretKey::from_bytes(&arr))
}

impl IrohListenerIO {
    pub async fn bind(hint: SocketAddr) -> io::Result<Self> {
        // Use the process-wide shared Endpoint so a bridge that
        // both listens and federates outbound has ONE iroh
        // Endpoint for both directions. This is what enables
        // iroh's built-in per-peer connection dedup across
        // accept and connect paths — without it, mutual-init
        // federation (K≥3) produces two ambiguous Connections
        // per peer which DRIFT's dual-init handler half-resolves,
        // leaving the mesh routing asymmetric. See the doc on
        // SHARED_ENDPOINT.
        let endpoint = shared_endpoint(Some(hint)).await?;
        let id = endpoint.id();
        let bound: Vec<SocketAddr> = endpoint.bound_sockets();
        tracing::info!(
            id = %id,
            sockets = ?bound,
            "iroh listener bound — connect with iroh://{}@<ip:port>",
            id
        );
        // Also print the endpoint id + sockets to stderr so
        // non-tracing-init callers (drift-bench, smoke scripts)
        // can scrape it without setting RUST_LOG. Parser-friendly
        // single line.
        eprintln!("iroh listener bound — id={} sockets={:?}", id, bound);
        // For the peer table / Transport surface, use the first
        // bound IPv4 socket if one exists, otherwise the unspecified
        // sockaddr — this `local_addr` is informational for the
        // Listener trait and isn't routed against.
        let local_addr = bound
            .into_iter()
            .find(|s| matches!(s, SocketAddr::V4(_)))
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

        let (ready_tx, ready_rx) = tokio::sync::mpsc::channel::<Arc<dyn PacketIO>>(16);
        let endpoint_for_accept = endpoint.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let Some(incoming) = endpoint_for_accept.accept().await else {
                    tracing::debug!("iroh listener: endpoint.accept() returned None");
                    return;
                };
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!(error = %e, "iroh listener: incoming.await failed");
                        continue;
                    }
                };
                // Datagram mode: the Connection itself is the
                // "ready" signal — no need to wait on accept_bi.
                // Wrap and ship.
                let peer = peer_addr_for_connection(&conn);
                let io: Arc<dyn PacketIO> =
                    Arc::new(IrohPacketIO::new(conn, peer, endpoint_for_accept.clone()));
                let _ = ready_tx.send(io).await;
            }
        });

        Ok(Self {
            local_addr,
            ready_rx: Mutex::new(ready_rx),
            _accept_task: accept_task,
        })
    }
}

#[async_trait]
impl Listener for IrohListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    fn is_multi(&self) -> bool {
        true
    }
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        let mut rx = self.ready_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "iroh listener closed"))
    }
}

// ─── Connector ───────────────────────────────────────────────────

async fn connect_iroh_client(spec: &str) -> io::Result<(Arc<dyn PacketIO>, SocketAddr)> {
    // Parse `<endpoint_id_hex>@<host:port>` — the URL dispatcher
    // strips the `iroh://` prefix and hands us the rest.
    let (id_hex, addr_str) = spec.split_once('@').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "iroh:// connector needs <endpoint_id_hex>@<host:port>",
        )
    })?;
    let id: EndpointId = id_hex
        .parse()
        .map_err(|e| io::Error::other(format!("iroh endpoint id parse: {}", e)))?;
    let direct: SocketAddr = addr_str
        .parse()
        .map_err(|e| io::Error::other(format!("iroh direct addr parse: {}", e)))?;
    let target = EndpointAddr::new(id).with_ip_addr(direct);

    // Use the same process-wide shared Endpoint as the listener
    // (and as any other concurrent connect call). This is the
    // key to iroh's per-peer connection dedup: when bridge1's
    // listener already has an accepted Connection from bridge2
    // AND bridge1's federation code tries to dial bridge2, iroh
    // recognizes the existing Connection and reuses it instead
    // of opening a second one. Without sharing, dual-init goes
    // through DRIFT's session-merge handler, which doesn't
    // populate both sides' federation_table — that's the K=3
    // BEACON-asymmetry bug.
    let endpoint = shared_endpoint(None).await?;
    let conn: Connection = endpoint
        .connect(target, ALPN)
        .await
        .map_err(|e| io::Error::other(format!("iroh connect: {}", e)))?;
    let peer = peer_addr_for_connection(&conn);
    let io: Arc<dyn PacketIO> = Arc::new(IrohPacketIO::new(conn, peer, endpoint));
    Ok((io, peer))
}

// ─── Factories + inventory registration ─────────────────────────

fn iroh_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        // Parse the listener addr (informational — iroh picks
        // its own UDP socket). Default to 0.0.0.0:0 if it fails.
        let hint: SocketAddr = addr_str
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        Ok(Box::new(IrohListenerIO::bind(hint).await?) as Box<dyn Listener>)
    })
}

fn iroh_connector_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>> {
    Box::pin(async move { connect_iroh_client(&addr_str).await })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "iroh",
        listener: iroh_listener_factory,
        connector: iroh_connector_factory,
    }
}
