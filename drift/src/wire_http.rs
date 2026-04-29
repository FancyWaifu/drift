//! `http://` — DRIFT shaped as plain HTTP/1.1.
//!
//! For environments where every other DRIFT transport (UDP /
//! TCP / WS / TLS) gets blocked by aggressive proxies but plain
//! HTTP gets through. Same threat model as `tls://` — wire
//! looks like a normal web app — but goes one level lower:
//! no WebSocket Upgrade header for proxies to strip, no TLS
//! ALPN to whitelist. Just `GET` and `POST` over HTTP/1.1.
//!
//! ## Wire shape
//!
//! Each DRIFT client opens **two** HTTP requests against the
//! server:
//!
//! - `GET /drift-sse` — held open as a Server-Sent Events
//!   stream. The server writes one SSE event per DRIFT packet,
//!   base64-encoded:
//!
//!     ```text
//!     data: <base64-of-DRIFT-packet>
//!
//!     ```
//!
//!   The very first event the server sends is
//!   `data: SID:<hex>` so the client can correlate its uplink
//!   POSTs with this stream.
//!
//! - `POST /drift-send?sid=<hex>` — one request per outbound
//!   packet from the client. Body is the raw DRIFT packet bytes.
//!
//! Two requests, one logical session. The session's `sid` is
//! the server's only key for routing inbound POSTs to the right
//! SSE stream.
//!
//! ## Why hand-rolled HTTP
//!
//! Hyper would do the parsing for us, but we only need GET +
//! POST + content-length, no chunked encoding, no compression.
//! Hand-rolling keeps `drift`'s dep tree small and the wire
//! transparent — easy to debug with `curl` and `nc`.
//!
//! ## Browser pairing
//!
//! `drift-wasm/src/wire_http.rs` is the WASM-side counterpart:
//! `EventSource` for the SSE channel, `fetch()` POST per packet
//! for upstream. Either side can be replaced independently as
//! long as the wire shape above stays the same.

use crate::io::{Listener, PacketIO, SchemeRegistration};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

// ─── Per-client queues ────────────────────────────────────────────
//
// Each established SSE client gets one `ClientQueues`. The
// inbound side feeds into `HttpPacketIO::recv_from`; the
// outbound side is written to by `HttpPacketIO::send_to` and
// drained by the SSE writer task that holds the GET connection
// open.

#[derive(Clone)]
struct ClientQueues {
    inbound_tx: mpsc::Sender<Vec<u8>>,
}

type Registry = Arc<Mutex<HashMap<u64, ClientQueues>>>;

// ─── HttpPacketIO ─────────────────────────────────────────────────

pub struct HttpPacketIO {
    inbound_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

#[async_trait]
impl PacketIO for HttpPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        // The SSE writer task drains `outbound_rx` and formats
        // each chunk as one SSE event. Dropping into the channel
        // is fire-and-forget; the writer applies real backpressure
        // when the bounded channel fills.
        self.outbound_tx
            .send(buf.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "SSE writer gone"))?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.inbound_rx.lock().await;
        let bytes = rx.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "HTTP client closed POST channel")
        })?;
        if bytes.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("HTTP packet too large: {} > buffer {}", bytes.len(), buf.len()),
            ));
        }
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), self.peer_addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

// ─── Listener ─────────────────────────────────────────────────────

pub struct HttpListenerIO {
    addr: SocketAddr,
    new_clients_rx: Mutex<mpsc::Receiver<Arc<dyn PacketIO>>>,
    _accept_task: tokio::task::JoinHandle<()>,
}

impl HttpListenerIO {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let actual = listener.local_addr()?;
        let (nct, ncr) = mpsc::channel::<Arc<dyn PacketIO>>(16);
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let handle = tokio::spawn(accept_loop(listener, nct, registry));
        Ok(Self {
            addr: actual,
            new_clients_rx: Mutex::new(ncr),
            _accept_task: handle,
        })
    }
}

#[async_trait]
impl Listener for HttpListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
    fn is_multi(&self) -> bool {
        true
    }
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        let mut rx = self.new_clients_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "HTTP listener closed"))
    }
}

async fn accept_loop(
    listener: TcpListener,
    new_clients_tx: mpsc::Sender<Arc<dyn PacketIO>>,
    registry: Registry,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "HTTP accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let registry = registry.clone();
        let nct = new_clients_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(stream, peer, registry, nct).await {
                tracing::debug!(error = %e, "HTTP request handler exited");
            }
        });
    }
}

// ─── HTTP request parsing ─────────────────────────────────────────

struct RequestHead {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

async fn parse_request_head<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> io::Result<RequestHead> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut parts = line.trim_end().split(' ');
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing path"))?
        .to_string();
    let mut headers = Vec::new();
    loop {
        let mut hl = String::new();
        let n = reader.read_line(&mut hl).await?;
        if n == 0 {
            break;
        }
        let hl = hl.trim_end();
        if hl.is_empty() {
            break;
        }
        if let Some((k, v)) = hl.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    Ok(RequestHead {
        method,
        path,
        headers,
    })
}

fn header<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

// ─── Request dispatch ─────────────────────────────────────────────

async fn handle_request(
    stream: TcpStream,
    peer: SocketAddr,
    registry: Registry,
    new_clients_tx: mpsc::Sender<Arc<dyn PacketIO>>,
) -> io::Result<()> {
    let local = stream.local_addr()?;
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let head = parse_request_head(&mut reader).await?;

    // Split path from optional query string.
    let (path, query) = match head.path.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (head.path.clone(), String::new()),
    };

    match (head.method.as_str(), path.as_str()) {
        ("GET", "/drift-sse") => {
            handle_sse(write_half, peer, local, registry, new_clients_tx).await
        }
        ("POST", "/drift-send") => {
            handle_post(reader, write_half, &head, &query, registry).await
        }
        ("OPTIONS", _) => write_cors_preflight(write_half).await,
        _ => write_404(write_half).await,
    }
}

// ─── Server-sent events stream (downstream) ──────────────────────

async fn handle_sse(
    mut write: tokio::net::tcp::OwnedWriteHalf,
    peer: SocketAddr,
    local: SocketAddr,
    registry: Registry,
    new_clients_tx: mpsc::Sender<Arc<dyn PacketIO>>,
) -> io::Result<()> {
    let sid: u64 = rand::random();
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(16);

    {
        let mut reg = registry.lock().await;
        reg.insert(sid, ClientQueues { inbound_tx: in_tx });
    }

    // Build the per-client PacketIO and hand it to the listener
    // via the new-clients channel before we start streaming —
    // otherwise we might deliver inbound bytes to a recv_from
    // that nobody's calling yet.
    let io_handle: Arc<dyn PacketIO> = Arc::new(HttpPacketIO {
        inbound_rx: Mutex::new(in_rx),
        outbound_tx: out_tx,
        peer_addr: peer,
        local_addr: local,
    });
    if new_clients_tx.send(io_handle).await.is_err() {
        // Listener dropped; clean up registry.
        registry.lock().await.remove(&sid);
        return Ok(());
    }

    // SSE response head.
    let head = "HTTP/1.1 200 OK\r\n\
                Content-Type: text/event-stream\r\n\
                Cache-Control: no-cache\r\n\
                Connection: keep-alive\r\n\
                Access-Control-Allow-Origin: *\r\n\
                \r\n";
    write.write_all(head.as_bytes()).await?;

    // First event tells the client its sid.
    let sid_event = format!("data: SID:{:016x}\n\n", sid);
    write.write_all(sid_event.as_bytes()).await?;
    write.flush().await?;

    // Drain outbound queue → SSE events. Loop ends when the
    // PacketIO's `out_tx` is dropped (peer side closed) or the
    // TCP stream errors (client disconnected).
    while let Some(packet) = out_rx.recv().await {
        let encoded = general_purpose::STANDARD_NO_PAD.encode(&packet);
        let event = format!("data: {}\n\n", encoded);
        if write.write_all(event.as_bytes()).await.is_err() {
            break;
        }
        if write.flush().await.is_err() {
            break;
        }
    }

    // Clean up so a stale sid doesn't accept POSTs forever.
    registry.lock().await.remove(&sid);
    Ok(())
}

// ─── POST upstream ────────────────────────────────────────────────

async fn handle_post(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut write: tokio::net::tcp::OwnedWriteHalf,
    head: &RequestHead,
    query: &str,
    registry: Registry,
) -> io::Result<()> {
    let sid = parse_sid(query).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "POST missing or bad ?sid=")
    })?;
    let len: usize = header(&head.headers, "content-length")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "POST missing Content-Length")
        })?;
    if len > 65 * 1024 {
        // DRIFT packets are well under 64 KiB; reject anything
        // huge to avoid DoS via giant POST bodies.
        return write_413(write).await;
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;

    let queues = {
        let reg = registry.lock().await;
        reg.get(&sid).cloned()
    };
    let Some(queues) = queues else {
        return write_404(write).await;
    };

    // Push into the inbound queue; the application's
    // `recv_from` will pick it up.
    let _ = queues.inbound_tx.send(body).await;

    let resp = "HTTP/1.1 200 OK\r\n\
                Content-Length: 0\r\n\
                Access-Control-Allow-Origin: *\r\n\
                \r\n";
    write.write_all(resp.as_bytes()).await?;
    write.flush().await?;
    Ok(())
}

fn parse_sid(query: &str) -> Option<u64> {
    for kv in query.split('&') {
        if let Some(("sid", v)) = kv.split_once('=') {
            return u64::from_str_radix(v, 16).ok();
        }
    }
    None
}

// ─── Stock responses ──────────────────────────────────────────────

async fn write_cors_preflight(
    mut write: tokio::net::tcp::OwnedWriteHalf,
) -> io::Result<()> {
    let resp = "HTTP/1.1 204 No Content\r\n\
                Access-Control-Allow-Origin: *\r\n\
                Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                Access-Control-Allow-Headers: Content-Type\r\n\
                Content-Length: 0\r\n\
                \r\n";
    write.write_all(resp.as_bytes()).await?;
    write.flush().await
}

async fn write_404(mut write: tokio::net::tcp::OwnedWriteHalf) -> io::Result<()> {
    let resp = "HTTP/1.1 404 Not Found\r\n\
                Content-Length: 0\r\n\
                Access-Control-Allow-Origin: *\r\n\
                \r\n";
    write.write_all(resp.as_bytes()).await?;
    write.flush().await
}

async fn write_413(mut write: tokio::net::tcp::OwnedWriteHalf) -> io::Result<()> {
    let resp = "HTTP/1.1 413 Payload Too Large\r\n\
                Content-Length: 0\r\n\
                Access-Control-Allow-Origin: *\r\n\
                \r\n";
    write.write_all(resp.as_bytes()).await?;
    write.flush().await
}

// ─── Connector (stub — clients are typically WASM) ────────────────
//
// For native-to-native HTTP/SSE, the connector would mirror the
// WASM client: open a streaming GET, parse incoming SSE events,
// fire POSTs for each outbound packet. That's mostly useful for
// testing; in practice the *purpose* of `http://` is to give
// browser clients a fallback wire when WS is blocked. So the
// native connector is left out for now and we error on
// `connect_url("http://...")`. Tests dial via the WASM client.

fn http_connector_factory(
    _addr_str: String,
) -> Pin<
    Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>,
> {
    Box::pin(async move {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "http:// connector is browser-only; use the WASM `connectHttp` client",
        ))
    })
}

fn http_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        let addr: SocketAddr = addr_str.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not a valid host:port {:?}: {}", addr_str, e),
            )
        })?;
        Ok(Box::new(HttpListenerIO::bind(addr).await?) as Box<dyn Listener>)
    })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "http",
        listener: http_listener_factory,
        connector: http_connector_factory,
    }
}
