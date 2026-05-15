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

use crate::io::{parse_ip_addr, Listener, PacketIO, SchemeRegistration};
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

// ─── Native HTTP connector ───────────────────────────────────────
//
// Mirrors the WASM `connectHttp` client. Opens a streaming GET
// against /drift-sse, parses the first event for the session id,
// spawns a background task that pumps subsequent SSE events into
// an mpsc channel, and exposes the channel via PacketIO::recv_from.
// Outbound packets become POSTs to /drift-send?sid=<sid>.
//
// Native-native HTTP isn't the *intended* path — the listener's
// main consumer is browser-side WASM — but having a native client
// closes the testability gap and makes http:// usable as a
// last-resort fallback for native binaries when every other
// transport is blocked.

use base64::Engine as _;

/// Internal: spawned task that drains the SSE stream into the
/// `inbound` channel. Each `data: <base64>\n\n` event becomes one
/// packet pushed onto the channel.
async fn sse_pump<S>(
    mut byte_stream: S,
    initial_leftover: Vec<u8>,
    inbound: tokio::sync::mpsc::Sender<Vec<u8>>,
) where
    S: futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin + Send,
{
    let mut leftover = initial_leftover;
    use futures_util::StreamExt;
    while let Some(chunk_res) = byte_stream.next().await {
        let chunk = match chunk_res {
            Ok(c) => c,
            Err(_) => return,
        };
        leftover.extend_from_slice(&chunk);
        // SSE events end with a blank line (\n\n or \r\n\r\n).
        loop {
            let Some(boundary) = find_event_boundary(&leftover) else {
                break;
            };
            let event_bytes: Vec<u8> = leftover.drain(..boundary.end).collect();
            // Each event is "data: <payload>\n" (possibly
            // multi-line, but our server emits single-line
            // data: payloads). Strip the prefix and \n.
            let event_str = match std::str::from_utf8(&event_bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for line in event_str.lines() {
                let payload = match line.strip_prefix("data: ") {
                    Some(p) => p,
                    None => continue,
                };
                // First event is `SID:<hex>` — handled by the
                // bootstrap path, not here. Subsequent events
                // are base64-encoded DRIFT packets.
                if let Some(_sid) = payload.strip_prefix("SID:") {
                    continue;
                }
                let bytes = match base64::engine::general_purpose::STANDARD
                    .decode(payload.as_bytes())
                {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if inbound.send(bytes).await.is_err() {
                    return; // receiver dropped
                }
            }
        }
    }
}

struct EventBoundary {
    end: usize,
}

/// Locate the end of the next SSE event in `buf`. SSE events
/// end with a blank line — `\n\n` or `\r\n\r\n`. Returns the
/// byte offset just past the trailing blank line, or `None` if
/// no complete event is buffered yet.
fn find_event_boundary(buf: &[u8]) -> Option<EventBoundary> {
    // Look for "\n\n" first (most common).
    for i in 1..buf.len() {
        if buf[i - 1] == b'\n' && buf[i] == b'\n' {
            return Some(EventBoundary { end: i + 1 });
        }
    }
    // Fall back to "\r\n\r\n".
    for i in 3..buf.len() {
        if &buf[i - 3..=i] == b"\r\n\r\n" {
            return Some(EventBoundary { end: i + 1 });
        }
    }
    None
}

/// PacketIO over native HTTP/SSE. Outbound packets become POSTs;
/// inbound packets are SSE events pumped into an internal mpsc.
pub struct HttpClientPacketIO {
    client: reqwest::Client,
    send_url: String,
    addr: SocketAddr,
    inbound_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    _sse_task: tokio::task::JoinHandle<()>,
}

#[async_trait]
impl PacketIO for HttpClientPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        let body = buf.to_vec();
        let n = body.len();
        self.client
            .post(&self.send_url)
            .body(body)
            .send()
            .await
            .map_err(io::Error::other)?;
        Ok(n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.inbound_rx.lock().await;
        match rx.recv().await {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok((n, self.addr))
            }
            None => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "SSE stream ended",
            )),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

fn http_connector_factory(
    addr_str: String,
) -> Pin<
    Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>,
> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str)?;
        let base = format!("http://{}", addr);
        let sse_url = format!("{}/drift-sse", base);

        // reqwest with no timeout for the SSE response — it's a
        // long-poll. The connect timeout still bounds initial
        // setup.
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(io::Error::other)?;

        // Open the streaming GET. The first event we'll see is
        // `SID:<hex>`; consume the response until that arrives,
        // then hand the rest of the stream to the pump task.
        let mut resp = client
            .get(&sse_url)
            .send()
            .await
            .map_err(io::Error::other)?;
        if !resp.status().is_success() {
            return Err(io::Error::other(format!(
                "SSE GET failed: HTTP {}",
                resp.status()
            )));
        }

        // Read chunks until we see the SID handshake event.
        use futures_util::StreamExt;
        let mut accum = Vec::<u8>::new();
        let mut sid: Option<String> = None;
        let mut byte_stream = resp.bytes_stream();
        // After SID parse, hand `byte_stream` + any leftover
        // bytes to the pump task — `resp` is consumed.
        while sid.is_none() {
            let chunk = match byte_stream.next().await {
                Some(Ok(c)) => c,
                Some(Err(e)) => return Err(io::Error::other(e)),
                None => {
                    return Err(io::Error::other(
                        "SSE stream ended before SID handshake",
                    ));
                }
            };
            accum.extend_from_slice(&chunk);
            // Look for the first `\n\n`-terminated event and try
            // to parse it as SID.
            if let Some(boundary) = find_event_boundary(&accum) {
                let event_bytes: Vec<u8> = accum.drain(..boundary.end).collect();
                let event_str = std::str::from_utf8(&event_bytes)
                    .map_err(io::Error::other)?;
                for line in event_str.lines() {
                    if let Some(payload) = line.strip_prefix("data: ") {
                        if let Some(s) = payload.strip_prefix("SID:") {
                            sid = Some(s.to_string());
                            break;
                        }
                    }
                }
                if sid.is_none() {
                    return Err(io::Error::other(format!(
                        "first SSE event not SID handshake: {:?}",
                        event_str.lines().next()
                    )));
                }
            }
        }
        let sid = sid.expect("loop exit invariant");

        // Drop the response we already consumed and reissue —
        // actually no, we need to KEEP this stream open and pump
        // subsequent events from it. The accum may already hold
        // a partial next event; feed that to the pump via a
        // wrapped stream.
        //
        // Simpler: pass the existing reqwest::Response by-move
        // into the pump task. accum is empty (we drained it).
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        // Hand the byte_stream + any leftover-from-SID-parse to
        // the pump task. Leftover is usually empty (the SID
        // event arrives in its own chunk) but we feed it
        // through anyway for correctness — a partial next event
        // baked into the SID chunk would otherwise be lost.
        let pump_task = tokio::spawn(sse_pump(byte_stream, accum, inbound_tx));

        let send_url = format!("{}/drift-send?sid={}", base, sid);
        let io: Arc<dyn PacketIO> = Arc::new(HttpClientPacketIO {
            client,
            send_url,
            addr,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
            _sse_task: pump_task,
        });
        Ok((io, addr))
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
