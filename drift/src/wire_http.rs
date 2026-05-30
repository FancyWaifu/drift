//! `http://` — DRIFT shaped as plain HTTP/1.1, server backed by hyper.
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
//! ## Server backend: hyper
//!
//! The server side uses `hyper::server::conn::http1` for request
//! parsing. We get RFC-compliant header handling, proper
//! Content-Length vs Transfer-Encoding semantics, header size
//! limits, and the largest fuzz corpus in the Rust HTTP
//! ecosystem — all for free. Per-IP connection caps and the
//! `header_read_timeout` close out slowloris-style stalls.
//!
//! Pre-hyper, this file hand-rolled a small HTTP/1.1 parser
//! (~250 LOC). It worked, but it was us-vs-the-RFC; the hyper
//! port closes that gap.
//!
//! ## Browser pairing
//!
//! `drift-wasm/src/wire_http.rs` is the WASM-side counterpart:
//! `EventSource` for the SSE channel, `fetch()` POST per packet
//! for upstream. Either side can be replaced independently as
//! long as the wire shape above stays the same.

use crate::io::{parse_ip_addr, ConnGuard, Listener, PacketIO, SchemeRegistration};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;

/// SEC.PEN.HIGH-1 hardening for the http:// listener — bound the
/// time hyper waits for the request head and cap concurrent
/// connections per source IP. Mirrors the WS / TLS adapter
/// constants from `crate::io`.
const HTTP_HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const DEFAULT_HTTP_CONNS_PER_IP: usize = 32;
/// Hard cap on a single POST body. DRIFT packets are well under
/// 64 KiB; anything larger is rejected before we allocate.
const MAX_POST_BODY: usize = 65 * 1024;

/// HTTP.OPT2 — when set, the http:// listener trusts upstream
/// reverse-proxy headers (X-Forwarded-For / X-Real-IP) for log
/// context and SKIPS the TCP-peer-based per-IP cap (because
/// every connection now comes from the proxy's IP, and the
/// per-IP cap would either let through far too many real users
/// or block them all). The reverse proxy is expected to do its
/// own per-source-IP rate limiting / connection management.
///
/// Toggled by `drift bridge --trust-proxy-headers`. Process-wide
/// because the scheme-registry factory signature
/// `fn(String) -> ...` doesn't carry config; an atomic flipped
/// before bind() is the simplest plumbing.
static TRUST_PROXY_HEADERS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// HTTP.OPT2 — operator hook to enable proxy-header trust before
/// any `bind()` call. Set by `drift bridge` when the operator
/// passes `--trust-proxy-headers`.
pub fn set_trust_proxy_headers(v: bool) {
    TRUST_PROXY_HEADERS.store(v, std::sync::atomic::Ordering::Relaxed);
}

fn trust_proxy_headers() -> bool {
    TRUST_PROXY_HEADERS.load(std::sync::atomic::Ordering::Relaxed)
}

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
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP client closed POST channel",
            )
        })?;
        if bytes.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "HTTP packet too large: {} > buffer {}",
                    bytes.len(),
                    buf.len()
                ),
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
        let per_ip: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let cap_per_ip = DEFAULT_HTTP_CONNS_PER_IP;
        let handle = tokio::spawn(accept_loop(
            listener, actual, nct, registry, per_ip, cap_per_ip,
        ));
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

/// Body type returned by every hyper service branch. Boxed so
/// the streaming SSE branch and the empty / error branches share
/// a single return type.
type RespBody = BoxBody<Bytes, io::Error>;

fn empty_body() -> RespBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

async fn accept_loop(
    listener: TcpListener,
    local: SocketAddr,
    new_clients_tx: mpsc::Sender<Arc<dyn PacketIO>>,
    registry: Registry,
    per_ip: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>>,
    cap_per_ip: usize,
) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "HTTP accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let ip = peer.ip();
        // Per-IP connection cap (mirror TcpListenerIO). When
        // running behind a trusted reverse proxy
        // (`--trust-proxy-headers`), skip — every connection
        // comes from the proxy's IP and the proxy is expected
        // to enforce its own rate limits.
        let admitted = if trust_proxy_headers() {
            true
        } else {
            let mut map = per_ip.lock().unwrap();
            let count = map.entry(ip).or_insert(0);
            if *count >= cap_per_ip {
                false
            } else {
                *count += 1;
                true
            }
        };
        if !admitted {
            drop(tcp);
            tracing::debug!(
                src = %ip,
                cap = cap_per_ip,
                "http accept: per-ip cap reached, refusing connection"
            );
            continue;
        }
        let _ = tcp.set_nodelay(true);
        let guard = ConnGuard::new(per_ip.clone(), ip);
        let registry = registry.clone();
        let nct = new_clients_tx.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(tcp);
            let svc = service_fn(move |req: Request<Incoming>| {
                let registry = registry.clone();
                let nct = nct.clone();
                async move { Ok::<_, Infallible>(handle_request(req, peer, local, registry, nct).await) }
            });
            // SEC.PEN.HIGH-1: header_read_timeout bounds the
            // time hyper waits for the request line + headers.
            // A client that opens a TCP connection and stalls
            // before sending the first request will be dropped.
            // The per-IP cap above is the second line of defense.
            let conn = hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .timer(TokioTimer::new())
                .header_read_timeout(HTTP_HEADER_READ_TIMEOUT)
                .serve_connection(io, svc);
            if let Err(e) = conn.await {
                tracing::debug!(?peer, error = ?e, "http1 connection ended");
            }
            drop(guard);
        });
    }
}

// ─── Request dispatch ─────────────────────────────────────────────

async fn handle_request(
    req: Request<Incoming>,
    peer: SocketAddr,
    local: SocketAddr,
    registry: Registry,
    new_clients_tx: mpsc::Sender<Arc<dyn PacketIO>>,
) -> Response<RespBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    match (method.as_str(), path.as_str()) {
        ("GET", "/drift-sse") => handle_sse(peer, local, registry, new_clients_tx).await,
        ("POST", "/drift-send") => handle_post(req, query, registry).await,
        ("OPTIONS", _) => cors_preflight(),
        _ => stock_response(StatusCode::NOT_FOUND),
    }
}

fn cors_preflight() -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .header("Content-Length", "0")
        .body(empty_body())
        .unwrap()
}

fn stock_response(status: StatusCode) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header("Access-Control-Allow-Origin", "*")
        .header("Content-Length", "0")
        .body(empty_body())
        .unwrap()
}

// ─── Server-sent events stream (downstream) ──────────────────────

async fn handle_sse(
    peer: SocketAddr,
    local: SocketAddr,
    registry: Registry,
    new_clients_tx: mpsc::Sender<Arc<dyn PacketIO>>,
) -> Response<RespBody> {
    let sid: u64 = rand::random();
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(16);

    {
        let mut reg = registry.lock().await;
        reg.insert(sid, ClientQueues { inbound_tx: in_tx });
    }

    let io_handle: Arc<dyn PacketIO> = Arc::new(HttpPacketIO {
        inbound_rx: Mutex::new(in_rx),
        outbound_tx: out_tx,
        peer_addr: peer,
        local_addr: local,
    });
    if new_clients_tx.send(io_handle).await.is_err() {
        registry.lock().await.remove(&sid);
        return stock_response(StatusCode::SERVICE_UNAVAILABLE);
    }

    // SSE response body: a stream of `Frame<Bytes>` chunks. The
    // formatter task below drains `out_rx` (packets from
    // HttpPacketIO::send_to), encodes each as one `data:
    // <base64>\n\n` SSE event, and forwards through `body_tx`.
    // Hyper drives the response body by pulling frames out of
    // the receiver as the underlying socket has buffer space.
    //
    // When `body_tx` is dropped (the formatter task exits OR the
    // client disconnects so hyper drops the receiver), the
    // ReceiverStream ends and hyper closes the response.
    let (body_tx, body_rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(8);

    let registry_cleanup = registry.clone();
    tokio::spawn(async move {
        // First event: SID handshake — paired with the client's
        // `drain_events` SID parse on the connector side.
        let sid_event = Bytes::from(format!("data: SID:{:016x}\n\n", sid));
        if body_tx.send(Ok(Frame::data(sid_event))).await.is_err() {
            registry_cleanup.lock().await.remove(&sid);
            return;
        }

        // Drain outbound queue → batched SSE events. Same
        // opportunistic-drain pattern the hand-rolled version
        // used: block for the first packet, drain any pending
        // packets up to 32 into one buffer, send as one Frame.
        // Hyper takes care of the TCP-level flush.
        let mut scratch = Vec::with_capacity(8192);
        while let Some(first) = out_rx.recv().await {
            scratch.clear();
            let append = |pkt: &[u8], buf: &mut Vec<u8>| {
                let encoded = general_purpose::STANDARD_NO_PAD.encode(pkt);
                buf.extend_from_slice(b"data: ");
                buf.extend_from_slice(encoded.as_bytes());
                buf.extend_from_slice(b"\n\n");
            };
            append(&first, &mut scratch);
            for _ in 0..31 {
                match out_rx.try_recv() {
                    Ok(next) => append(&next, &mut scratch),
                    Err(_) => break,
                }
            }
            let frame = Frame::data(Bytes::copy_from_slice(&scratch));
            if body_tx.send(Ok(frame)).await.is_err() {
                break; // client disconnected
            }
        }
        // Stale sid would otherwise accept POSTs forever.
        registry_cleanup.lock().await.remove(&sid);
    });

    let body = StreamBody::new(ReceiverStream::new(body_rx)).boxed();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .header("Access-Control-Allow-Origin", "*")
        .body(body)
        .unwrap()
}

// ─── POST upstream ────────────────────────────────────────────────

async fn handle_post(
    req: Request<Incoming>,
    query: String,
    registry: Registry,
) -> Response<RespBody> {
    let Some(sid) = parse_sid(&query) else {
        return stock_response(StatusCode::BAD_REQUEST);
    };
    // Bound the body read at MAX_POST_BODY. http_body_util's
    // `Limited` errors out cleanly once the limit is exceeded,
    // which we translate to 413.
    let limited = http_body_util::Limited::new(req.into_body(), MAX_POST_BODY);
    let body_bytes = match limited.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return stock_response(StatusCode::PAYLOAD_TOO_LARGE),
    };

    let queues = { registry.lock().await.get(&sid).cloned() };
    let Some(queues) = queues else {
        return stock_response(StatusCode::NOT_FOUND);
    };
    let _ = queues.inbound_tx.send(body_bytes.to_vec()).await;
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Length", "0")
        .header("Access-Control-Allow-Origin", "*")
        .body(empty_body())
        .unwrap()
}

fn parse_sid(query: &str) -> Option<u64> {
    for kv in query.split('&') {
        if let Some(("sid", v)) = kv.split_once('=') {
            return u64::from_str_radix(v, 16).ok();
        }
    }
    None
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

/// Internal: spawned task that drains the SSE stream into the
/// `inbound` channel. Each `data: <base64>\n\n` event becomes one
/// packet pushed onto the channel.
///
/// `initial_leftover` carries any bytes that arrived in the
/// SID-bootstrap chunk but weren't consumed by SID parsing. These
/// can include a complete subsequent event (e.g. the bridge bundles
/// SID + HELLO_ACK in one HTTP chunk) — so we drain `leftover`
/// FIRST, before blocking on the next chunk. Without this, the
/// pre-loaded events sit unprocessed until the next-chunk poll,
/// which can stall the entire handshake on a chatty bridge that
/// pauses between events.
async fn sse_pump<S>(
    mut byte_stream: S,
    initial_leftover: Vec<u8>,
    inbound: tokio::sync::mpsc::Sender<Vec<u8>>,
) where
    S: futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin + Send,
{
    let mut leftover = initial_leftover;
    use futures_util::StreamExt;

    // Drain any pre-loaded events first. This handles the case
    // where the bridge's first HTTP chunk carries SID + at least
    // one DATA event together.
    drain_events(&mut leftover, &inbound).await;
    if inbound.is_closed() {
        return;
    }

    while let Some(chunk_res) = byte_stream.next().await {
        let chunk = match chunk_res {
            Ok(c) => c,
            Err(_) => return,
        };
        leftover.extend_from_slice(&chunk);
        drain_events(&mut leftover, &inbound).await;
        if inbound.is_closed() {
            return;
        }
    }
}

/// Drain every complete SSE event from `leftover` and push each
/// decoded DRIFT packet onto `inbound`. Returns when there are no
/// more complete events to drain.
async fn drain_events(leftover: &mut Vec<u8>, inbound: &tokio::sync::mpsc::Sender<Vec<u8>>) {
    loop {
        let Some(boundary) = find_event_boundary(leftover) else {
            return;
        };
        let event_bytes: Vec<u8> = leftover.drain(..boundary.end).collect();
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
            // bootstrap path, not here. Subsequent events are
            // base64-encoded DRIFT packets.
            if let Some(_sid) = payload.strip_prefix("SID:") {
                continue;
            }
            // Server encodes with STANDARD_NO_PAD (see
            // `handle_sse` above) — match it. The padding-strict
            // STANDARD decoder would silently reject every event,
            // which is exactly the bug this comment exists to
            // prevent recurring.
            let bytes =
                match base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload.as_bytes()) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
            if inbound.send(bytes).await.is_err() {
                return; // receiver dropped
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
) -> Pin<Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str).await?;
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
        let resp = client
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
                    return Err(io::Error::other("SSE stream ended before SID handshake"));
                }
            };
            accum.extend_from_slice(&chunk);
            // Look for the first `\n\n`-terminated event and try
            // to parse it as SID.
            if let Some(boundary) = find_event_boundary(&accum) {
                let event_bytes: Vec<u8> = accum.drain(..boundary.end).collect();
                let event_str = std::str::from_utf8(&event_bytes).map_err(io::Error::other)?;
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
