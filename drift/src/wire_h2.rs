//! `h2://` — drift packets over a single HTTP/2 bidirectional stream pair.
//!
//! Built for federation between drift bridges. Two bridges open one
//! HTTP/2 connection (one TCP + optional TLS) and exchange drift
//! packets as length-prefixed frames over the request body
//! (client → server) and response body (server → client). The
//! single connection multiplexes the federation for the lifetime
//! of the link.
//!
//! Wire shape:
//!
//!   Method:   POST  /drift-fed
//!   Both bodies stream `[len:u16 BE][packet bytes]` repeats.
//!
//! Versus the `http://` adapter (POST per packet + SSE long-poll):
//!   - no per-packet HTTP request overhead
//!   - no base64 (drift bytes flow as raw HTTP/2 DATA frame payload)
//!   - true bidirectional, no asymmetric POST+SSE pattern
//!   - one TCP + (optionally one TLS) handshake total, not per packet
//!
//! Versus `tcp://` federation:
//!   - looks like normal HTTP/2 to middleboxes (port 443 + ALPN h2),
//!     so it survives proxies/firewalls that block raw TCP
//!   - multiplexes alongside any other HTTP/2 traffic on the same
//!     connection (future hook for control / telemetry streams)
//!   - real TLS via standard cert tooling when desired
//!
//! Cleartext h2 (h2c) by default for direct bridge-to-bridge. For
//! TLS, put caddy / nginx in front and configure ALPN h2 — the
//! drift bridge stays h2c on the backend, the proxy handles TLS.
//! (Same pattern as `http://` + reverse proxy from docs/reverse-proxy.md.)

use crate::io::{parse_ip_addr, Listener, PacketIO, SchemeRegistration};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http_body_util::{combinators::BoxBody, BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;

/// Length-prefix framing: 2 bytes BE, then `len` packet bytes.
/// Same shape as the TCP / TLS adapters use, so debugging across
/// `tcp://` and `h2://` reads the same.
const FRAME_LEN_PREFIX: usize = 2;
/// Hard cap on a single drift packet over h2. Drift's own
/// MAX_PAYLOAD is well under this; we cap just to bound buffer
/// growth.
const MAX_H2_FRAME: usize = 65535;

/// Bounded channels keep per-stream memory in a predictable
/// range; backpressure is real if either direction stalls.
const SEND_QUEUE_DEPTH: usize = 256;
const RECV_QUEUE_DEPTH: usize = 256;

type RespBody = BoxBody<Bytes, io::Error>;

// ─── PacketIO over an h2 stream pair ──────────────────────────────

/// Wraps one HTTP/2 bidirectional stream as a `PacketIO`. The
/// listener side and the connector side both produce one of
/// these per accepted / opened connection. From here on the
/// drift transport doesn't distinguish h2 from raw TCP.
pub struct H2StreamPacketIO {
    /// Caller's outbound bytes flow into this channel; the
    /// `body_pump` task drains it and writes framed packets
    /// into the HTTP/2 body stream.
    send_tx: mpsc::Sender<Bytes>,
    /// Inbound framed packets land here after the `body_drain`
    /// task parses them from the remote's HTTP/2 body stream.
    recv_rx: Mutex<mpsc::Receiver<Bytes>>,
    /// The peer's view of "where we are." For client-side
    /// wraps this is the bridge's TCP address; for server-side
    /// wraps it's the connecting peer's TCP address.
    addr: SocketAddr,
}

impl H2StreamPacketIO {
    pub fn new(
        send_tx: mpsc::Sender<Bytes>,
        recv_rx: mpsc::Receiver<Bytes>,
        addr: SocketAddr,
    ) -> Self {
        Self {
            send_tx,
            recv_rx: Mutex::new(recv_rx),
            addr,
        }
    }
}

#[async_trait]
impl PacketIO for H2StreamPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        if buf.len() > MAX_H2_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("h2 packet too large: {} > {}", buf.len(), MAX_H2_FRAME),
            ));
        }
        // Frame on the way out so the remote's `body_drain` can
        // parse without re-allocating per packet.
        let mut framed = BytesMut::with_capacity(FRAME_LEN_PREFIX + buf.len());
        framed.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        framed.extend_from_slice(buf);
        self.send_tx
            .send(framed.freeze())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "h2 send pump gone"))?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.recv_rx.lock().await;
        let bytes = rx.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "h2 stream closed")
        })?;
        if bytes.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("h2 packet larger than caller buffer: {} > {}", bytes.len(), buf.len()),
            ));
        }
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), self.addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

// ─── Helpers: drain an HTTP/2 body stream into framed packets ─────

/// Reads `Incoming` body frames, accumulates bytes, and splits
/// them on the 2-byte length prefix. Each whole drift packet
/// gets pushed to `tx`. Returns when the stream ends or `tx`
/// is dropped.
async fn drain_h2_body_into_packets(
    mut body: Incoming,
    tx: mpsc::Sender<Bytes>,
) {
    use http_body_util::BodyExt;
    let mut acc = BytesMut::with_capacity(8192);
    loop {
        let frame = match body.frame().await {
            Some(Ok(f)) => f,
            Some(Err(e)) => {
                tracing::debug!(error = ?e, "h2 body frame error; ending pump");
                return;
            }
            None => return, // peer closed
        };
        if let Some(data) = frame.data_ref() {
            acc.extend_from_slice(data);
            while acc.len() >= FRAME_LEN_PREFIX {
                let len = u16::from_be_bytes([acc[0], acc[1]]) as usize;
                if len > MAX_H2_FRAME {
                    tracing::warn!(len, "h2 frame oversized; closing stream");
                    return;
                }
                if acc.len() < FRAME_LEN_PREFIX + len {
                    break; // need more bytes
                }
                // Drop the prefix, take the body.
                let _ = acc.split_to(FRAME_LEN_PREFIX);
                let pkt = acc.split_to(len).freeze();
                if tx.send(pkt).await.is_err() {
                    return; // consumer dropped
                }
            }
        }
    }
}

// ─── Listener ─────────────────────────────────────────────────────

/// `h2://` listener: standard hyper http2 server bound on a TCP
/// socket. Each accepted POST /drift-fed becomes one
/// `H2StreamPacketIO` handed back through the `Listener::accept`
/// channel.
pub struct H2ListenerIO {
    local_addr: SocketAddr,
    ready_rx: Mutex<mpsc::Receiver<Arc<dyn PacketIO>>>,
    _accept_task: tokio::task::JoinHandle<()>,
}

impl H2ListenerIO {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let (ready_tx, ready_rx) = mpsc::channel::<Arc<dyn PacketIO>>(16);

        let accept_task = tokio::spawn(async move {
            loop {
                let (tcp, peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!(error = %e, "h2 accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);
                let ready_tx = ready_tx.clone();
                tokio::spawn(async move {
                    serve_one_h2_connection(tcp, peer, ready_tx).await;
                });
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
impl Listener for H2ListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    fn is_multi(&self) -> bool {
        true
    }
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        let mut rx = self.ready_rx.lock().await;
        rx.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "h2 listener closed")
        })
    }
}

async fn serve_one_h2_connection(
    tcp: TcpStream,
    peer: SocketAddr,
    ready_tx: mpsc::Sender<Arc<dyn PacketIO>>,
) {
    let io = TokioIo::new(tcp);
    let svc = service_fn(move |req: Request<Incoming>| {
        let ready_tx = ready_tx.clone();
        async move {
            Ok::<_, Infallible>(handle_h2_request(req, peer, ready_tx).await)
        }
    });
    let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .serve_connection(io, svc);
    if let Err(e) = conn.await {
        tracing::debug!(?peer, error = ?e, "h2 connection ended");
    }
}

async fn handle_h2_request(
    req: Request<Incoming>,
    peer: SocketAddr,
    ready_tx: mpsc::Sender<Arc<dyn PacketIO>>,
) -> Response<RespBody> {
    if req.method() != hyper::Method::POST || req.uri().path() != "/drift-fed" {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())
            .unwrap();
    }
    // Inbound channel: parse incoming request body into packets,
    // hand to the new PacketIO.
    let (in_tx, in_rx) = mpsc::channel::<Bytes>(RECV_QUEUE_DEPTH);
    // Outbound channel: PacketIO writes packets here; we drain
    // into the response body.
    let (out_tx, out_rx) = mpsc::channel::<Bytes>(SEND_QUEUE_DEPTH);

    let body = req.into_body();
    tokio::spawn(drain_h2_body_into_packets(body, in_tx));

    let io_handle: Arc<dyn PacketIO> = Arc::new(H2StreamPacketIO::new(out_tx, in_rx, peer));
    if ready_tx.send(io_handle).await.is_err() {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(empty_body())
            .unwrap();
    }

    // Build a streaming response body fed by `out_rx`.
    let response_stream =
        ReceiverStream::new(out_rx).map(|chunk| Ok::<_, io::Error>(Frame::data(chunk)));
    let body = BodyExt::boxed(StreamBody::new(response_stream));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(body)
        .unwrap()
}

fn empty_body() -> RespBody {
    use http_body_util::Empty;
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

// ─── Connector ────────────────────────────────────────────────────

async fn connect_h2_client(
    addr: SocketAddr,
) -> io::Result<(Arc<dyn PacketIO>, SocketAddr)> {
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    let io = TokioIo::new(tcp);

    // Set up the HTTP/2 client connection. http2::handshake gives
    // us the SendRequest handle to issue our single POST.
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .handshake::<_, StreamBody<Pin<Box<dyn futures_util::Stream<Item = Result<Frame<Bytes>, io::Error>> + Send>>>>(io)
        .await
        .map_err(io::Error::other)?;

    // The connection future drives the underlying HTTP/2 frame
    // machine. Spawn it; it ends when either side closes.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = ?e, "h2 client connection ended");
        }
    });

    let (out_tx, out_rx) = mpsc::channel::<Bytes>(SEND_QUEUE_DEPTH);
    let (in_tx, in_rx) = mpsc::channel::<Bytes>(RECV_QUEUE_DEPTH);

    // Outbound: drain out_rx into a stream of Frame<Bytes> that
    // becomes the request body.
    let body_stream: Pin<
        Box<dyn futures_util::Stream<Item = Result<Frame<Bytes>, io::Error>> + Send>,
    > = Box::pin(
        ReceiverStream::new(out_rx).map(|chunk| Ok::<_, io::Error>(Frame::data(chunk))),
    );
    let req_body = StreamBody::new(body_stream);

    let req = Request::builder()
        .method(hyper::Method::POST)
        .uri("/drift-fed")
        .header("host", format!("{}:{}", addr.ip(), addr.port()))
        .header("content-type", "application/octet-stream")
        .body(req_body)
        .map_err(io::Error::other)?;

    let resp = sender.send_request(req).await.map_err(io::Error::other)?;
    if !resp.status().is_success() {
        return Err(io::Error::other(format!(
            "h2 POST /drift-fed failed: HTTP {}",
            resp.status()
        )));
    }

    // Inbound: parse the response body into packets pushed to in_tx.
    let resp_body = resp.into_body();
    tokio::spawn(drain_h2_body_into_packets(resp_body, in_tx));

    let io_handle: Arc<dyn PacketIO> = Arc::new(H2StreamPacketIO::new(out_tx, in_rx, addr));
    Ok((io_handle, addr))
}

// ─── Scheme registration ──────────────────────────────────────────

fn h2_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str).await?;
        Ok(Box::new(H2ListenerIO::bind(addr).await?) as Box<dyn Listener>)
    })
}

fn h2_connector_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str).await?;
        connect_h2_client(addr).await
    })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "h2",
        listener: h2_listener_factory,
        connector: h2_connector_factory,
    }
}

// futures-util re-export so the StreamExt usage above compiles
// without an explicit import in users of this module.
use futures_util::StreamExt;
