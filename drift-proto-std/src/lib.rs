//! `drift-proto-std` — a synchronous, runtime-free driver for the
//! sans-IO DRIFT engine ([`drift_proto::Endpoint`]).
//!
//! The engine is bytes-in/bytes-out with no sockets and no executor.
//! This crate is the thin, **blocking** I/O shell that turns it into
//! a usable client/server over `std::net::TcpStream`, using the same
//! native `tcp://` 2-byte big-endian length framing as the tokio
//! transport's TCP adapter — so a `drift-proto-std` peer talks to any
//! native drift node directly.
//!
//! It exists so portable tools (Redox, embedded-ish std targets, any
//! place tokio won't build) don't each hand-roll the same framing +
//! poll loop. It pulls in **no tokio, no async** — only `std` and
//! `drift-proto`, so it compiles wherever those do.
//!
//! # Model
//! [`Connection`] is a **datagram** channel, mirroring the engine: a
//! [`Connection::send`] of more than [`MAX_PAYLOAD`] bytes is split
//! across multiple DATA datagrams, and [`Connection::recv`] returns
//! one DATA payload at a time. This crate imposes **no** message
//! framing of its own — that is deliberate, so the bytes on the wire
//! stay byte-identical to native drift DATA. If you need message
//! boundaries for payloads larger than [`MAX_PAYLOAD`], add your own
//! length prefix at the application layer (e.g. `LEN\n` then body).
//!
//! # Example (request / response)
//! ```no_run
//! use drift_proto_std::{Connection, Config, Identity, server_config};
//! use std::net::TcpListener;
//!
//! // Server: accept one session, echo the first datagram.
//! let listener = TcpListener::bind("127.0.0.1:9100").unwrap();
//! std::thread::spawn(move || {
//!     let (stream, _) = listener.accept().unwrap();
//!     let id = Identity::from_secret_bytes([0x5d; 32]);
//!     let mut conn = Connection::accept(stream, id, server_config()).unwrap();
//!     if let Some(req) = conn.recv().unwrap() {
//!         conn.send(&req).unwrap();
//!     }
//!     let _ = conn.recv(); // linger until the client closes
//! });
//!
//! // Client: dial, send, read the echo.
//! let server_pub = Identity::from_secret_bytes([0x5d; 32]).public_bytes();
//! let id = Identity::from_secret_bytes([0xc1; 32]);
//! let mut conn = Connection::connect("127.0.0.1:9100", server_pub, id, Config::default()).unwrap();
//! conn.send(b"hello").unwrap();
//! assert_eq!(conn.recv().unwrap().as_deref(), Some(&b"hello"[..]));
//! conn.close().unwrap();
//! ```

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub use drift_proto::{derive_peer_id, Config, Endpoint, Event, Identity, PeerId, MAX_PAYLOAD};

/// How often the blocking read unblocks so the loop can drive the
/// engine's timers (handshake retransmits, rekey, etc.).
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Default ceiling on a single [`Connection::recv`] before it returns
/// a timeout error, so a hung peer can't block a tool forever.
pub const DEFAULT_RECV_TIMEOUT: Duration = Duration::from_secs(120);

// ── framing: native drift tcp:// 2-byte BE length prefix ─────────

/// Frame an engine datagram with the native `tcp://` length prefix
/// and write it to the stream.
pub fn write_packet(s: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    debug_assert!(data.len() <= u16::MAX as usize);
    let mut framed = Vec::with_capacity(2 + data.len());
    framed.extend_from_slice(&(data.len() as u16).to_be_bytes());
    framed.extend_from_slice(data);
    s.write_all(&framed)
}

/// Incremental length-prefix frame parser. Survives mid-frame read
/// timeouts (a blocking `read_exact` with a timeout would lose the
/// partial bytes), so the caller can poll with a short read timeout
/// and still reassemble whole datagrams.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Pull whatever bytes are available. Returns `Ok(false)` on EOF;
    /// a read timeout / `WouldBlock` returns `Ok(true)` with no new
    /// data so the caller can drive timers and retry.
    pub fn fill(&mut self, s: &mut TcpStream) -> io::Result<bool> {
        let mut tmp = [0u8; 4096];
        match s.read(&mut tmp) {
            Ok(0) => Ok(false),
            Ok(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    /// Extract the next complete datagram, if one is fully buffered.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
        if self.buf.len() < 2 + len {
            return None;
        }
        let frame = self.buf[2..2 + len].to_vec();
        self.buf.drain(..2 + len);
        Some(frame)
    }
}

// ── helpers ──────────────────────────────────────────────────────

/// The engine's `SocketAddr` arguments are bookkeeping only when the
/// transport is a single TCP pipe; a fixed placeholder is fine (same
/// trick the WASM and Redox drivers use).
pub fn wire_addr() -> SocketAddr {
    SocketAddr::from(([1, 1, 1, 1], 1))
}

/// A server [`Config`] that accepts any well-formed peer (no static
/// allowlist). Callers that need mutual auth should instead build a
/// [`Config`] with an explicit allowlist and leave `accept_any_peer`
/// off.
pub fn server_config() -> Config {
    Config {
        accept_any_peer: true,
        ..Config::default()
    }
}

/// Dial `addr`, retrying for a while — for hosts (e.g. Redox at boot)
/// whose networking isn't up the instant a tool starts.
pub fn connect_retry(addr: &str, attempts: u32, gap: Duration) -> io::Result<TcpStream> {
    let mut last = None;
    for _ in 0..attempts.max(1) {
        match TcpStream::connect(addr) {
            Ok(c) => return Ok(c),
            Err(e) => {
                last = Some(e);
                thread::sleep(gap);
            }
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("connect_retry: no attempts")))
}

/// Bind a [`std::net::TcpListener`], retrying — for Redox DHCP/boot
/// timing and to ride out a fast service restart racing the rebind.
/// Bind a **specific** interface IP on Redox: smolnetd RSTs all
/// inbound on a wildcard (`0.0.0.0`) bind.
pub fn bind_retry(bind: &str, attempts: u32, gap: Duration) -> io::Result<std::net::TcpListener> {
    let mut last = None;
    for _ in 0..attempts.max(1) {
        match std::net::TcpListener::bind(bind) {
            Ok(l) => return Ok(l),
            Err(e) => {
                last = Some(e);
                thread::sleep(gap);
            }
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("bind_retry: no attempts")))
}

// ── Connection ───────────────────────────────────────────────────

/// A single established (or establishing) DRIFT session over one TCP
/// connection — a blocking datagram channel.
///
/// Client side: [`connect`](Connection::connect) and you may
/// [`send`](Connection::send) immediately (payloads park until the
/// handshake completes). Server side:
/// [`accept`](Connection::accept) a stream from a listener, then
/// [`recv`](Connection::recv) the first request — which is also what
/// drives the handshake and learns the peer id, so you can reply.
pub struct Connection {
    ep: Endpoint,
    stream: TcpStream,
    reader: FrameReader,
    /// Known immediately on the client (from `connect`); learned on
    /// the server when the session establishes (first DATA).
    peer: Option<PeerId>,
    established: bool,
    closed: bool,
    handshake_failed: bool,
    rx: VecDeque<Vec<u8>>,
    recv_timeout: Duration,
}

impl Connection {
    fn wrap(ep: Endpoint, stream: TcpStream, peer: Option<PeerId>) -> io::Result<Self> {
        stream.set_read_timeout(Some(POLL_INTERVAL))?;
        Ok(Self {
            ep,
            stream,
            reader: FrameReader::new(),
            peer,
            established: false,
            closed: false,
            handshake_failed: false,
            rx: VecDeque::new(),
            recv_timeout: DEFAULT_RECV_TIMEOUT,
        })
    }

    /// Dial `addr` and start a session to the server identified by
    /// `server_pub` (its 32-byte static public key). Returns as soon
    /// as the HELLO is on the wire; the handshake finishes lazily on
    /// the first [`send`](Self::send)/[`recv`](Self::recv). Use
    /// [`wait_established`](Self::wait_established) to block for it.
    pub fn connect(
        addr: &str,
        server_pub: [u8; 32],
        identity: Identity,
        config: Config,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        let mut ep = Endpoint::new(identity, config);
        let peer = ep.connect(Instant::now(), server_pub, wire_addr());
        let mut conn = Self::wrap(ep, stream, Some(peer))?;
        conn.flush()?; // emit the initial HELLO
        Ok(conn)
    }

    /// Wrap an already-accepted inbound `stream` (from a
    /// [`std::net::TcpListener`]) as the responder. The peer id is
    /// unknown until the first [`recv`](Self::recv) completes the
    /// handshake.
    pub fn accept(stream: TcpStream, identity: Identity, config: Config) -> io::Result<Self> {
        let ep = Endpoint::new(identity, config);
        Self::wrap(ep, stream, None)
    }

    /// The remote peer id, once known (immediately on the client,
    /// after the first established DATA on the server).
    pub fn peer(&self) -> Option<PeerId> {
        self.peer
    }

    /// Whether the session has reached `Established`.
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// Override the per-[`recv`](Self::recv) timeout (default
    /// [`DEFAULT_RECV_TIMEOUT`]).
    pub fn set_recv_timeout(&mut self, d: Duration) {
        self.recv_timeout = d;
    }

    /// Send `data` as one or more DATA datagrams. Buffers larger than
    /// [`MAX_PAYLOAD`] are split; the peer receives each chunk as a
    /// separate [`recv`](Self::recv). No message framing is added —
    /// layer your own if you need boundaries. Empty `data` is a no-op.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let peer = self.peer.ok_or_else(|| {
            io::Error::new(
                ErrorKind::NotConnected,
                "no peer yet (server must recv a request first)",
            )
        })?;
        let now = Instant::now();
        for chunk in data.chunks(MAX_PAYLOAD) {
            self.ep
                .send(now, &peer, chunk, 0, 0)
                .map_err(|e| io::Error::other(format!("drift send: {e}")))?;
        }
        self.flush()
    }

    /// Block until the next DATA payload arrives. Returns `Ok(None)`
    /// when the peer closes the session cleanly, or a timeout error
    /// after `recv_timeout` with no traffic.
    pub fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + self.recv_timeout;
        loop {
            if let Some(p) = self.rx.pop_front() {
                return Ok(Some(p));
            }
            if self.handshake_failed {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "drift handshake timed out",
                ));
            }
            if self.closed {
                return Ok(None);
            }
            if !self.pump()? {
                // socket EOF; surface any payload buffered before it.
                return Ok(self.rx.pop_front());
            }
            if Instant::now() > deadline {
                return Err(io::Error::new(ErrorKind::TimedOut, "drift recv timed out"));
            }
        }
    }

    /// Drive the handshake to completion (or failure), blocking up to
    /// `recv_timeout`. Useful when a tool wants a confirmed session
    /// before doing work.
    pub fn wait_established(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + self.recv_timeout;
        while !self.established {
            if self.handshake_failed {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "drift handshake timed out",
                ));
            }
            if self.closed || !self.pump()? {
                return Err(io::Error::new(
                    ErrorKind::NotConnected,
                    "closed before established",
                ));
            }
            if Instant::now() > deadline {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "drift handshake timed out",
                ));
            }
        }
        Ok(())
    }

    /// Send an authenticated Close and flush it. The session is done;
    /// drop the `Connection` afterwards.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(peer) = self.peer {
            let _ = self.ep.close(&peer);
            self.flush()?;
        }
        self.closed = true;
        Ok(())
    }

    /// One non-blocking-ish iteration: flush queued transmits, read
    /// whatever is available, feed it to the engine, harvest events.
    /// Returns `Ok(false)` on socket EOF.
    fn pump(&mut self) -> io::Result<bool> {
        self.flush()?;
        if !self.reader.fill(&mut self.stream)? {
            self.closed = true;
            return Ok(false);
        }
        let now = Instant::now();
        while let Some(frame) = self.reader.next_frame() {
            // A malformed/foreign datagram is dropped by the engine,
            // not fatal to the session.
            let _ = self.ep.handle_datagram(now, wire_addr(), &frame);
        }
        self.ep.handle_timeout(now);
        while let Some(ev) = self.ep.poll_event() {
            match ev {
                Event::Connected { peer } => {
                    self.peer = Some(peer);
                    self.established = true;
                }
                Event::Data { payload, .. } => self.rx.push_back(payload),
                Event::Closed { .. } => self.closed = true,
                Event::HandshakeTimedOut { .. } => self.handshake_failed = true,
            }
        }
        self.flush()?; // push out HELLO_ACK / DATA / Close generated above
        Ok(true)
    }

    fn flush(&mut self) -> io::Result<()> {
        while let Some(t) = self.ep.poll_transmit() {
            write_packet(&mut self.stream, &t.contents)?;
        }
        Ok(())
    }
}

// ── Session (full-duplex) ────────────────────────────────────────

/// A full-duplex DRIFT session: data flows both directions at once,
/// driven by two threads sharing one engine. Use this for interactive
/// or streaming tools — a remote shell, a tunnel / port-forward, a
/// chat — where you can't predict whose turn it is to talk. For
/// request/response tools, [`Connection`] is simpler.
///
/// The engine is a single `&mut self` state machine, so it lives
/// behind a mutex. [`SessionSender`] (from [`sender`](Session::sender))
/// is a cloneable, `Send` handle any thread can transmit on, while
/// [`pump`](Session::pump) runs the receive side on the current
/// thread. [`pipe`](Session::pipe) wires both to ordinary
/// [`Read`]/[`Write`] handles in one call.
///
/// # Example (the remote-shell shape)
/// ```no_run
/// use drift_proto_std::{Session, Config, Identity, server_config};
/// use std::net::TcpListener;
/// use std::process::{Command, Stdio};
///
/// // Server: pipe an engine session <-> /bin/sh.
/// let listener = TcpListener::bind("127.0.0.1:9200").unwrap();
/// let (stream, _) = listener.accept().unwrap();
/// let mut sh = Command::new("/bin/sh")
///     .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
/// let (sh_in, sh_out) = (sh.stdin.take().unwrap(), sh.stdout.take().unwrap());
/// let session = Session::accept(stream, Identity::from_secret_bytes([0x5d; 32]), server_config()).unwrap();
/// session.pipe(sh_out, sh_in).unwrap(); // sh stdout -> peer, peer -> sh stdin
/// let _ = sh.kill();                     // release the detached reader thread
/// ```
pub struct Session {
    inner: Arc<SessionInner>,
    /// Read half of the socket (a `try_clone`), owned by whoever runs
    /// the receive [`pump`](Session::pump).
    reader: TcpStream,
}

struct SessionInner {
    ep: Mutex<Endpoint>,
    sock: Mutex<TcpStream>, // write half
    peer: Mutex<Option<PeerId>>,
    established: AtomicBool,
    done: AtomicBool,
}

/// A cloneable, `Send` transmit handle for a [`Session`]. Any number
/// of threads may hold one and [`send`](SessionSender::send) on it.
#[derive(Clone)]
pub struct SessionSender {
    inner: Arc<SessionInner>,
}

impl SessionInner {
    fn flush(&self) -> io::Result<()> {
        // Collect transmits under the engine lock, then write them
        // under the socket lock — never hold both at once.
        let mut out = Vec::new();
        {
            let mut ep = self.ep.lock().unwrap();
            while let Some(t) = ep.poll_transmit() {
                out.push(t.contents);
            }
        }
        let mut sock = self.sock.lock().unwrap();
        for c in out {
            write_packet(&mut sock, &c)?;
        }
        Ok(())
    }

    /// Send an authenticated Close once established, then mark done.
    /// Tolerates a fast input EOF racing the handshake (`close` fails
    /// until established) by retrying briefly.
    fn close_when_idle(&self) {
        for _ in 0..400 {
            // ~10 s budget for the handshake to complete.
            let peer = *self.peer.lock().unwrap();
            if let Some(p) = peer {
                if self.ep.lock().unwrap().close(&p).is_ok() {
                    let _ = self.flush();
                    break;
                }
            }
            if self.done.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        self.done.store(true, Ordering::SeqCst);
    }
}

impl SessionSender {
    /// Transmit `data` (split across DATA datagrams if larger than
    /// [`MAX_PAYLOAD`]). Blocks until the handshake establishes if it
    /// hasn't yet — the input source may produce bytes first. Errors
    /// once the session is closed.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        let peer = loop {
            if let Some(p) = *self.inner.peer.lock().unwrap() {
                break p;
            }
            if self.inner.done.load(Ordering::SeqCst) {
                return Err(io::Error::other("session closed before established"));
            }
            thread::sleep(Duration::from_millis(25));
        };
        {
            let mut ep = self.inner.ep.lock().unwrap();
            for chunk in data.chunks(MAX_PAYLOAD) {
                ep.send(Instant::now(), &peer, chunk, 0, 0)
                    .map_err(|e| io::Error::other(format!("drift send: {e}")))?;
            }
        }
        self.inner.flush()
    }

    /// Send an authenticated Close; ends the peer's
    /// [`pump`](Session::pump).
    pub fn close(&self) {
        self.inner.close_when_idle();
    }

    /// Whether the session has ended.
    pub fn is_done(&self) -> bool {
        self.inner.done.load(Ordering::SeqCst)
    }
}

impl Session {
    fn wrap(ep: Endpoint, stream: TcpStream, peer: Option<PeerId>) -> io::Result<Self> {
        stream.set_read_timeout(Some(POLL_INTERVAL))?;
        let reader = stream.try_clone()?;
        Ok(Self {
            inner: Arc::new(SessionInner {
                ep: Mutex::new(ep),
                sock: Mutex::new(stream),
                peer: Mutex::new(peer),
                established: AtomicBool::new(false),
                done: AtomicBool::new(false),
            }),
            reader,
        })
    }

    /// Dial `addr` and start a full-duplex session to `server_pub`.
    pub fn connect(
        addr: &str,
        server_pub: [u8; 32],
        identity: Identity,
        config: Config,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        let mut ep = Endpoint::new(identity, config);
        let peer = ep.connect(Instant::now(), server_pub, wire_addr());
        let s = Self::wrap(ep, stream, Some(peer))?;
        s.inner.flush()?; // emit the initial HELLO
        Ok(s)
    }

    /// Wrap an accepted inbound `stream` as the responder.
    pub fn accept(stream: TcpStream, identity: Identity, config: Config) -> io::Result<Self> {
        let ep = Endpoint::new(identity, config);
        Self::wrap(ep, stream, None)
    }

    /// A cloneable transmit handle. Obtain it before
    /// [`pump`](Self::pump) / [`pipe`](Self::pipe) consumes the
    /// session.
    pub fn sender(&self) -> SessionSender {
        SessionSender {
            inner: self.inner.clone(),
        }
    }

    /// The remote peer id, once known.
    pub fn peer(&self) -> Option<PeerId> {
        *self.inner.peer.lock().unwrap()
    }

    /// Whether the session has reached `Established`.
    pub fn is_established(&self) -> bool {
        self.inner.established.load(Ordering::SeqCst)
    }

    /// Run the receive side on the current thread: read the socket,
    /// drive the engine, and call `on_data` for each authenticated
    /// DATA payload. Returns when the peer closes the session, the
    /// socket ends, or a [`SessionSender::close`] marks it done.
    /// Transmit concurrently via a [`sender`](Self::sender).
    pub fn pump<F: FnMut(&[u8]) -> io::Result<()>>(self, mut on_data: F) -> io::Result<()> {
        let Session { inner, mut reader } = self;
        let mut fr = FrameReader::new();
        while !inner.done.load(Ordering::SeqCst) {
            inner.flush()?;
            match fr.fill(&mut reader) {
                Ok(true) => {}
                _ => break, // socket EOF
            }
            let now = Instant::now();
            let mut events = Vec::new();
            {
                let mut ep = inner.ep.lock().unwrap();
                while let Some(frame) = fr.next_frame() {
                    let _ = ep.handle_datagram(now, wire_addr(), &frame);
                }
                ep.handle_timeout(now);
                while let Some(ev) = ep.poll_event() {
                    events.push(ev);
                }
            }
            inner.flush()?;
            for ev in events {
                match ev {
                    Event::Connected { peer } => {
                        *inner.peer.lock().unwrap() = Some(peer);
                        inner.established.store(true, Ordering::SeqCst);
                    }
                    Event::Data { payload, .. } => on_data(&payload)?,
                    Event::Closed { .. } | Event::HandshakeTimedOut { .. } => {
                        inner.done.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
        inner.done.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Full-duplex convenience: pipe `src` → the session and the
    /// session → `dst`, each on its own thread, until the remote
    /// closes (the receive side). The `src` reader thread is
    /// **detached** — it ends when `src` hits EOF (which closes the
    /// session) or the process exits. A server should drop/kill its
    /// `src` (e.g. the child's stdout) after this returns to release
    /// that thread.
    pub fn pipe<R, W>(self, src: R, mut dst: W) -> io::Result<()>
    where
        R: Read + Send + 'static,
        W: Write,
    {
        let tx = self.sender();
        thread::spawn(move || {
            let mut src = src;
            let mut buf = [0u8; MAX_PAYLOAD];
            loop {
                match src.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        tx.close();
                        return;
                    }
                    Ok(n) => {
                        if tx.send(&buf[..n]).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        self.pump(move |data| {
            dst.write_all(data)?;
            dst.flush()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn server_id() -> Identity {
        Identity::from_secret_bytes([0x5d; 32])
    }
    fn client_id() -> Identity {
        Identity::from_secret_bytes([0xc1; 32])
    }

    /// Full PQ-hybrid handshake + request/response over real loopback
    /// TCP, end-to-end through the public API.
    #[test]
    fn loopback_request_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = Connection::accept(stream, server_id(), server_config()).unwrap();
            let req = conn.recv().unwrap().expect("request datagram");
            assert_eq!(&req, b"ping");
            assert!(conn.is_established());
            assert!(conn.peer().is_some());
            conn.send(b"pong").unwrap();
            let tail = conn.recv().unwrap(); // None once the client closes
            assert!(tail.is_none());
        });

        let mut conn = Connection::connect(
            &addr.to_string(),
            server_id().public_bytes(),
            client_id(),
            Config::default(),
        )
        .unwrap();
        conn.send(b"ping").unwrap();
        let resp = conn.recv().unwrap().expect("response datagram");
        assert_eq!(&resp, b"pong");
        conn.close().unwrap();
        srv.join().unwrap();
    }

    /// A buffer larger than MAX_PAYLOAD is split across datagrams and
    /// the receiver reassembles by total byte count — the pattern the
    /// file-transfer tool uses.
    #[test]
    fn multi_datagram_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let total = MAX_PAYLOAD * 3 + 17;
        let srv = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = Connection::accept(stream, server_id(), server_config()).unwrap();
            let mut got = Vec::new();
            while got.len() < total {
                match conn.recv().unwrap() {
                    Some(chunk) => got.extend_from_slice(&chunk),
                    None => break,
                }
            }
            got
        });

        let mut conn = Connection::connect(
            &addr.to_string(),
            server_id().public_bytes(),
            client_id(),
            Config::default(),
        )
        .unwrap();
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        conn.send(&payload).unwrap();
        conn.wait_established().unwrap();
        // Give the datagrams a moment to land, then close.
        thread::sleep(Duration::from_millis(200));
        conn.close().unwrap();
        let got = srv.join().unwrap();
        assert_eq!(got, payload);
    }

    /// Full-duplex: the server echoes (receive `pump` feeding its own
    /// `sender`), the client transmits on a `sender` from one thread
    /// while collecting echoes on `pump` in another — data crossing
    /// both directions concurrently over one session.
    #[test]
    fn duplex_session_echo() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let session = Session::accept(stream, server_id(), server_config()).unwrap();
            let echo = session.sender();
            // Echo every received payload straight back.
            session.pump(move |data| echo.send(data)).unwrap();
        });

        let session = Session::connect(
            &addr.to_string(),
            server_id().public_bytes(),
            client_id(),
            Config::default(),
        )
        .unwrap();
        let tx = session.sender();
        let sender = thread::spawn(move || {
            tx.send(b"ping").unwrap();
            thread::sleep(Duration::from_millis(150));
            tx.send(b"pong").unwrap();
            thread::sleep(Duration::from_millis(250));
            tx.close();
        });

        let got = Arc::new(Mutex::new(Vec::new()));
        let collected = got.clone();
        session
            .pump(move |data| {
                collected.lock().unwrap().extend_from_slice(data);
                Ok(())
            })
            .unwrap();

        sender.join().unwrap();
        srv.join().unwrap();
        assert_eq!(&*got.lock().unwrap(), b"pingpong");
    }
}
