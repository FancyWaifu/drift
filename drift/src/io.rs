//! Medium-agnostic packet I/O trait.
//!
//! DRIFT's transport layer talks to the network through this
//! trait instead of directly calling `tokio::net::UdpSocket`.
//! The default implementation (`UdpPacketIO`) wraps the
//! existing UDP socket exactly as before — zero behavior
//! change for existing users. Alternative implementations
//! can carry DRIFT packets over TCP, WebSocket, serial,
//! or any other medium that can move bytes.
//!
//! # For users
//!
//! Most users never touch this. `Transport::bind` creates a
//! UDP transport automatically. Only use `Transport::bind_with_io`
//! if you need a non-UDP transport.
//!
//! # For adapter authors
//!
//! Implement `PacketIO` for your medium. The contract is
//! simple: `send_to` delivers a discrete packet (not a byte
//! stream) to a destination, `recv_from` returns the next
//! complete packet and its source. If your medium is a byte
//! stream (TCP, serial), you need framing (length-prefix,
//! SLIP, COBS) to recover packet boundaries — see
//! `TcpPacketIO` for an example.

use async_trait::async_trait;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Trait for sending and receiving discrete packets over
/// any medium. Object-safe so DRIFT can hold `Arc<dyn PacketIO>`.
#[async_trait]
pub trait PacketIO: Send + Sync + 'static {
    /// Send `buf` as a single packet to `dest`. Returns
    /// the number of bytes handed to the underlying medium.
    /// For datagram transports (UDP), this is one sendto.
    /// For stream transports (TCP), this writes a
    /// length-prefixed frame.
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize>;

    /// Send a batch of packets in one syscall when the
    /// underlying medium supports it (Linux UDP via
    /// `sendmmsg(2)`). Default implementation just loops
    /// `send_to` — correct everywhere, faster on Linux UDP.
    /// Returns the number of packets handed to the kernel
    /// (may be less than `packets.len()` on partial sends).
    async fn send_to_batch(
        &self,
        packets: &[(Vec<u8>, SocketAddr)],
    ) -> io::Result<usize> {
        let mut sent = 0;
        for (bytes, dst) in packets {
            self.send_to(bytes, *dst).await?;
            sent += 1;
        }
        Ok(sent)
    }

    /// Receive the next complete packet. Returns
    /// `(bytes_read, source_address)`. Blocks until a
    /// packet is available.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// Receive a batch of packets. `buf` must be sized for
    /// the coalesced case (UDP_GRO returns up to ~64 KiB
    /// of concatenated segments per call); 64 KiB is the
    /// recommended size on Linux. On return, `out` contains
    /// one `(offset, length, source)` tuple per packet
    /// extracted from `buf` — segments live in-place in
    /// `buf` and the caller dispatches each without copying.
    ///
    /// Default implementation: one `recv_from`, push a
    /// single segment tuple. Linux UDP override uses
    /// `recvmsg` with `UDP_GRO` cmsg parsing to coalesce.
    /// Callers must `out.clear()` before each invocation.
    async fn recv_from_batch(
        &self,
        buf: &mut [u8],
        out: &mut Vec<(usize, usize, SocketAddr)>,
    ) -> io::Result<()> {
        let (n, src) = self.recv_from(buf).await?;
        out.push((0, n, src));
        Ok(())
    }

    /// The local address this transport is bound to.
    /// Returns a placeholder for mediums where "local
    /// address" isn't meaningful (serial, BLE).
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Optional: access the raw fd for platform-specific
    /// features (ECN, sendmmsg). Returns None for
    /// non-fd-backed transports. Default: None.
    #[cfg(unix)]
    fn as_raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        None
    }
}

/// Standard UDP packet I/O. Wraps `tokio::net::UdpSocket`
/// with zero overhead — every existing DRIFT deployment
/// uses this.
pub struct UdpPacketIO {
    pub(crate) socket: Arc<UdpSocket>,
}

impl UdpPacketIO {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    /// Access the underlying tokio UdpSocket for
    /// platform-specific operations (ECN setsockopt,
    /// sendmmsg batching). Only available through this
    /// concrete type, not through the trait.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

#[async_trait]
impl PacketIO for UdpPacketIO {
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, dest).await
    }

    /// Override the default loop with a real `sendmmsg(2)`
    /// on Linux. One syscall per batch instead of N per
    /// packet — typically 3-10× throughput improvement on
    /// high-pps workloads.
    async fn send_to_batch(
        &self,
        packets: &[(Vec<u8>, SocketAddr)],
    ) -> io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }
        // 1-packet "batches" can't benefit from sendmmsg/GSO —
        // skip the bookkeeping. For 2+ packets, GSO collapses
        // same-dst same-size batches into one syscall + one skb,
        // and sendmmsg handles the heterogeneous case. Lowered
        // from <=2 in PERF.4: with GSO landed, even 2-packet
        // batches are strictly worth one syscall.
        if packets.len() == 1 {
            self.socket.send_to(&packets[0].0, packets[0].1).await?;
            return Ok(1);
        }
        #[cfg(unix)]
        {
            crate::transport::batch::send_batch(&self.socket, packets).await
        }
        #[cfg(not(unix))]
        {
            // No sendmmsg on Windows; loop the single-send path.
            // The 1.5 Gbps userspace ceiling cited in the README
            // is the Linux+macOS number; Windows is slower here
            // but functionally identical.
            for (bytes, dst) in packets {
                self.socket.send_to(bytes, *dst).await?;
            }
            Ok(packets.len())
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    /// On Linux, use `recvmsg` and parse the `UDP_GRO` cmsg
    /// (if present) to split the kernel-coalesced super-buffer
    /// into one tuple per original packet. Caller-owned `buf`
    /// must be sized for coalesced reads (64 KiB recommended).
    /// Without UDP_GRO support this still works — just yields
    /// one segment per call, same as the default.
    async fn recv_from_batch(
        &self,
        buf: &mut [u8],
        out: &mut Vec<(usize, usize, SocketAddr)>,
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            crate::transport::batch::recv_batch_gro(&self.socket, buf, out).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let (n, src) = self.socket.recv_from(buf).await?;
            out.push((0, n, src));
            Ok(())
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        Some(self.socket.as_raw_fd())
    }
}

/// TCP packet I/O with length-prefix framing. Each DRIFT
/// packet is wrapped as `[length: u16 BE][payload]` on the
/// wire. The TCP stream handles reliable delivery; DRIFT's
/// own congestion control should be disabled when using
/// this adapter to avoid the "double CC" problem.
///
/// This adapter is for DRIFT-over-TCP — running DRIFT
/// packets through a TCP connection for firewall traversal.
/// NOT the same as drift-tun (which tunnels TCP apps over
/// DRIFT).
pub struct TcpPacketIO {
    reader: tokio::sync::Mutex<tokio::io::ReadHalf<tokio::net::TcpStream>>,
    writer: tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    /// Optional per-IP connection-counter guard. Set by
    /// `TcpListenerIO::accept` so the slot releases when the
    /// PacketIO drops; client-side `TcpPacketIO::new` leaves it
    /// None (outbound connections aren't subject to the listener
    /// cap because there's no listener counting them).
    #[allow(dead_code)]
    _conn_guard: Option<ConnGuard>,
}

impl TcpPacketIO {
    /// Wrap an established TCP connection. The connection
    /// must already be connected — this adapter doesn't
    /// handle TCP setup. `peer_addr` is used as the
    /// "destination" for all send_to calls (since TCP is
    /// point-to-point, the destination is always the same).
    pub fn new(stream: tokio::net::TcpStream) -> io::Result<Self> {
        Self::new_inner(stream, None)
    }

    /// Variant used by `TcpListenerIO::accept` that attaches a
    /// per-IP-count guard. When the PacketIO drops (recv loop
    /// exits + F1's `InterfaceSet::remove` clears the Arc), the
    /// guard releases the connection slot back to the listener's
    /// per-IP map.
    pub(crate) fn new_with_guard(
        stream: tokio::net::TcpStream,
        guard: ConnGuard,
    ) -> io::Result<Self> {
        Self::new_inner(stream, Some(guard))
    }

    fn new_inner(
        stream: tokio::net::TcpStream,
        guard: Option<ConnGuard>,
    ) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;
        let _ = stream.set_nodelay(true);
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: tokio::sync::Mutex::new(reader),
            writer: tokio::sync::Mutex::new(writer),
            peer_addr,
            local_addr,
            _conn_guard: guard,
        })
    }
}

#[async_trait]
impl PacketIO for TcpPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        use tokio::io::AsyncWriteExt;
        if buf.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too large for TCP framing (max 65535)",
            ));
        }
        // Build one contiguous buffer so the kernel sees a single
        // write (one syscall, one TCP segment in the common MTU-
        // bounded case). Drift packets are ≤ 64 KiB; the alloc is
        // small. Was two write_all calls + a flush, all three of
        // which yield to the runtime — net 4 awaits per packet
        // for what should be one syscall.
        //
        // TCP_NODELAY is already enabled (new_inner) so Nagle
        // isn't pooling small writes; explicit flush() per packet
        // was forcing an unneeded kernel-level commit on every
        // send_to. Without it, the kernel autoflushes when the
        // socket buffer fills or the next write triggers it.
        let mut framed = Vec::with_capacity(2 + buf.len());
        framed.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        framed.extend_from_slice(buf);
        let mut writer = self.writer.lock().await;
        writer.write_all(&framed).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        let len = read_one_tcp_frame(&mut *reader, buf).await?;
        Ok((len, self.peer_addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

/// Read one length-prefixed packet from `reader` into `buf`.
///
/// Wire: 2-byte big-endian length, then `len` body bytes.
/// Errors:
///   * `UnexpectedEof` if the connection closes mid-prefix or mid-body.
///   * `InvalidData` if the advertised length exceeds `buf.len()`.
///
/// Exposed for fuzzing (`fuzz/fuzz_targets/tcp_deframe.rs`) and
/// for any future adapter that wants to share the framing logic
/// (e.g. the Tor-circuit adapter at the bottom of this file).
pub async fn read_one_tcp_frame<R>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
{
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "TCP frame too large: {} bytes, buffer is {}",
                len,
                buf.len()
            ),
        ));
    }
    reader.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

/// In-memory packet I/O via `tokio::sync::mpsc` channels.
/// No network, no sockets, no kernel involvement — just Rust
/// async channels passing `Vec<u8>` packets between two
/// endpoints. Useful for:
///
///   * **Testing**: deterministic, no port conflicts, no
///     timing jitter from the kernel.
///   * **Same-process IPC**: two DRIFT transports in the same
///     binary talking to each other with zero syscall overhead.
///   * **Proof of universality**: if DRIFT works over bare
///     channels, it works over anything.
///
/// Create a connected pair with `MemPacketIO::pair()`.
pub struct MemPacketIO {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    /// Placeholder address used as both local and remote.
    /// Since there's no real network, this is purely for the
    /// PacketIO trait's SocketAddr requirements.
    addr: SocketAddr,
}

impl MemPacketIO {
    /// Create a connected pair. Packets sent on side A arrive
    /// on side B's recv, and vice versa. Each side gets a
    /// unique placeholder SocketAddr so DRIFT can distinguish
    /// them in its peer table.
    pub fn pair() -> (Self, Self) {
        let (tx_a, rx_b) = tokio::sync::mpsc::channel(1024);
        let (tx_b, rx_a) = tokio::sync::mpsc::channel(1024);
        let addr_a: SocketAddr = "127.0.0.1:60000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:60001".parse().unwrap();
        (
            Self {
                tx: tx_a,
                rx: tokio::sync::Mutex::new(rx_a),
                addr: addr_a,
            },
            Self {
                tx: tx_b,
                rx: tokio::sync::Mutex::new(rx_b),
                addr: addr_b,
            },
        )
    }
}

#[async_trait]
impl PacketIO for MemPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionReset, "channel closed"))?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        let packet = rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionReset, "channel closed"))?;
        let n = packet.len().min(buf.len());
        buf[..n].copy_from_slice(&packet[..n]);
        Ok((n, self.addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

/// WebSocket packet I/O. Each DRIFT packet becomes one
/// WebSocket binary message. No framing needed — WebSocket
/// already preserves message boundaries natively. This is
/// the adapter for browser-to-server communication: a WASM
/// DRIFT client in a browser talks to a server through
/// WebSocket, which passes through every CDN, reverse proxy,
/// and firewall on earth because it looks like normal HTTP
/// traffic.
///
/// Create from an established WebSocket stream (either
/// client-side from `tokio_tungstenite::connect_async` or
/// server-side from `tokio_tungstenite::accept_async`).
pub struct WsPacketIO<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> {
    writer: tokio::sync::Mutex<
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<S>,
            tokio_tungstenite::tungstenite::Message,
        >,
    >,
    reader: tokio::sync::Mutex<
        futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<S>>,
    >,
    addr: SocketAddr,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> WsPacketIO<S> {
    /// Wrap an established WebSocket stream. `addr` is a
    /// placeholder SocketAddr for the trait's requirements —
    /// for server-accepted connections, use the client's TCP
    /// peer address; for client connections, use the server's
    /// address.
    pub fn new(ws: tokio_tungstenite::WebSocketStream<S>, addr: SocketAddr) -> Self {
        use futures_util::StreamExt;
        let (writer, reader) = ws.split();
        Self {
            writer: tokio::sync::Mutex::new(writer),
            reader: tokio::sync::Mutex::new(reader),
            addr,
        }
    }
}

#[async_trait]
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static> PacketIO
    for WsPacketIO<S>
{
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        use futures_util::SinkExt;
        let msg = tokio_tungstenite::tungstenite::Message::Binary(buf.to_vec());
        let mut writer = self.writer.lock().await;
        writer.send(msg).await.map_err(io::Error::other)?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use futures_util::StreamExt;
        let mut reader = self.reader.lock().await;
        loop {
            match reader.next().await {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok((n, self.addr));
                }
                Some(Ok(_)) => continue, // skip text, ping, pong, close frames
                Some(Err(e)) => {
                    return Err(io::Error::other(e));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "websocket closed",
                    ));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

/// WebRTC data channel packet I/O. Each DRIFT packet becomes
/// one WebRTC `DataChannelMessage` (binary). Unlike TCP/WS,
/// WebRTC is peer-to-peer — there's no "server" in the classic
/// sense; both ends establish an SDP exchange (usually via a
/// signaling server) and then talk directly through a
/// DTLS-over-SCTP-over-ICE stack. The big win: this works
/// browser-to-browser, punching through NAT automatically with
/// STUN/TURN, with no server in the data path.
///
/// Incoming messages are delivered through an mpsc channel
/// because the underlying `on_message` hook is callback-style
/// rather than async-read style. The channel buffer is sized to
/// absorb short bursts; sustained overrun causes the callback
/// to drop packets (matching UDP-like semantics for a fair
/// comparison with DRIFT's other datagram adapters).
pub struct WebRTCPacketIO {
    dc: std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    addr: SocketAddr,
}

impl WebRTCPacketIO {
    /// Wrap an already-open data channel. Installs an
    /// `on_message` handler that forwards incoming bytes into
    /// an mpsc channel drained by `recv_from`. `addr` is a
    /// placeholder for the `PacketIO` trait's SocketAddr
    /// requirement — WebRTC connections aren't addressed by
    /// ip:port at the peer level.
    pub fn new(dc: std::sync::Arc<webrtc::data_channel::RTCDataChannel>, addr: SocketAddr) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let tx_arc = std::sync::Arc::new(tx);
        let tx_hook = tx_arc.clone();
        dc.on_message(Box::new(
            move |msg: webrtc::data_channel::data_channel_message::DataChannelMessage| {
                let tx = tx_hook.clone();
                Box::pin(async move {
                    // Binary messages only; string payloads are
                    // not part of DRIFT's wire format. A
                    // full-buffer try_send drops the packet to
                    // stay callback-non-blocking.
                    if !msg.is_string {
                        let _ = tx.try_send(msg.data.to_vec());
                    }
                })
            },
        ));
        Self {
            dc,
            rx: tokio::sync::Mutex::new(rx),
            addr,
        }
    }
}

#[async_trait]
impl PacketIO for WebRTCPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        let bytes = bytes::Bytes::copy_from_slice(buf);
        self.dc
            .send(&bytes)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let data =
            self.rx.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionReset, "data channel closed")
            })?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, self.addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

/// WebTransport packet I/O. Wraps a `wtransport::Connection`
/// and uses its datagram channel as the byte-mover. Each DRIFT
/// packet becomes one QUIC datagram — unreliable, unordered,
/// the real thing (no TCP retransmit tax). Matches the browser-
/// side `drift-wasm::wire_webtransport` adapter exactly, so a
/// browser WebTransport client can talk to a node running this.
///
/// Each instance handles ONE accepted WebTransport connection.
/// The server-side accept loop wraps each new connection and
/// calls `Transport::add_interface`, same pattern as the WS
/// adapter.
pub struct WebTransportPacketIO {
    conn: Arc<wtransport::Connection>,
    addr: SocketAddr,
}

impl WebTransportPacketIO {
    /// Wrap an already-accepted `wtransport::Connection`. The
    /// server's accept loop is the caller. `addr` is the
    /// browser-side remote address, recorded for the trait's
    /// SocketAddr requirement.
    pub fn new(conn: wtransport::Connection, addr: SocketAddr) -> Self {
        Self {
            conn: Arc::new(conn),
            addr,
        }
    }
}

#[async_trait]
impl PacketIO for WebTransportPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        // QUIC datagrams have a peer-negotiated max size; if buf
        // exceeds it, wtransport returns an error. DRIFT's
        // typical packets are well under 1500 B so this is
        // rarely hit in practice.
        self.conn
            .send_datagram(buf.to_vec())
            .map_err(io::Error::other)?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let dgram = self
            .conn
            .receive_datagram()
            .await
            .map_err(io::Error::other)?;
        let payload = dgram.payload();
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        Ok((n, self.addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

/// A set of named packet I/O interfaces that a single DRIFT
/// transport listens on simultaneously. Incoming packets
/// from ANY interface are multiplexed into a single recv
/// stream; outgoing packets are routed to the interface
/// tagged on the destination peer.
///
/// Example: a node with `interfaces[0] = UdpPacketIO` and
/// `interfaces[1] = TcpPacketIO` can talk to UDP peers via
/// index 0 and TCP peers via index 1 without any manual
/// bridging — the mesh routing layer forwards between them
/// automatically because both interfaces feed the same
/// DRIFT transport.
pub struct InterfaceSet {
    /// Slot is `Some(_)` while the underlying `PacketIO` is alive,
    /// `None` once `remove()` has been called for that index.
    /// Slots are never reused — index assignment is monotonic —
    /// so existing peer `interface_id` values remain stable across
    /// connection deaths.
    interfaces: std::sync::RwLock<Vec<(String, Option<Arc<dyn PacketIO>>)>>,
}

impl InterfaceSet {
    /// Create an interface set with a single adapter (the
    /// common case for backward compatibility).
    pub fn single(name: impl Into<String>, io: Arc<dyn PacketIO>) -> Self {
        Self {
            interfaces: std::sync::RwLock::new(vec![(name.into(), Some(io))]),
        }
    }

    /// Add a new interface. Returns its index (used as the
    /// `interface_id` on peers reached through it). Safe
    /// to call while recv loops are running — the RwLock
    /// ensures concurrent reads aren't interrupted.
    pub fn add(&self, name: impl Into<String>, io: Arc<dyn PacketIO>) -> usize {
        let mut ifaces = self.interfaces.write().unwrap();
        let idx = ifaces.len();
        ifaces.push((name.into(), Some(io)));
        idx
    }

    /// Mark the interface at `idx` as dead and drop its
    /// `Arc<dyn PacketIO>`. This is the universal fix for the
    /// per-connection FD leak that affects any connection-oriented
    /// adapter (TCP, TLS, WS, …): when the recv loop for a
    /// connection-backed PacketIO exits on error, dropping the Arc
    /// here lets the underlying socket close. UDP and other
    /// connectionless adapters can also be removed without harm —
    /// only the run_recv_loop_for caller decides when removal is
    /// appropriate.
    ///
    /// The slot index stays reserved (set to None) so peers that
    /// previously routed through this interface get a clean "no
    /// path" error on their next send rather than silently being
    /// redirected to a different connection that happened to land
    /// at the same index later.
    pub fn remove(&self, idx: usize) {
        let mut ifaces = self.interfaces.write().unwrap();
        if let Some(slot) = ifaces.get_mut(idx) {
            slot.1 = None;
        }
    }

    /// Number of slots (including removed ones). The index
    /// monotonicity invariant — never reuse slot indices —
    /// means peers reached through any interface, dead or alive,
    /// retain stable `interface_id` values. Use `live_count()`
    /// for the number of currently-live interfaces.
    pub fn len(&self) -> usize {
        self.interfaces.read().unwrap().len()
    }

    /// Number of live interfaces. Less than or equal to `len()`;
    /// the difference is the count of slots that `remove()` has
    /// nullified.
    pub fn live_count(&self) -> usize {
        self.interfaces
            .read()
            .unwrap()
            .iter()
            .filter(|(_, io)| io.is_some())
            .count()
    }

    /// True when no interfaces have been registered at all.
    pub fn is_empty(&self) -> bool {
        self.interfaces.read().unwrap().is_empty()
    }

    /// Send a packet via a specific interface by index.
    /// Clones the Arc under the read lock, releases the
    /// lock, then awaits the send — the lock is never
    /// held across an async boundary. Returns NotFound if
    /// the index is out of range OR if the interface has
    /// been removed (dead connection).
    pub async fn send_via(
        &self,
        interface_id: usize,
        buf: &[u8],
        dest: SocketAddr,
    ) -> io::Result<usize> {
        let io = {
            let ifaces = self.interfaces.read().unwrap();
            ifaces
                .get(interface_id)
                .and_then(|(_, io)| io.clone())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "interface index out of range or removed",
                    )
                })?
        };
        io.send_to(buf, dest).await
    }

    /// Send via interface 0 (default). Convenience for code
    /// paths that don't (yet) track per-peer interfaces.
    pub async fn send_default(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        self.send_via(0, buf, dest).await
    }

    /// Get a cloned Arc to a specific interface by index.
    /// Returns None for both out-of-range and removed slots.
    pub fn get(&self, idx: usize) -> Option<Arc<dyn PacketIO>> {
        let ifaces = self.interfaces.read().unwrap();
        ifaces.get(idx).and_then(|(_, io)| io.clone())
    }

    /// The local address of the first live interface.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let ifaces = self.interfaces.read().unwrap();
        ifaces
            .iter()
            .find_map(|(_, io)| io.clone())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no live interfaces"))?
            .local_addr()
    }

    /// Raw fd of the first live interface (for ECN etc).
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        let ifaces = self.interfaces.read().unwrap();
        ifaces.iter().find_map(|(_, io)| io.clone()).and_then(|io| io.as_raw_fd())
    }

    /// Send via a specific interface, falling back to the
    /// first live interface if the requested index is out of
    /// range OR removed. This is the safe version that doesn't
    /// error on bad indices — it just degrades to whatever live
    /// path is available.
    pub async fn send_for(&self, iface: usize, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        let io = {
            let ifaces = self.interfaces.read().unwrap();
            ifaces
                .get(iface)
                .and_then(|(_, io)| io.clone())
                .or_else(|| ifaces.iter().find_map(|(_, io)| io.clone()))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no live interfaces"))?
        };
        io.send_to(buf, dest).await
    }

    /// Batched variant of `send_for`. All packets go via
    /// `iface`; the underlying `PacketIO` decides whether to
    /// use a real batched syscall (UDP `sendmmsg`) or fall
    /// back to a loop. Drops the read lock before awaiting,
    /// same as `send_for`.
    pub async fn send_batch_for(
        &self,
        iface: usize,
        packets: &[(Vec<u8>, SocketAddr)],
    ) -> io::Result<usize> {
        let io = {
            let ifaces = self.interfaces.read().unwrap();
            ifaces
                .get(iface)
                .and_then(|(_, io)| io.clone())
                .or_else(|| ifaces.iter().find_map(|(_, io)| io.clone()))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no live interfaces"))?
        };
        io.send_to_batch(packets).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_framing_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        let client_io = TcpPacketIO::new(client_stream).unwrap();
        let server_io = TcpPacketIO::new(server_stream).unwrap();

        // Send a few packets from client to server.
        client_io.send_to(b"hello-drift", addr).await.unwrap();
        client_io.send_to(b"second-packet", addr).await.unwrap();

        // Receive on the server side.
        let mut buf = vec![0u8; 1400];
        let (n, src) = server_io.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-drift");
        assert_eq!(src, client_io.local_addr().unwrap());

        let (n2, _) = server_io.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"second-packet");
    }

    #[tokio::test]
    async fn tcp_framing_preserves_packet_boundaries() {
        // Send 100 variable-length packets rapidly and
        // verify each arrives with its exact original length
        // — no merging, no splitting, no truncation.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let client_io = Arc::new(TcpPacketIO::new(client).unwrap());
        let server_io = Arc::new(TcpPacketIO::new(server).unwrap());

        let sender = tokio::spawn({
            let io = client_io.clone();
            async move {
                for i in 0u32..100 {
                    let payload: Vec<u8> = (0..((i % 50) + 1) as usize)
                        .map(|j| ((i as usize + j) & 0xFF) as u8)
                        .collect();
                    io.send_to(&payload, addr).await.unwrap();
                }
            }
        });

        let receiver = tokio::spawn({
            let io = server_io.clone();
            async move {
                let mut buf = vec![0u8; 1400];
                for i in 0u32..100 {
                    let (n, _) = io.recv_from(&mut buf).await.unwrap();
                    let expected_len = ((i % 50) + 1) as usize;
                    assert_eq!(n, expected_len, "packet {} length mismatch", i);
                }
            }
        });

        sender.await.unwrap();
        receiver.await.unwrap();
    }
}

// ─── Listener / URL dispatch ──────────────────────────────────────
//
// Higher-level abstractions on top of `PacketIO`:
//
//   * `Listener` — "give me the next inbound connection as a
//     `PacketIO`." UDP yields its single socket once and is done.
//     TCP and other connection-oriented adapters yield one
//     `PacketIO` per accepted client.
//
//   * URL dispatch — `make_listener("tcp://0.0.0.0:9100")` and
//     `make_connector("udp://host:9100")` route to the right
//     adapter based on scheme. New transports plug in by adding
//     an arm here, with no changes to application code.
//
// These together let `Transport::bind_url` / `Transport::connect_url`
// be transport-agnostic — applications don't care whether they're
// running over UDP, TCP, or anything else.

/// Abstraction over "accept the next inbound connection."
///
/// Two flavours of listener exist:
///
///   * **Single-shot** (`is_multi() == false`): yields a single
///     `PacketIO` from `accept()` exactly once, then returns
///     "exhausted" on subsequent calls. Used for connectionless
///     transports like UDP where one socket serves all peers.
///
///   * **Multi-shot** (`is_multi() == true`): yields one
///     `PacketIO` per accepted client. Used for connection-
///     oriented transports like TCP and WebSocket.
///
/// `Transport::bind_url` uses `is_multi()` to decide whether to
/// wire up a single primary interface or to spawn an accept loop
/// that adds interfaces dynamically as clients connect.
#[async_trait]
pub trait Listener: Send + Sync + 'static {
    /// Local address this listener is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Whether this listener can yield more than one PacketIO.
    /// Multi-shot listeners need an accept loop on the consumer
    /// side; single-shot ones are used directly as the primary.
    fn is_multi(&self) -> bool;

    /// Yields the next inbound `PacketIO`. Single-shot listeners
    /// return `Err(NotFound)` after the first call. Multi-shot
    /// listeners block until the next client connects.
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>>;
}

/// UDP listener — a single bound socket served as one PacketIO.
/// Once `accept()` has been called, subsequent calls error out
/// with `NotFound`. The single socket handles all UDP peers via
/// the connectionless model; per-peer state is the Transport's
/// job, not the adapter's.
pub struct UdpListenerIO {
    /// Some until first accept, then None.
    socket: Option<Arc<UdpSocket>>,
    addr: SocketAddr,
}

impl UdpListenerIO {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr).await?;
        try_enable_udp_gro(&sock);
        let local = sock.local_addr()?;
        Ok(Self {
            socket: Some(Arc::new(sock)),
            addr: local,
        })
    }

    /// Bind + apply `SO_RCVBUF = recv_buffer_bytes` if set.
    /// The kernel may clamp the requested size; the granted
    /// size is logged at info level. A failure to set the
    /// option is logged at warn and does NOT fail the bind.
    pub async fn bind_with_recv_buffer(
        addr: SocketAddr,
        recv_buffer_bytes: Option<usize>,
    ) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr).await?;
        if let Some(want) = recv_buffer_bytes {
            apply_udp_recv_buffer(&sock, want);
        }
        try_enable_udp_gro(&sock);
        let local = sock.local_addr()?;
        Ok(Self {
            socket: Some(Arc::new(sock)),
            addr: local,
        })
    }
}

/// Enable `UDP_GRO` on the socket if available (Linux ≥ 5.0).
/// Best-effort: failures are silently ignored — older kernels
/// just keep doing one packet per recvmsg. When enabled, the
/// kernel coalesces same-flow packets into a single recvmsg
/// up to ~64 KiB; per-packet segment size lands in a
/// `SOL_UDP / UDP_GRO` control message.
fn try_enable_udp_gro(sock: &UdpSocket) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_UDP,
                libc::UDP_GRO,
                &on as *const _ as *const _,
                std::mem::size_of_val(&on) as libc::socklen_t,
            )
        };
        if rc != 0 {
            tracing::debug!(
                error = %io::Error::last_os_error(),
                "UDP_GRO setsockopt unavailable (kernel < 5.0 or unsupported)"
            );
        } else {
            tracing::debug!("UDP_GRO enabled — recv may coalesce same-flow packets");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sock;
    }
}

/// Apply `SO_RCVBUF` to a bound `tokio::net::UdpSocket` via
/// `socket2`. Logs the granted size (which the kernel may
/// have clamped — see `sysctl net.core.rmem_max` on Linux,
/// `kern.ipc.maxsockbuf` on macOS) at info level. Failures
/// are logged at warn and silently tolerated.
pub(crate) fn apply_udp_recv_buffer(sock: &UdpSocket, want_bytes: usize) {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    // SAFETY: socket2::Socket::from_raw_fd takes ownership of
    // the fd. We use into_raw_fd() to forget the temporary and
    // hand the fd back to socket2 just for the setsockopt
    // call, then immediately into_raw_fd() back out and let
    // it drop without close.
    let fd = sock.as_raw_fd();
    // socket2 wants an owned Socket; we conjure one from the
    // borrowed fd just long enough to call set_recv_buffer_size.
    // Critical: we must NOT close this fd at the end — the
    // tokio UdpSocket still owns it. into_raw_fd consumes the
    // socket2::Socket without running its drop (which would
    // close()), giving us back the same raw fd.
    let s2 = unsafe { socket2::Socket::from_raw_fd(fd) };
    let req_result = s2.set_recv_buffer_size(want_bytes);
    let granted = s2.recv_buffer_size().ok();
    let _leak = s2.into_raw_fd(); // see SAFETY note above
    match req_result {
        Ok(()) => match granted {
            Some(g) if g < want_bytes => tracing::info!(
                requested = want_bytes,
                granted = g,
                "SO_RCVBUF clamped by kernel; raise sysctl rmem_max for full size"
            ),
            Some(g) => tracing::info!(
                requested = want_bytes,
                granted = g,
                "SO_RCVBUF applied"
            ),
            None => tracing::info!(
                requested = want_bytes,
                "SO_RCVBUF requested (granted size unreadable)"
            ),
        },
        Err(e) => tracing::warn!(
            requested = want_bytes,
            error = ?e,
            "SO_RCVBUF setsockopt failed — keeping OS default"
        ),
    }
}

#[async_trait]
impl Listener for UdpListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
    fn is_multi(&self) -> bool {
        false
    }
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        match self.socket.take() {
            Some(s) => Ok(Arc::new(UdpPacketIO::new(s))),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "UDP listener is single-shot and was already consumed",
            )),
        }
    }
}

/// TCP listener — wraps `tokio::net::TcpListener`. Each
/// `accept()` returns a fresh `TcpPacketIO` for the next
/// inbound client. Multi-shot.
///
/// Per-source-IP connection cap: a single attacker can otherwise
/// rapidly open up to `ulimit -n` connections against the bridge,
/// each consuming an FD slot. We cap concurrent in-flight
/// accepted connections per source IP at `MAX_TCP_CONNS_PER_IP`
/// (default 32, configurable via `set_per_ip_cap`). Excess
/// connections are accepted-then-immediately-dropped, which closes
/// the socket cleanly with a `FIN` from our side — the attacker's
/// kernel sees the close, no spinning retry. The decrement on
/// each per-IP counter happens via the `ConnGuard` returned to
/// the accepted PacketIO; once that Arc drops (recv loop exits +
/// `InterfaceSet::remove` clears it via the F1 fix), the guard
/// releases the slot.
pub struct TcpListenerIO {
    listener: tokio::net::TcpListener,
    per_ip: Arc<std::sync::Mutex<HashMap<std::net::IpAddr, usize>>>,
    cap_per_ip: usize,
}

/// RAII guard that decrements a per-IP connection counter when
/// dropped. Held inside `TcpPacketIO` so the slot is released as
/// soon as the PacketIO Arc count hits zero — which happens when
/// the recv loop exits AND `InterfaceSet::remove()` drops the
/// transport-side reference.
pub(crate) struct ConnGuard {
    per_ip: Arc<std::sync::Mutex<HashMap<std::net::IpAddr, usize>>>,
    ip: std::net::IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.per_ip.lock() {
            if let Some(c) = map.get_mut(&self.ip) {
                if *c > 0 {
                    *c -= 1;
                }
                if *c == 0 {
                    map.remove(&self.ip);
                }
            }
        }
    }
}

const DEFAULT_TCP_CONNS_PER_IP: usize = 32;

impl TcpListenerIO {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            per_ip: Arc::new(std::sync::Mutex::new(HashMap::new())),
            cap_per_ip: DEFAULT_TCP_CONNS_PER_IP,
        })
    }

    /// Adjust the per-source-IP concurrent-connection cap. The
    /// default (32) is a reasonable balance for federation
    /// bridges that may legitimately have a handful of clients
    /// from the same NAT but should never accept hundreds from
    /// a single IP. Set very high (e.g. usize::MAX) to disable.
    pub fn set_per_ip_cap(&mut self, cap: usize) {
        self.cap_per_ip = cap;
    }
}

#[async_trait]
impl Listener for TcpListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    fn is_multi(&self) -> bool {
        true
    }
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let ip = peer.ip();

            // Try to claim a slot for this source IP. If the cap
            // is hit, we drop the stream — closing the socket
            // cleanly — and keep accepting. Single attacker
            // can't exhaust our FDs.
            let admitted = {
                let mut map = self.per_ip.lock().unwrap();
                let count = map.entry(ip).or_insert(0);
                if *count >= self.cap_per_ip {
                    false
                } else {
                    *count += 1;
                    true
                }
            };
            if !admitted {
                drop(stream);
                tracing::debug!(
                    src = %ip,
                    cap = self.cap_per_ip,
                    "tcp accept: per-ip cap reached, refusing connection"
                );
                continue;
            }

            let guard = ConnGuard {
                per_ip: self.per_ip.clone(),
                ip,
            };
            let io = TcpPacketIO::new_with_guard(stream, guard)?;
            return Ok(Arc::new(io));
        }
    }
}

/// WebSocket listener — wraps a `tokio::net::TcpListener` and
/// runs the HTTP→WebSocket upgrade handshake on each accepted
/// connection before handing the resulting `WsPacketIO` back.
/// Multi-shot.
///
/// Useful as a port-443 fallback transport: WebSocket-over-TCP
/// gets through HTTP-only proxies and corporate firewalls that
/// block UDP and even raw TCP on non-HTTP ports. To clients in
/// such environments, drift-http traffic is indistinguishable
/// from a normal HTTPS WebSocket app.
pub struct WsListenerIO {
    listener: tokio::net::TcpListener,
}

impl WsListenerIO {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        Ok(Self { listener })
    }
}

#[async_trait]
impl Listener for WsListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    fn is_multi(&self) -> bool {
        true
    }
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        let (stream, peer) = self.listener.accept().await?;
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .map_err(|e| io::Error::other(e))?;
        Ok(Arc::new(WsPacketIO::new(ws, peer)))
    }
}

// ─── TLS-wrapped TCP (`tls://`) ──────────────────────────────────
//
// DRIFT-shaped traffic disguised as HTTPS. The framing on the
// wire is identical to `TcpPacketIO` (length-prefix per packet);
// the only difference is the bytes are inside a TLS record stream
// instead of a raw TCP one. From a middlebox's perspective this
// looks like a normal HTTPS connection — TLS handshake, then
// encrypted application data.
//
// Important — the TLS layer adds NO security. DRIFT already
// authenticates peers by X25519 pubkey + AEAD-seals every packet.
// The cert is a randomly-generated self-signed cert, the client
// doesn't validate it, and the keys are ephemeral. It's pure
// camouflage — designed to pass DPI middleboxes that allow only
// HTTPS-shaped traffic, not to add a second layer of crypto.

/// One-shot constructor of a self-signed cert + key for the TLS
/// listener. Generated fresh on each `bind`. The client side
/// won't validate it (see [`NoCertVerifier`]).
fn generate_self_signed_cert() -> io::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|e| io::Error::other(format!("rcgen: {}", e)))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        cert.key_pair.serialize_der(),
    ));
    Ok((vec![cert_der], key_der))
}

/// Cert verifier that blindly accepts any server cert. Used on
/// the client side because DRIFT auth happens at the AEAD layer,
/// not the TLS layer.
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// Adapter for an established TLS-over-TCP connection. Same
/// length-prefix framing as `TcpPacketIO` — just lives inside
/// a TLS record stream. The concrete TLS stream type is split
/// into read/write halves before being type-erased into trait
/// objects, so the same struct holds either server- or client-
/// side TLS streams.
pub struct TlsPacketIO {
    reader: tokio::sync::Mutex<
        Box<dyn tokio::io::AsyncRead + Unpin + Send + Sync + 'static>,
    >,
    writer: tokio::sync::Mutex<
        Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync + 'static>,
    >,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl TlsPacketIO {
    /// Wrap an established TLS stream — either a server- or
    /// client-side `tokio_rustls::TlsStream`. Splits the stream
    /// in half so reader / writer can run concurrently.
    pub fn new<S>(stream: S, peer_addr: SocketAddr, local_addr: SocketAddr) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (r, w) = tokio::io::split(stream);
        let boxed_r: Box<dyn tokio::io::AsyncRead + Unpin + Send + Sync + 'static> =
            Box::new(r);
        let boxed_w: Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync + 'static> =
            Box::new(w);
        Self {
            reader: tokio::sync::Mutex::new(boxed_r),
            writer: tokio::sync::Mutex::new(boxed_w),
            peer_addr,
            local_addr,
        }
    }
}

#[async_trait]
impl PacketIO for TlsPacketIO {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        use tokio::io::AsyncWriteExt;
        if buf.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too large for TLS framing (max 65535)",
            ));
        }
        // Same optimization as TcpPacketIO::send_to: one contiguous
        // write_all, no explicit flush. rustls' write path encrypts
        // and forwards to the underlying TCP socket; the inner
        // TcpStream already has TCP_NODELAY enabled. Forcing flush
        // here was making rustls flush its TLS record buffer per
        // packet, which serializes record building + TCP send
        // pointlessly when the next packet would have batched.
        let mut framed = Vec::with_capacity(2 + buf.len());
        framed.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        framed.extend_from_slice(buf);
        let mut writer = self.writer.lock().await;
        writer.write_all(&framed).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use tokio::io::AsyncReadExt;
        let mut reader = self.reader.lock().await;
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TLS frame too large: {} > buffer {}", len, buf.len()),
            ));
        }
        reader.read_exact(&mut buf[..len]).await?;
        Ok((len, self.peer_addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

/// TLS listener — wraps a `tokio::net::TcpListener` and runs
/// the TLS handshake on each accept with a self-signed cert.
pub struct TlsListenerIO {
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListenerIO {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        // Install a default crypto provider exactly once per
        // process. rustls 0.23 requires this for ServerConfig
        // builders that don't take an explicit provider.
        install_default_crypto_provider();
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let (certs, key) = generate_self_signed_cert()?;
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| io::Error::other(format!("rustls server config: {}", e)))?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        Ok(Self { listener, acceptor })
    }
}

#[async_trait]
impl Listener for TlsListenerIO {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    fn is_multi(&self) -> bool {
        true
    }
    async fn accept(&mut self) -> io::Result<Arc<dyn PacketIO>> {
        let (tcp, peer) = self.listener.accept().await?;
        let local = tcp.local_addr()?;
        let _ = tcp.set_nodelay(true);
        let tls = self
            .acceptor
            .accept(tcp)
            .await
            .map_err(|e| io::Error::other(format!("TLS handshake: {}", e)))?;
        Ok(Arc::new(TlsPacketIO::new(tls, peer, local)))
    }
}

/// Install the default rustls crypto provider once per process.
/// Safe to call multiple times; subsequent calls are no-ops.
fn install_default_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ─── Scheme registry ──────────────────────────────────────────────
//
// The URL dispatcher is registry-driven rather than match-driven so
// new transports register themselves at link time and drift core
// stays additively-extensible. Each adapter file submits a
// `SchemeRegistration` via `inventory::submit!`; `make_listener`
// and `make_connector` find it by iterating the inventory at
// runtime. Drop in a new file → it works. No edits to existing
// code.

/// Async factory for a server-side `Listener`. Adapters provide
/// one of these via `SchemeRegistration`. The address is passed
/// as an opaque `String` — each adapter parses it however its
/// transport addresses bytes (IP `host:port` for UDP/TCP/TLS/WS,
/// `<base32>.onion:<port>` for Tor, BLE MAC, etc.). The pinned-Box
/// return type is what lets us store these as plain `fn` pointers
/// (and therefore as values inside an `inventory::submit!` block).
pub type ListenerFactory =
    fn(String) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>>;

/// Async factory for a client-side connector. Returns the
/// connected `PacketIO` plus the remote `SocketAddr` to pass to
/// `Transport::add_peer`. Non-IP transports (Tor, BLE, …)
/// synthesize a unique loopback `SocketAddr` for the peer-table
/// key — the actual destination is held inside the `PacketIO`.
pub type ConnectorFactory = fn(
    String,
) -> Pin<
    Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>,
>;

/// One adapter's registration in the URL dispatcher. Each
/// adapter submits exactly one of these; the `scheme` field
/// must be unique across all submissions.
pub struct SchemeRegistration {
    pub scheme: &'static str,
    pub listener: ListenerFactory,
    pub connector: ConnectorFactory,
}

inventory::collect!(SchemeRegistration);

/// Parse `<scheme>://<host:port>` URL. Bare `host:port` (no
/// scheme) defaults to `udp` for back-compat.
fn split_url(url: &str) -> io::Result<(&str, &str)> {
    if let Some(idx) = url.find("://") {
        Ok((&url[..idx], &url[idx + 3..]))
    } else {
        Ok(("udp", url))
    }
}

fn lookup_scheme(scheme: &str) -> Option<&'static SchemeRegistration> {
    inventory::iter::<SchemeRegistration>
        .into_iter()
        .find(|r| r.scheme == scheme)
}

/// Build a `Listener` from a URL. The address portion is
/// handed to the adapter as an opaque string — each transport
/// parses it however its address space requires. Adapter
/// dispatch is by runtime registry; no edits to this function
/// are needed when a new transport is added.
pub async fn make_listener(url: &str) -> io::Result<Box<dyn Listener>> {
    let (scheme, addr_str) = split_url(url)?;
    let reg = lookup_scheme(scheme).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "no listener registered for scheme {:?} (registered: {:?})",
                scheme,
                registered_schemes()
            ),
        )
    })?;
    (reg.listener)(addr_str.to_string()).await
}

/// Client-side URL dispatch. Returns the connected `PacketIO`
/// plus the remote `SocketAddr` that the application should use
/// when calling `transport.add_peer(...)`. Adapter dispatch is
/// by runtime registry — same plug-and-play story as listeners.
pub async fn make_connector(url: &str) -> io::Result<(Arc<dyn PacketIO>, SocketAddr)> {
    let (scheme, addr_str) = split_url(url)?;
    let reg = lookup_scheme(scheme).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "no connector registered for scheme {:?} (registered: {:?})",
                scheme,
                registered_schemes()
            ),
        )
    })?;
    (reg.connector)(addr_str.to_string()).await
}

/// Helper: parse a `host:port` address string for IP-addressed
/// transports (UDP, TCP, TLS, WS). Non-IP adapters skip this and
/// parse their own address shape.
pub(crate) fn parse_ip_addr(addr_str: &str) -> io::Result<SocketAddr> {
    addr_str.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a valid host:port {:?}: {}", addr_str, e),
        )
    })
}

/// All schemes currently registered. Useful for diagnostics
/// (printed in the error when an unknown scheme arrives).
pub fn registered_schemes() -> Vec<&'static str> {
    inventory::iter::<SchemeRegistration>
        .into_iter()
        .map(|r| r.scheme)
        .collect()
}

// ─── Built-in adapter registrations ───────────────────────────────
//
// The three adapters that ship in drift core register themselves
// here. New built-ins follow the same pattern. External crates
// can add their own via the same `inventory::submit!` macro from
// anywhere — even outside this file or this crate.

fn udp_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str)?;
        Ok(Box::new(UdpListenerIO::bind(addr).await?) as Box<dyn Listener>)
    })
}

fn udp_connector_factory(
    addr_str: String,
) -> Pin<
    Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>,
> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str)?;
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let io: Arc<dyn PacketIO> = Arc::new(UdpPacketIO::new(Arc::new(sock)));
        Ok((io, addr))
    })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "udp",
        listener: udp_listener_factory,
        connector: udp_connector_factory,
    }
}

fn tcp_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str)?;
        Ok(Box::new(TcpListenerIO::bind(addr).await?) as Box<dyn Listener>)
    })
}

fn tcp_connector_factory(
    addr_str: String,
) -> Pin<
    Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>,
> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str)?;
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let io: Arc<dyn PacketIO> = Arc::new(TcpPacketIO::new(stream)?);
        Ok((io, addr))
    })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "tcp",
        listener: tcp_listener_factory,
        connector: tcp_connector_factory,
    }
}

fn ws_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str)?;
        Ok(Box::new(WsListenerIO::bind(addr).await?) as Box<dyn Listener>)
    })
}

fn ws_connector_factory(
    addr_str: String,
) -> Pin<
    Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>,
> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str)?;
        // tokio-tungstenite's connect_async expects a full
        // ws:// URL — synthesize one from the host:port.
        let url = format!("ws://{}/", addr);
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| io::Error::other(e))?;
        let io: Arc<dyn PacketIO> = Arc::new(WsPacketIO::new(ws, addr));
        Ok((io, addr))
    })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "ws",
        listener: ws_listener_factory,
        connector: ws_connector_factory,
    }
}

fn tls_listener_factory(
    addr_str: String,
) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Listener>>> + Send>> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str)?;
        Ok(Box::new(TlsListenerIO::bind(addr).await?) as Box<dyn Listener>)
    })
}

fn tls_connector_factory(
    addr_str: String,
) -> Pin<
    Box<dyn Future<Output = io::Result<(Arc<dyn PacketIO>, SocketAddr)>> + Send>,
> {
    Box::pin(async move {
        let addr = parse_ip_addr(&addr_str)?;
        install_default_crypto_provider();
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let _ = tcp.set_nodelay(true);
        let local = tcp.local_addr()?;
        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        // SNI just needs to be a syntactically-valid DNS name —
        // the cert isn't validated. "localhost" works for any
        // peer.
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .map_err(|e| io::Error::other(format!("server name: {}", e)))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| io::Error::other(format!("TLS handshake: {}", e)))?;
        let io: Arc<dyn PacketIO> = Arc::new(TlsPacketIO::new(tls, addr, local));
        Ok((io, addr))
    })
}

inventory::submit! {
    SchemeRegistration {
        scheme: "tls",
        listener: tls_listener_factory,
        connector: tls_connector_factory,
    }
}
