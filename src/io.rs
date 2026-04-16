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
use std::io;
use std::net::SocketAddr;
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

    /// Receive the next complete packet. Returns
    /// `(bytes_read, source_address)`. Blocks until a
    /// packet is available.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

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

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
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
}

impl TcpPacketIO {
    /// Wrap an established TCP connection. The connection
    /// must already be connected — this adapter doesn't
    /// handle TCP setup. `peer_addr` is used as the
    /// "destination" for all send_to calls (since TCP is
    /// point-to-point, the destination is always the same).
    pub fn new(stream: tokio::net::TcpStream) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;
        let _ = stream.set_nodelay(true);
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: tokio::sync::Mutex::new(reader),
            writer: tokio::sync::Mutex::new(writer),
            peer_addr,
            local_addr,
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
        let len_bytes = (buf.len() as u16).to_be_bytes();
        let mut writer = self.writer.lock().await;
        writer.write_all(&len_bytes).await?;
        writer.write_all(buf).await?;
        writer.flush().await?;
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
                format!(
                    "TCP frame too large: {} bytes, buffer is {}",
                    len,
                    buf.len()
                ),
            ));
        }
        reader.read_exact(&mut buf[..len]).await?;
        Ok((len, self.peer_addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
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
    interfaces: std::sync::RwLock<Vec<(String, Arc<dyn PacketIO>)>>,
}

impl InterfaceSet {
    /// Create an interface set with a single adapter (the
    /// common case for backward compatibility).
    pub fn single(name: impl Into<String>, io: Arc<dyn PacketIO>) -> Self {
        Self {
            interfaces: std::sync::RwLock::new(vec![(name.into(), io)]),
        }
    }

    /// Add a new interface. Returns its index (used as the
    /// `interface_id` on peers reached through it). Safe
    /// to call while recv loops are running — the RwLock
    /// ensures concurrent reads aren't interrupted.
    pub fn add(&self, name: impl Into<String>, io: Arc<dyn PacketIO>) -> usize {
        let mut ifaces = self.interfaces.write().unwrap();
        let idx = ifaces.len();
        ifaces.push((name.into(), io));
        idx
    }

    /// Number of interfaces.
    pub fn len(&self) -> usize {
        self.interfaces.read().unwrap().len()
    }

    /// Send a packet via a specific interface by index.
    /// Clones the Arc under the read lock, releases the
    /// lock, then awaits the send — the lock is never
    /// held across an async boundary.
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
                .map(|(_, io)| io.clone())
                .ok_or_else(|| io::Error::new(
                    io::ErrorKind::NotFound,
                    "interface index out of range",
                ))?
        };
        io.send_to(buf, dest).await
    }

    /// Send via interface 0 (default). Convenience for code
    /// paths that don't (yet) track per-peer interfaces.
    pub async fn send_default(
        &self,
        buf: &[u8],
        dest: SocketAddr,
    ) -> io::Result<usize> {
        self.send_via(0, buf, dest).await
    }

    /// Get a cloned Arc to a specific interface by index.
    pub fn get(&self, idx: usize) -> Option<Arc<dyn PacketIO>> {
        let ifaces = self.interfaces.read().unwrap();
        ifaces.get(idx).map(|(_, io)| io.clone())
    }

    /// The local address of the first (default) interface.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let ifaces = self.interfaces.read().unwrap();
        ifaces
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no interfaces"))?
            .1
            .local_addr()
    }

    /// Raw fd of the first interface (for ECN etc).
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        let ifaces = self.interfaces.read().unwrap();
        ifaces.first().and_then(|(_, io)| io.as_raw_fd())
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
        client_io
            .send_to(b"hello-drift", addr)
            .await
            .unwrap();
        client_io
            .send_to(b"second-packet", addr)
            .await
            .unwrap();

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
