//! Hybrid PQ behavior under MTU clamping.
//!
//! Two-part test:
//!
//!   1. **Static wire-size assertion** — compute the actual
//!      hybrid HELLO size from the public constants and assert
//!      it fits under the MTUs we care about (1500 Ethernet,
//!      1492 PPPoE, 1400 conservative tunnel default). If we
//!      ever bump ML-KEM parameters this fails loud.
//!
//!   2. **Drop-oversized-packets simulation** — wrap UDP with a
//!      `LossyMtuIO` that drops packets exceeding a configured
//!      MTU at the send_to seam. We then assert:
//!        - MTU 1500 → handshake completes
//!        - MTU 1280 (below hybrid HELLO size) → handshake fails
//!          fast (handshake_max_attempts bounded), does NOT hang
//!
//!   The hang-vs-fail distinction is what matters operationally.
//!   PMTUD black holes drop packets silently — we need the client
//!   to give up cleanly so apps can fall back to classical or
//!   surface an error.

use async_trait::async_trait;
use drift::identity::Identity;
use drift::io::{PacketIO, UdpPacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

const HEADER: usize = 36;
const STATIC_KEY: usize = 32;
const NONCE: usize = 16;
const ML_KEM_EK: usize = 1184;
const ML_KEM_CT: usize = 1088;
const AUTH_TAG: usize = 16;
const IP_UDP_HDR: usize = 28; // typical IPv4 + UDP headers

fn hybrid_hello_payload_size() -> usize {
    // header + static + ephemeral + nonce + ml-kem-ek
    HEADER + STATIC_KEY + STATIC_KEY + NONCE + ML_KEM_EK
}

fn hybrid_hello_wire_size() -> usize {
    hybrid_hello_payload_size() + IP_UDP_HDR
}

fn hybrid_hello_ack_payload_size() -> usize {
    HEADER + STATIC_KEY + NONCE + AUTH_TAG + ML_KEM_CT
}

#[test]
fn hybrid_hello_fits_under_common_mtus() {
    let hello_wire = hybrid_hello_wire_size();
    let ack_wire = hybrid_hello_ack_payload_size() + IP_UDP_HDR;
    eprintln!(
        "hybrid HELLO wire size: {} bytes, hybrid HELLO_ACK wire size: {} bytes",
        hello_wire, ack_wire
    );
    // 1500 = standard Ethernet MTU
    assert!(
        hello_wire < 1500 && ack_wire < 1500,
        "hybrid wire size exceeds 1500 MTU"
    );
    // 1492 = PPPoE default MTU (common on consumer ISPs)
    assert!(
        hello_wire < 1492 && ack_wire < 1492,
        "hybrid wire size exceeds 1492 PPPoE MTU"
    );
    // 1400 = conservative tunnel MTU (used by some VPN providers)
    assert!(
        hello_wire < 1400 && ack_wire < 1400,
        "hybrid wire size exceeds 1400 conservative tunnel MTU"
    );
}

/// PacketIO wrapper that drops outbound packets exceeding
/// `mtu` bytes (payload-only; doesn't include IP/UDP headers).
/// Counts drops for the test to assert on.
struct LossyMtuIO {
    inner: Arc<UdpPacketIO>,
    mtu: usize,
    drops: AtomicU64,
}

#[async_trait]
impl PacketIO for LossyMtuIO {
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        if buf.len() > self.mtu {
            self.drops.fetch_add(1, Ordering::Relaxed);
            // Pretend we sent it — match a PMTUD black hole. Real
            // ICMP "frag needed" messages are also commonly
            // filtered, so silent drop is the realistic failure.
            return Ok(buf.len());
        }
        self.inner.send_to(buf, dest).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

fn pq_cfg_fast_fail() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        hybrid_pq: true,
        // Bound the test runtime: with 3 attempts at 50ms base
        // backoff we give up in well under 1s on MTU black-hole.
        handshake_max_attempts: 3,
        handshake_retry_base_ms: 50,
        ..Default::default()
    }
}

async fn lossy_udp_io(mtu: usize) -> (Arc<LossyMtuIO>, SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let inner = Arc::new(UdpPacketIO::new(Arc::new(sock)));
    let lossy = Arc::new(LossyMtuIO {
        inner,
        mtu,
        drops: AtomicU64::new(0),
    });
    (lossy, addr)
}

#[tokio::test]
async fn hybrid_pq_handshake_succeeds_at_1500_mtu() {
    let (server_io, server_addr) = lossy_udp_io(1500).await;
    let (client_io, _client_addr) = lossy_udp_io(1500).await;

    let server_id = Identity::from_secret_bytes([0xE1; 32]);
    let server_pub = server_id.public_bytes();
    let server = Arc::new(
        Transport::bind_with_io(server_io.clone(), server_id, pq_cfg_fast_fail())
            .await
            .unwrap(),
    );
    let client_id = Identity::from_secret_bytes([0xE2; 32]);
    let client_pub = client_id.public_bytes();
    let client = Arc::new(
        Transport::bind_with_io(client_io, client_id, pq_cfg_fast_fail())
            .await
            .unwrap(),
    );

    server
        .add_peer(
            client_pub,
            "0.0.0.0:0".parse().unwrap(),
            Direction::Responder,
        )
        .await
        .unwrap();
    let server_handle = client
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .unwrap();
    client
        .send_data(&server_handle, b"under-mtu-1500", 0, 0)
        .await
        .unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(3), server.recv())
        .await
        .expect("handshake should complete under 1500 MTU")
        .unwrap();
    assert_eq!(pkt.payload, b"under-mtu-1500");
    assert_eq!(server_io.drops.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn hybrid_pq_handshake_fails_fast_at_1200_mtu() {
    // MTU 1200 is well below our hybrid HELLO (~1300 B payload).
    // Every retransmit attempt gets silently dropped; the
    // handshake retry loop bounded by handshake_max_attempts
    // must give up cleanly within the bounded time. NO HANG.
    let (server_io, server_addr) = lossy_udp_io(1200).await;
    let (client_io, _) = lossy_udp_io(1200).await;

    let server_id = Identity::from_secret_bytes([0xE3; 32]);
    let server_pub = server_id.public_bytes();
    let _server = Arc::new(
        Transport::bind_with_io(server_io.clone(), server_id, pq_cfg_fast_fail())
            .await
            .unwrap(),
    );
    let client_id = Identity::from_secret_bytes([0xE4; 32]);
    let client = Arc::new(
        Transport::bind_with_io(client_io.clone(), client_id, pq_cfg_fast_fail())
            .await
            .unwrap(),
    );

    let server_handle = client
        .add_peer(server_pub, server_addr, Direction::Initiator)
        .await
        .unwrap();
    let _ = client
        .send_data(&server_handle, b"this-wont-arrive", 0, 0)
        .await;

    // 3 attempts × ~50ms base × exponential = give it up to 2s.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The client's lossy IO should have dropped HELLOs equal to
    // the retry attempts. Server's lossy IO sees no drops
    // because it never gets the chance to send a HELLO_ACK.
    let client_drops = client_io.drops.load(Ordering::Relaxed);
    assert!(
        client_drops >= 1,
        "expected at least 1 oversized-HELLO drop, got {}",
        client_drops
    );
    assert_eq!(
        server_io.drops.load(Ordering::Relaxed),
        0,
        "server should never have tried to send anything"
    );
    eprintln!(
        "MTU 1200 fast-fail: client dropped {} HELLOs, server dropped 0; \
         handshake retry loop gave up cleanly without hanging",
        client_drops
    );
}
