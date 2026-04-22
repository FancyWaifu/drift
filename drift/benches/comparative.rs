//! Comparative benches: DRIFT vs raw UDP vs QUIC vs WireGuard.
//!
//! Two axes:
//!   1. Data-plane throughput on loopback (DRIFT, raw UDP, QUIC,
//!      WireGuard). Measures per-packet protocol cost once the
//!      session is established.
//!   2. Cold handshake latency (DRIFT, QUIC, WireGuard). Measures
//!      time-to-first-byte over a fresh connection.
//!
//! Raw UDP is the floor — no encryption, no state. Everything
//! above raw UDP is the protocol tax. QUIC and DRIFT both run
//! over UDP on loopback. WireGuard is driven in-memory via
//! boringtun's `Tunn` API (no tun device, no sockets), so the
//! WG numbers measure pure protocol work — handshake crypto +
//! AEAD data plane.
//!
//! Run with `cargo bench --bench comparative`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use drift::identity::Identity;
use drift::io::{MemPacketIO, PacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

// ───────────────────── DRIFT (UDP) ─────────────────────

async fn drift_setup() -> (Transport, Transport, [u8; 8]) {
    let (alice_id, bob_id) = (
        Identity::from_secret_bytes([0x11; 32]),
        Identity::from_secret_bytes([0x22; 32]),
    );
    let alice_pub = alice_id.public_bytes();
    let bob_pub = bob_id.public_bytes();

    let bob = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), bob_id)
        .await
        .unwrap();
    bob.add_peer(
        alice_pub,
        "0.0.0.0:0".parse().unwrap(),
        Direction::Responder,
    )
    .await
    .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    let alice = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), alice_id)
        .await
        .unwrap();
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, Direction::Initiator)
        .await
        .unwrap();
    alice.send_data(&bob_peer, &[0u8; 32], 0, 0).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(200), bob.recv()).await;

    (alice, bob, bob_peer)
}

fn bench_drift(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("comparative/drift");
    group.sample_size(20);

    // Sizes capped at 1024: DRIFT's MAX_PAYLOAD is 1348 bytes
    // (1400 MTU − 36 header − 16 AEAD tag). Going above that
    // would require userspace chunking, which changes what the
    // bench measures. For apples-to-apples we stick to single-
    // packet sizes on all three transports.
    for size in [256usize, 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.to_async(&rt).iter_custom(|iters| async move {
                let (alice, bob, bob_peer) = drift_setup().await;
                let payload = vec![0xA5u8; size];
                let start = Instant::now();
                for _ in 0..iters {
                    alice.send_data(&bob_peer, &payload, 0, 0).await.unwrap();
                    bob.recv().await.unwrap();
                }
                start.elapsed()
            });
        });
    }
    group.finish();
}

// ───────────────────── Raw UDP baseline ─────────────────────
//
// Plain `tokio::net::UdpSocket::send_to` / `recv_from`. No
// encryption, no state machine, nothing. This is the absolute
// ceiling for UDP on the host; DRIFT and QUIC are measured
// against this.

fn bench_raw_udp(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("comparative/raw_udp");
    group.sample_size(20);

    // Sizes capped at 1024: DRIFT's MAX_PAYLOAD is 1348 bytes
    // (1400 MTU − 36 header − 16 AEAD tag). Going above that
    // would require userspace chunking, which changes what the
    // bench measures. For apples-to-apples we stick to single-
    // packet sizes on all three transports.
    for size in [256usize, 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.to_async(&rt).iter_custom(|iters| async move {
                let recv_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let recv_addr = recv_sock.local_addr().unwrap();
                let send_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                send_sock.connect(recv_addr).await.unwrap();

                let payload = vec![0xA5u8; size];
                let mut buf = vec![0u8; 65536];
                let start = Instant::now();
                for _ in 0..iters {
                    send_sock.send(&payload).await.unwrap();
                    recv_sock.recv_from(&mut buf).await.unwrap();
                }
                start.elapsed()
            });
        });
    }
    group.finish();
}

// ───────────────────── QUIC (quinn) ─────────────────────

fn make_quinn_endpoints() -> (quinn::Endpoint, quinn::Endpoint, SocketAddr) {
    use quinn::ServerConfig;
    use rcgen::{CertificateParams, KeyPair};

    // Generate a self-signed cert for localhost.
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der: rustls::pki_types::CertificateDer<'static> = cert.der().clone();
    let key_der =
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

    // Install ring as the default CryptoProvider (rustls
    // requires exactly one). Idempotent — multiple installs
    // error silently but don't break.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server_config =
        ServerConfig::with_single_cert(vec![cert_der.clone()], key_der).unwrap();

    // Server endpoint bound to a random loopback port.
    let server =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Client endpoint: trust the server's self-signed cert.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(quic_client));
    let mut client =
        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);

    (client, server, server_addr)
}

fn bench_quic(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("comparative/quic");
    group.sample_size(20);

    // Sizes capped at 1024: DRIFT's MAX_PAYLOAD is 1348 bytes
    // (1400 MTU − 36 header − 16 AEAD tag). Going above that
    // would require userspace chunking, which changes what the
    // bench measures. For apples-to-apples we stick to single-
    // packet sizes on all three transports.
    for size in [256usize, 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.to_async(&rt).iter_custom(|iters| async move {
                let (client, server, server_addr) = make_quinn_endpoints();

                // Handshake + accept a single bidi stream,
                // reused for all iters in this benchmark run.
                let connecting_client = client.connect(server_addr, "localhost").unwrap();
                let connecting_server = server.accept().await.unwrap();
                let (client_conn, server_conn) = tokio::join!(
                    async { connecting_client.await.unwrap() },
                    async { connecting_server.await.unwrap() },
                );

                let (mut send, _recv_client_peer) =
                    client_conn.open_bi().await.unwrap();
                // Quinn's `open_bi` is local — no stream frame
                // goes on the wire until we write. accept_bi on
                // the server side blocks on that first frame, so
                // prime the stream with one byte before we let
                // the server accept, and drain it after.
                send.write_all(&[0u8]).await.unwrap();
                send.flush().await.unwrap();
                let (_send_server_peer, mut recv) = server_conn.accept_bi().await.unwrap();
                let mut prime = [0u8; 1];
                recv.read_exact(&mut prime).await.unwrap();

                let payload = vec![0xA5u8; size];
                let mut buf = vec![0u8; size];

                // Prime the stream with a length-prefixed
                // framing scheme. For a fair comparison we
                // send one `size` chunk and read it back on
                // the server side per iter.
                let start = Instant::now();
                for _ in 0..iters {
                    send.write_all(&payload).await.unwrap();
                    send.flush().await.unwrap();
                    // Fill `buf` exactly — QUIC streams can
                    // deliver partial reads, so loop until
                    // we've got `size` bytes.
                    let mut got = 0;
                    while got < size {
                        let n = recv.read(&mut buf[got..]).await.unwrap().unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        got += n;
                    }
                }
                start.elapsed()
            });
        });
    }
    group.finish();
}

// ───────────────────── WireGuard (boringtun, in-memory) ─────────────────────
//
// We drive boringtun's `Tunn` directly — no tun device, no
// sockets, no kernel. Each iteration is pure crypto work:
// Noise_IKpsk2 handshake for the handshake bench, and
// ChaCha20-Poly1305 encap/decap for the data-plane bench.
// Payloads are formatted as minimal IPv4 packets because
// boringtun's decapsulate parses the total-length field from
// the IP header — sending raw bytes yields InvalidPacket.

/// Build a minimal valid IPv4 packet that boringtun will accept.
/// Fills the 20-byte IPv4 header's version / IHL / total-length
/// fields; everything else is zero. The `size` parameter is the
/// full packet length (header + payload).
fn fake_ipv4(size: usize) -> Vec<u8> {
    assert!(size >= 20);
    let mut pkt = vec![0u8; size];
    pkt[0] = 0x45; // version=4, IHL=5 (20-byte header)
    pkt[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    pkt
}

/// Run one complete WireGuard handshake in memory. Returns the
/// two `Tunn` sides once the session is established. Used by
/// both the handshake latency bench (measure this whole call)
/// and the data-plane bench (call once for setup, then loop
/// encap/decap).
fn wg_handshake(alice_seed: [u8; 32], bob_seed: [u8; 32]) -> (boringtun::noise::Tunn, boringtun::noise::Tunn) {
    use boringtun::noise::{Tunn, TunnResult};
    use x25519_dalek::{PublicKey, StaticSecret};

    let alice_sk = StaticSecret::from(alice_seed);
    let bob_sk = StaticSecret::from(bob_seed);
    let alice_pk = PublicKey::from(&alice_sk);
    let bob_pk = PublicKey::from(&bob_sk);

    let mut alice = Tunn::new(alice_sk, bob_pk, None, None, 0, None);
    let mut bob = Tunn::new(bob_sk, alice_pk, None, None, 1, None);

    let mut a_buf = vec![0u8; 2048];
    let mut b_buf = vec![0u8; 2048];

    // Step 1: Alice triggers handshake by encapsulating a
    // dummy packet. Result is the HandshakeInit on the wire;
    // the packet itself is queued internally.
    let init = match alice.encapsulate(&fake_ipv4(28), &mut a_buf) {
        TunnResult::WriteToNetwork(w) => w.to_vec(),
        r => panic!("alice encap init: {:?}", r),
    };

    // Step 2: Bob receives HandshakeInit -> sends HandshakeResponse.
    let resp = match bob.decapsulate(None, &init, &mut b_buf) {
        TunnResult::WriteToNetwork(w) => w.to_vec(),
        r => panic!("bob decap init: {:?}", r),
    };

    // Step 3: Alice receives HandshakeResponse -> session
    // established. Boringtun may flush the queued packet here
    // as a WriteToNetwork — we accept either outcome.
    match alice.decapsulate(None, &resp, &mut a_buf) {
        TunnResult::WriteToNetwork(_) | TunnResult::Done => {}
        r => panic!("alice decap response: {:?}", r),
    }

    (alice, bob)
}

fn bench_wireguard(c: &mut Criterion) {
    use boringtun::noise::TunnResult;

    let mut group = c.benchmark_group("comparative/wireguard");
    group.sample_size(20);

    // Data-plane throughput: handshake once, then loop
    // encapsulate / decapsulate. Matches the DRIFT / QUIC /
    // raw-UDP loop body.
    for size in [256usize, 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_custom(|iters| {
                let (mut alice, mut bob) = wg_handshake([0x11; 32], [0x22; 32]);
                let payload = fake_ipv4(size);
                let mut a_buf = vec![0u8; size + 128];
                let mut b_buf = vec![0u8; size + 128];

                let start = Instant::now();
                for _ in 0..iters {
                    let wire = match alice.encapsulate(&payload, &mut a_buf) {
                        TunnResult::WriteToNetwork(w) => w.to_vec(),
                        r => panic!("encap: {:?}", r),
                    };
                    match bob.decapsulate(None, &wire, &mut b_buf) {
                        TunnResult::WriteToTunnelV4(_, _)
                        | TunnResult::WriteToTunnelV6(_, _) => {}
                        r => panic!("decap: {:?}", r),
                    }
                }
                start.elapsed()
            });
        });
    }
    group.finish();
}

// ───────────────────── Handshake latency ─────────────────────

/// DRIFT cold handshake over MemPacketIO (in-memory). Matches
/// the `handshake.rs` cold bench but lives here so the numbers
/// appear alongside QUIC and WireGuard in one report.
fn bench_drift_handshake(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("comparative/handshake");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("drift", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                let alice_id = Identity::from_secret_bytes([(i % 254 + 1) as u8; 32]);
                let alice_pub = alice_id.public_bytes();
                let bob_id = Identity::from_secret_bytes([((i + 1) % 254 + 1) as u8; 32]);
                let bob_pub = bob_id.public_bytes();

                let (a_io, b_io) = MemPacketIO::pair();
                let a_io: Arc<dyn PacketIO> = Arc::new(a_io);
                let b_io: Arc<dyn PacketIO> = Arc::new(b_io);
                let a_addr = a_io.local_addr().unwrap();
                let b_addr = b_io.local_addr().unwrap();

                let bob =
                    Transport::bind_with_io(b_io, bob_id, TransportConfig::default())
                        .await
                        .unwrap();
                bob.add_peer(alice_pub, a_addr, Direction::Responder)
                    .await
                    .unwrap();
                let alice = Transport::bind_with_io(
                    a_io,
                    alice_id,
                    TransportConfig::default(),
                )
                .await
                .unwrap();
                let bob_peer = alice
                    .add_peer(bob_pub, b_addr, Direction::Initiator)
                    .await
                    .unwrap();

                let start = Instant::now();
                alice.send_data(&bob_peer, b"go", 0, 0).await.unwrap();
                let _ = bob.recv().await.unwrap();
                total += start.elapsed();
            }
            total
        });
    });
    group.finish();
}

/// QUIC cold handshake: from `client.connect` to the
/// connection being usable (both sides have completed TLS 1.3
/// + QUIC transport params). Measured up to — but not
/// including — the first bidi stream's data transfer, so the
/// numbers isolate the handshake proper.
fn bench_quic_handshake(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("comparative/handshake");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(6));

    group.bench_function("quic", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let (client, server, server_addr) = make_quinn_endpoints();

                let start = Instant::now();
                let connecting_client = client.connect(server_addr, "localhost").unwrap();
                let connecting_server = server.accept().await.unwrap();
                let _ = tokio::join!(
                    async { connecting_client.await.unwrap() },
                    async { connecting_server.await.unwrap() },
                );
                total += start.elapsed();
            }
            total
        });
    });
    group.finish();
}

/// WireGuard (Noise_IKpsk2) cold handshake, all in-memory.
/// One HandshakeInit + one HandshakeResponse + one encapsulate
/// + one decapsulate = session established + first data byte
/// delivered. No sockets, so this is pure crypto + state work.
fn bench_wg_handshake(c: &mut Criterion) {
    use boringtun::noise::TunnResult;

    let mut group = c.benchmark_group("comparative/handshake");
    group.sample_size(20);

    group.bench_function("wireguard", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                let alice_seed = [(i % 254 + 1) as u8; 32];
                let bob_seed = [((i + 1) % 254 + 1) as u8; 32];
                let mut a_buf = vec![0u8; 2048];
                let mut b_buf = vec![0u8; 2048];

                let start = Instant::now();
                let (mut alice, mut bob) = wg_handshake(alice_seed, bob_seed);

                // First data packet after handshake — matches
                // DRIFT's "first DATA delivered" semantics.
                let wire = match alice.encapsulate(&fake_ipv4(28), &mut a_buf) {
                    TunnResult::WriteToNetwork(w) => w.to_vec(),
                    r => panic!("encap first: {:?}", r),
                };
                match bob.decapsulate(None, &wire, &mut b_buf) {
                    TunnResult::WriteToTunnelV4(_, _)
                    | TunnResult::WriteToTunnelV6(_, _) => {}
                    r => panic!("decap first: {:?}", r),
                }

                total += start.elapsed();
            }
            total
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_drift,
    bench_raw_udp,
    bench_quic,
    bench_wireguard,
    bench_drift_handshake,
    bench_quic_handshake,
    bench_wg_handshake,
);
criterion_main!(benches);
