//! Comparative throughput: DRIFT vs raw UDP vs QUIC on loopback.
//!
//! The goal: validate (or falsify) the README's "QUIC-grade
//! performance" claim with numbers. DRIFT is layered on top of
//! UDP; we expect to be near raw UDP's ceiling, below it by
//! the cost of AEAD + handshake state per packet. QUIC should
//! land in the same ballpark — both do congestion control,
//! AEAD, and per-packet state, though QUIC has more machinery
//! per flow (multiplexing, flow control, stream state).
//!
//! Run with `cargo bench --bench comparative`.
//!
//! All three run on the same loopback interface so we're
//! measuring protocol overhead, not network delivery. The
//! point is relative positioning, not absolute numbers on any
//! particular machine.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use drift::identity::Identity;
use drift::{Direction, Transport};
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

criterion_group!(benches, bench_drift, bench_raw_udp, bench_quic);
criterion_main!(benches);
