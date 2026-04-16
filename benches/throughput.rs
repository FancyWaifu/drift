//! Throughput benchmarks for DRIFT.
//!
//! Measures:
//!  - Raw header encode/decode
//!  - ChaCha20-Poly1305 seal/open at various payload sizes
//!  - End-to-end loopback packet delivery

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use drift::crypto::{Direction, SessionKey};
use drift::header::{canonical_aad, Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::Transport;
use std::net::SocketAddr;

fn bench_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("header");
    group.bench_function("encode", |b| {
        let h = Header::new(PacketType::Data, 42, [1; 8], [2; 8]).with_deadline(200);
        let mut buf = [0u8; HEADER_LEN];
        b.iter(|| {
            h.encode(&mut buf);
        });
    });
    group.bench_function("decode", |b| {
        let h = Header::new(PacketType::Data, 42, [1; 8], [2; 8]).with_deadline(200);
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        b.iter(|| {
            let _ = Header::decode(&buf);
        });
    });
    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");
    let key = [7u8; 32];
    let sender = SessionKey::new(&key, Direction::Initiator);
    let receiver = SessionKey::new(&key, Direction::Initiator);

    for size in [16usize, 64, 256, 1024] {
        let payload = vec![0xAAu8; size];
        let h = Header::new(PacketType::Data, 1, [1; 8], [2; 8]);
        let mut hbuf = [0u8; HEADER_LEN];
        h.encode(&mut hbuf);
        let aad = canonical_aad(&hbuf);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("seal", size), &size, |b, _| {
            b.iter(|| sender.seal(1, PacketType::Data as u8, &aad, &payload).unwrap());
        });

        let ct = sender.seal(1, PacketType::Data as u8, &aad, &payload).unwrap();
        group.bench_with_input(BenchmarkId::new("open", size), &size, |b, _| {
            b.iter(|| receiver.open(1, PacketType::Data as u8, &aad, &ct).unwrap());
        });
    }
    group.finish();
}

fn bench_loopback(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("loopback");
    group.sample_size(20);

    for size in [64usize, 256, 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("send_data", size), &size, |b, &size| {
            b.to_async(&rt).iter_custom(|iters| async move {
                let (alice_id, bob_id) = (
                    Identity::from_secret_bytes([0x11; 32]),
                    Identity::from_secret_bytes([0x22; 32]),
                );
                let alice_pub = alice_id.public_bytes();
                let bob_pub = bob_id.public_bytes();

                let bob = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), bob_id)
                    .await
                    .unwrap();
                bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
                    .await.unwrap();
                let bob_addr = bob.local_addr().unwrap();

                let alice = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), alice_id)
                    .await
                    .unwrap();
                let bob_peer = alice
                    .add_peer(bob_pub, bob_addr, Direction::Initiator)
                    .await.unwrap();

                // Warm up handshake with one packet.
                alice.send_data(&bob_peer, &vec![0u8; size], 0, 0).await.unwrap();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    bob.recv(),
                )
                .await;

                let payload = vec![0x55u8; size];
                let start = std::time::Instant::now();
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

criterion_group!(benches, bench_header, bench_aead, bench_loopback);
criterion_main!(benches);
