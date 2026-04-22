//! Throughput benchmarks for DRIFT.
//!
//! Measures:
//!  - Raw header encode/decode
//!  - ChaCha20-Poly1305 seal/open at various payload sizes
//!  - End-to-end loopback packet delivery (short-header fast path
//!    vs long-header, to quantify the claimed 56% overhead reduction)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use drift::crypto::{Direction, SessionKey};
use drift::header::{canonical_aad, Header, PacketType, HEADER_LEN};
use drift::identity::Identity;
use drift::Transport;
use std::net::SocketAddr;

/// Wire overhead per packet, in bytes, for each header flavor.
/// Useful in commit messages + docs: the short-header path's
/// payload-fraction advantage is most visible at small payload
/// sizes, where the fixed per-packet overhead dominates.
const LONG_HEADER_OVERHEAD: usize = 36 + 16; // header + AEAD tag
const SHORT_HEADER_OVERHEAD: usize = 7 + 16; // compact header + AEAD tag

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
            b.iter(|| {
                sender
                    .seal(1, PacketType::Data as u8, &aad, &payload)
                    .unwrap()
            });
        });

        let ct = sender
            .seal(1, PacketType::Data as u8, &aad, &payload)
            .unwrap();
        group.bench_with_input(BenchmarkId::new("open", size), &size, |b, _| {
            b.iter(|| receiver.open(1, PacketType::Data as u8, &aad, &ct).unwrap());
        });
    }
    group.finish();
}

/// Shared setup used by both loopback benches: builds a warm
/// Alice ↔ Bob session over UDP loopback.
async fn build_session() -> (drift::Transport, drift::Transport, [u8; 8]) {
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
        drift::Direction::Responder,
    )
    .await
    .unwrap();
    let bob_addr = bob.local_addr().unwrap();

    let alice = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), alice_id)
        .await
        .unwrap();
    let bob_peer = alice
        .add_peer(bob_pub, bob_addr, drift::Direction::Initiator)
        .await
        .unwrap();

    // Warm up so the session is Established before we start the
    // measurement loop.
    alice
        .send_data(&bob_peer, &[0u8; 32], 0, 0)
        .await
        .unwrap();
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), bob.recv()).await;

    (alice, bob, bob_peer)
}

/// Short-header path: `send_data(peer, payload, 0, 0)` — no
/// deadline, no coalesce group — uses the 7-byte compact header
/// once the session is Established.
fn bench_loopback_short_header(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("loopback_short_header");
    group.sample_size(20);

    for size in [64usize, 256, 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("send_data", size), &size, |b, &size| {
            b.to_async(&rt).iter_custom(|iters| async move {
                let (alice, bob, bob_peer) = build_session().await;
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

/// Long-header path: `send_data(peer, payload, deadline=200, 0)`
/// — a non-zero deadline forces the long header (short header
/// has no deadline field). 5 extra bytes per packet than short
/// header + everything a feature-tagged packet needs.
fn bench_loopback_long_header(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("loopback_long_header");
    group.sample_size(20);

    for size in [64usize, 256, 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("send_data", size), &size, |b, &size| {
            b.to_async(&rt).iter_custom(|iters| async move {
                let (alice, bob, bob_peer) = build_session().await;
                let payload = vec![0x55u8; size];
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    alice
                        .send_data(&bob_peer, &payload, 200 /* deadline_ms */, 0)
                        .await
                        .unwrap();
                    bob.recv().await.unwrap();
                }
                start.elapsed()
            });
        });
    }
    group.finish();
}

/// Pure header-overhead math, tabulated on stdout for docs. Not
/// a benchmark per se — prints the header overhead fraction at
/// typical payload sizes so the README can be accurate about
/// wire efficiency.
fn bench_header_overhead_table(c: &mut Criterion) {
    // Print once. `bench_function` with a single iter gives us
    // criterion's setup without running anything meaningful.
    let mut group = c.benchmark_group("overhead_table");
    group.sample_size(10);
    group.bench_function("print", |b| {
        b.iter(|| {
            // One-time print when the group first runs.
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                eprintln!();
                eprintln!(
                    "== Per-packet wire overhead (header + AEAD tag) =="
                );
                eprintln!(
                    "  payload |  long hdr  |  short hdr | saved%"
                );
                for payload in [16, 64, 256, 1024] {
                    let long_total = payload + LONG_HEADER_OVERHEAD;
                    let short_total = payload + SHORT_HEADER_OVERHEAD;
                    let saved =
                        100.0 * (long_total - short_total) as f64 / long_total as f64;
                    eprintln!(
                        "  {:>5} B | {:>4} B/pkt | {:>4} B/pkt | {:>5.1}%",
                        payload, long_total, short_total, saved
                    );
                }
                eprintln!();
            });
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_header,
    bench_aead,
    bench_loopback_short_header,
    bench_loopback_long_header,
    bench_header_overhead_table
);
criterion_main!(benches);
