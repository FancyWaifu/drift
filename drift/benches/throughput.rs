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
use drift::io::{MemPacketIO, PacketIO};
use drift::{Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;

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

/// Head-to-head: ring's ChaCha20-Poly1305 (what boringtun uses)
/// vs the RustCrypto `chacha20poly1305` crate (what DRIFT uses).
/// Same key, same payloads, same AAD. Any throughput gap is the
/// implementation — that's the ceiling we could hit by swapping
/// backends. NEON cfg is already enabled workspace-wide so the
/// RustCrypto side isn't penalized for being on the soft path.
fn bench_aead_ring_vs_rustcrypto(c: &mut Criterion) {
    use ring::aead::{Aad as RingAad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

    let mut group = c.benchmark_group("aead_head_to_head");
    let key = [7u8; 32];
    let sender = SessionKey::new(&key, Direction::Initiator);
    let ring_key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap());

    // Both runs use the same 12-byte AAD to keep the comparison
    // fair (header-tag AAD the way ring expects it).
    let aad_bytes = [0x99u8; 12];

    for size in [64usize, 256, 1024] {
        let payload = vec![0xAAu8; size];
        let h = Header::new(PacketType::Data, 1, [1; 8], [2; 8]);
        let mut hbuf = [0u8; HEADER_LEN];
        h.encode(&mut hbuf);
        let rc_aad = canonical_aad(&hbuf);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("rustcrypto_seal", size), &size, |b, _| {
            b.iter(|| {
                sender
                    .seal(1, PacketType::Data as u8, &rc_aad, &payload)
                    .unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("ring_seal", size), &size, |b, _| {
            b.iter(|| {
                // Fresh in/out buffer each call to match the
                // RustCrypto path, which returns a new Vec.
                let mut inout = payload.clone();
                inout.extend_from_slice(&[0u8; 16]);
                let nonce = Nonce::assume_unique_for_key([0u8; 12]);
                let tag = ring_key
                    .seal_in_place_separate_tag(nonce, RingAad::from(aad_bytes), &mut inout[..size])
                    .unwrap();
                inout[size..].copy_from_slice(tag.as_ref());
                inout
            });
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

/// DRIFT round-trip over MemPacketIO (in-memory channels). This
/// removes UDP syscalls, kernel routing, and NIC interrupt cost
/// from the measurement — what's left is DRIFT's protocol work
/// (AEAD + header encode/decode + peer-table / CID lookups +
/// mpsc channel dispatch + tokio task wakeups) on top of a
/// zero-cost transport.
///
/// Compare to `loopback_short_header` (same workload over real
/// UDP) to see how much of the per-round-trip cost is UDP vs
/// protocol: UDP = loopback_short - loopback_mem.
fn bench_loopback_mem(c: &mut Criterion) {
    async fn build_mem_session() -> (Transport, Transport, [u8; 8]) {
        let (alice_id, bob_id) = (
            Identity::from_secret_bytes([0x11; 32]),
            Identity::from_secret_bytes([0x22; 32]),
        );
        let alice_pub = alice_id.public_bytes();
        let bob_pub = bob_id.public_bytes();

        let (a_io, b_io) = MemPacketIO::pair();
        let a_io: Arc<dyn PacketIO> = Arc::new(a_io);
        let b_io: Arc<dyn PacketIO> = Arc::new(b_io);
        let a_addr = a_io.local_addr().unwrap();
        let b_addr = b_io.local_addr().unwrap();

        let bob = Transport::bind_with_io(b_io, bob_id, TransportConfig::default())
            .await
            .unwrap();
        bob.add_peer(alice_pub, a_addr, drift::Direction::Responder)
            .await
            .unwrap();

        let alice = Transport::bind_with_io(a_io, alice_id, TransportConfig::default())
            .await
            .unwrap();
        let bob_peer = alice
            .add_peer(bob_pub, b_addr, drift::Direction::Initiator)
            .await
            .unwrap();

        // Warm up so short-header fast path kicks in.
        alice.send_data(&bob_peer, &[0u8; 32], 0, 0).await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), bob.recv()).await;

        (alice, bob, bob_peer)
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("loopback_mem_short_header");
    group.sample_size(20);

    for size in [64usize, 256, 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("send_data", size), &size, |b, &size| {
            b.to_async(&rt).iter_custom(|iters| async move {
                let (alice, bob, bob_peer) = build_mem_session().await;
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
    bench_aead_ring_vs_rustcrypto,
    bench_loopback_short_header,
    bench_loopback_long_header,
    bench_loopback_mem,
    bench_header_overhead_table
);
criterion_main!(benches);
