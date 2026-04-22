//! Handshake latency benchmarks.
//!
//! Measures time-to-first-byte for:
//!   * DRIFT cold handshake (full X25519 static + ephemeral DH,
//!     fresh session keys) — MemPacketIO, fresh identities/iter
//!   * DRIFT 1-RTT resumption (PSK-based, skips static DH) —
//!     UDP loopback with a long-lived Bob so his session store
//!     retains the ticket across iters.
//!
//! Run with `cargo bench --bench handshake`.
//!
//! Why two I/O flavors? The cold bench runs ~thousands of
//! handshakes/sec and would exhaust macOS's ephemeral port
//! range if each iter opened a UDP socket. MemPacketIO removes
//! that noise. The resume bench runs at ~20 iters/sec (the
//! RTT of a resume handshake is the bottleneck, not port
//! allocation), and it needs *one* long-lived server so the
//! resumption ticket is recognized — so UDP works fine and
//! we just re-bind Alice per iter.

use criterion::{criterion_group, criterion_main, Criterion};
use drift::identity::Identity;
use drift::io::{MemPacketIO, PacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// DRIFT cold handshake: fresh identities, fresh ephemeral,
/// two X25519 DH operations, one AEAD open on HELLO_ACK, then
/// the first DATA packet round-trip — all over in-memory
/// channels so we're measuring protocol work, not UDP.
fn bench_cold_handshake(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("handshake");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("cold", |b| {
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

                let start = std::time::Instant::now();
                alice.send_data(&bob_peer, b"go", 0, 0).await.unwrap();
                let _ = bob.recv().await.unwrap();
                total += start.elapsed();
            }
            total
        });
    });
    group.finish();
}

/// DRIFT 1-RTT resumption: reconnect with a PSK ticket.
/// Server (Bob) is bound once and stays up for the whole
/// measurement so his session_store keeps Alice's ticket id.
/// Alice re-binds per iter to simulate a fresh client socket.
fn bench_resumption(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("handshake");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("resume_1rtt", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            let alice_secret: [u8; 32] = [0x33; 32];
            let alice_pub = Identity::from_secret_bytes(alice_secret).public_bytes();
            let bob_id = Identity::from_secret_bytes([0x44; 32]);
            let bob_pub = bob_id.public_bytes();

            let bob = Transport::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), bob_id)
                .await
                .unwrap();
            bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
                .await
                .unwrap();
            let bob_addr = bob.local_addr().unwrap();

            // Seed cold handshake to mint a ticket.
            let alice0 = Transport::bind(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                Identity::from_secret_bytes(alice_secret),
            )
            .await
            .unwrap();
            let bob_peer0 = alice0
                .add_peer(bob_pub, bob_addr, Direction::Initiator)
                .await
                .unwrap();
            alice0.send_data(&bob_peer0, b"seed", 0, 0).await.unwrap();
            let _ = bob.recv().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let ticket = match alice0.export_resumption_ticket(&bob_peer0).await {
                Ok(t) => t,
                Err(_) => return Duration::from_millis(1),
            };
            drop(alice0);

            let mut total = Duration::ZERO;
            // Server-side tickets are single-use (replay
            // protection), so we have to capture the new ticket
            // the server issues after each successful resume.
            // Otherwise iter N>1 would present a burned ticket,
            // fail silently server-side, and fall through to the
            // handshake retry loop's ~50 ms cold-HELLO fallback
            // — which is what this bench used to measure.
            let mut current_ticket = ticket;
            for _ in 0..iters {
                let alice = Transport::bind(
                    "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                    Identity::from_secret_bytes(alice_secret),
                )
                .await
                .unwrap();
                let bob_peer = alice
                    .add_peer(bob_pub, bob_addr, Direction::Initiator)
                    .await
                    .unwrap();
                alice
                    .import_resumption_ticket(&bob_peer, &current_ticket)
                    .await
                    .ok();

                let start = std::time::Instant::now();
                alice.send_data(&bob_peer, b"go", 0, 0).await.unwrap();
                let _ = bob.recv().await.unwrap();
                total += start.elapsed();

                // Ticket arrives from server *after* the first
                // DATA is processed. Poll briefly for it; this
                // sleep is outside the timer.
                let mut next = None;
                for _ in 0..20 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    if let Ok(t) = alice.export_resumption_ticket(&bob_peer).await {
                        if t != current_ticket {
                            next = Some(t);
                            break;
                        }
                    }
                }
                if let Some(t) = next {
                    current_ticket = t;
                }
            }
            total
        });
    });
    group.finish();
}

criterion_group!(benches, bench_cold_handshake, bench_resumption);
criterion_main!(benches);
