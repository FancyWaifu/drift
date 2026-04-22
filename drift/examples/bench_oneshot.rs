//! One-shot cold-handshake timer, independent of criterion.
//! Runs N fresh handshakes sequentially over MemPacketIO and
//! prints per-iter + cumulative timings, plus breakdown by
//! phase (bind, add_peer, send+recv).
//!
//! Usage: `cargo run --release --example bench_oneshot`

use drift::identity::Identity;
use drift::io::{MemPacketIO, PacketIO};
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Instant;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Verify the short-header fast path is actually engaged
    // by inspecting bytes-on-wire for a 64 B payload with
    // deadline=0 (short path) vs deadline=200 (long path).
    verify_short_path().await;

    const N: u32 = 100;
    let mut bind_total = std::time::Duration::ZERO;
    let mut add_peer_total = std::time::Duration::ZERO;
    let mut send_recv_total = std::time::Duration::ZERO;
    let mut overall = std::time::Duration::ZERO;

    // Warm up twice (criterion-style) to get past JIT-ish
    // artifacts from the scheduler.
    for _ in 0..3 {
        run_one().await;
    }

    for i in 0..N {
        let t0 = Instant::now();
        let alice_id = Identity::from_secret_bytes([(i % 254 + 1) as u8; 32]);
        let alice_pub = alice_id.public_bytes();
        let bob_id =
            Identity::from_secret_bytes([((i + 1) % 254 + 1) as u8; 32]);
        let bob_pub = bob_id.public_bytes();

        let (a_io, b_io) = MemPacketIO::pair();
        let a_io: Arc<dyn PacketIO> = Arc::new(a_io);
        let b_io: Arc<dyn PacketIO> = Arc::new(b_io);
        let a_addr = a_io.local_addr().unwrap();
        let b_addr = b_io.local_addr().unwrap();

        let t_bind = Instant::now();
        let bob = Transport::bind_with_io(b_io, bob_id, TransportConfig::default())
            .await
            .unwrap();
        let alice = Transport::bind_with_io(a_io, alice_id, TransportConfig::default())
            .await
            .unwrap();
        bind_total += t_bind.elapsed();

        let t_peer = Instant::now();
        bob.add_peer(alice_pub, a_addr, Direction::Responder)
            .await
            .unwrap();
        let bob_peer = alice
            .add_peer(bob_pub, b_addr, Direction::Initiator)
            .await
            .unwrap();
        add_peer_total += t_peer.elapsed();

        let t_sr = Instant::now();
        alice.send_data(&bob_peer, b"go", 0, 0).await.unwrap();
        let _ = bob.recv().await.unwrap();
        send_recv_total += t_sr.elapsed();

        overall += t0.elapsed();
    }

    let us = |d: std::time::Duration| d.as_micros() as f64 / N as f64;
    println!("Cold handshake over MemPacketIO, N={}", N);
    println!("  overall:   {:>8.1} µs/iter", us(overall));
    println!("  bind x2:   {:>8.1} µs/iter", us(bind_total));
    println!("  add_peer:  {:>8.1} µs/iter", us(add_peer_total));
    println!("  send+recv: {:>8.1} µs/iter", us(send_recv_total));
    println!();
    println!(
        "Ratio send_recv / overall: {:.1}%",
        100.0 * send_recv_total.as_secs_f64() / overall.as_secs_f64()
    );
}

async fn verify_short_path() {
    let alice_id = Identity::from_secret_bytes([0x11; 32]);
    let bob_id = Identity::from_secret_bytes([0x22; 32]);
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
    bob.add_peer(alice_pub, a_addr, Direction::Responder)
        .await
        .unwrap();
    let alice = Transport::bind_with_io(a_io, alice_id, TransportConfig::default())
        .await
        .unwrap();
    let bob_peer = alice
        .add_peer(bob_pub, b_addr, Direction::Initiator)
        .await
        .unwrap();

    // Warm up the session (completes handshake, installs CIDs).
    alice.send_data(&bob_peer, b"warm", 0, 0).await.unwrap();
    bob.recv().await.unwrap();

    // Send 64 B payload via short path (deadline=0).
    let payload = vec![0x55u8; 64];
    let bytes_before = alice.metrics().bytes_sent;
    alice.send_data(&bob_peer, &payload, 0, 0).await.unwrap();
    bob.recv().await.unwrap();
    let short_bytes = alice.metrics().bytes_sent - bytes_before;

    // Send 64 B via long path (deadline=200).
    let bytes_before = alice.metrics().bytes_sent;
    alice.send_data(&bob_peer, &payload, 200, 0).await.unwrap();
    bob.recv().await.unwrap();
    let long_bytes = alice.metrics().bytes_sent - bytes_before;

    println!("Wire bytes for 64 B payload:");
    println!("  short-header path (deadline=0):   {} bytes", short_bytes);
    println!("  long-header path  (deadline=200): {} bytes", long_bytes);
    println!(
        "  expected short = 64 + 7 + 16 = 87 ; long = 64 + 36 + 16 = 116"
    );
    println!();
}

async fn run_one() {
    let alice_id = Identity::from_secret_bytes([200u8; 32]);
    let bob_id = Identity::from_secret_bytes([201u8; 32]);
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
    bob.add_peer(alice_pub, a_addr, Direction::Responder)
        .await
        .unwrap();
    let alice = Transport::bind_with_io(a_io, alice_id, TransportConfig::default())
        .await
        .unwrap();
    let bob_peer = alice
        .add_peer(bob_pub, b_addr, Direction::Initiator)
        .await
        .unwrap();
    alice.send_data(&bob_peer, b"go", 0, 0).await.unwrap();
    let _ = bob.recv().await.unwrap();
}
