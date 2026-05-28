#![no_main]
//! Fuzz target: stateful handshake / send / restart FSM.
//!
//! Tier-2 target. Sets up two real `Transport` instances over a
//! `MemPacketIO::pair()` (in-memory, no sockets, no syscalls) and
//! drives them through arbitrary event sequences. Byte-level
//! decoders are covered by the Tier-1 targets; this one targets
//! state-machine bugs:
//!
//!   * Send-after-restart races (handshake state vs. cached
//!     resumption ticket interaction).
//!   * Out-of-order delivery under load.
//!   * Recv-loop survival across restart_handshake.
//!   * Path-state / replay-window invariants under churn.
//!
//! Throughput is intentionally low (per-iter cost includes async
//! task scheduling). libFuzzer's coverage signal still steers
//! toward novel state transitions.
//!
//! Limitations: legitimate (AEAD-valid) packets only — arbitrary
//! byte injection would require a custom PacketIO wrapper and
//! belongs in a separate target. Restart events are bounded so a
//! single fuzz input can't trivially DoS the harness.

use arbitrary::Arbitrary;
use drift::identity::Identity;
use drift::io::MemPacketIO;
use drift::transport::TransportConfig;
use drift::{Direction, Transport};
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::time::timeout;

#[derive(Debug, Arbitrary)]
enum Event {
    /// Send a small body from A → B.
    SendAtoB { body_len: u8 },
    /// Send a small body from B → A.
    SendBtoA { body_len: u8 },
    /// Restart A's handshake with B.
    RestartA,
    /// Restart B's handshake with A.
    RestartB,
    /// Drain up to `count` packets from A's recv queue.
    DrainA { count: u8 },
    /// Drain up to `count` packets from B's recv queue.
    DrainB { count: u8 },
}

struct Pair {
    rt: Arc<Runtime>,
    a: Arc<Transport>,
    b: Arc<Transport>,
    a_handle_for_b: drift::PeerId,
    b_handle_for_a: drift::PeerId,
}

static PAIR: OnceLock<Pair> = OnceLock::new();

fn pair() -> &'static Pair {
    PAIR.get_or_init(|| {
        let rt = Arc::new(Runtime::new().expect("build tokio runtime"));
        let (a, b, a_handle_for_b, b_handle_for_a) = rt.block_on(async {
            let id_a = Identity::from_secret_bytes([0x11; 32]);
            let id_b = Identity::from_secret_bytes([0x22; 32]);
            let pub_a = id_a.public_bytes();
            let pub_b = id_b.public_bytes();

            let cfg = TransportConfig::default();
            let (io_a, io_b) = MemPacketIO::pair();
            let a = Arc::new(
                Transport::bind_with_io(Arc::new(io_a), id_a, cfg.clone())
                    .await
                    .expect("bind A"),
            );
            let b = Arc::new(
                Transport::bind_with_io(Arc::new(io_b), id_b, cfg)
                    .await
                    .expect("bind B"),
            );

            // MemPacketIO addrs are fixed placeholders; the actual
            // routing happens via the channel pair, so the addr
            // we pass here is cosmetic.
            let placeholder_a: std::net::SocketAddr = "127.0.0.1:60000".parse().unwrap();
            let placeholder_b: std::net::SocketAddr = "127.0.0.1:60001".parse().unwrap();

            let a_handle_for_b = a
                .add_peer(pub_b, placeholder_b, Direction::Initiator)
                .await
                .expect("a.add_peer(b)");
            let b_handle_for_a = b
                .add_peer(pub_a, placeholder_a, Direction::Responder)
                .await
                .expect("b.add_peer(a)");

            // Warm up: drive a handshake so both sides reach Established.
            a.send_data(&a_handle_for_b, b"hi", 0, 0)
                .await
                .expect("warmup send a→b");
            // Pump recv on both sides briefly — bounded so the
            // OnceLock init can't hang the fuzzer if the handshake
            // is broken.
            let _ = timeout(Duration::from_millis(200), b.recv()).await;
            let _ = timeout(Duration::from_millis(50), a.recv()).await;

            (a, b, a_handle_for_b, b_handle_for_a)
        });
        Pair {
            rt,
            a,
            b,
            a_handle_for_b,
            b_handle_for_a,
        }
    })
}

fuzz_target!(|events: Vec<Event>| {
    let pair = pair();
    // Cap event count per iteration so libFuzzer can't grow a
    // pathological input that takes seconds to execute.
    let events: Vec<_> = events.into_iter().take(32).collect();

    pair.rt.block_on(async {
        for ev in events {
            match ev {
                Event::SendAtoB { body_len } => {
                    let body = vec![0xA1u8; body_len.min(64) as usize];
                    let _ = pair.a.send_data(&pair.a_handle_for_b, &body, 0, 0).await;
                }
                Event::SendBtoA { body_len } => {
                    let body = vec![0xB2u8; body_len.min(64) as usize];
                    let _ = pair.b.send_data(&pair.b_handle_for_a, &body, 0, 0).await;
                }
                Event::RestartA => {
                    let _ = pair.a.restart_handshake(&pair.a_handle_for_b).await;
                }
                Event::RestartB => {
                    let _ = pair.b.restart_handshake(&pair.b_handle_for_a).await;
                }
                Event::DrainA { count } => {
                    for _ in 0..count.min(8) {
                        match timeout(Duration::from_millis(5), pair.a.recv()).await {
                            Ok(Some(_)) => {}
                            _ => break,
                        }
                    }
                }
                Event::DrainB { count } => {
                    for _ in 0..count.min(8) {
                        match timeout(Duration::from_millis(5), pair.b.recv()).await {
                            Ok(Some(_)) => {}
                            _ => break,
                        }
                    }
                }
            }
        }
    });
});
