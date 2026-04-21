//! Lossy UDP proxy for stress-testing DRIFT.
//!
//! A transparent bidirectional UDP forwarder that injects configurable
//! network badness: packet drops, reordering, duplication, and latency.
//!
//! Usage:
//!   lossy-proxy <listen_addr> <target_addr> [--drop F] [--dup F]
//!               [--reorder F] [--latency MS] [--jitter MS]
//!
//! Example — 10% drops, 5% dup, 50ms+20ms jitter:
//!   lossy-proxy 127.0.0.1:9500 127.0.0.1:9000 \
//!       --drop 0.1 --dup 0.05 --latency 50 --jitter 20
//!
//! Both directions of traffic are corrupted symmetrically. The proxy keeps
//! a single mapping slot from client→server by watching incoming sources.

use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
struct Config {
    listen: SocketAddr,
    target: SocketAddr,
    drop_rate: f64,
    dup_rate: f64,
    reorder_rate: f64,
    latency_ms: u64,
    jitter_ms: u64,
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let listen: SocketAddr = args
        .get(1)
        .expect("listen addr required")
        .parse()
        .expect("bad listen");
    let target: SocketAddr = args
        .get(2)
        .expect("target addr required")
        .parse()
        .expect("bad target");

    let mut cfg = Config {
        listen,
        target,
        drop_rate: 0.0,
        dup_rate: 0.0,
        reorder_rate: 0.0,
        latency_ms: 0,
        jitter_ms: 0,
    };

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--drop" => {
                cfg.drop_rate = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--dup" => {
                cfg.dup_rate = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--reorder" => {
                cfg.reorder_rate = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--latency" => {
                cfg.latency_ms = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--jitter" => {
                cfg.jitter_ms = args[i + 1].parse().unwrap();
                i += 2;
            }
            other => panic!("unknown flag: {}", other),
        }
    }
    cfg
}

#[derive(Default)]
struct Stats {
    received: u64,
    dropped: u64,
    duplicated: u64,
    reordered: u64,
    forwarded: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = parse_args();
    eprintln!("lossy-proxy {:#?}", cfg);

    let socket = Arc::new(UdpSocket::bind(cfg.listen).await?);
    let stats = Arc::new(Mutex::new(Stats::default()));

    // Map of peer addresses so the proxy can translate replies.
    // The first thing we see becomes the "client" side; all other traffic
    // from the target gets forwarded back to that client.
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let stats2 = stats.clone();
    let stats_printer = tokio::spawn(async move {
        let mut tk = tokio::time::interval(Duration::from_secs(2));
        loop {
            tk.tick().await;
            let s = stats2.lock().await;
            eprintln!(
                "[proxy] rx={} fwd={} drop={} dup={} reorder={}",
                s.received, s.forwarded, s.dropped, s.duplicated, s.reordered
            );
        }
    });

    let mut buf = vec![0u8; 65535];
    let mut rng = rand::rngs::StdRng::from_entropy();

    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();

        {
            let mut s = stats.lock().await;
            s.received += 1;
        }

        // Determine destination. If packet came from `target`, send to
        // whoever is registered as the client. Otherwise, register the
        // sender as the client and forward to `target`.
        let dst = if src == cfg.target {
            let ca = client_addr.lock().await;
            match *ca {
                Some(a) => a,
                None => continue,
            }
        } else {
            let mut ca = client_addr.lock().await;
            if ca.is_none() {
                *ca = Some(src);
            }
            cfg.target
        };

        // Drop?
        if cfg.drop_rate > 0.0 && rng.gen::<f64>() < cfg.drop_rate {
            stats.lock().await.dropped += 1;
            continue;
        }

        // Compute delay.
        let jitter = if cfg.jitter_ms > 0 {
            rng.gen_range(0..=cfg.jitter_ms)
        } else {
            0
        };
        let mut delay_ms = cfg.latency_ms + jitter;

        // Reorder = extra random delay so it arrives after a later packet.
        let reorder = cfg.reorder_rate > 0.0 && rng.gen::<f64>() < cfg.reorder_rate;
        if reorder {
            delay_ms += rng.gen_range(20..=200);
            stats.lock().await.reordered += 1;
        }

        // Duplicate?
        let dup = cfg.dup_rate > 0.0 && rng.gen::<f64>() < cfg.dup_rate;
        if dup {
            stats.lock().await.duplicated += 1;
        }

        let socket2 = socket.clone();
        let data2 = data.clone();
        let stats2 = stats.clone();
        tokio::spawn(async move {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            let _ = socket2.send_to(&data2, dst).await;
            let mut s = stats2.lock().await;
            s.forwarded += 1;
            if dup {
                drop(s);
                let _ = socket2.send_to(&data2, dst).await;
                stats2.lock().await.forwarded += 1;
            }
        });

        // Silence unused warning when no stats printer feature used.
        let _ = &stats_printer;
        let _: HashMap<(), ()> = HashMap::new();
    }
}
