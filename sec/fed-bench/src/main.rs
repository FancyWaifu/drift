//! Per-wire-scheme throughput probe for drift.
//!
//! Two modes, picked by `MODE` env var:
//!   - `listen` — bind a drift bridge on $LISTEN_URL using the
//!     identity at $IDENTITY_FILE. Drain recv(); every 1 s print
//!     bytes-received + Mbit/s for the previous second. Exit on
//!     SIGINT.
//!   - `send`   — connect via $DIAL_URL to a peer with pubkey
//!     $TARGET_PUB. Establish session, then push $PKT_SIZE-byte
//!     packets in a tight loop for $DURATION_SECS. Final summary
//!     prints total bytes + MB/s.
//!
//! The listener's number is the ground truth for throughput; the
//! sender's is for "did we hit a local bottleneck (CPU, channel
//! backpressure)" vs "did the wire/link cap us."

use anyhow::{bail, Context, Result};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn load_identity_file(path: &str) -> Result<Identity> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path))?;
    let bytes: [u8; 32] = if raw.len() == 36 && &raw[..4] == b"DRFT" {
        raw[4..].try_into().expect("32 after DRFT magic")
    } else if raw.len() == 32 {
        raw[..].try_into().expect("32")
    } else {
        bail!("identity file is wrong size: {}", raw.len());
    };
    Ok(Identity::from_secret_bytes(bytes))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let mode = std::env::var("MODE").context("set MODE=listen or MODE=send")?;
    match mode.as_str() {
        "listen" => listen_mode().await,
        "send" => send_mode().await,
        other => bail!("unknown MODE={:?}; want listen|send", other),
    }
}

fn cfg() -> TransportConfig {
    TransportConfig {
        accept_any_peer: true,
        beacon_interval_ms: 500,
        ..TransportConfig::default()
    }
}

async fn listen_mode() -> Result<()> {
    let listen_url = std::env::var("LISTEN_URL").context("set LISTEN_URL")?;
    let identity_file = std::env::var("IDENTITY_FILE").context("set IDENTITY_FILE")?;
    let identity = load_identity_file(&identity_file)?;
    let pub_hex = hex::encode(identity.public_bytes());
    eprintln!("[listen] pubkey: {}", pub_hex);
    eprintln!("[listen] url:    {}", listen_url);

    let (transport, bound) = Transport::bind_url(&listen_url, identity, cfg())
        .await
        .context("bind_url")?;
    let transport = Arc::new(transport);
    eprintln!("[listen] bound at {}", bound);

    let bytes_total = Arc::new(AtomicU64::new(0));
    let pkts_total = Arc::new(AtomicU64::new(0));

    // Periodic ticker — prints bytes/Mbit for the previous second
    // so the operator sees live progress and end-of-run averages.
    let bt = bytes_total.clone();
    let pt = pkts_total.clone();
    tokio::spawn(async move {
        let mut last_bytes = 0u64;
        let mut last_pkts = 0u64;
        let mut last_t = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.tick().await; // skip immediate first tick
        loop {
            tick.tick().await;
            let now = Instant::now();
            let cur_bytes = bt.load(Ordering::Relaxed);
            let cur_pkts = pt.load(Ordering::Relaxed);
            let elapsed = now.duration_since(last_t).as_secs_f64();
            let dbytes = cur_bytes - last_bytes;
            let dpkts = cur_pkts - last_pkts;
            if dbytes > 0 {
                let mbit = (dbytes as f64 * 8.0) / 1_000_000.0 / elapsed;
                let mbs = (dbytes as f64) / 1_000_000.0 / elapsed;
                let pps = (dpkts as f64) / elapsed;
                eprintln!(
                    "[listen] +{:>10} B / +{:>7} pkts in {:.2}s = {:>8.2} MB/s ({:>6.0} Mbit/s, {:>7.0} pps)",
                    dbytes, dpkts, elapsed, mbs, mbit, pps
                );
            }
            last_bytes = cur_bytes;
            last_pkts = cur_pkts;
            last_t = now;
        }
    });

    // Drain forever — never stop, sender will Ctrl-C us when done.
    loop {
        match transport.recv().await {
            Some(pkt) => {
                bytes_total.fetch_add(pkt.payload.len() as u64, Ordering::Relaxed);
                pkts_total.fetch_add(1, Ordering::Relaxed);
            }
            None => break,
        }
    }
    eprintln!(
        "[listen] FINAL: {} bytes / {} packets",
        bytes_total.load(Ordering::Relaxed),
        pkts_total.load(Ordering::Relaxed)
    );
    Ok(())
}

async fn send_mode() -> Result<()> {
    let dial_url = std::env::var("DIAL_URL").context("set DIAL_URL")?;
    let target_pub_hex = std::env::var("TARGET_PUB").context("set TARGET_PUB (64-hex)")?;
    let pkt_size: usize = std::env::var("PKT_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);
    let duration_secs: u64 = std::env::var("DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let target_pub: [u8; 32] = hex::decode(&target_pub_hex)
        .context("TARGET_PUB hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("TARGET_PUB len {}", v.len()))?;

    eprintln!("[send] DIAL_URL    = {}", dial_url);
    eprintln!("[send] TARGET_PUB  = {}", &target_pub_hex[..16]);
    eprintln!("[send] PKT_SIZE    = {} bytes", pkt_size);
    eprintln!("[send] DURATION    = {} s", duration_secs);

    let me = Identity::generate();
    let (transport, peer_addr) = Transport::connect_url(&dial_url, me, cfg())
        .await
        .context("connect_url")?;
    let transport = Arc::new(transport);
    let target_handle = transport
        .add_peer(target_pub, peer_addr, Direction::Initiator)
        .await
        .context("add_peer")?;

    // Warm-up: send a single tiny packet and wait for the session
    // to reach Established so we measure steady-state, not
    // handshake cost.
    transport.send_data(&target_handle, b"warmup", 5000, 0).await?;
    let warmup_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(pm) = transport.peer_metrics(&target_handle).await {
            if pm.is_established {
                break;
            }
        }
        if Instant::now() >= warmup_deadline {
            bail!("send_mode: handshake didn't reach Established in 5s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!("[send] session Established; starting timed pump");

    // Pump payload at max rate. send_data queues and returns;
    // drift's internal channel applies backpressure when the
    // outbound socket can't keep up.
    let payload = vec![0xAAu8; pkt_size];
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let start = Instant::now();
    let mut pkts_sent: u64 = 0;
    let mut send_errs: u64 = 0;
    while Instant::now() < deadline {
        match transport.send_data(&target_handle, &payload, 0, 0).await {
            Ok(_) => pkts_sent += 1,
            Err(_) => send_errs += 1,
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let bytes_sent = pkts_sent * pkt_size as u64;
    let mbs = (bytes_sent as f64) / 1_000_000.0 / elapsed;
    let mbit = mbs * 8.0;
    let pps = (pkts_sent as f64) / elapsed;
    eprintln!(
        "[send] FINAL: {} packets, {} bytes, {} send errors in {:.2}s",
        pkts_sent, bytes_sent, send_errs, elapsed
    );
    eprintln!(
        "[send] FINAL: {:.2} MB/s, {:.1} Mbit/s, {:.0} pkts/s",
        mbs, mbit, pps
    );
    println!(
        "SENDER RESULT mode=send pkt_size={} duration={} pkts_sent={} bytes_sent={} mbs={:.2} mbit={:.1} pps={:.0}",
        pkt_size, duration_secs, pkts_sent, bytes_sent, mbs, mbit, pps
    );

    // Briefly hold the session so the listener drains any
    // backlog before we tear down.
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}
