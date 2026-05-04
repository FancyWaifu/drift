//! DRIFT server + client bench implementations.
//!
//! Both sides use a fixed identity per role so the client
//! knows the server's peer_id ahead of time without a discovery
//! step — this isolates the handshake measurement from any
//! rendezvous work.

use crate::{report::Report, Cli, Workload};
use anyhow::{Context, Result};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Force a `<scheme>://` prefix on a possibly-bare address. Bare
/// `host:port` defaults to `udp` so old bench configs keep
/// working unchanged.
fn ensure_scheme(s: &str) -> String {
    if s.contains("://") {
        s.to_string()
    } else {
        format!("udp://{}", s)
    }
}

// Fixed *server* seed so the client knows the server's peer_id
// up front (avoids a discovery step in the measurement). The
// client uses `Identity::generate()` for fresh static keys per
// iteration where the workload demands it (`Workload::Handshake`).
const SERVER_SEED: [u8; 32] = [0xAA; 32];

pub async fn server(cli: &Cli) -> Result<Option<Report>> {
    let server_id = Identity::from_secret_bytes(SERVER_SEED);
    let listen_url = ensure_scheme(&cli.listen);
    // `accept_any_peer = true` so each fresh client identity
    // (Handshake workload) gets admitted via the responder path
    // without us pre-registering its pubkey. Single-session
    // workloads (Rtt, Throughput) work fine under the same flag.
    let mut config = TransportConfig::default();
    config.accept_any_peer = true;
    let (server, bound_url) = Transport::bind_url(&listen_url, server_id, config)
        .await
        .with_context(|| format!("DRIFT server bind on {}", listen_url))?;
    let server = Arc::new(server);
    eprintln!("drift server listening on {}", bound_url);

    match cli.workload {
        Workload::Handshake | Workload::Rtt | Workload::Throughput => {
            // All three workloads echo every received DATA back
            // to its sender. Throughput uses the echo to measure
            // round-trip goodput on the client side; Rtt uses it
            // for ping-pong timing; Handshake uses it as the
            // "first byte acked" boundary.
            loop {
                match tokio::time::timeout(Duration::from_secs(30), server.recv()).await {
                    Ok(Some(msg)) => {
                        let _ = server.send_data(&msg.peer_id, &msg.payload, 0, 0).await;
                    }
                    _ => break,
                }
            }
        }
    }
    Ok(None)
}

pub async fn client(cli: &Cli) -> Result<Option<Report>> {
    let server_pub = Identity::from_secret_bytes(SERVER_SEED).public_bytes();
    let target_url = ensure_scheme(&cli.target);

    match cli.workload {
        Workload::Handshake => run_handshake(cli, server_pub, &target_url).await,
        Workload::Rtt | Workload::Throughput => {
            // Fresh client identity per data-plane run too — the
            // long-lived session is meant to mirror "first
            // connect from a new process," not "reconnect with
            // saved keys."
            let client_id = Identity::generate();
            let (client, peer_addr) = Transport::connect_url(
                &target_url,
                client_id,
                TransportConfig::default(),
            )
            .await
            .with_context(|| format!("connecting to {}", target_url))?;
            let client = Arc::new(client);
            let server_peer = client
                .add_peer(server_pub, peer_addr, Direction::Initiator)
                .await?;
            match cli.workload {
                Workload::Rtt => run_rtt(cli, &client, &server_peer).await,
                Workload::Throughput => run_throughput(cli, client.clone(), &server_peer).await,
                Workload::Handshake => unreachable!("dispatched above"),
            }
        }
    }
}

async fn run_handshake(
    cli: &Cli,
    server_pub: [u8; 32],
    target_url: &str,
) -> Result<Option<Report>> {
    let mut report = Report::new("drift", "handshake");
    let mut samples: Vec<u128> = Vec::with_capacity(cli.handshake_iters);

    // Each iter: fresh client identity (new X25519 static keys),
    // fresh Transport (fresh socket, fresh peer table, fresh
    // session). What we measure is from `send_data` (the
    // implicit handshake trigger) to the first `recv` from the
    // server's echo — i.e. **handshake completion plus one
    // application round-trip**. We deliberately don't try to
    // separate the two: there's no public DRIFT API surface
    // that fires precisely at "HELLO_ACK seen and verified" on
    // the client side, so any split would be lying about its
    // boundary. Reporting "first-byte time" is the honest
    // measure that matches what every other benched protocol
    // (QUIC, WireGuard) reports: connect → first byte echoed.
    for _ in 0..cli.handshake_iters {
        let client_id = Identity::generate();
        let (client, peer_addr) = Transport::connect_url(
            target_url,
            client_id,
            TransportConfig::default(),
        )
        .await?;
        let client = Arc::new(client);
        let server_peer = client
            .add_peer(server_pub, peer_addr, Direction::Initiator)
            .await?;

        let start = Instant::now();
        client.send_data(&server_peer, b"go", 0, 0).await?;
        let _ = tokio::time::timeout(Duration::from_secs(5), client.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("server closed before ack"))?;
        samples.push(start.elapsed().as_micros());
        // Transport drops here, cleaning up its background
        // tasks via the TaskGuard we added earlier.
    }
    crate::report::summarize_handshakes(&mut samples, &mut report);
    Ok(Some(report))
}

async fn run_rtt(
    cli: &Cli,
    client: &Transport,
    server_peer: &[u8; 8],
) -> Result<Option<Report>> {
    let mut report = Report::new("drift", "rtt");
    let payload = vec![0xA5u8; cli.payload_bytes];

    // Warm the handshake — the first ping-pong pays the cold
    // handshake cost and would skew the percentile math.
    client.send_data(server_peer, &payload, 0, 0).await?;
    let _ = tokio::time::timeout(Duration::from_secs(5), client.recv()).await;

    let mut samples: Vec<u128> = Vec::with_capacity(cli.rtt_iters);
    for _ in 0..cli.rtt_iters {
        let start = Instant::now();
        client.send_data(server_peer, &payload, 0, 0).await?;
        let _ = tokio::time::timeout(Duration::from_secs(5), client.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("server closed"))?;
        samples.push(start.elapsed().as_micros());
    }
    crate::report::summarize_rtts(&mut samples, &mut report);
    Ok(Some(report))
}

async fn run_throughput(
    cli: &Cli,
    client: Arc<Transport>,
    server_peer: &[u8; 8],
) -> Result<Option<Report>> {
    let mut report = Report::new("drift", "throughput");
    let payload = vec![0xA5u8; cli.payload_bytes];

    // Warm the handshake (echoed back by the server-side loop).
    client.send_data(server_peer, b"warm", 0, 0).await?;
    let _ = tokio::time::timeout(Duration::from_secs(5), client.recv()).await?;

    let duration = Duration::from_secs(cli.duration_secs);
    let start = Instant::now();

    // Drain the server's echoed packets *concurrently* with our
    // sends. The headline number is "bytes that round-tripped"
    // — i.e. goodput, not pump-rate. If our sends outpace the
    // server's ability to echo back, the gap shows up as the
    // recv side falling behind, which is exactly how a real
    // application's flow control would look.
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
    let recv_bytes = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let recv_client = client.clone();
    let recv_bytes_for_task = recv_bytes.clone();
    let stop_for_task = stop.clone();
    let recv_task = tokio::spawn(async move {
        while !stop_for_task.load(AtomicOrdering::Relaxed) {
            match tokio::time::timeout(Duration::from_millis(200), recv_client.recv()).await {
                Ok(Some(msg)) => {
                    recv_bytes_for_task.fetch_add(msg.payload.len() as u64, AtomicOrdering::Relaxed);
                }
                _ => continue,
            }
        }
    });

    let mut sent_bytes = 0u64;
    while start.elapsed() < duration {
        client.send_data(server_peer, &payload, 0, 0).await?;
        sent_bytes += payload.len() as u64;
    }

    // Grace period to let the last few echoes come back.
    tokio::time::sleep(Duration::from_secs(1)).await;
    stop.store(true, AtomicOrdering::Relaxed);
    let _ = recv_task.await;

    let elapsed = start.elapsed().as_secs_f64();
    let goodput_bytes = recv_bytes.load(AtomicOrdering::Relaxed);

    eprintln!(
        "drift throughput: sent {} B, echoed back {} B in {:.2}s ({:.1}% return ratio)",
        sent_bytes,
        goodput_bytes,
        elapsed,
        (goodput_bytes as f64 / sent_bytes as f64) * 100.0,
    );

    report.bytes_moved = Some(goodput_bytes);
    report.duration_s = Some(elapsed);
    report.throughput_mbps = Some((goodput_bytes as f64 * 8.0) / (elapsed * 1_000_000.0));
    Ok(Some(report))
}
