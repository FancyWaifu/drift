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

/// DRIFT's URL dispatcher parses the address portion as a literal
/// `SocketAddr`, so a Docker hostname like `server:9000` would
/// fail. Resolve via `crate::resolve_target` and rewrite the URL
/// with the resulting IP.
async fn resolve_url(url: &str) -> Result<String> {
    if let Some(idx) = url.find("://") {
        let scheme = &url[..idx];
        let host = &url[idx + 3..];
        // Already an IP literal? Skip resolution.
        if host.parse::<std::net::SocketAddr>().is_ok() {
            return Ok(url.to_string());
        }
        // iroh:// uses `<endpoint_id>@<sockaddr>` — the host
        // portion isn't a hostname to DNS-resolve, it's a
        // pubkey + direct addr pair. Pass through unchanged.
        if scheme == "iroh" {
            return Ok(url.to_string());
        }
        let addr = crate::resolve_target(host).await?;
        Ok(format!("{}://{}", scheme, addr))
    } else {
        // No scheme — resolve, then default to udp.
        if url.parse::<std::net::SocketAddr>().is_ok() {
            return Ok(format!("udp://{}", url));
        }
        let addr = crate::resolve_target(url).await?;
        Ok(format!("udp://{}", addr))
    }
}

// Fixed *server* seed so the client knows the server's peer_id
// up front (avoids a discovery step in the measurement). The
// client uses `Identity::generate()` for fresh static keys per
// iteration where the workload demands it (`Workload::Handshake`).
const SERVER_SEED: [u8; 32] = [0xAA; 32];

pub(crate) async fn server(cli: &Cli) -> Result<Option<Report>> {
    let server_id = Identity::from_secret_bytes(SERVER_SEED);
    let listen_url = ensure_scheme(&cli.listen);
    // `accept_any_peer = true` so each fresh client identity
    // (Handshake workload) gets admitted via the responder path
    // without us pre-registering its pubkey. Single-session
    // workloads (Rtt, Throughput) work fine under the same flag.
    let config = TransportConfig {
        accept_any_peer: true,
        ..TransportConfig::default()
    };
    let (server, bound_url) = Transport::bind_url(&listen_url, server_id, config)
        .await
        .with_context(|| format!("DRIFT server bind on {}", listen_url))?;
    let server = Arc::new(server);
    eprintln!("drift server listening on {}", bound_url);

    match cli.workload {
        Workload::Handshake | Workload::Rtt => {
            // Handshake: echo so the client measures connect→
            // first-byte-back. Rtt: echo for ping-pong timing.
            while let Ok(Some(msg)) =
                tokio::time::timeout(Duration::from_secs(30), server.recv()).await
            {
                let _ = server.send_data(&msg.peer_id, &msg.payload, 0, 0).await;
            }
        }
        Workload::Throughput => {
            // One-way bulk transfer (iperf3-shaped). Drain the
            // recv channel without echoing; track first/last
            // packet times + total bytes; emit standardized
            // markers on idle. The harness scrapes these from
            // server stderr to compute goodput, so all three
            // protocols measure the same thing.
            let mut total_bytes = 0u64;
            let mut first_recv: Option<Instant> = None;
            let mut last_recv: Option<Instant> = None;
            while let Ok(Some(msg)) =
                tokio::time::timeout(Duration::from_secs(5), server.recv()).await
            {
                let now = Instant::now();
                if first_recv.is_none() {
                    first_recv = Some(now);
                }
                last_recv = Some(now);
                total_bytes += msg.payload.len() as u64;
            }
            if let (Some(s), Some(l)) = (first_recv, last_recv) {
                let dur = (l - s).as_secs_f64();
                eprintln!("BENCH_BYTES_RECEIVED={}", total_bytes);
                eprintln!("BENCH_DURATION_S={:.6}", dur);
            }
        }
    }
    Ok(None)
}

pub(crate) async fn client(cli: &Cli) -> Result<Option<Report>> {
    let server_pub = Identity::from_secret_bytes(SERVER_SEED).public_bytes();
    let target_url = resolve_url(&ensure_scheme(&cli.target)).await?;

    match cli.workload {
        Workload::Handshake => run_handshake(cli, server_pub, &target_url).await,
        Workload::Rtt | Workload::Throughput => {
            // Fresh client identity per data-plane run too — the
            // long-lived session is meant to mirror "first
            // connect from a new process," not "reconnect with
            // saved keys."
            let client_id = Identity::generate();
            let (client, peer_addr) =
                Transport::connect_url(&target_url, client_id, TransportConfig::default())
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
        let (client, peer_addr) =
            Transport::connect_url(target_url, client_id, TransportConfig::default()).await?;
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

async fn run_rtt(cli: &Cli, client: &Transport, server_peer: &[u8; 8]) -> Result<Option<Report>> {
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
    // Warmup probe so the handshake completes before timing
    // starts. The server doesn't echo in throughput mode any
    // more, so we don't recv() — just sleep briefly to let
    // HELLO_ACK arrive.
    client.send_data(server_peer, b"warm", 0, 0).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let duration = Duration::from_secs(cli.duration_secs);
    let start = Instant::now();

    // One-way pump. The server tracks bytes received + duration
    // and emits BENCH_BYTES_RECEIVED / BENCH_DURATION_S markers
    // on stderr; the bench harness uses those to compute the
    // canonical throughput (so all three protocols measure the
    // same thing). The numbers we report client-side are
    // pump-rate — informational, not the headline.
    let mut sent_bytes = 0u64;
    while start.elapsed() < duration {
        client.send_data(server_peer, &payload, 0, 0).await?;
        sent_bytes += payload.len() as u64;
    }
    let elapsed = start.elapsed().as_secs_f64();

    eprintln!(
        "drift client pumped {} B in {:.2}s ({:.1} Mbps pump-rate; canonical goodput from server stderr)",
        sent_bytes,
        elapsed,
        (sent_bytes as f64 * 8.0) / (elapsed * 1_000_000.0),
    );

    report.bytes_moved = Some(sent_bytes);
    report.duration_s = Some(elapsed);
    report.throughput_mbps = Some((sent_bytes as f64 * 8.0) / (elapsed * 1_000_000.0));
    Ok(Some(report))
}
