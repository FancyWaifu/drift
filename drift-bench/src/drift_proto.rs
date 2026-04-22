//! DRIFT server + client bench implementations.
//!
//! Both sides use a fixed identity per role so the client
//! knows the server's peer_id ahead of time without a discovery
//! step — this isolates the handshake measurement from any
//! rendezvous work.

use crate::{report::Report, Cli, Workload};
use anyhow::Result;
use drift::identity::Identity;
use drift::{Direction, Transport};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

// Fixed identity seeds so server + client always derive the
// same peer_ids regardless of which container hits the net
// first. Hardcoding is fine — this is a bench, not prod.
const SERVER_SEED: [u8; 32] = [0xAA; 32];
const CLIENT_SEED: [u8; 32] = [0xBB; 32];

pub async fn server(cli: &Cli) -> Result<Option<Report>> {
    let server_id = Identity::from_secret_bytes(SERVER_SEED);
    let client_pub = Identity::from_secret_bytes(CLIENT_SEED).public_bytes();
    let listen: SocketAddr = cli.listen.parse()?;

    let server = Transport::bind(listen, server_id).await?;
    // Learn the client identity up front so first incoming DATA
    // doesn't get rejected as "unknown peer" during cold start.
    server
        .add_peer(client_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
        .await?;
    eprintln!("drift server listening on {}", listen);

    match cli.workload {
        Workload::Handshake => {
            // For DRIFT, a "cold handshake" per iter means a
            // *fresh client identity* (new static keys, new
            // session state). The client picks a new identity
            // each time and adds the server as a peer; the
            // server side just echoes whatever arrives. The
            // server never needs to rebuild — it accepts any
            // configured peer — so a single long-running
            // server loop handles all N handshake samples.
            for _ in 0..cli.handshake_iters {
                match tokio::time::timeout(Duration::from_secs(10), server.recv()).await {
                    Ok(Some(msg)) => {
                        let _ = server.send_data(&msg.peer_id, &msg.payload, 0, 0).await;
                    }
                    _ => break,
                }
            }
        }
        Workload::Rtt => {
            // Echo-until-client-disconnects. The client drives
            // `rtt_iters` iterations, we echo each one back.
            // Keep going until the client stops sending.
            loop {
                match tokio::time::timeout(Duration::from_secs(30), server.recv()).await {
                    Ok(Some(msg)) => {
                        let _ = server.send_data(&msg.peer_id, &msg.payload, 0, 0).await;
                    }
                    _ => break,
                }
            }
        }
        Workload::Throughput => {
            // Drain until idle; the client sends for
            // `duration_secs` then stops. Count bytes for a
            // sanity check echo.
            let mut total = 0u64;
            loop {
                match tokio::time::timeout(Duration::from_secs(30), server.recv()).await {
                    Ok(Some(msg)) => total += msg.payload.len() as u64,
                    _ => break,
                }
            }
            eprintln!("drift server received {} bytes", total);
        }
    }
    Ok(None)
}

pub async fn client(cli: &Cli) -> Result<Option<Report>> {
    let server_pub = Identity::from_secret_bytes(SERVER_SEED).public_bytes();
    let target: SocketAddr = crate::resolve_target(&cli.target).await?;

    match cli.workload {
        Workload::Handshake => run_handshake(cli, server_pub, target).await,
        Workload::Rtt | Workload::Throughput => {
            // Single long-lived session for the data-plane
            // workloads — matches what a real app would do.
            let client_id = Identity::from_secret_bytes(CLIENT_SEED);
            let client =
                Transport::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap(), client_id)
                    .await?;
            let server_peer = client
                .add_peer(server_pub, target, Direction::Initiator)
                .await?;
            match cli.workload {
                Workload::Rtt => run_rtt(cli, &client, &server_peer).await,
                Workload::Throughput => run_throughput(cli, &client, &server_peer).await,
                _ => unreachable!(),
            }
        }
    }
}

async fn run_handshake(
    cli: &Cli,
    server_pub: [u8; 32],
    target: SocketAddr,
) -> Result<Option<Report>> {
    let mut report = Report::new("drift", "handshake");
    let mut samples: Vec<u128> = Vec::with_capacity(cli.handshake_iters);

    // Each iter: fresh client Transport (fresh socket, fresh
    // peer table, fresh session). The server keeps the same
    // peer_pub across all iters, so "cold" here means
    // "fresh client state, full HELLO/HELLO_ACK" — which is
    // what a reconnecting client actually pays.
    for _ in 0..cli.handshake_iters {
        let client_id = Identity::from_secret_bytes(CLIENT_SEED);
        let client =
            Transport::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap(), client_id).await?;
        let server_peer = client
            .add_peer(server_pub, target, Direction::Initiator)
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
    client: &Transport,
    server_peer: &[u8; 8],
) -> Result<Option<Report>> {
    let mut report = Report::new("drift", "throughput");
    let payload = vec![0xA5u8; cli.payload_bytes];

    // Warm the handshake.
    client.send_data(server_peer, &[0u8; 8], 0, 0).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let duration = Duration::from_secs(cli.duration_secs);
    let start = Instant::now();
    let mut bytes = 0u64;
    while start.elapsed() < duration {
        client.send_data(server_peer, &payload, 0, 0).await?;
        bytes += payload.len() as u64;
    }
    let elapsed = start.elapsed().as_secs_f64();

    report.bytes_moved = Some(bytes);
    report.duration_s = Some(elapsed);
    report.throughput_mbps = Some((bytes as f64 * 8.0) / (elapsed * 1_000_000.0));
    Ok(Some(report))
}
