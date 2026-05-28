//! Iroh server + client bench implementations.
//!
//! Iroh is n0-computer's pubkey-addressed QUIC overlay (the
//! closest direct comparable to DRIFT). For the bench we
//! disable its relay infrastructure so localhost runs measure
//! the raw transport cost, not the relay round-trip.
//!
//! Server emits its `NodeId` + direct socket addrs to
//! `/tmp/iroh-nodeaddr.json`; the client reads that file and
//! constructs an `EndpointAddr` for direct connection.

use crate::{report::Report, Cli, Workload};
use anyhow::{anyhow, Context, Result};
use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use std::time::{Duration, Instant};

const NODEADDR_PATH: &str = "/tmp/iroh-nodeaddr.json";
const ALPN: &[u8] = b"drift-bench/iroh/1";

#[derive(serde::Serialize, serde::Deserialize)]
struct PublishedAddr {
    node_id: String,
    addrs: Vec<String>,
}

async fn build_server_endpoint() -> Result<Endpoint> {
    // `Minimal` preset sets only the mandatory crypto-provider
    // option; no relay, no DNS discovery. Right shape for a
    // loopback bench measuring raw transport cost.
    Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| anyhow!("iroh server bind: {}", e))
}

async fn build_client_endpoint() -> Result<Endpoint> {
    Endpoint::builder(presets::Minimal)
        .bind()
        .await
        .map_err(|e| anyhow!("iroh client bind: {}", e))
}

async fn publish_server_addr(endpoint: &Endpoint) -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let id = endpoint.id();
    // bound_sockets() returns the wildcard binds (0.0.0.0 / ::),
    // which aren't valid connect destinations. For a loopback
    // bench we rewrite the address part to 127.0.0.1 and drop
    // the IPv6 form. A real deployment would use an address-
    // lookup service or a relay to do this discovery.
    let addrs: Vec<String> = endpoint
        .bound_sockets()
        .into_iter()
        .filter_map(|s| match s {
            SocketAddr::V4(_) => Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), s.port())),
            SocketAddr::V6(_) => None,
        })
        .map(|s| s.to_string())
        .collect();
    let published = PublishedAddr {
        node_id: id.to_string(),
        addrs,
    };
    std::fs::write(NODEADDR_PATH, serde_json::to_string(&published)?)?;
    eprintln!(
        "iroh server: id={} addrs={:?}",
        published.node_id, published.addrs
    );
    Ok(())
}

async fn load_server_addr() -> Result<EndpointAddr> {
    let raw = std::fs::read_to_string(NODEADDR_PATH)
        .with_context(|| format!("reading {}", NODEADDR_PATH))?;
    let published: PublishedAddr = serde_json::from_str(&raw)?;
    let id: EndpointId = published
        .node_id
        .parse()
        .map_err(|e| anyhow!("parse endpoint id: {}", e))?;
    let mut addr = EndpointAddr::new(id);
    for s in &published.addrs {
        let sock: std::net::SocketAddr = s
            .parse()
            .map_err(|e| anyhow!("parse addr {}: {}", s, e))?;
        addr = addr.with_ip_addr(sock);
    }
    Ok(addr)
}

pub async fn server(cli: &Cli) -> Result<Option<Report>> {
    let endpoint = build_server_endpoint().await?;
    publish_server_addr(&endpoint).await?;

    match cli.workload {
        Workload::Handshake => {
            // Each iter: accept a connection, echo one message,
            // let the client tear down. Stays in the loop until
            // the client side closes the endpoint.
            for _ in 0..cli.handshake_iters {
                let Some(incoming) = endpoint.accept().await else {
                    break;
                };
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let mut buf = [0u8; 16];
                    if let Ok(Ok(n)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        recv.read(&mut buf),
                    )
                    .await
                    {
                        if let Some(n) = n {
                            let _ = send.write_all(&buf[..n]).await;
                            let _ = send.finish();
                        }
                    }
                    conn.closed().await;
                }
            }
        }
        Workload::Rtt => {
            // One long-lived connection, echo every recv.
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| anyhow!("iroh server: no incoming"))?;
            let conn = incoming.await?;
            let (mut send, mut recv) = conn.accept_bi().await?;
            let mut buf = vec![0u8; cli.payload_bytes];
            loop {
                match tokio::time::timeout(Duration::from_secs(30), recv.read_exact(&mut buf))
                    .await
                {
                    Ok(Ok(())) => {
                        if send.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }
        Workload::Throughput => {
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| anyhow!("iroh server: no incoming"))?;
            let conn = incoming.await?;
            let (mut _send, mut recv) = conn.accept_bi().await?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut bytes_received: u64 = 0;
            let start = Instant::now();
            loop {
                match tokio::time::timeout(Duration::from_secs(2), recv.read(&mut buf)).await {
                    Ok(Ok(Some(n))) => bytes_received += n as u64,
                    _ => break,
                }
            }
            let elapsed = start.elapsed().as_secs_f64();
            eprintln!("BENCH_BYTES_RECEIVED={}", bytes_received);
            eprintln!("BENCH_DURATION_S={:.6}", elapsed);
        }
    }

    endpoint.close().await;
    let _ = std::fs::remove_file(NODEADDR_PATH);
    Ok(None)
}

pub async fn client(cli: &Cli) -> Result<Option<Report>> {
    match cli.workload {
        Workload::Handshake => run_handshake(cli).await,
        Workload::Rtt => run_rtt(cli).await,
        Workload::Throughput => run_throughput(cli).await,
    }
}

async fn connect_one(endpoint: &Endpoint, target: &EndpointAddr) -> Result<Connection> {
    endpoint
        .connect(target.clone(), ALPN)
        .await
        .map_err(|e| anyhow!("iroh connect: {}", e))
}

async fn run_handshake(cli: &Cli) -> Result<Option<Report>> {
    let target = load_server_addr().await?;
    let mut report = Report::new("iroh", "handshake");
    let mut samples: Vec<u128> = Vec::with_capacity(cli.handshake_iters);

    for _ in 0..cli.handshake_iters {
        // Fresh endpoint per iter — fresh NodeId, fresh sockets.
        // Matches what the other protos do (fresh QUIC endpoint /
        // fresh DRIFT Transport per handshake sample).
        let endpoint = build_client_endpoint().await?;

        let start = Instant::now();
        let conn = connect_one(&endpoint, &target).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(b"go").await?;
        send.finish()?;
        let mut buf = [0u8; 16];
        let _ = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await??;
        samples.push(start.elapsed().as_micros());

        drop(conn);
        endpoint.close().await;
    }
    crate::report::summarize_handshakes(&mut samples, &mut report);
    Ok(Some(report))
}

async fn run_rtt(cli: &Cli) -> Result<Option<Report>> {
    let target = load_server_addr().await?;
    let endpoint = build_client_endpoint().await?;
    let conn = connect_one(&endpoint, &target).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let payload = vec![0xA5u8; cli.payload_bytes];
    let mut buf = vec![0u8; cli.payload_bytes];

    // Warm.
    send.write_all(&payload).await?;
    recv.read_exact(&mut buf).await?;

    let mut report = Report::new("iroh", "rtt");
    let mut samples: Vec<u128> = Vec::with_capacity(cli.rtt_iters);
    for _ in 0..cli.rtt_iters {
        let start = Instant::now();
        send.write_all(&payload).await?;
        recv.read_exact(&mut buf).await?;
        samples.push(start.elapsed().as_micros());
    }
    crate::report::summarize_rtts(&mut samples, &mut report);

    drop(conn);
    endpoint.close().await;
    Ok(Some(report))
}

async fn run_throughput(cli: &Cli) -> Result<Option<Report>> {
    let target = load_server_addr().await?;
    let endpoint = build_client_endpoint().await?;
    let conn = connect_one(&endpoint, &target).await?;
    let (mut send, _recv) = conn.open_bi().await?;
    let payload = vec![0xA5u8; cli.payload_bytes];

    // Warm.
    send.write_all(b"warm").await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let duration = Duration::from_secs(cli.duration_secs);
    let start = Instant::now();
    let mut sent_bytes: u64 = 0;
    while start.elapsed() < duration {
        send.write_all(&payload).await?;
        sent_bytes += payload.len() as u64;
    }
    let elapsed = start.elapsed().as_secs_f64();
    let _ = send.finish();
    drop(conn);
    endpoint.close().await;

    eprintln!(
        "iroh client pumped {} B in {:.2}s ({:.1} Mbps pump-rate; canonical from server stderr)",
        sent_bytes,
        elapsed,
        (sent_bytes as f64 * 8.0) / (elapsed * 1_000_000.0),
    );

    let mut report = Report::new("iroh", "throughput");
    report.bytes_moved = Some(sent_bytes);
    report.duration_s = Some(elapsed);
    report.throughput_mbps = Some((sent_bytes as f64 * 8.0) / (elapsed * 1_000_000.0));
    Ok(Some(report))
}
