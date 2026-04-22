//! QUIC server + client using quinn. Self-signed cert is
//! generated fresh each server run and its DER bytes are
//! written to `/tmp/quic-cert.der` so the client (in a sibling
//! container sharing /tmp via a volume) can load it for
//! verification.
//!
//! No ALPN, no HTTP/3 — raw bidi streams. One connection,
//! one stream per workload, no reuse.

use crate::{report::Report, Cli, Workload};
use anyhow::{anyhow, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
const CERT_PATH: &str = "/tmp/quic-cert.der";

/// Accept N short connections, echo one datagram on each,
/// close. The endpoint stays up for the whole loop so the
/// UDP socket doesn't rebind between iterations — only the
/// per-connection QUIC state is fresh.
async fn handshake_server_loop(endpoint: &Endpoint, iters: usize) {
    for _ in 0..iters {
        let incoming = match endpoint.accept().await {
            Some(i) => i,
            None => return,
        };
        let connection = match incoming.await {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Ok(bytes) = connection.read_datagram().await {
            let _ = connection.send_datagram(bytes);
            // Let quinn flush before the client tears down.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Install ring as rustls' default CryptoProvider. Idempotent
/// — rustls errors on repeated installs but doesn't break.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn server(cli: &Cli) -> Result<Option<Report>> {
    ensure_crypto_provider();

    use rcgen::{CertificateParams, KeyPair};
    let mut params = CertificateParams::new(vec!["localhost".into(), "bench-server".into()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_der: rustls::pki_types::CertificateDer<'static> = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

    // Write the cert so the client can load it. Shared /tmp
    // volume in docker-compose makes this trivial; local runs
    // on one host work because both processes see /tmp.
    std::fs::write(CERT_PATH, cert_der.as_ref())?;
    eprintln!("wrote cert to {}", CERT_PATH);

    let mut server_config = ServerConfig::with_single_cert(vec![cert_der], key_der)?;
    // Enable QUIC DATAGRAM frames (RFC 9221). Datagrams are
    // unreliable and skip the stream-accept handshake, which
    // makes them the cleanest shape for our ping-pong RTT +
    // throughput tests. Also: WG's data plane is packet-
    // oriented, so datagrams make the apples-to-apples
    // comparison more direct.
    //
    // The extension has to be *advertised* in transport
    // params on both sides during the TLS handshake, or
    // send_datagram silently fails. Setting a non-zero
    // receive buffer is what flips that advertisement on.
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65536));
    transport.datagram_send_buffer_size(65536);
    server_config.transport_config(Arc::new(transport));
    let listen: SocketAddr = cli.listen.parse()?;
    let endpoint = Endpoint::server(server_config, listen)?;
    eprintln!("quic server listening on {}", listen);

    // Handshake loops over many fresh connections; the other
    // workloads need one long-lived connection. Structure:
    // branch first, accept inside.
    if matches!(cli.workload, Workload::Handshake) {
        handshake_server_loop(&endpoint, cli.handshake_iters).await;
        return Ok(None);
    }

    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| anyhow!("endpoint closed before any connection"))?;
    let connection = incoming.await?;

    // Swallow normal disconnect errors — they're expected
    // when the client's one-shot workload finishes and tears
    // down the connection.
    match cli.workload {
        Workload::Handshake => unreachable!(),
        Workload::Rtt => {
            // Datagrams: each send_datagram maps to one QUIC
            // DATAGRAM frame — no stream accept, no flow
            // control. Matches the ping-pong shape of the
            // DRIFT and WG RTT tests exactly.
            loop {
                match connection.read_datagram().await {
                    Ok(bytes) => {
                        if connection.send_datagram(bytes).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        Workload::Throughput => {
            // Streams (not datagrams) for throughput: QUIC
            // streams apply flow control, so client write_all
            // only returns when the server-side buffer has
            // room. That gives a real on-wire throughput
            // number instead of the buffer-queue rate that
            // datagrams measure.
            let mut recv = connection.accept_uni().await?;
            let mut buf = vec![0u8; 65536];
            let mut total = 0u64;
            loop {
                match recv.read(&mut buf).await? {
                    Some(n) if n > 0 => total += n as u64,
                    _ => break,
                }
            }
            eprintln!("quic server received {} bytes", total);
        }
    }
    Ok(None)
}

async fn build_client() -> Result<Endpoint> {
    ensure_crypto_provider();

    // Wait up to 10 s for the server to drop its cert blob.
    let mut cert_bytes = None;
    for _ in 0..100 {
        if let Ok(b) = std::fs::read(CERT_PATH) {
            cert_bytes = Some(b);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let cert_bytes = cert_bytes
        .ok_or_else(|| anyhow!("server cert {} never appeared", CERT_PATH))?;

    let cert = rustls::pki_types::CertificateDer::from(cert_bytes);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?;
    let mut client_config = ClientConfig::new(Arc::new(quic_client));
    // Mirror the server's DATAGRAM support so the transport
    // params negotiate the extension on.
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65536));
    transport.datagram_send_buffer_size(65536);
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().unwrap())?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

pub async fn client(cli: &Cli) -> Result<Option<Report>> {
    let target: SocketAddr = crate::resolve_target(&cli.target).await?;
    let endpoint = build_client().await?;

    match cli.workload {
        Workload::Handshake => {
            let mut report = Report::new("quic", "handshake");
            let mut samples: Vec<u128> = Vec::with_capacity(cli.handshake_iters);
            // Each iter needs a fresh Endpoint so the UDP
            // source port changes — otherwise quinn may reuse
            // a cached 0-RTT state and we'd be measuring
            // resumption, not a cold handshake.
            for _ in 0..cli.handshake_iters {
                let ep = build_client().await?;
                let start = Instant::now();
                let conn = ep.connect(target, "bench-server")?.await?;
                let probe: bytes::Bytes = vec![0xA5u8; 32].into();
                conn.send_datagram(probe)?;
                let _ =
                    tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
                        .await??;
                samples.push(start.elapsed().as_micros());
                // Close the connection + drop endpoint so the
                // next iter is genuinely cold.
                conn.close(0u32.into(), b"bye");
                ep.wait_idle().await;
            }
            crate::report::summarize_handshakes(&mut samples, &mut report);
            Ok(Some(report))
        }
        Workload::Rtt => {
            let mut report = Report::new("quic", "rtt");
            let conn = endpoint.connect(target, "bench-server")?.await?;
            let payload: bytes::Bytes = vec![0xA5u8; cli.payload_bytes].into();

            // Warm-up ping so the first timed iteration isn't
            // paying for any path MTU probing or early ack
            // coalescing.
            conn.send_datagram(payload.clone())?;
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram()).await?;

            let mut samples: Vec<u128> = Vec::with_capacity(cli.rtt_iters);
            for _ in 0..cli.rtt_iters {
                let start = Instant::now();
                conn.send_datagram(payload.clone())?;
                let _ = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
                    .await??;
                samples.push(start.elapsed().as_micros());
            }
            crate::report::summarize_rtts(&mut samples, &mut report);
            Ok(Some(report))
        }
        Workload::Throughput => {
            let mut report = Report::new("quic", "throughput");
            let conn = endpoint.connect(target, "bench-server")?.await?;
            // Uni stream + write_all: QUIC flow control blocks
            // write_all when the server's receive window is
            // full, so this measures genuine wire throughput
            // (same contract as DRIFT/WG where the send API
            // blocks until the kernel has the bytes).
            let mut send = conn.open_uni().await?;
            let payload = vec![0xA5u8; cli.payload_bytes];

            let duration = Duration::from_secs(cli.duration_secs);
            let start = Instant::now();
            let mut bytes = 0u64;
            while start.elapsed() < duration {
                send.write_all(&payload).await?;
                bytes += payload.len() as u64;
            }
            send.finish()?;
            // Wait for the stream to actually drain — otherwise
            // we'd count buffered bytes that haven't been acked.
            let _ = send.stopped().await;
            let elapsed = start.elapsed().as_secs_f64();

            report.bytes_moved = Some(bytes);
            report.duration_s = Some(elapsed);
            report.throughput_mbps = Some((bytes as f64 * 8.0) / (elapsed * 1_000_000.0));
            Ok(Some(report))
        }
    }
}
