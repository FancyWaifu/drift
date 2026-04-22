//! WireGuard (Noise_IKpsk2) server + client using boringtun's
//! `Tunn` as the protocol engine. We drive the socket and
//! packet ferry ourselves — no tun device, no kernel, no
//! wg-quick. Each side has a UDP socket; incoming bytes go into
//! Tunn::decapsulate, outgoing bench payloads go through
//! Tunn::encapsulate.
//!
//! WireGuard framing: the "inner" payload looks like an IPv4
//! packet to boringtun's decoder — it reads the total-length
//! field from the header to know where the packet ends. Our
//! workload payloads are therefore prefixed with a minimal
//! 20-byte IPv4 header (version=4, IHL=5, total_len=size).
//! The server echoes / drains the raw buffer; it doesn't care
//! about the "IP" content.

use crate::{report::Report, Cli, Workload};
use anyhow::{anyhow, Result};
use boringtun::noise::{Tunn, TunnResult};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SEED: [u8; 32] = [0xCC; 32];
const CLIENT_SEED: [u8; 32] = [0xDD; 32];
const BUF_LEN: usize = 2048;

/// Build a minimal valid IPv4 packet of exactly `size` bytes.
fn fake_ipv4(size: usize) -> Vec<u8> {
    assert!(size >= 20);
    let mut pkt = vec![0u8; size];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    pkt
}

/// Drive a single inbound packet through Tunn. Returns
/// `Some(plaintext)` on data, `None` if the packet was a
/// protocol message (handshake, cookie) — in that case any
/// response has already been sent via `sock.send_to`.
async fn handle_inbound(
    tunn: &mut Tunn,
    sock: &UdpSocket,
    peer_addr: SocketAddr,
    datagram: &[u8],
) -> Result<Option<Vec<u8>>> {
    let mut out = [0u8; BUF_LEN];
    // Loop because decapsulate may return WriteToNetwork for
    // queued packets after a handshake completes — spec says
    // "repeat with empty datagram until Done".
    let mut data_bytes: Option<Vec<u8>> = None;
    // First pass: process the incoming datagram. Subsequent
    // passes call decapsulate with an empty datagram to drain
    // any queued follow-ups (spec: "repeat until Done").
    let initial = tunn.decapsulate(Some(peer_addr.ip()), datagram, &mut out);
    let followup_needed = match initial {
        TunnResult::WriteToNetwork(w) => {
            sock.send_to(w, peer_addr).await?;
            true
        }
        TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
            data_bytes = Some(data.to_vec());
            false
        }
        TunnResult::Done => false,
        TunnResult::Err(e) => return Err(anyhow!("wg error: {:?}", e)),
    };
    if followup_needed {
        let mut followup = [0u8; BUF_LEN];
        loop {
            let r = tunn.decapsulate(None, &[], &mut followup);
            match r {
                TunnResult::WriteToNetwork(wf) => {
                    sock.send_to(wf, peer_addr).await?;
                }
                _ => break,
            }
        }
    }
    Ok(data_bytes)
}

/// Drive an outbound application payload through Tunn's
/// encapsulate. Sends the resulting wire packet to `peer_addr`.
async fn send_out(
    tunn: &mut Tunn,
    sock: &UdpSocket,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let mut out = [0u8; BUF_LEN];
    match tunn.encapsulate(payload, &mut out) {
        TunnResult::WriteToNetwork(w) => {
            sock.send_to(w, peer_addr).await?;
            Ok(())
        }
        TunnResult::Done => Ok(()),
        TunnResult::Err(e) => Err(anyhow!("wg encap: {:?}", e)),
        _ => Err(anyhow!("unexpected encap result")),
    }
}

pub async fn server(cli: &Cli) -> Result<Option<Report>> {
    let server_sk = StaticSecret::from(SERVER_SEED);
    let client_pk = PublicKey::from(&StaticSecret::from(CLIENT_SEED));
    let mut tunn = Tunn::new(server_sk, client_pk, None, None, 1, None);

    let listen: SocketAddr = cli.listen.parse()?;
    let sock = UdpSocket::bind(listen).await?;
    eprintln!("wg server listening on {}", listen);

    let mut buf = [0u8; BUF_LEN];
    // The server learns the client's ephemeral UDP address
    // from the first incoming HandshakeInit.
    let mut peer_addr: Option<SocketAddr> = None;

    match cli.workload {
        Workload::Handshake => {
            // Wait for first data packet (post-handshake) and
            // echo so the client can time a full round trip.
            loop {
                let (n, src) = sock.recv_from(&mut buf).await?;
                peer_addr = Some(src);
                if let Some(data) =
                    handle_inbound(&mut tunn, &sock, src, &buf[..n]).await?
                {
                    send_out(&mut tunn, &sock, src, &data).await?;
                    break;
                }
            }
        }
        Workload::Rtt => {
            loop {
                let recv =
                    tokio::time::timeout(Duration::from_secs(30), sock.recv_from(&mut buf))
                        .await;
                let (n, src) = match recv {
                    Ok(Ok(v)) => v,
                    _ => break,
                };
                peer_addr = Some(src);
                if let Some(data) =
                    handle_inbound(&mut tunn, &sock, src, &buf[..n]).await?
                {
                    send_out(&mut tunn, &sock, src, &data).await?;
                }
            }
        }
        Workload::Throughput => {
            let mut total = 0u64;
            loop {
                let recv =
                    tokio::time::timeout(Duration::from_secs(30), sock.recv_from(&mut buf))
                        .await;
                let (n, src) = match recv {
                    Ok(Ok(v)) => v,
                    _ => break,
                };
                peer_addr = Some(src);
                if let Some(data) =
                    handle_inbound(&mut tunn, &sock, src, &buf[..n]).await?
                {
                    total += data.len() as u64;
                }
            }
            eprintln!("wg server received {} bytes", total);
        }
    }
    let _ = peer_addr;
    Ok(None)
}

pub async fn client(cli: &Cli) -> Result<Option<Report>> {
    let client_sk = StaticSecret::from(CLIENT_SEED);
    let server_pk = PublicKey::from(&StaticSecret::from(SERVER_SEED));
    let mut tunn = Tunn::new(client_sk, server_pk, None, None, 0, None);

    let peer_addr: SocketAddr = cli.target.parse()?;
    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    match cli.workload {
        Workload::Handshake => {
            let mut report = Report::new("wireguard", "handshake");
            let start = Instant::now();
            complete_handshake(&mut tunn, &sock, peer_addr, cli.payload_bytes).await?;
            // Wait for the server's echo of our first data
            // frame. Keeps the measurement semantics the same
            // as DRIFT and QUIC.
            let mut buf = [0u8; BUF_LEN];
            loop {
                let (n, src) = tokio::time::timeout(
                    Duration::from_secs(5),
                    sock.recv_from(&mut buf),
                )
                .await??;
                if let Some(_) = handle_inbound(&mut tunn, &sock, src, &buf[..n]).await? {
                    break;
                }
            }
            report.handshake_us = Some(start.elapsed().as_micros() as u64);
            Ok(Some(report))
        }
        Workload::Rtt => {
            let mut report = Report::new("wireguard", "rtt");
            let payload = fake_ipv4(cli.payload_bytes.max(20));
            // Handshake + first data frame; also drains the
            // echo so timing starts cleanly.
            complete_handshake(&mut tunn, &sock, peer_addr, cli.payload_bytes).await?;
            // Wait for server echo of the handshake probe so
            // subsequent pings have a quiet baseline.
            let mut buf = [0u8; BUF_LEN];
            let (n, src) =
                tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
                    .await??;
            let _ = handle_inbound(&mut tunn, &sock, src, &buf[..n]).await?;

            let mut samples: Vec<u128> = Vec::with_capacity(cli.rtt_iters);
            for _ in 0..cli.rtt_iters {
                let start = Instant::now();
                send_out(&mut tunn, &sock, peer_addr, &payload).await?;
                loop {
                    let (n, src) = tokio::time::timeout(
                        Duration::from_secs(5),
                        sock.recv_from(&mut buf),
                    )
                    .await??;
                    if let Some(_) =
                        handle_inbound(&mut tunn, &sock, src, &buf[..n]).await?
                    {
                        break;
                    }
                }
                samples.push(start.elapsed().as_micros());
            }
            crate::report::summarize_rtts(&mut samples, &mut report);
            Ok(Some(report))
        }
        Workload::Throughput => {
            let mut report = Report::new("wireguard", "throughput");
            let payload = fake_ipv4(cli.payload_bytes.max(20));
            complete_handshake(&mut tunn, &sock, peer_addr, cli.payload_bytes).await?;

            let duration = Duration::from_secs(cli.duration_secs);
            let start = Instant::now();
            let mut bytes = 0u64;
            while start.elapsed() < duration {
                send_out(&mut tunn, &sock, peer_addr, &payload).await?;
                bytes += payload.len() as u64;
            }
            let elapsed = start.elapsed().as_secs_f64();

            report.bytes_moved = Some(bytes);
            report.duration_s = Some(elapsed);
            report.throughput_mbps = Some((bytes as f64 * 8.0) / (elapsed * 1_000_000.0));
            Ok(Some(report))
        }
    }
}

/// Run the Noise_IKpsk2 handshake to completion, then deliver
/// one data frame so the timing aligns with the "connect +
/// first byte ack" definition used by the DRIFT and QUIC
/// handshake workloads.
async fn complete_handshake(
    tunn: &mut Tunn,
    sock: &UdpSocket,
    peer_addr: SocketAddr,
    payload_bytes: usize,
) -> Result<()> {
    let payload = fake_ipv4(payload_bytes.max(20));

    // Client-initiated: `encapsulate` of a data packet with
    // no session triggers a HandshakeInit.
    send_out(tunn, sock, peer_addr, &payload).await?;

    // Read handshake response, deliver to tunn, which may emit
    // a queued data packet next.
    let mut buf = [0u8; BUF_LEN];
    let (n, src) =
        tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf)).await??;
    let _ = handle_inbound(tunn, sock, src, &buf[..n]).await?;

    // Ensure the first real data frame makes it — boringtun
    // queues during handshake and flushes via
    // send_queued_packet, but we also re-send explicitly to
    // guarantee the server observes a data packet.
    send_out(tunn, sock, peer_addr, &payload).await?;
    Ok(())
}
