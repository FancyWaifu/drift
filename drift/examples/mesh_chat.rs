//! Mesh-routed chat between two clients separated by one or more
//! bridges. Each side:
//!
//!   1. connects directly to its nearest bridge (`--bridge`)
//!   2. registers the bridge as a direct peer
//!   3. registers the TARGET (the peer on the other side of the
//!      bridge chain) as a *mesh-routed* peer — `via_mesh=true`,
//!      `hop_ttl > 1`, no direct addr
//!   4. sends DATA to the target; DRIFT's mesh layer forwards
//!      packets through the bridge(s) using `learned_route`
//!      lookups populated by beacon traffic.
//!
//! Used in the 4-node mesh test (D1 client → D2 bridge → D3 bridge
//! → D4 client) to verify two-hop mesh routing with random bytes.
//!
//! Usage:
//!
//! ```sh
//! mesh-chat \
//!   --bridge udp://192.0.2.168:51820@<D2-pubkey-hex> \
//!   --target <D4-pubkey-hex> \
//!   --count 5
//! ```
//!
//! Output is line-prefixed (`[evt]`, `[done]`) so the test
//! harness can grep + assert just like with `transport-peer`.

use clap::Parser;
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
struct Args {
    /// Direct bridge connection: <url>@<bridge-pubkey-hex>
    #[arg(long)]
    bridge: String,

    /// Mesh-routed target peer pubkey (hex).
    #[arg(long)]
    target: String,

    /// Number of DATA messages to send to the target.
    #[arg(short, long, default_value = "5")]
    count: usize,

    /// Text body for each send; suffixed with #N.
    #[arg(long, default_value = "mesh-chat")]
    send_text: String,

    /// Hard deadline for the receive loop.
    #[arg(long, default_value = "60")]
    timeout: u64,

    /// Initial pause after handshake to let beacons propagate
    /// and mesh routes converge.
    #[arg(long, default_value = "3")]
    settle_secs: u64,

    /// Per-send retry budget if the mesh route isn't learned
    /// yet (UnknownPeer error). Each retry waits 500 ms.
    #[arg(long, default_value = "20")]
    send_retries: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let (bridge_url, bridge_pub_hex) = args
        .bridge
        .split_once('@')
        .ok_or("--bridge expected format <url>@<pubkey-hex>")?;
    let bridge_pub = parse_hex32(bridge_pub_hex)?;
    let target_pub = parse_hex32(&args.target)?;

    let identity = Identity::generate();
    let my_pub = identity.public_bytes();
    let my_hex = hex::encode(my_pub);

    // 1. Connect directly to the bridge over UDP/TCP/WS/whatever.
    let (transport, bridge_addr) = Transport::connect_url(
        bridge_url,
        identity,
        TransportConfig {
            accept_any_peer: true,
            ..TransportConfig::default()
        },
    )
    .await?;
    let transport = Arc::new(transport);

    // 2. Register bridge as a direct peer.
    let bridge_handle = transport
        .add_peer(bridge_pub, bridge_addr, Direction::Initiator)
        .await?;

    // 3. Register the target as a mesh-routed peer. via_mesh=true
    //    so DRIFT sends with hop_ttl > 1 and consults the mesh
    //    routing table on every send_data instead of trying a
    //    direct path.
    let target_handle = transport
        .add_mesh_peer(target_pub, Direction::Initiator)
        .await?;

    // 4. Kick the bridge handshake. add_peer alone does NOT
    //    initiate HELLO — DRIFT only drives a handshake when
    //    there's data to send. send_data to mesh-routed targets
    //    won't trigger a HELLO to the BRIDGE (it tries to forward
    //    via mesh, which can't work yet because the route hasn't
    //    been learned). So we fire a single "trigger" DATA at the
    //    bridge to force the direct handshake; once that lands,
    //    beacons start flowing and the mesh route to `target` can
    //    be learned through them.
    //
    //    The bridge process discards everything it receives (it's
    //    just a relay), so this byte is harmless.
    if let Err(e) = transport
        .send_data(&bridge_handle, b".", 0, 0)
        .await
    {
        eprintln!("[evt] bridge trigger send_data error: {} (continuing)", e);
    }

    println!(
        "[evt] role=mesh-chat my_pub={} bridge={} target={} settle={}s",
        my_hex,
        &bridge_pub_hex[..16],
        &args.target[..16],
        args.settle_secs
    );

    // 4. Receiver task — print every DATA from the target.
    let recv_t = transport.clone();
    let (got_tx, mut got_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        let mut got: usize = 0;
        while let Some(pkt) = recv_t.recv().await {
            got += 1;
            let preview: String = pkt
                .payload
                .iter()
                .take(48)
                .map(|b| {
                    if b.is_ascii_graphic() || *b == b' ' {
                        char::from(*b)
                    } else {
                        '.'
                    }
                })
                .collect();
            println!(
                "[evt] recv #{} bytes={} preview={:?}",
                got,
                pkt.payload.len(),
                preview
            );
            let _ = got_tx.send(pkt.payload);
        }
    });

    // 5. Let the bridge handshake complete + beacons propagate
    //    so the bridge learns the route to the target. Without
    //    this, the first few send_data calls return UnknownPeer.
    println!("[evt] waiting {}s for mesh route to settle...", args.settle_secs);
    tokio::time::sleep(Duration::from_secs(args.settle_secs)).await;

    // 6. Send count messages to the mesh-routed target. Each
    //    one is plain text suffix + a 32-byte random nonce so
    //    every packet's bytes are unique (random) per the test
    //    spec, while staying easy to log.
    use rand::RngCore;
    for i in 0..args.count {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut msg = format!("{}#{} | ", args.send_text, i).into_bytes();
        msg.extend_from_slice(&hex::encode(nonce).into_bytes());

        // Retry loop in case the mesh route isn't learned yet.
        let mut tries = 0;
        loop {
            match transport
                .send_data(&target_handle, &msg, 0, 0)
                .await
            {
                Ok(_) => break,
                Err(e) => {
                    tries += 1;
                    if tries >= args.send_retries {
                        return Err(format!("send_data #{} gave up after {} retries: {}", i, tries, e).into());
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        println!(
            "[evt] sent #{} bytes={} retries={}",
            i + 1,
            msg.len(),
            tries
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // 7. Wait for inbound to converge OR timeout.
    let want = args.count;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);
    let mut got: usize = 0;
    while got < want {
        tokio::select! {
            r = got_rx.recv() => match r {
                Some(_) => got += 1,
                None => break,
            },
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }

    // 8. Report.
    let m = transport.metrics();
    println!(
        "[done] role=mesh-chat my_pub={} sent={} recv_msgs={} handshakes={} auth_fail={} packets_sent={} packets_recv={}",
        my_hex,
        args.count,
        got,
        m.handshakes_completed,
        m.auth_failures,
        m.packets_sent,
        m.packets_received,
    );
    Ok(())
}

fn parse_hex32(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
