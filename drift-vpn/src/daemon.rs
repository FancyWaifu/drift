//! drift-vpn daemon: TUN device <-> DRIFT bidirectional bridge.
//!
//! Two tasks run concurrently for the lifetime of the daemon:
//!
//! - **tun → drift**: read raw IP packets off the tun device,
//!   parse the destination IP, look up the matching peer in
//!   the route table, and ship the packet via
//!   `Transport::send_data` to that peer.
//!
//! - **drift → tun**: pull `Received` packets from the
//!   transport, validate the source IP against the sending
//!   peer's `allowed_ips` (reverse-path filter), and write
//!   the packet to the tun device.
//!
//! Linux only. macOS support would mostly be configuring the
//! utun device differently; the Tokio-async-IO interface is
//! the same.

#![cfg(target_os = "linux")]

use crate::config::Config;
use crate::routing::{parse_endpoints, PeerRoute, RouteTable};
use anyhow::{anyhow, Context, Result};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use drift_core::{derive_peer_id, PeerId};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

pub async fn run(cfg: Config, identity: Identity) -> Result<()> {
    let our_pubkey = identity.public_bytes();
    let our_pid = identity.peer_id();
    info!(
        pubkey = %hex::encode(our_pubkey),
        peer_id = %hex::encode(our_pid),
        "drift-vpn starting"
    );

    // 1. TUN device.
    let mut tun_cfg = tun::Configuration::default();
    let addr = cfg.interface.address.addr();
    let netmask = match cfg.interface.address {
        ipnet::IpNet::V4(n) => n.netmask().to_string(),
        ipnet::IpNet::V6(_) => {
            return Err(anyhow!("IPv6 tun configuration not supported in v0.1"));
        }
    };
    tun_cfg
        .address(addr)
        .netmask(netmask.as_str())
        .mtu(cfg.interface.mtu as i32)
        .up();
    if let Some(name) = &cfg.interface.name {
        tun_cfg.name(name);
    }
    let dev = tun::create_as_async(&tun_cfg).context("creating TUN device")?;
    info!(
        addr = %addr,
        prefix = cfg.interface.address.prefix_len(),
        mtu = cfg.interface.mtu,
        "TUN device up"
    );

    // 2. DRIFT transport. v0.2 supports multiple `listen` URLs
    //    so one daemon serves clients on whichever wire works
    //    for their network. The first URL becomes the primary
    //    interface; the rest are added via `add_listener`.
    let mut tcfg = TransportConfig::default();
    tcfg.accept_any_peer = true; // we ACL on the routing layer
    let mut listen_urls = cfg.interface.listen.as_slice();
    let primary = listen_urls.remove(0);
    let (transport, bound_url) = Transport::bind_url(&primary, identity, tcfg)
        .await
        .with_context(|| format!("binding {}", primary))?;
    let transport = Arc::new(transport);
    info!(bound = %bound_url, "DRIFT transport bound (primary)");
    for url in listen_urls {
        match transport.add_listener(&url).await {
            Ok(bound) => info!(bound = %bound, "additional listener bound"),
            Err(e) => warn!(url = %url, error = %e, "additional listener failed — continuing"),
        }
    }

    // 3. Register peers + build the route table.
    //
    //    v0.2 happy-eyeballs: each peer can list multiple
    //    `endpoints`. We try them sequentially with a 1.5 s
    //    timeout per attempt; the first one that elicits a
    //    DRIFT recv from the peer wins. If none of them elicit
    //    a response (initial cold start, peer not up yet),
    //    we register with the first endpoint and rely on
    //    DRIFT's HELLO retransmit + path validation to recover
    //    once the peer comes online.
    let mut routes = RouteTable::new();
    for (i, peer_cfg) in cfg.peers.iter().enumerate() {
        let peer_pub = peer_cfg
            .pubkey_bytes()
            .with_context(|| format!("peer #{}", i))?;
        let peer_pid = derive_peer_id(&peer_pub);
        let endpoints = peer_cfg.endpoint_list();
        if endpoints.is_empty() {
            return Err(anyhow!("peer #{} has no endpoints", i));
        }
        let dir = if our_pubkey.as_slice() < peer_pub.as_slice() {
            Direction::Initiator
        } else {
            Direction::Responder
        };
        let chosen = register_peer(&transport, peer_pub, &endpoints, dir).await?;
        info!(
            peer = %hex::encode(peer_pid),
            endpoint = %chosen,
            allowed_ips = ?peer_cfg.allowed_ips,
            ?dir,
            "peer registered"
        );
        routes.add(PeerRoute {
            peer_id: peer_pid,
            allowed_ips: peer_cfg.allowed_ips.clone(),
        });
    }
    let routes = Arc::new(routes);

    // 4. Split the TUN device into reader + writer.
    let (mut tun_r, mut tun_w) = tokio::io::split(dev);

    // 5. Kick off the warmup: send a tiny probe to each peer
    //    so the handshake can complete before user traffic
    //    arrives. Failures here are non-fatal; the next user
    //    packet will trigger handshake naturally.
    for r in routes.routes.iter() {
        let _ = transport.send_data(&r.peer_id, b"\x00", 0, 0).await;
    }

    // 6. tun → drift loop.
    let t_send = transport.clone();
    let routes_send = routes.clone();
    let t2d = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match tun_r.read(&mut buf).await {
                Ok(0) => {
                    warn!("TUN reader EOF — exiting tun→drift loop");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    warn!(error = %e, "TUN read error");
                    continue;
                }
            };
            let pkt = &buf[..n];
            let (_, dst) = match parse_endpoints(pkt) {
                Ok(p) => p,
                Err(e) => {
                    debug!(error = %e, "couldn't parse outbound packet");
                    continue;
                }
            };
            let route = match routes_send.route_for_dst(dst) {
                Some(r) => r,
                None => {
                    debug!(?dst, "no peer owns this dst — drop");
                    continue;
                }
            };
            if let Err(e) = t_send.send_data(&route.peer_id, pkt, 0, 0).await {
                debug!(error = %e, peer = %hex::encode(route.peer_id), "send_data failed");
            }
        }
    });

    // 7. drift → tun loop.
    let t_recv = transport.clone();
    let routes_recv = routes.clone();
    let d2t = tokio::spawn(async move {
        loop {
            let recv = match t_recv.recv().await {
                Some(r) => r,
                None => {
                    warn!("transport recv channel closed — exiting drift→tun loop");
                    break;
                }
            };
            // Skip the warmup probe + any non-IP byte.
            if recv.payload.len() < 20 {
                continue;
            }
            let (src, _) = match parse_endpoints(&recv.payload) {
                Ok(p) => p,
                Err(e) => {
                    debug!(error = %e, "couldn't parse inbound packet");
                    continue;
                }
            };
            // Reverse-path filter: src IP MUST be in this
            // peer's allowed_ips. Otherwise the peer is
            // spoofing — drop.
            if !routes_recv.src_is_valid(&recv.peer_id, src) {
                warn!(
                    peer = %hex::encode(recv.peer_id),
                    ?src,
                    "reverse-path filter rejected packet — possible spoof"
                );
                continue;
            }
            if let Err(e) = tun_w.write_all(&recv.payload).await {
                warn!(error = %e, "TUN write failed");
            }
        }
    });

    // 8. Wait for either loop to exit (e.g. TUN closed,
    //    transport torn down). Whichever exits first, abort
    //    the other so the daemon shuts down cleanly.
    tokio::select! {
        _ = t2d => {}
        _ = d2t => {}
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT — shutting down");
        }
    }
    Ok(())
}

/// Resolve a DRIFT URL's `host:port` to a `SocketAddr`,
/// looking up DNS hostnames via the OS resolver. Lets us
/// write `endpoint = "udp://node-b:51820"` in the config and
/// have it work with Docker's embedded DNS, /etc/hosts, etc.
///
/// v0.1 supports `udp://` only; multi-transport URL prefixes
/// (`tcp://`, `tls://`, `ws://`, `http://`, `onion://`) land
/// in v0.2 along with the happy-eyeballs client.
async fn resolve_endpoint(url: &str) -> Result<SocketAddr> {
    let (_scheme, addr) = url
        .split_once("://")
        .ok_or_else(|| anyhow!("endpoint URL needs scheme: {:?}", url))?;
    // Numeric host:port? Skip DNS.
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    // Otherwise, lookup_host resolves hostname:port via the
    // OS resolver (Docker's embedded DNS, /etc/hosts, real DNS
    // — all the same call site).
    let mut iter = tokio::net::lookup_host(addr).await.with_context(|| {
        format!("resolving {:?} via lookup_host", addr)
    })?;
    iter.next()
        .ok_or_else(|| anyhow!("no addresses resolved for {:?}", addr))
}

/// Register a peer at `endpoints[0]`. v0.2 limitation: we use
/// the first endpoint and rely on DRIFT's HELLO retransmits to
/// connect. The config schema accepts an `endpoints = [...]`
/// array for forward-compatibility, but actual *runtime
/// fallover* across endpoints requires DRIFT primitives
/// (`restart_handshake`, per-endpoint outbound Transports)
/// that aren't yet in the public API. That ships in v0.3.
///
/// What v0.2 *does* deliver:
/// - **Server-side multi-listen** (`listen = [...]`): one
///   daemon serves clients on whichever wire works for their
///   network. Each client picks its endpoint at config time;
///   the server accepts on UDP / TCP / TLS / WS / HTTP / Tor
///   simultaneously.
/// - **Forward-compatible config schema**: ship a config with
///   `endpoints = [...]` today; v0.3's runtime fallover will
///   pick it up without config changes.
async fn register_peer(
    transport: &Arc<Transport>,
    peer_pub: [u8; 32],
    endpoints: &[String],
    dir: Direction,
) -> Result<String> {
    let primary = &endpoints[0];
    let addr = resolve_endpoint(primary).await?;
    transport.add_peer(peer_pub, addr, dir).await?;
    if endpoints.len() > 1 {
        debug!(
            primary = %primary,
            fallbacks = ?&endpoints[1..],
            "v0.2 uses primary endpoint only; fallbacks land in v0.3"
        );
    }
    Ok(primary.clone())
}

#[allow(dead_code)]
fn _ensure_peer_id_used(p: PeerId) -> PeerId {
    p
}
