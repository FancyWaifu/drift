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
//! v0.12: Linux + macOS support via the `tun` crate's
//! cross-platform abstraction. Windows (Wintun) needs a
//! different status-server (named pipe), so the daemon is
//! Unix-only at the file level.

#![cfg(unix)]

use crate::config::Config;
use crate::metrics::DaemonMetrics;
use crate::routing::{parse_endpoints, PeerRoute, RouteTable};
use crate::status::{KnownPeer, StatusContext};
use std::path::PathBuf;
use anyhow::{anyhow, Context, Result};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use drift_core::{derive_peer_id, PeerId};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

pub async fn run(cfg: Config, identity: Identity, status_socket: PathBuf) -> Result<()> {
    let our_pubkey = identity.public_bytes();
    let our_pid = identity.peer_id();
    info!(
        pubkey = %hex::encode(our_pubkey),
        peer_id = %hex::encode(our_pid),
        "drift-vpn starting"
    );

    let metrics = Arc::new(DaemonMetrics::new());
    let started_at = std::time::Instant::now();
    let mut known_peers: Vec<KnownPeer> = Vec::new();

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
    // Read the kernel-assigned name back from the device. Doing
    // this AFTER creation matters: if `cfg.interface.name` is
    // None, the kernel picks the first free `tunN` — which on a
    // multi-tun host might be `tun3`, not `tun0`. The previous
    // hardcoded "tun0" fallback would silently disable offloads
    // on the wrong interface and ours kept TSO on, leading to
    // exactly the silent-drop class of bug v0.3 was supposed to
    // make impossible.
    use tun::Device;
    let tun_name = dev
        .get_ref()
        .name()
        .context("reading tun device name from kernel")?;
    info!(
        addr = %addr,
        prefix = cfg.interface.address.prefix_len(),
        mtu = cfg.interface.mtu,
        iface = %tun_name,
        "TUN device up"
    );

    // Disable TSO/GSO/etc. on the tun. Linux generic-
    // segmentation-offload can hand us 64KB pseudo-segments
    // that exceed DRIFT's MAX_PAYLOAD (1348 bytes) and get
    // dropped. Disabling forces the kernel to emit real
    // MTU-sized segments. macOS utun doesn't have these
    // offloads, so this is a no-op on non-Linux.
    #[cfg(target_os = "linux")]
    disable_offloads_and_verify(&tun_name).await;
    #[cfg(not(target_os = "linux"))]
    let _ = &tun_name; // silence unused-var on non-Linux

    // 2. DRIFT transport. v0.2 supports multiple `listen` URLs
    //    so one daemon serves clients on whichever wire works
    //    for their network. The first URL becomes the primary
    //    interface; the rest are added via `add_listener`.
    let mut tcfg = TransportConfig::default();
    tcfg.accept_any_peer = true; // we ACL on the routing layer
    // Tie the DRIFT keepalive to the failover supervisor's
    // staleness threshold: we want at least two Ping rounds
    // inside a stale_secs window so that a healthy tunnel
    // doesn't get flagged as stale just because it's quiet
    // between user packets. Default is `stale_secs * 1000 / 3`
    // ms, capped at 2s for fast detection on low staleness.
    let probe_ms = std::cmp::min(
        2_000_u64,
        (cfg.failover.stale_secs.saturating_mul(1000)) / 3,
    );
    tcfg.rtt_probe_interval_ms = std::cmp::max(500, probe_ms);
    // Caller already validated that `listen` is non-empty.
    let listen_urls: &[String] = &cfg.interface.listen;
    let primary = &listen_urls[0];
    let extras = &listen_urls[1..];
    let (transport, bound_url) = Transport::bind_url(primary, identity, tcfg)
        .await
        .with_context(|| format!("binding {}", primary))?;
    let transport = Arc::new(transport);
    info!(bound = %bound_url, "DRIFT transport bound (primary)");
    for url in extras {
        match transport.add_listener(url).await {
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
    let mut supervisor_states: Vec<SupervisorState> = Vec::new();
    // Mesh-only peers we need to bootstrap: their initial HELLO
    // can't fire until the mesh route table has a learned
    // route, which arrives via a beacon AFTER the daemon is
    // running. The warmup task below retries `send_data` for
    // each one every 2s until they reach Established (or get
    // dropped from the table). The batched tun→drift sender
    // skips Pending peers silently — without this retry the
    // first user packet to a mesh-only peer would just be
    // dropped, indefinitely.
    let mut mesh_only_peers: Vec<PeerId> = Vec::new();
    for (i, peer_cfg) in cfg.peers.iter().enumerate() {
        let peer_pub = peer_cfg
            .pubkey_bytes()
            .with_context(|| format!("peer #{}", i))?;
        let peer_pid = derive_peer_id(&peer_pub);
        let endpoints = peer_cfg.endpoint_list();
        // Both sides use Direction::Initiator. DRIFT's dual-
        // initiation tiebreaker resolves the simultaneous-HELLO
        // case correctly (lower pubkey "wins" as Responder),
        // and crucially: this means EITHER side can re-trigger a
        // handshake after a restart. With deterministic
        // direction (lower=Initiator, higher=Responder), if the
        // Responder side dies and restarts, it never sends HELLO
        // (only Initiator does in send_data) and the surviving
        // Initiator side stays in Established with stale keys.
        // Always-Initiator avoids that deadlock.
        let dir = Direction::Initiator;
        let chosen_for_supervisor: Option<String> = if endpoints.is_empty() {
            // v0.8 mesh-only peer: no direct endpoint, will be
            // reached via forwarding once another peer (the
            // hub) advertises a route via beacons. We pre-
            // register so our routing layer knows about
            // peer_pid and so the transport's mesh router has
            // a target to set `peer.addr` on once a route is
            // learned. No supervisor — there's nothing to fail
            // over to.
            transport.add_mesh_peer(peer_pub, dir).await?;
            mesh_only_peers.push(peer_pid);
            info!(
                peer = %hex::encode(peer_pid),
                allowed_ips = ?peer_cfg.allowed_ips,
                ?dir,
                "mesh-only peer registered (no endpoint; reach via forwarding)"
            );
            None
        } else {
            let chosen = try_endpoints(&transport, peer_pub, &peer_pid, &endpoints, dir).await?;
            info!(
                peer = %hex::encode(peer_pid),
                endpoint = %chosen,
                allowed_ips = ?peer_cfg.allowed_ips,
                ?dir,
                "peer registered"
            );
            Some(chosen)
        };
        routes.add(PeerRoute {
            peer_id: peer_pid,
            allowed_ips: peer_cfg.allowed_ips.clone(),
        });
        known_peers.push(KnownPeer {
            peer_id: peer_pid,
            pubkey: peer_pub,
            allowed_ips: peer_cfg
                .allowed_ips
                .iter()
                .map(|n| n.to_string())
                .collect(),
        });

        // v0.6: collect supervisor state per multi-endpoint
        // peer; we'll start ONE supervisor task that walks the
        // whole list each tick (rather than N tasks all firing
        // simultaneously). This lets us share a global probe-
        // rate limiter and avoid the thundering herd when many
        // peers see the same outage at once.
        if cfg.failover.enabled && endpoints.len() > 1 {
            // chosen_for_supervisor is always Some when
            // endpoints isn't empty, but pattern-match for
            // safety.
            if let Some(chosen) = chosen_for_supervisor {
                let initial_idx = endpoints
                    .iter()
                    .position(|e| e == &chosen)
                    .unwrap_or(0);
                supervisor_states.push(SupervisorState::new(
                    peer_pid, endpoints, initial_idx,
                ));
            }
        }
    }
    let routes = Arc::new(routes);

    // Spawn the single supervisor task if any peer needs it.
    if !supervisor_states.is_empty() {
        let sup_transport = transport.clone();
        let sup_metrics = metrics.clone();
        let sup_cfg = cfg.failover.clone();
        tokio::spawn(async move {
            supervise_all(sup_transport, sup_metrics, supervisor_states, sup_cfg).await;
        });
    }

    // Spawn the mesh-only warmup retrier. Calls `send_data`
    // (the per-packet, handshake-bootstrapping API) on each
    // pending mesh-only peer every 2s. Once a peer reaches
    // Established, it's removed from the list. When the list
    // is empty, the task exits.
    if !mesh_only_peers.is_empty() {
        let warm_transport = transport.clone();
        tokio::spawn(async move {
            let mut pending = mesh_only_peers;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                // Filter out peers that have reached Established
                // or disappeared from the table. We can't use
                // `Vec::retain` directly because the predicate
                // needs to await; loop manually.
                let mut next = Vec::with_capacity(pending.len());
                for pid in pending.into_iter() {
                    let still_pending = match warm_transport.peer_metrics(&pid).await {
                        Some(m) => !m.is_established,
                        None => false, // gone — stop trying
                    };
                    if still_pending {
                        next.push(pid);
                    }
                }
                pending = next;
                if pending.is_empty() {
                    debug!("mesh-only warmup: all peers established or gone — exiting");
                    break;
                }
                for pid in pending.iter() {
                    // 1-byte payload triggers HELLO if the
                    // peer is Pending; harmless DATA if
                    // Established (lost the race).
                    let _ = warm_transport.send_data(pid, b"\x00", 0, 0).await;
                }
            }
        });
    }

    // 4a. Spawn the status server. Best-effort — if the socket
    //     dir isn't writable we log and continue without status.
    {
        let status_ctx = Arc::new(StatusContext {
            local_pubkey: our_pubkey,
            local_peer_id: our_pid,
            iface_name: tun_name.clone(),
            local_addr: format!("{}/{}", addr, cfg.interface.address.prefix_len()),
            started_at,
            transport: transport.clone(),
            metrics: metrics.clone(),
            peers: known_peers,
        });
        let path = status_socket.clone();
        let ctx_for_status = status_ctx.clone();
        tokio::spawn(async move {
            crate::status::run_server(path, ctx_for_status).await;
        });
        // 4b. v0.9: optional Prometheus /metrics endpoint.
        // Operators opt in by setting `prom_listen`. Disabled
        // by default since not every deployment runs Prometheus.
        if let Some(prom_addr_str) = cfg.interface.prom_listen.as_deref() {
            match prom_addr_str.parse::<std::net::SocketAddr>() {
                Ok(prom_addr) => {
                    let ctx_for_prom = status_ctx.clone();
                    tokio::spawn(async move {
                        crate::status::run_prom_server(prom_addr, ctx_for_prom).await;
                    });
                }
                Err(e) => {
                    warn!(
                        addr = %prom_addr_str,
                        error = %e,
                        "interface.prom_listen isn't a valid host:port — Prometheus endpoint disabled"
                    );
                }
            }
        }
    }

    // 4. Split the TUN device into reader + writer.
    let (mut tun_r, mut tun_w) = tokio::io::split(dev);

    // 5. Kick off the warmup: send a tiny probe to each peer
    //    so the handshake can complete before user traffic
    //    arrives. Failures here are non-fatal; the next user
    //    packet will trigger handshake naturally.
    for r in routes.routes.iter() {
        let _ = transport.send_data(&r.peer_id, b"\x00", 0, 0).await;
    }

    // 6. tun → drift pipeline (v0.7 opportunistic batcher).
    //
    // Two tasks instead of one:
    //   * READER: blocking read from the tun, parse + route +
    //     classify, push a `BatchItem` into an mpsc channel.
    //     One packet per iteration; never builds a Vec.
    //   * SENDER: drain the channel in mini-batches. Block on
    //     `recv()` for the first item, then `try_recv` until
    //     either MAX_BATCH or the channel is empty, then flush
    //     via `send_data_batch_qos`.
    //
    // Result: under heavy traffic, sendmmsg ships up to N packets
    // per syscall AND the per-shard peer locks are taken N times
    // total instead of N times per packet. Under sparse traffic,
    // batches naturally degenerate to size 1 — no extra latency,
    // no per-packet timer, no allocation that the per-packet path
    // didn't already pay.
    const MAX_BATCH: usize = 32;
    const QUEUE_CAP: usize = 1024;

    let (out_tx, mut out_rx) =
        tokio::sync::mpsc::channel::<drift::transport::BatchItem>(QUEUE_CAP);

    let routes_send = routes.clone();
    let metrics_send = metrics.clone();
    let t2d_reader = tokio::spawn(async move {
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
                    metrics_send
                        .no_route_drops
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    debug!(?dst, "no peer owns this dst — drop");
                    continue;
                }
            };
            let (deadline_ms, coalesce_group) =
                crate::routing::classify_for_qos(pkt);
            // Backpressure: if the sender is behind, the tun
            // reader blocks here, which propagates back through
            // the kernel queue. Same semantics as the previous
            // per-packet code where a slow send_data also stalled
            // the reader.
            let item = drift::transport::BatchItem {
                peer: route.peer_id,
                payload: pkt.to_vec(),
                deadline_ms,
                coalesce_group,
            };
            if out_tx.send(item).await.is_err() {
                warn!("send queue closed — exiting tun→drift reader");
                break;
            }
        }
    });

    let t_send = transport.clone();
    let metrics_send2 = metrics.clone();
    let t2d_sender = tokio::spawn(async move {
        use std::sync::atomic::Ordering::Relaxed;
        let mut batch: Vec<drift::transport::BatchItem> = Vec::with_capacity(MAX_BATCH);
        loop {
            // Block until at least one item is available.
            let first = match out_rx.recv().await {
                Some(item) => item,
                None => {
                    debug!("send queue closed — exiting tun→drift sender");
                    break;
                }
            };
            batch.push(first);
            // Opportunistically grab any more packets that are
            // already queued, up to MAX_BATCH. This drives real
            // sendmmsg batching when traffic is heavy.
            while batch.len() < MAX_BATCH {
                match out_rx.try_recv() {
                    Ok(item) => batch.push(item),
                    Err(_) => break,
                }
            }

            let n_attempted = batch.len();
            // Pre-compute oversized-packet warnings before
            // we hand the items off — the batched API will
            // silently skip them, but we still want to see
            // those warnings for diagnosis.
            for it in batch.iter() {
                if it.payload.len() > drift::transport::MAX_PAYLOAD {
                    warn!(
                        pkt_len = it.payload.len(),
                        peer = %hex::encode(it.peer),
                        "oversized packet — check `ethtool -k <iface>`, offloads may be stuck on"
                    );
                }
            }

            match t_send.send_data_batch_qos(&batch).await {
                Ok(sent) => {
                    metrics_send2
                        .send_data_ok
                        .fetch_add(sent as u64, Relaxed);
                    if sent < n_attempted {
                        // Some packets were skipped (peer not
                        // established yet, oversized, etc.).
                        // The transport doesn't tell us which.
                        metrics_send2
                            .send_data_errs
                            .fetch_add((n_attempted - sent) as u64, Relaxed);
                    }
                }
                Err(e) => {
                    metrics_send2
                        .send_data_errs
                        .fetch_add(n_attempted as u64, Relaxed);
                    warn!(error = %e, n = n_attempted, "send_data_batch_qos failed");
                }
            }
            batch.clear();
        }
    });

    // 7. drift → tun loop.
    let t_recv = transport.clone();
    let routes_recv = routes.clone();
    let metrics_recv = metrics.clone();
    let d2t = tokio::spawn(async move {
        use std::sync::atomic::Ordering::Relaxed;
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
                    metrics_recv.rpfilter.parse_failed.fetch_add(1, Relaxed);
                    debug!(error = %e, "couldn't parse inbound packet");
                    continue;
                }
            };
            // Reverse-path filter with cause distinction.
            // Three buckets:
            //   - peer not in our route table (mesh-forwarded
            //     traffic from a peer-of-peer we don't directly
            //     know, or pre-startup race)
            //   - peer known but src not in their allowed_ips
            //     (almost always config mismatch, occasionally
            //     a legitimate per-app misconfig)
            //   - parse failed (already handled above)
            // Real attacks are rare and look like the second
            // bucket; the first bucket is mostly harmless noise.
            // Splitting them lets operators tell the difference.
            match routes_recv.src_status(&recv.peer_id, src) {
                crate::routing::SrcStatus::Allowed => {}
                crate::routing::SrcStatus::UnknownPeer => {
                    metrics_recv.rpfilter.unknown_peer.fetch_add(1, Relaxed);
                    debug!(
                        peer = %hex::encode(recv.peer_id),
                        ?src,
                        "rpfilter dropped: peer not in route table (mesh forward?)"
                    );
                    continue;
                }
                crate::routing::SrcStatus::ConfigMismatch => {
                    metrics_recv.rpfilter.config_mismatch.fetch_add(1, Relaxed);
                    warn!(
                        peer = %hex::encode(recv.peer_id),
                        ?src,
                        "rpfilter dropped: src not in peer's allowed_ips \
                         (check config — peer's tun IP may differ from configured)"
                    );
                    continue;
                }
            }
            match tun_w.write_all(&recv.payload).await {
                Ok(_) => {
                    metrics_recv.tun_writes.fetch_add(1, Relaxed);
                    metrics_recv
                        .tun_bytes_written
                        .fetch_add(recv.payload.len() as u64, Relaxed);
                }
                Err(e) => {
                    metrics_recv.tun_write_errs.fetch_add(1, Relaxed);
                    warn!(error = %e, len = recv.payload.len(), "TUN write failed");
                }
            }
        }
    });

    // 8. Wait for either loop to exit (e.g. TUN closed,
    //    transport torn down). Whichever exits first, abort
    //    the other so the daemon shuts down cleanly.
    tokio::select! {
        _ = t2d_reader => {}
        _ = t2d_sender => {}
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
/// Disable NIC offloads on the tun and verify they actually
/// stuck. Some kernels/drivers report success on `-K` requests
/// while leaving the offload enabled (especially under
/// virtualization). Reading back with `-k` and checking each
/// flag catches those silent failures.
///
/// Best-effort: if `ethtool` isn't available, log and continue.
/// Verification mismatches log at WARN with a hint pointing
/// at `ethtool -k` so operators can investigate.
#[cfg(target_os = "linux")]
async fn disable_offloads_and_verify(iface: &str) {
    const FLAGS: &[&str] = &["tso", "gso", "gro", "lro"];

    let mut args = vec!["-K", iface];
    for f in FLAGS {
        args.push(f);
        args.push("off");
    }
    match tokio::process::Command::new("ethtool")
        .args(&args)
        .output()
        .await
    {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            warn!(
                iface,
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "ethtool -K returned non-zero — TCP throughput may be degraded"
            );
            return;
        }
        Err(e) => {
            warn!(
                error = %e,
                iface,
                "couldn't run ethtool (offload not disabled) — TCP throughput may be degraded"
            );
            return;
        }
    }

    // Read back. Output format is one feature per line:
    //     tcp-segmentation-offload: off
    //     generic-segmentation-offload: off
    //     ...
    let readback = match tokio::process::Command::new("ethtool")
        .args(["-k", iface])
        .output()
        .await
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => {
            warn!(iface, "couldn't read back ethtool offload state — assuming disabled");
            return;
        }
    };
    let text = String::from_utf8_lossy(&readback);
    let mut bad: Vec<&str> = Vec::new();
    for (flag, full_name) in [
        ("tso", "tcp-segmentation-offload"),
        ("gso", "generic-segmentation-offload"),
        ("gro", "generic-receive-offload"),
        ("lro", "large-receive-offload"),
    ] {
        // A line like `tcp-segmentation-offload: on` means the
        // offload is still active despite our -K request.
        let on_line = format!("{}: on", full_name);
        if text.lines().any(|l| l.trim_start().starts_with(&on_line)) {
            bad.push(flag);
        }
    }

    if bad.is_empty() {
        info!(iface, "disabled TSO/GSO/GRO/LRO via ethtool (verified)");
    } else {
        warn!(
            iface,
            still_on = ?bad,
            "ethtool -K succeeded but offloads still report ON — \
             expect large-packet drops; check `ethtool -k {}`",
            iface
        );
    }
}

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

/// Happy-eyeballs across a peer's `endpoints` list (v0.3).
///
/// Try each endpoint in priority order:
///   1. Resolve `url` → SocketAddr.
///   2. On the first attempt, `add_peer` at that addr.
///      On subsequent attempts, `update_peer_addr` + `restart_handshake`
///      to wipe the previous session state and re-arm HELLO.
///   3. Send a 1-byte probe to trigger handshake.
///   4. Watch the global `handshakes_completed` counter for
///      advancement within `PROBE_TIMEOUT`. First endpoint
///      that lands a session wins.
///
/// If no endpoint lands a session at startup (peer isn't up
/// yet), the peer stays registered at `endpoints[0]` and DRIFT's
/// HELLO retransmit will recover when the peer comes online.
async fn try_endpoints(
    transport: &Arc<Transport>,
    peer_pub: [u8; 32],
    peer_pid: &PeerId,
    endpoints: &[String],
    dir: Direction,
) -> Result<String> {
    use rand::Rng;
    use std::time::Duration;
    const PROBE_BASE: Duration = Duration::from_millis(1500);
    const PROBE_JITTER_MAX_MS: u64 = 500;

    let first_addr = resolve_endpoint(&endpoints[0]).await?;
    transport.add_peer(peer_pub, first_addr, dir).await?;

    // Per-peer probe timeout with random jitter. Symmetric
    // peers (same configs, started together) would otherwise
    // probe in lockstep and converge on the same race window.
    // Jitter in [0, 500ms] breaks the symmetry on the first
    // cycle so even pathological scheduling diverges fast.
    let probe_timeout = PROBE_BASE
        + Duration::from_millis(rand::thread_rng().gen_range(0..PROBE_JITTER_MAX_MS));

    for (i, url) in endpoints.iter().enumerate() {
        let addr = match resolve_endpoint(url).await {
            Ok(a) => a,
            Err(e) => {
                warn!(endpoint = %url, error = %e, "endpoint resolve failed — trying next");
                continue;
            }
        };

        if i > 0 {
            // Swap addr + wipe the previous attempt's session
            // state so the next send triggers a fresh HELLO at
            // the new addr.
            if !transport.update_peer_addr(peer_pid, addr).await {
                warn!(endpoint = %url, "peer disappeared mid-fallback — re-adding");
                transport.add_peer(peer_pub, addr, dir).await?;
            }
            if let Err(e) = transport.restart_handshake(peer_pid).await {
                warn!(endpoint = %url, error = %e, "restart_handshake failed — trying next");
                continue;
            }
        }

        let _ = transport.send_data(peer_pid, b"\x00", 0, 0).await;

        // Per-peer probe with addr verification. The transport
        // accepts incoming HELLOs by static_pub match and
        // auto-updates `peer.addr` to the source. So if the
        // remote peer simultaneously fell through to its real
        // endpoint and its HELLO landed here, our peer would
        // become Established at THAT addr — not the dead one
        // we're probing. We only attribute "winner" to the
        // current endpoint if BOTH the session is Established
        // AND `peer.addr` still matches the addr we set.
        let deadline = tokio::time::Instant::now() + probe_timeout;
        let mut completed = false;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if transport.peer_is_established(peer_pid).await
                && transport.peer_addr(peer_pid).await == Some(addr)
            {
                completed = true;
                break;
            }
        }
        if completed {
            info!(
                endpoint = %url,
                tried = i + 1,
                of = endpoints.len(),
                "happy-eyeballs winner"
            );
            return Ok(url.clone());
        }
        warn!(endpoint = %url, "no handshake within timeout — trying next");
    }

    warn!(
        peer = %hex::encode(peer_pid),
        "no endpoint completed handshake at startup; \
         tunnel may be one-sided until peer connects"
    );
    Ok(endpoints[0].clone())
}

/// Per-peer state held by the (single) failover supervisor task.
struct SupervisorState {
    peer_pid: PeerId,
    endpoints: Vec<String>,
    /// Index into `endpoints` of the currently-active path.
    current_idx: usize,
    /// When the last successful failover landed. Drives the
    /// `hold_secs` hysteresis.
    last_switch: std::time::Instant,
    /// Baseline SRTT for the rtt-degradation signal — captured
    /// the first time we observed an SRTT after landing on the
    /// current endpoint.
    baseline_rtt: Option<std::time::Duration>,
    /// Consecutive ticks where SRTT exceeded the baseline limit.
    /// Reset to zero on any sample within bounds.
    high_rtt_strikes: u32,
}

impl SupervisorState {
    fn new(peer_pid: PeerId, endpoints: Vec<String>, initial_idx: usize) -> Self {
        Self {
            peer_pid,
            endpoints,
            current_idx: initial_idx,
            last_switch: std::time::Instant::now(),
            baseline_rtt: None,
            high_rtt_strikes: 0,
        }
    }
}

/// v0.6 single-task health supervisor. Replaces the per-peer
/// `tokio::spawn` model with one task that walks every
/// supervised peer per tick. Three benefits:
///
///   * **No thundering herd**: when one upstream link dies, all
///     peers go stale at once. With per-peer tasks each fires
///     a probe simultaneously, hammering the alternate link
///     before any of them have committed. The single-task
///     model picks at most `MAX_PROBES_PER_TICK` peers per tick.
///
///   * **Coordinated rate-limiting**: a global cap on probes-
///     per-second is straightforward (we just count what we did
///     this tick) instead of needing cross-task state.
///
///   * **Cheap at scale**: 100 peers stays one task, not 100.
///
/// Wakes every `check_interval`, asks the transport for each
/// peer's link metrics, and decides whether to fail over.
/// Three failure signals (any one is enough):
///
///   * **Hard absence**: `peer_metrics()` returned `None`. The
///     peer was somehow dropped from the table (rare —
///     `close_peer` or shard reaper). Restart the handshake
///     against the current endpoint and let it recover.
///
///   * **Staleness**: no AEAD-valid traffic in `stale_secs`.
///     The default 5s rtt-probe interval makes this two
///     missed pings worth of silence — enough to call the link
///     dead without overreacting to one lost packet.
///
///   * **RTT degradation** (opt-in via `rtt_multiplier > 0`):
///     SRTT exceeds `rtt_multiplier × baseline` for several
///     consecutive samples. Default off; too easy to misconfigure
///     and ping-pong on noisy WAN.
///
/// On failure: probe the next endpoint via `Transport::probe_candidate_path`,
/// wait up to ~3s for the peer.addr swap to commit. On success
/// we're done — keep watching at the new endpoint with a hold
/// window before the next switch is allowed. On failure: try
/// the endpoint after that, and so on. If we cycle all the way
/// back to the original primary and it still doesn't work, do
/// a `restart_handshake` as last resort — that wipes session
/// state and forces a fresh handshake.
async fn supervise_all(
    transport: Arc<Transport>,
    metrics: Arc<DaemonMetrics>,
    mut peers: Vec<SupervisorState>,
    cfg: crate::config::Failover,
) {
    use std::sync::atomic::Ordering::Relaxed;
    use std::time::{Duration, Instant};

    let check_interval = Duration::from_millis(cfg.check_interval_ms);
    let stale_threshold = Duration::from_secs(cfg.stale_secs);
    let hold_time = Duration::from_secs(cfg.hold_secs);
    const PROBE_COMMIT_TIMEOUT: Duration = Duration::from_millis(3500);
    const RTT_STRIKES_TO_FAILOVER: u32 = 3;
    /// Cap on probe attempts launched per tick across ALL
    /// peers. Keeps a simultaneous-outage scenario from
    /// hammering an already-degraded alternate link with N
    /// probes at once. Subsequent ticks pick up the rest.
    const MAX_PROBES_PER_TICK: usize = 4;

    info!(
        peers = peers.len(),
        check_interval_ms = cfg.check_interval_ms,
        stale_secs = cfg.stale_secs,
        hold_secs = cfg.hold_secs,
        rtt_multiplier = cfg.rtt_multiplier,
        max_probes_per_tick = MAX_PROBES_PER_TICK,
        "failover supervisor started (single-task v0.6)"
    );

    loop {
        tokio::time::sleep(check_interval).await;

        let mut probes_this_tick: usize = 0;
        for state in peers.iter_mut() {
            // Honor the global per-tick probe cap. Peers we
            // skip get re-evaluated on the next tick — staleness
            // grows monotonically, so they don't get forgotten.
            if probes_this_tick >= MAX_PROBES_PER_TICK {
                break;
            }

            let m = match transport.peer_metrics(&state.peer_pid).await {
                Some(m) => m,
                None => {
                    // Peer evicted from the table — best effort
                    // restart at the current endpoint.
                    warn!(
                        peer = %hex::encode(state.peer_pid),
                        "peer disappeared from transport — attempting restart"
                    );
                    metrics.failover_restarts.fetch_add(1, Relaxed);
                    let _ = transport.restart_handshake(&state.peer_pid).await;
                    continue;
                }
            };

            let stale = Instant::now().duration_since(m.last_seen) > stale_threshold;
            let rtt_bad = if cfg.rtt_multiplier > 0.0 {
                match (m.srtt, state.baseline_rtt) {
                    (Some(srtt), None) => {
                        state.baseline_rtt = Some(srtt);
                        false
                    }
                    (Some(srtt), Some(base)) => {
                        let limit = base.mul_f32(cfg.rtt_multiplier);
                        if srtt > limit {
                            state.high_rtt_strikes += 1;
                        } else {
                            state.high_rtt_strikes = 0;
                        }
                        state.high_rtt_strikes >= RTT_STRIKES_TO_FAILOVER
                    }
                    _ => false,
                }
            } else {
                false
            };

            if !(stale || rtt_bad) {
                continue;
            }

            if state.last_switch.elapsed() < hold_time {
                metrics.failover_hold_skipped.fetch_add(1, Relaxed);
                debug!(
                    peer = %hex::encode(state.peer_pid),
                    in_hold_for_secs = (hold_time - state.last_switch.elapsed()).as_secs(),
                    "unhealthy but in hold window — skipping failover"
                );
                continue;
            }

            probes_this_tick += 1;
            warn!(
                peer = %hex::encode(state.peer_pid),
                current = %state.endpoints[state.current_idx],
                stale_for_ms = Instant::now().duration_since(m.last_seen).as_millis() as u64,
                srtt_us = m.srtt.map(|d| d.as_micros() as u64).unwrap_or(0),
                "peer unhealthy — looking for next endpoint"
            );

            let n = state.endpoints.len();
            let mut switched = false;
            for offset in 1..n {
                let next_idx = (state.current_idx + offset) % n;
                let next_url = state.endpoints[next_idx].clone();
                let (next_io, next_addr) = match drift::io::make_connector(&next_url).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(endpoint = %next_url, error = %e, "couldn't open connector");
                        continue;
                    }
                };
                let next_iface = transport
                    .add_interface(format!("failover-{}", state.current_idx + offset), next_io);
                if let Err(e) = transport
                    .probe_candidate_path_via(&state.peer_pid, next_addr, next_iface)
                    .await
                {
                    warn!(endpoint = %next_url, error = ?e, "probe_candidate_path_via failed");
                    continue;
                }
                // Wait for the addr swap.
                let deadline = Instant::now() + PROBE_COMMIT_TIMEOUT;
                let mut committed = false;
                while Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if transport.peer_addr(&state.peer_pid).await == Some(next_addr) {
                        committed = true;
                        break;
                    }
                }
                if committed {
                    info!(
                        peer = %hex::encode(state.peer_pid),
                        from = %state.endpoints[state.current_idx],
                        to = %next_url,
                        iface = next_iface,
                        "failover committed via path probe"
                    );
                    metrics.note_failover_to(&next_url);
                    state.current_idx = next_idx;
                    state.last_switch = Instant::now();
                    state.baseline_rtt = None;
                    state.high_rtt_strikes = 0;
                    switched = true;
                    break;
                }
                warn!(endpoint = %next_url, "no path probe response — trying next");
            }

            if !switched {
                warn!(
                    peer = %hex::encode(state.peer_pid),
                    "no endpoint responded — restarting handshake at primary"
                );
                metrics.failover_restarts.fetch_add(1, Relaxed);
                let primary = state.endpoints[0].clone();
                if let Ok(addr) = resolve_endpoint(&primary).await {
                    transport.update_peer_addr(&state.peer_pid, addr).await;
                }
                let _ = transport.restart_handshake(&state.peer_pid).await;
                let _ = transport.send_data(&state.peer_pid, b"\x00", 0, 0).await;
                state.current_idx = 0;
                state.last_switch = Instant::now();
                state.baseline_rtt = None;
                state.high_rtt_strikes = 0;
            }
        }
    }
}

