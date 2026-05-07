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

    // Disable TSO/GSO/etc. on the tun. Linux generic-
    // segmentation-offload can hand us 64KB pseudo-segments
    // that exceed DRIFT's MAX_PAYLOAD (1348 bytes) and get
    // dropped. Disabling forces the kernel to emit real
    // MTU-sized segments. Best-effort — if `ethtool` isn't
    // available we log a warning but continue (the user may
    // notice degraded TCP throughput).
    let tun_name = cfg.interface.name.as_deref().unwrap_or("tun0");
    disable_offloads_and_verify(tun_name).await;

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
        let chosen = try_endpoints(&transport, peer_pub, &peer_pid, &endpoints, dir).await?;
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

        // v0.4: spawn a per-peer supervisor that watches link
        // health and fails over to the next endpoint when the
        // current one degrades. Single-endpoint peers and the
        // globally-disabled case skip this.
        if cfg.failover.enabled && endpoints.len() > 1 {
            let initial_idx = endpoints.iter().position(|e| e == &chosen).unwrap_or(0);
            let sup_transport = transport.clone();
            let sup_peer_pub = peer_pub;
            let sup_peer_pid = peer_pid;
            let sup_endpoints = endpoints.clone();
            let sup_cfg = cfg.failover.clone();
            tokio::spawn(async move {
                supervise_peer(
                    sup_transport,
                    sup_peer_pub,
                    sup_peer_pid,
                    sup_endpoints,
                    initial_idx,
                    sup_cfg,
                )
                .await;
            });
        }
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
                // WARN, not DEBUG — silently dropping outbound
                // packets degrades the VPN; users want to know.
                // The most common cause for repeated drops in
                // steady state is `payload > MAX_PAYLOAD` from
                // Linux GSO/TSO (kernel hands us 64KB pseudo-
                // segments). The startup `disable_offloads_and_verify`
                // catches most cases; a stuck driver is the
                // remaining one.
                let hint = if pkt.len() > drift::transport::MAX_PAYLOAD {
                    " (oversized — check `ethtool -k <iface>`, offloads may be stuck on)"
                } else {
                    ""
                };
                warn!(
                    error = %e,
                    pkt_len = pkt.len(),
                    peer = %hex::encode(route.peer_id),
                    "send_data dropped packet{}",
                    hint
                );
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
/// Disable NIC offloads on the tun and verify they actually
/// stuck. Some kernels/drivers report success on `-K` requests
/// while leaving the offload enabled (especially under
/// virtualization). Reading back with `-k` and checking each
/// flag catches those silent failures.
///
/// Best-effort: if `ethtool` isn't available, log and continue.
/// Verification mismatches log at WARN with a hint pointing
/// at `ethtool -k` so operators can investigate.
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

/// Per-peer health supervisor (v0.4 runtime auto-failover).
///
/// Wakes every `check_interval`, asks the transport for the
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
async fn supervise_peer(
    transport: Arc<Transport>,
    peer_pub: [u8; 32],
    peer_pid: PeerId,
    endpoints: Vec<String>,
    initial_idx: usize,
    cfg: crate::config::Failover,
) {
    use std::time::{Duration, Instant};
    let _ = peer_pub; // currently unused; kept for future "re-add on disappear"

    let check_interval = Duration::from_millis(cfg.check_interval_ms);
    let stale_threshold = Duration::from_secs(cfg.stale_secs);
    let hold_time = Duration::from_secs(cfg.hold_secs);
    // Probe-then-commit timeout. Slightly longer than DRIFT's
    // internal PATH_PROBE_TIMEOUT (3s) to give the response
    // time to arrive.
    const PROBE_COMMIT_TIMEOUT: Duration = Duration::from_millis(3500);

    let mut current_idx = initial_idx;
    let mut last_switch = Instant::now();
    // Track baseline RTT for the rtt-degradation signal — the
    // SRTT we saw the first time we measured at this endpoint.
    let mut baseline_rtt: Option<Duration> = None;
    let mut high_rtt_strikes: u32 = 0;
    const RTT_STRIKES_TO_FAILOVER: u32 = 3;

    info!(
        peer = %hex::encode(peer_pid),
        endpoint = %endpoints[current_idx],
        check_interval_ms = cfg.check_interval_ms,
        stale_secs = cfg.stale_secs,
        hold_secs = cfg.hold_secs,
        rtt_multiplier = cfg.rtt_multiplier,
        "failover supervisor started"
    );

    loop {
        tokio::time::sleep(check_interval).await;

        let m = match transport.peer_metrics(&peer_pid).await {
            Some(m) => m,
            None => {
                // Peer evicted from the table — best effort
                // restart at the current endpoint.
                warn!(
                    peer = %hex::encode(peer_pid),
                    "peer disappeared from transport — attempting restart"
                );
                let _ = transport.restart_handshake(&peer_pid).await;
                continue;
            }
        };

        let stale = Instant::now().duration_since(m.last_seen) > stale_threshold;

        // RTT degradation: capture baseline on first sample,
        // count strikes against it.
        let rtt_bad = if cfg.rtt_multiplier > 0.0 {
            match (m.srtt, baseline_rtt) {
                (Some(srtt), None) => {
                    baseline_rtt = Some(srtt);
                    false
                }
                (Some(srtt), Some(base)) => {
                    let limit = base.mul_f32(cfg.rtt_multiplier);
                    if srtt > limit {
                        high_rtt_strikes += 1;
                    } else {
                        high_rtt_strikes = 0;
                    }
                    high_rtt_strikes >= RTT_STRIKES_TO_FAILOVER
                }
                _ => false,
            }
        } else {
            false
        };

        let unhealthy = stale || rtt_bad;
        if !unhealthy {
            continue;
        }

        // Hold window: don't switch again right after we just
        // switched. Avoids ping-pong on flaky links.
        if last_switch.elapsed() < hold_time {
            debug!(
                peer = %hex::encode(peer_pid),
                in_hold_for_secs = (hold_time - last_switch.elapsed()).as_secs(),
                "unhealthy but in hold window — skipping failover"
            );
            continue;
        }

        warn!(
            peer = %hex::encode(peer_pid),
            current = %endpoints[current_idx],
            stale_for_ms = Instant::now().duration_since(m.last_seen).as_millis() as u64,
            srtt_us = m.srtt.map(|d| d.as_micros() as u64).unwrap_or(0),
            "peer unhealthy — looking for next endpoint"
        );

        // Try every other endpoint exactly once (round-robin
        // starting after current). On success the loop breaks;
        // on full cycle without success, fall back to a hard
        // restart at the original primary.
        let n = endpoints.len();
        let mut switched = false;
        for offset in 1..n {
            let next_idx = (current_idx + offset) % n;
            let next_url = &endpoints[next_idx];
            let next_addr = match resolve_endpoint(next_url).await {
                Ok(a) => a,
                Err(e) => {
                    warn!(endpoint = %next_url, error = %e, "endpoint resolve failed during failover");
                    continue;
                }
            };
            if let Err(e) = transport.probe_candidate_path(&peer_pid, next_addr).await {
                warn!(endpoint = %next_url, error = ?e, "probe_candidate_path failed");
                continue;
            }
            // Wait for the addr swap (transport commits on
            // matching PathResponse).
            let deadline = Instant::now() + PROBE_COMMIT_TIMEOUT;
            let mut committed = false;
            while Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if transport.peer_addr(&peer_pid).await == Some(next_addr) {
                    committed = true;
                    break;
                }
            }
            if committed {
                info!(
                    peer = %hex::encode(peer_pid),
                    from = %endpoints[current_idx],
                    to = %next_url,
                    "failover committed via path probe"
                );
                current_idx = next_idx;
                last_switch = Instant::now();
                baseline_rtt = None;
                high_rtt_strikes = 0;
                switched = true;
                break;
            }
            warn!(endpoint = %next_url, "no path probe response — trying next");
        }

        if !switched {
            // No endpoint responded to probes. Last resort:
            // wipe the session and fresh-handshake at endpoint
            // 0. If THAT fails too, the next iteration of this
            // loop will try again.
            warn!(
                peer = %hex::encode(peer_pid),
                "no endpoint responded — restarting handshake at primary"
            );
            let primary = &endpoints[0];
            if let Ok(addr) = resolve_endpoint(primary).await {
                transport.update_peer_addr(&peer_pid, addr).await;
            }
            let _ = transport.restart_handshake(&peer_pid).await;
            // Nudge the handshake along with a 1-byte send.
            let _ = transport.send_data(&peer_pid, b"\x00", 0, 0).await;
            current_idx = 0;
            last_switch = Instant::now();
            baseline_rtt = None;
            high_rtt_strikes = 0;
        }
    }
}

#[allow(dead_code)]
fn _ensure_peer_id_used(p: PeerId) -> PeerId {
    p
}
