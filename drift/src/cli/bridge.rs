//! `drift bridge` — run this device as a multi-transport DRIFT
//! bridge. Lighter than `drift-vpn`: no TUN device, no IP-level
//! routing — just a Transport that binds on multiple wires and
//! lets DRIFT's mesh layer forward packets between peers.
//!
//! Two ways to drive it:
//!
//!   drift bridge --listen udp://0.0.0.0:51820 --listen tcp://0.0.0.0:443
//!
//! or, after running `drift-config keygen --name <hostname>
//! --endpoint udp://0.0.0.0:51820 --endpoint tcp://0.0.0.0:443`:
//!
//!   drift bridge        # picks up listen URLs from drift.toml
//!
//! Either way the bridge runs in the foreground; SIGINT to stop.
//! Bridges accept any peer (`accept_any_peer = true`) — they're
//! designed to relay between strangers, like a public meeting
//! point.

use super::identity::load_identity;
use super::{expand_path, BridgeArgs};
use anyhow::{anyhow, bail, Context, Result};
use drift::identity::Identity;
use drift::{Direction, Transport, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn run(args: &BridgeArgs, identity_path: &str) -> Result<()> {
    // Resolve listen URLs: explicit --listen flags win; otherwise
    // pull from drift.toml.
    let listen_urls = if !args.listen.is_empty() {
        args.listen.clone()
    } else {
        listen_urls_from_inventory(args)?
    };
    if listen_urls.is_empty() {
        bail!(
            "no listen URLs — pass --listen <url> (repeatable), or run \
             `drift-config keygen --name <this-host> --endpoint <url>` \
             to register endpoints in drift.toml first"
        );
    }

    // HTTP.OPT2: enable proxy-header trust on the http://
    // adapter before binding. Operators behind nginx / caddy /
    // any reverse proxy set this so the per-IP cap doesn't fire
    // on the proxy's loopback IP — the proxy is expected to do
    // its own per-source rate limiting. See docs/reverse-proxy.md.
    if args.trust_proxy_headers {
        drift::wire_http::set_trust_proxy_headers(true);
    }

    let secret = load_identity(&expand_path(identity_path))?;
    let id = Identity::from_secret_bytes(secret);
    let pubkey_hex = hex::encode(id.public_bytes());

    let config = TransportConfig {
        // Bridges are meeting points — anyone with the pubkey
        // can connect, like a public website. Peer authorization
        // happens via the application layer above.
        accept_any_peer: true,
        // SEC.FIX.1: open-relay guard. Drop forward requests whose
        // source IP isn't one of our established peers. Default-off
        // in TransportConfig so in-process mesh-chain tests keep
        // working; default-on here because bridges are internet-
        // facing and must not reflect unauthenticated traffic.
        // CLI escape hatch: `--allow-open-relay` (legacy behaviour;
        // intended only for trusted-mesh test scenarios).
        require_src_for_forward: !args.allow_open_relay,
        // Faster beacon interval (500 ms instead of the 2 s
        // default). Bridges are the route advertisers in the
        // mesh; quicker beacons mean cross-bridge mesh routes
        // converge within a few seconds. Same value the
        // two_bridge_demo uses.
        beacon_interval_ms: 500,
        // Phase PQ + G knobs, exposed as bridge CLI flags so
        // operators can toggle without rebuilding. Hybrid PQ
        // is default-on per `TransportConfig::default()`; CLI
        // exposes `--no-hybrid-pq` as the escape hatch.
        hybrid_pq: !args.no_hybrid_pq,
        bridge_fault_skip_threshold: args.bridge_fault_skip_threshold,
        // Phase PQ-T.11: bridges absorb thundering-herd
        // reconnects (and large hybrid PQ HELLOs) — bump the
        // UDP recv buffer from the ~200 KB OS default to
        // `args.udp_recv_buffer_bytes` (default 4 MiB; CLI
        // override available). Kernel may clamp; the granted
        // size is logged at info level.
        udp_recv_buffer_bytes: Some(args.udp_recv_buffer_bytes),
        // First-HELLO jitter to disperse synchronized
        // reconnect storms (e.g. clients reconnecting after a
        // bridge restart). Default matches WireGuard's
        // RekeyTimeoutJitterMaxMs = 334.
        handshake_jitter_ms: args.handshake_jitter_ms,
        ..TransportConfig::default()
    };

    // First listen URL becomes the primary; the rest are attached
    // via add_listener.
    let mut iter = listen_urls.iter();
    let primary = iter.next().expect("non-empty checked above");
    let (transport, primary_url) = Transport::bind_url(primary, id, config).await?;
    let transport = Arc::new(transport);

    eprintln!();
    eprintln!("┌─ drift bridge ─────────────────────────────────────────");
    eprintln!("│ pubkey: {}", pubkey_hex);
    eprintln!("│ listen:");
    eprintln!("│   {}", primary_url);
    for extra in iter {
        let bound = transport.add_listener(extra).await?;
        eprintln!("│   {}", bound);
    }
    eprintln!("│ accept_any_peer: true (any peer with the pubkey can connect)");

    // Register outbound peers (the bridge-to-bridge link case).
    // For each `--peer <url>@<pubhex>`, parse the addr, add
    // the peer as Initiator, and then fire a one-byte "trigger"
    // DATA at it to kick off the HELLO handshake. add_peer alone
    // does NOT initiate — DRIFT only drives a handshake when
    // there's data to send. Without this trigger, the bridge-to-
    // bridge session never establishes, beacons never flow, and
    // clients on the other bridge are unroutable.
    let mut outbound_handles: Vec<drift_core::PeerId> = Vec::new();
    if !args.peers.is_empty() {
        eprintln!("│ outbound peers:");
        for spec in &args.peers {
            let (addr, pubkey) = parse_peer_spec(spec)?;
            let handle = transport
                .add_peer(pubkey, addr, Direction::Initiator)
                .await
                .with_context(|| format!("add_peer for {}", spec))?;
            outbound_handles.push(handle);
            eprintln!("│   {} ({})", spec, &hex::encode(pubkey)[..16]);
        }
    }

    // Federation peers: open a real outbound connection on the
    // URL's scheme and pin the peer to that interface. Reusing the
    // bridge's primary listener socket — like the --peer path does —
    // only works for UDP (one shared socket for in and out). For
    // TCP/TLS/WS, a listener can't initiate outbound, so we need an
    // honest connect on the federate's own scheme. `connect_federate`
    // does the connect + add_interface + add_peer + interface_id pin
    // + federation_table insert in one shot.
    //
    // Symmetric `--federate` is required for bidirectional federation
    // (the security model — see Transport::handle_federated). For
    // TCP/TLS/WS pairs this creates a startup race: both bridges try
    // to connect to each other before either is listening. We tolerate
    // initial connect failure by spawning a background retry task,
    // so eventually-up-on-both-sides connects without operator
    // intervention.
    if !args.federates.is_empty() {
        eprintln!("│ federation peers:");
        for spec in &args.federates {
            let (url, pubkey) = parse_federate_spec(spec)?;
            // HTTP.FED.STRICT — federation links MUST use the
            // modern HTTP/2-family backbone (h2 / h2s /
            // webtransport). These are multiplexed,
            // middlebox-friendly, reverse-proxy-ready, AND —
            // discovered the hard way in the
            // docker/federation-pentagon K5 test — their
            // bidirectional TLS-style handshakes avoid the
            // asymmetric UDP mutual-init races that hit at
            // higher federation densities.
            //
            // Client connections via `--listen` still accept
            // any wire scheme; only outbound `--federate` URLs
            // are gated. Operators who genuinely need UDP/TCP
            // federation (single-host integration tests, niche
            // hardware) opt in with `--allow-legacy-federation`.
            //
            // Previous versions had an RFC1918 carve-out that
            // exempted LAN targets from the strict check. That
            // carve-out was removed: the K5 pentagon test
            // proved that the same UDP mutual-init race occurs
            // on LAN federation as on WAN, and the latency
            // savings of UDP-over-LAN are negligible compared
            // to the reliability cost. Federation behavior is
            // now identical regardless of whether the target
            // is a homelab IP or a public WAN one.
            let scheme = url
                .split_once("://")
                .map(|(s, _)| s)
                .unwrap_or(&url);
            let preferred = matches!(scheme, "h2" | "h2s" | "webtransport");
            if !preferred && !args.allow_legacy_federation {
                bail!(
                    "refusing to federate over `{}://` — drift bridge \
                     restricts federation to h2:// / h2s:// / \
                     webtransport:// regardless of target network \
                     (LAN, WAN, or loopback). Use one of those schemes \
                     on the remote bridge, OR pass \
                     `--allow-legacy-federation` to opt into the \
                     pre-v0.18 legacy path (UDP/TCP federation; not \
                     recommended — see docker/federation-pentagon for \
                     the scaling failure mode that motivated the change).",
                    scheme
                );
            }
            match transport.connect_federate(&url, pubkey).await {
                Ok(handle) => {
                    outbound_handles.push(handle);
                    eprintln!(
                        "│   {} ({})",
                        spec,
                        &hex::encode(pubkey)[..16]
                    );
                }
                Err(e) => {
                    eprintln!(
                        "│   {} ({}) — initial connect failed ({}); \
                         will retry in background",
                        spec,
                        &hex::encode(pubkey)[..16],
                        e
                    );
                    let t = transport.clone();
                    let url_owned = url.clone();
                    tokio::spawn(async move {
                        let mut backoff =
                            std::time::Duration::from_millis(500);
                        let max = std::time::Duration::from_secs(10);
                        loop {
                            tokio::time::sleep(backoff).await;
                            match t.connect_federate(&url_owned, pubkey).await {
                                Ok(handle) => {
                                    tracing::info!(
                                        target = %url_owned,
                                        "federation peer connected after retry"
                                    );
                                    // Now run the keep-alive ping
                                    // loop for this peer inline,
                                    // since the outer for-loop has
                                    // already moved past it.
                                    let mut ticker = tokio::time::interval(
                                        std::time::Duration::from_secs(2),
                                    );
                                    loop {
                                        ticker.tick().await;
                                        let _ = t
                                            .send_data(&handle, b".", 0, 0)
                                            .await;
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        target = %url_owned,
                                        error = %e,
                                        "federation peer still unreachable; \
                                         will retry"
                                    );
                                    backoff = (backoff * 2).min(max);
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    eprintln!("└───────────────────────────────────────────────────────");
    eprintln!();
    eprintln!("ready. share the pubkey above with anyone you want to bridge.");
    eprintln!("ctrl-c to stop.");

    // Periodic ping to each outbound peer. Three jobs in one:
    //   1) Triggers the initial HELLO (add_peer alone never does).
    //   2) Keeps the bridge-bridge link warm so beacons keep
    //      propagating route updates across it.
    //   3) Re-establishes the link if either bridge restarts.
    // The receiving bridge silently drains these pings.
    for handle in outbound_handles {
        let t = transport.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                ticker.tick().await;
                let _ = t.send_data(&handle, b".", 0, 0).await;
            }
        });
    }

    // Federation directory announcer: every 7 s, broadcast the
    // pubkeys of every client currently connected to us to all
    // of our federation peers. Receiving bridges record those
    // pubkeys in their peer directory with a 20 s TTL; clients
    // dialing a target whose bridge they don't know can then
    // send Federated envelopes with `target_bridge_pub = ZERO`
    // and let any transit bridge in the chain resolve via its
    // directory. See drift::UNKNOWN_BRIDGE_PUB and
    // Transport::announce_directory.
    //
    // The receiver treats each announce as the COMPLETE current
    // set of this bridge's clients, not a delta — so a client
    // disconnecting from us silently drops out of peers'
    // directories within one announce interval (≤7 s). Combined
    // with first-write-wins on cross-announcer conflicts and
    // send-failure eviction in handle_federated case (3), this
    // gets the directory back to consistent state fast under
    // both graceful and ungraceful peer changes.
    {
        let t = transport.clone();
        tokio::spawn(async move {
            // Stagger the first announce by 1 s so the bridge
            // gets a moment to settle in (initial connect_federate
            // calls, peer-table warmup) before we publish state.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(7));
            loop {
                let entries = t.established_client_entries().await;
                let n = entries.len();
                t.announce_directory(&entries).await;
                tracing::debug!(
                    n_clients = n,
                    "federation directory: announced"
                );
                ticker.tick().await;
            }
        });
    }

    // Pump received DATA. The bridge does no application
    // processing — it exists for cross-transport mesh forwarding,
    // which Transport handles internally regardless of whether
    // we drain `recv()`. We still drain so the recv channel
    // doesn't back up forever.
    loop {
        match transport.recv().await {
            Some(_) => {} // ignored — bridges don't terminate sessions
            None => {
                eprintln!("bridge: transport closed; exiting");
                break;
            }
        }
    }
    Ok(())
}

/// Look up this host's `[hosts.<name>]` entry in drift.toml and
/// return its `endpoints` as the listen URLs.
fn listen_urls_from_inventory(args: &BridgeArgs) -> Result<Vec<String>> {
    let path = match &args.config {
        Some(p) => p.clone(),
        None => drift_config::io::default_path()
            .context("resolve default drift.toml path")?,
    };
    if !path.exists() {
        bail!(
            "no listen URLs given, and {} does not exist — \
             pass --listen <url> or run `drift-config init` and \
             `drift-config keygen --name <this-host> --endpoint <url>` first",
            path.display()
        );
    }
    let doc = drift_config::io::read(&path)
        .with_context(|| format!("read {}", path.display()))?;

    let host_name = match &args.host_name {
        Some(n) => n.clone(),
        None => detect_hostname()?,
    };
    let host = doc.hosts.get(&host_name).ok_or_else(|| {
        anyhow!(
            "no [hosts.{}] entry in {} — \
             run `drift-config keygen --name {} --endpoint <url>` first, \
             or pass --host <name> to pick a different inventory entry",
            host_name,
            path.display(),
            host_name
        )
    })?;
    if host.endpoints.is_empty() {
        bail!(
            "[hosts.{}] in {} has no endpoints — \
             can't bridge a host with no listeners. Add some with \
             `drift-config peer add` or rerun keygen with --endpoint flags.",
            host_name,
            path.display()
        );
    }
    Ok(host.endpoints.clone())
}

/// Parse a `--peer <url>@<pubkey-hex>` spec into a (SocketAddr,
/// 32-byte pubkey) pair. The URL syntax is `<scheme>://<host>:<port>`;
/// the SocketAddr is just the `host:port` portion. (We don't
/// resolve through `make_connector` here because we want the
/// bridge's existing listener socket to be used for outbound
/// sends, not a fresh connector socket.)
fn parse_peer_spec(spec: &str) -> Result<(SocketAddr, [u8; 32])> {
    let (url, pub_hex) = spec.split_once('@').ok_or_else(|| {
        anyhow!(
            "--peer spec {:?} missing '@'; format is <url>@<pubkey-hex>",
            spec
        )
    })?;
    let pubkey_bytes = hex::decode(pub_hex)
        .with_context(|| format!("hex decode of pubkey in {:?}", spec))?;
    if pubkey_bytes.len() != 32 {
        bail!(
            "--peer {} pubkey must be 64 hex chars (32 bytes), got {}",
            spec,
            pubkey_bytes.len()
        );
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pubkey_bytes);

    // Strip the scheme prefix. We only need the host:port part
    // because the bridge already has a listener socket bound;
    // `add_peer(addr, Initiator)` records the addr and DRIFT
    // uses the existing interface to send to it.
    let host_port = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url);
    let addr: SocketAddr = host_port
        .parse()
        .with_context(|| format!("parse host:port from {:?}", url))?;
    Ok((addr, pubkey))
}

/// Parse a `--federate <url>@<pubkey-hex>` spec into a (URL,
/// 32-byte pubkey) pair. Unlike `parse_peer_spec`, this *preserves*
/// the URL scheme — `connect_federate` uses it to decide how to
/// open the outbound connection (UDP socket, TCP connect, TLS
/// connect, WS upgrade, …).
fn parse_federate_spec(spec: &str) -> Result<(String, [u8; 32])> {
    let (url, pub_hex) = spec.split_once('@').ok_or_else(|| {
        anyhow!(
            "--federate spec {:?} missing '@'; format is <url>@<pubkey-hex>",
            spec
        )
    })?;
    let pubkey_bytes = hex::decode(pub_hex)
        .with_context(|| format!("hex decode of pubkey in {:?}", spec))?;
    if pubkey_bytes.len() != 32 {
        bail!(
            "--federate {} pubkey must be 64 hex chars (32 bytes), got {}",
            spec,
            pubkey_bytes.len()
        );
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pubkey_bytes);
    Ok((url.to_string(), pubkey))
}

/// Best-effort hostname detection. `$HOSTNAME` is set on most
/// shells; otherwise read /etc/hostname (Linux/macOS).
fn detect_hostname() -> Result<String> {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return Ok(h);
        }
    }
    let s = std::fs::read_to_string("/etc/hostname")
        .context("read /etc/hostname (or pass --host <name>)")?;
    let name = s.trim();
    if name.is_empty() {
        return Err(anyhow!(
            "couldn't detect hostname; pass --host <name> to pick a drift.toml entry"
        ));
    }
    Ok(name.to_string())
}

// We use load_identity from the existing identity module, which
// already handles "raw 32-byte" vs "64 hex chars" formats. This
// keeps `drift bridge` interoperable with the same identity
// files drift-vpn / drift-config already write.
//
// (If load_identity isn't pub, the existing super:: import
// path works — see other commands for the pattern.)
fn _link_identity_module() {}

// Note: pre-v0.18 versions of HTTP.FED.STRICT had an RFC1918
// carve-out that exempted private/loopback/link-local/ULA/CGNAT
// federation targets from the h2/h2s/webtransport requirement.
// That carve-out was removed once docker/federation-pentagon
// demonstrated the same UDP mutual-init race occurs on LAN as
// on WAN — so the strict-scheme rule now applies uniformly and
// the address-classification helpers it depended on were dropped.
// If LAN-classification is needed elsewhere in the future, the
// helpers live in the git history at the commit that removed them.
