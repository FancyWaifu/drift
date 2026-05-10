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

    let secret = load_identity(&expand_path(identity_path))?;
    let id = Identity::from_secret_bytes(secret);
    let pubkey_hex = hex::encode(id.public_bytes());

    let config = TransportConfig {
        // Bridges are meeting points — anyone with the pubkey
        // can connect, like a public website. Peer authorization
        // happens via the application layer above.
        accept_any_peer: true,
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
    // For each `--peer <url>@<pubhex>`, parse the addr and add
    // the peer as Initiator on the bridge's existing transport.
    // DRIFT's mesh layer will exchange beacons so each side learns
    // routes to the other's clients.
    if !args.peers.is_empty() {
        eprintln!("│ outbound peers:");
        for spec in &args.peers {
            let (addr, pubkey) = parse_peer_spec(spec)?;
            transport
                .add_peer(pubkey, addr, Direction::Initiator)
                .await
                .with_context(|| format!("add_peer for {}", spec))?;
            eprintln!("│   {} ({})", spec, &hex::encode(pubkey)[..16]);
        }
    }

    eprintln!("└───────────────────────────────────────────────────────");
    eprintln!();
    eprintln!("ready. share the pubkey above with anyone you want to bridge.");
    eprintln!("ctrl-c to stop.");

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
