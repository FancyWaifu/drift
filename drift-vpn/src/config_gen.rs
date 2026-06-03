//! `drift-vpn config` subcommand: read the shared drift.toml
//! inventory + VPN overlay, generate per-host drift-vpn daemon
//! `config.toml` files.
//!
//! Three subcommands:
//!
//! - `init` — add a `[vpn]` block to drift.toml with a CIDR.
//! - `assign` — set per-host `[vpn.X] tun_addr=... role=...`.
//! - `gen`  — emit `out/<host>/config.toml` for every host that
//!   has an entry in both `[hosts.X]` and `[vpn.X]`.
//!
//! No SSH side; that's `drift-vpn config push` for v0.2.
//!
//! ## Generated config shape
//!
//! Each output file matches what `drift-vpn up -c <file>` reads:
//!
//! ```toml
//! [interface]
//! identity_file = "/etc/drift/identity.key"
//! address       = "10.99.0.1/24"
//! listen        = ["udp://0.0.0.0:51820", "tcp://0.0.0.0:443"]
//! mtu           = 1340
//!
//! [[peer]]   # one block per other host in the inventory
//! public_key  = "<peer-pubkey-hex>"
//! allowed_ips = ["10.99.0.2/32"]
//! endpoints   = ["udp://...", "tcp://..."]
//! ```

use anyhow::{anyhow, bail, Context, Result};
use drift_config::io as cfg_io;
use drift_config::schema::{DriftToml, Host, VpnHost, VpnOverlay};
use std::path::{Path, PathBuf};

/// `drift-vpn config init --cidr 10.99.0.0/24`
pub(crate) fn init(config_path: &Path, cidr: &str, mtu: u32) -> Result<()> {
    if !cidr.contains('/') {
        bail!("--cidr must be a CIDR like 10.99.0.0/24");
    }
    let mut doc = cfg_io::read_or_default(config_path)?;
    if doc.vpn.is_some() {
        bail!(
            "{} already has a [vpn] block — edit drift.toml directly or remove it first",
            config_path.display()
        );
    }
    doc.vpn = Some(VpnOverlay {
        cidr: cidr.to_string(),
        mtu,
        hosts: Default::default(),
    });
    cfg_io::write(config_path, &doc)?;
    println!(
        "added [vpn] cidr={} mtu={} to {}",
        cidr,
        mtu,
        config_path.display()
    );
    println!();
    println!("next step: assign tun addresses to hosts");
    println!("  drift-vpn config assign <host> --tun 10.99.0.1 --role hub");
    Ok(())
}

/// `drift-vpn config assign <host> --tun 10.99.0.1 --role hub`
pub(crate) fn assign(config_path: &Path, host: &str, tun_addr: &str, role: &str) -> Result<()> {
    let mut doc = cfg_io::read_or_default(config_path)?;
    if !doc.hosts.contains_key(host) {
        bail!("no [hosts.{}] entry in drift.toml — add it first with `drift-config peer add` or `drift-config keygen --name {}`", host, host);
    }
    if !["hub", "spoke", "client"].contains(&role) {
        bail!("--role must be hub|spoke|client (got {:?})", role);
    }
    let vpn = doc.vpn.as_mut().ok_or_else(|| {
        anyhow!("no [vpn] block in drift.toml — run `drift-vpn config init --cidr ...` first")
    })?;
    vpn.hosts.insert(
        host.to_string(),
        VpnHost {
            tun_addr: tun_addr.to_string(),
            role: role.to_string(),
        },
    );
    cfg_io::write(config_path, &doc)?;
    println!("assigned: {} → {} (role={})", host, tun_addr, role);
    Ok(())
}

/// `drift-vpn config gen [--out ./out]`
///
/// For every host that has BOTH a `[hosts.X]` entry and a
/// `[vpn.X]` entry, write `out/<host>/config.toml` containing
/// the daemon-ready config.
pub(crate) fn gen(config_path: &Path, out_dir: &Path) -> Result<()> {
    let doc = cfg_io::read(config_path)?;
    let vpn = doc.vpn.as_ref().ok_or_else(|| {
        anyhow!("no [vpn] block in drift.toml — run `drift-vpn config init` first")
    })?;
    if vpn.hosts.is_empty() {
        bail!("[vpn] has no host assignments — run `drift-vpn config assign ...`");
    }

    std::fs::create_dir_all(out_dir).with_context(|| format!("mkdir -p {}", out_dir.display()))?;

    let cidr_suffix = cidr_prefix_suffix(&vpn.cidr)?;
    let mut written = 0;

    // For each host with a VPN assignment, emit its config.
    for (name, vh) in &vpn.hosts {
        let host = doc.hosts.get(name).ok_or_else(|| {
            anyhow!(
                "vpn assigns {:?} but [hosts.{}] is missing — run `drift-config validate`",
                name,
                name
            )
        })?;
        let cfg = render_host_config(name, host, vh, &doc, vpn, &cidr_suffix)?;
        let host_dir = out_dir.join(name);
        std::fs::create_dir_all(&host_dir)
            .with_context(|| format!("mkdir -p {}", host_dir.display()))?;
        let cfg_path = host_dir.join("config.toml");
        std::fs::write(&cfg_path, cfg).with_context(|| format!("write {}", cfg_path.display()))?;
        println!("  {} → {}", name, cfg_path.display());
        written += 1;
    }

    println!();
    println!(
        "wrote {} config{} to {}",
        written,
        if written == 1 { "" } else { "s" },
        out_dir.display()
    );
    println!();
    println!("deploy each one with:");
    println!(
        "  scp {0}/<host>/config.toml root@<host>:/etc/drift-vpn/config.toml",
        out_dir.display()
    );
    println!("  ssh root@<host> 'drift-vpn up -c /etc/drift-vpn/config.toml'");
    Ok(())
}

// ─── rendering ────────────────────────────────────────────────────

fn render_host_config(
    name: &str,
    host: &Host,
    vpn_host: &VpnHost,
    doc: &DriftToml,
    vpn: &VpnOverlay,
    cidr_suffix: &str,
) -> Result<String> {
    let mut out = String::new();

    // Header comment so the file is self-explanatory if someone
    // opens it after deploy.
    out.push_str(
        "# Generated by `drift-vpn config gen`. Source-of-truth is\n\
         # the drift.toml managed by drift-config — re-run `gen` to\n\
         # propagate any changes.\n\n",
    );

    out.push_str("[interface]\n");
    out.push_str("identity_file = \"/etc/drift/identity.key\"\n");
    out.push_str(&format!(
        "address       = \"{}/{}\"\n",
        vpn_host.tun_addr, cidr_suffix,
    ));
    if !host.endpoints.is_empty() {
        // This host listens — generate `listen = [...]` from its
        // endpoints, but rewrite `host:port` to `0.0.0.0:port` so
        // the daemon binds the wildcard interface (the actual IP
        // is the LAN/WAN IP, not what we'd want bound).
        let listen_urls: Vec<String> = host
            .endpoints
            .iter()
            .map(|ep| rewrite_endpoint_to_bind(ep))
            .collect();
        out.push_str("listen        = [\n");
        for u in &listen_urls {
            out.push_str(&format!("  \"{}\",\n", u));
        }
        out.push_str("]\n");
    } else {
        // Roaming client: bind UDP on a random port for outbound
        // traffic. drift-vpn requires `listen` even for clients.
        out.push_str("listen        = \"udp://0.0.0.0:0\"\n");
    }
    out.push_str(&format!("mtu           = {}\n", vpn.mtu));
    out.push_str(&format!("name          = \"drift-{}\"\n\n", name));

    // [[peer]] block for every OTHER host in the VPN.
    for (other_name, other_vh) in &vpn.hosts {
        if other_name == name {
            continue;
        }
        let Some(other_host) = doc.hosts.get(other_name) else {
            continue;
        };
        out.push_str(&format!(
            "[[peer]]    # {}{}\n",
            other_name,
            match other_vh.role.as_str() {
                "hub" => " (hub — direct path, mesh route advertiser)",
                "spoke" => "",
                "client" => " (roaming client)",
                _ => "",
            }
        ));
        out.push_str(&format!("public_key  = \"{}\"\n", other_host.pubkey));
        out.push_str(&format!("allowed_ips = [\"{}/32\"]\n", other_vh.tun_addr,));

        // endpoints: connection target, picked based on whether
        // we need direct reach OR mesh-only routing.
        let endpoint_block = endpoint_block_for_peer(name, other_name, other_host, other_vh, vpn)?;
        out.push_str(&endpoint_block);
        out.push('\n');
    }

    Ok(out)
}

/// Decide which `endpoints = [...]` to emit for one peer in this
/// host's config:
///
/// - If THIS host is a hub: every other peer gets its full
///   endpoint list (hub has direct paths to everyone).
/// - If THIS host is a spoke or client AND the OTHER host is a
///   hub: emit hub's endpoints.
/// - If THIS host is spoke/client AND the OTHER is also
///   spoke/client: NO endpoint — mesh-only peer, route via hub.
fn endpoint_block_for_peer(
    self_name: &str,
    other_name: &str,
    other_host: &Host,
    other_vh: &VpnHost,
    vpn: &VpnOverlay,
) -> Result<String> {
    let self_role = vpn
        .hosts
        .get(self_name)
        .map(|v| v.role.as_str())
        .unwrap_or("client");

    let direct = match (self_role, other_vh.role.as_str()) {
        ("hub", _) => true,
        (_, "hub") => true,
        // spoke ↔ spoke, client ↔ client, etc. — mesh-only.
        _ => false,
    };

    if !direct || other_host.endpoints.is_empty() {
        return Ok(format!(
            "# (mesh-only — daemon learns route to {} via the hub's beacons)\n",
            other_name
        ));
    }

    let mut s = String::from("endpoints   = [\n");
    for ep in &other_host.endpoints {
        s.push_str(&format!("  \"{}\",\n", ep));
    }
    s.push_str("]\n");
    Ok(s)
}

/// Convert "udp://1.2.3.4:51820" → "udp://0.0.0.0:51820" for the
/// `listen` side. The IP in the inventory is the address peers
/// REACH, which isn't necessarily what we'd want to bind to.
fn rewrite_endpoint_to_bind(ep: &str) -> String {
    let Some(scheme_end) = ep.find("://") else {
        return ep.to_string();
    };
    let (scheme, rest) = ep.split_at(scheme_end + 3);
    let port = rest.rsplit_once(':').map(|(_, p)| p).unwrap_or("0");
    format!("{}0.0.0.0:{}", scheme, port)
}

/// Pull the "/24" off "10.99.0.0/24".
fn cidr_prefix_suffix(cidr: &str) -> Result<String> {
    cidr.split_once('/')
        .map(|(_, suffix)| suffix.to_string())
        .ok_or_else(|| anyhow!("[vpn] cidr {:?} missing /N suffix", cidr))
}

// Identity-path helper for callers that want to know where each
// host's identity file lives.
#[allow(dead_code)]
pub(crate) fn default_identity_path() -> PathBuf {
    PathBuf::from("/etc/drift/identity.key")
}
