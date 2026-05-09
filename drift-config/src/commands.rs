//! Command implementations. Each is a thin function that takes
//! the parsed args + resolved file paths and does the I/O.

use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use std::path::{Path, PathBuf};

use crate::cli::*;
use drift_config::io as cfg_io;
use drift_config::schema::*;

// ─── init ─────────────────────────────────────────────────────────

pub fn init(args: &InitArgs, config_path: &Path) -> Result<()> {
    if config_path.exists() && !args.force {
        bail!(
            "{} already exists; pass --force to overwrite",
            config_path.display()
        );
    }
    let doc = DriftToml {
        network: Network {
            name: args.name.clone(),
        },
        ..Default::default()
    };
    cfg_io::write(config_path, &doc)?;
    println!("created {} (network={:?})", config_path.display(), args.name);
    println!();
    println!("next steps:");
    println!("  drift-config keygen --name <this-host> [--endpoint udp://0.0.0.0:51820]");
    println!("  drift-config peer add <other-host> --pubkey <hex> --endpoint udp://...");
    Ok(())
}

// ─── keygen ───────────────────────────────────────────────────────

pub fn keygen(
    args: &KeygenArgs,
    config_path: &Path,
    identity_path: &Path,
) -> Result<()> {
    if identity_path.exists() && !args.force {
        bail!(
            "identity already exists at {}; pass --force to regenerate (this will rotate your pubkey)",
            identity_path.display()
        );
    }
    // Same generation flow as `drift-vpn keygen`: pull 32 bytes
    // from OsRng, feed to Identity::from_secret_bytes, save the
    // raw secret as 64 hex chars on disk. That on-disk format is
    // exactly what drift-vpn / drift-mosh / drift-http all read,
    // so a single identity file works for every tool.
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let identity = drift_core::Identity::from_secret_bytes(secret);
    cfg_io::write_identity(identity_path, &secret)?;
    let pubkey = identity.public_bytes();
    let pubkey_hex = hex::encode(pubkey);

    let name = match &args.name {
        Some(n) => n.clone(),
        None => hostname_or_unknown(),
    };

    let mut doc = cfg_io::read_or_default(config_path)?;
    let host = Host {
        pubkey: pubkey_hex.clone(),
        endpoints: args.endpoints.clone(),
    };
    doc.hosts.insert(name.clone(), host);
    cfg_io::write(config_path, &doc)?;

    println!("identity:  {}", identity_path.display());
    println!("pubkey:    {}", pubkey_hex);
    println!("registered host {:?} in {}", name, config_path.display());
    if !args.endpoints.is_empty() {
        println!("endpoints:");
        for ep in &args.endpoints {
            println!("  {}", ep);
        }
    } else {
        println!("(no endpoints — this host is a roaming client)");
    }
    Ok(())
}

// ─── peer add / ls / rm ──────────────────────────────────────────

pub fn peer_add(args: &PeerAddArgs, config_path: &Path) -> Result<()> {
    validate_pubkey(&args.pubkey)?;
    for ep in &args.endpoints {
        validate_endpoint(ep)?;
    }
    let mut doc = cfg_io::read_or_default(config_path)?;
    if doc.hosts.contains_key(&args.name) {
        bail!(
            "host {:?} already exists; remove it first with `drift-config peer rm`",
            args.name
        );
    }
    doc.hosts.insert(
        args.name.clone(),
        Host {
            pubkey: args.pubkey.to_lowercase(),
            endpoints: args.endpoints.clone(),
        },
    );
    cfg_io::write(config_path, &doc)?;
    println!("added peer {:?}", args.name);
    Ok(())
}

pub fn peer_ls(config_path: &Path) -> Result<()> {
    let doc = cfg_io::read_or_default(config_path)?;
    if doc.hosts.is_empty() {
        println!("(no hosts registered yet)");
        return Ok(());
    }
    println!("network: {}", doc.network.name);
    println!();
    for (name, h) in &doc.hosts {
        let pub_short = if h.pubkey.len() >= 16 {
            &h.pubkey[..16]
        } else {
            h.pubkey.as_str()
        };
        let role_hint = if h.endpoints.is_empty() {
            "client"
        } else {
            "listener"
        };
        println!("  {} ({})", name, role_hint);
        println!("    pubkey:  {}…", pub_short);
        for ep in &h.endpoints {
            println!("    via:     {}", ep);
        }
    }
    Ok(())
}

pub fn peer_rm(args: &PeerRmArgs, config_path: &Path) -> Result<()> {
    let mut doc = cfg_io::read_or_default(config_path)?;
    if doc.hosts.remove(&args.name).is_none() {
        bail!("no host named {:?} in {}", args.name, config_path.display());
    }
    // Also remove any [vpn.<name>] block that referenced it so
    // the file stays consistent.
    if let Some(vpn) = doc.vpn.as_mut() {
        vpn.hosts.remove(&args.name);
    }
    cfg_io::write(config_path, &doc)?;
    println!("removed host {:?}", args.name);
    Ok(())
}

// ─── show ─────────────────────────────────────────────────────────

pub fn show(config_path: &Path) -> Result<()> {
    let doc = cfg_io::read(config_path)?;
    println!("# {}", config_path.display());
    println!("network: {}", doc.network.name);
    println!("hosts:   {}", doc.hosts.len());
    if let Some(vpn) = &doc.vpn {
        println!("vpn:     {} ({} assigned)", vpn.cidr, vpn.hosts.len());
    } else {
        println!("vpn:     (no overlay configured)");
    }
    println!();
    peer_ls(config_path)?;
    if let Some(vpn) = &doc.vpn {
        println!();
        println!("vpn overlay:");
        println!("  cidr: {}", vpn.cidr);
        println!("  mtu:  {}", vpn.mtu);
        for (name, vh) in &vpn.hosts {
            println!("  {} → {} ({})", name, vh.tun_addr, vh.role);
        }
    }
    Ok(())
}

// ─── validate ─────────────────────────────────────────────────────

pub fn validate(config_path: &Path) -> Result<()> {
    let doc = cfg_io::read(config_path)?;
    let mut problems: Vec<String> = Vec::new();

    let mut seen_pubkeys: std::collections::HashMap<String, String> = Default::default();
    for (name, host) in &doc.hosts {
        if let Err(e) = validate_pubkey(&host.pubkey) {
            problems.push(format!("host {:?}: {}", name, e));
        }
        if let Some(prev) = seen_pubkeys.insert(host.pubkey.clone(), name.clone()) {
            problems.push(format!(
                "duplicate pubkey: hosts {:?} and {:?} share the same identity",
                prev, name
            ));
        }
        for ep in &host.endpoints {
            if let Err(e) = validate_endpoint(ep) {
                problems.push(format!("host {:?} endpoint {:?}: {}", name, ep, e));
            }
        }
    }

    if let Some(vpn) = &doc.vpn {
        // Every vpn.X entry must reference an existing [hosts.X].
        for name in vpn.hosts.keys() {
            if !doc.hosts.contains_key(name) {
                problems.push(format!(
                    "vpn assigns tun_addr to {:?}, but no [hosts.{}] entry exists",
                    name, name
                ));
            }
        }
        // CIDR shape sanity (very loose — full CIDR parsing is
        // drift-vpn's problem).
        if !vpn.cidr.contains('/') {
            problems.push(format!("vpn.cidr {:?} missing /N suffix", vpn.cidr));
        }
        // Tun address uniqueness.
        let mut seen_tun: std::collections::HashSet<&str> = Default::default();
        for (name, vh) in &vpn.hosts {
            if !seen_tun.insert(vh.tun_addr.as_str()) {
                problems.push(format!(
                    "vpn host {:?}: duplicate tun_addr {}",
                    name, vh.tun_addr
                ));
            }
            if !["hub", "spoke", "client"].contains(&vh.role.as_str()) {
                problems.push(format!(
                    "vpn host {:?}: role must be hub|spoke|client (got {:?})",
                    name, vh.role
                ));
            }
        }
    }

    if problems.is_empty() {
        println!("ok: {} (network={}, {} hosts)",
            config_path.display(), doc.network.name, doc.hosts.len());
        Ok(())
    } else {
        for p in &problems {
            println!("- {}", p);
        }
        Err(anyhow!("{} validation problem(s)", problems.len()))
    }
}

// ─── helpers ──────────────────────────────────────────────────────

fn validate_pubkey(s: &str) -> Result<()> {
    if s.len() != 64 {
        bail!("pubkey must be 64 hex chars, got {}", s.len());
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("pubkey must be hex (0-9 a-f A-F)");
    }
    Ok(())
}

fn validate_endpoint(s: &str) -> Result<()> {
    // Loose check: scheme://addr. Schemes drift recognizes today.
    let known = [
        "udp://", "tcp://", "ws://", "tls://", "dns://", "doh://", "http://", "onion://",
    ];
    if !known.iter().any(|k| s.starts_with(k)) {
        bail!(
            "endpoint must start with one of {:?}",
            known.iter().map(|k| &k[..k.len() - 3]).collect::<Vec<_>>()
        );
    }
    Ok(())
}

fn hostname_or_unknown() -> String {
    // No std hostname API; gethostname-the-crate would do this
    // but we don't want another dep just for a default. Use the
    // env's HOSTNAME or fall back. (Linux LXCs commonly set it.)
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    // /etc/hostname on Linux/macOS:
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let name = s.trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    "unknown-host".to_string()
}

/// Resolve `--config` (or the default) into a real path.
pub fn resolve_config_path(opt: &Option<PathBuf>) -> Result<PathBuf> {
    match opt {
        Some(p) => Ok(p.clone()),
        None => cfg_io::default_path(),
    }
}

/// Resolve `--identity` (or default).
pub fn resolve_identity_path(
    opt: &Option<PathBuf>,
    config_path: &Path,
) -> Result<PathBuf> {
    if let Some(p) = opt {
        return Ok(p.clone());
    }
    // Default: alongside drift.toml, named identity.key.
    Ok(config_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join(cfg_io::IDENTITY_FILENAME))
}
