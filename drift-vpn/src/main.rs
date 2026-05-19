//! `drift-vpn` — identity-routed multi-transport VPN built on
//! DRIFT. See drift-vpn/README.md for design + config docs.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod config;
mod config_gen;
#[cfg(unix)]
mod doctor;
mod identity;
#[cfg(unix)]
mod install;
mod metrics;
mod rotate;
mod routing;
mod status;

// v0.12: tun/utun via the `tun` crate works on Linux + macOS;
// Windows Wintun is on the roadmap.
#[cfg(unix)]
mod daemon;
#[cfg(unix)]
mod bridge_failover;

#[derive(Parser)]
#[clap(
    name = "drift-vpn",
    about = "Identity-routed multi-transport VPN over DRIFT",
    version
)]
struct Cli {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Bring up the VPN. Reads a TOML config and runs the
    /// daemon in the foreground; SIGINT to stop.
    Up {
        /// Path to TOML config. When omitted, drift-vpn walks a
        /// list of candidate paths and uses the first one that
        /// exists: on macOS `~/Library/Application Support/
        /// drift-vpn/config.toml` then `~/.config/drift-vpn/
        /// config.toml`; on Linux `$XDG_CONFIG_HOME/drift-vpn/
        /// config.toml` (defaults to `~/.config/drift-vpn/
        /// config.toml`); then `/etc/drift-vpn/config.toml` as
        /// the system-level fallback. Pass `--config` to bypass
        /// the auto-discovery.
        #[clap(short, long)]
        config: Option<PathBuf>,
        /// Override the status-socket path. Default is
        /// `/run/drift-vpn/status.sock`. Useful for running
        /// multiple daemons on one host (give each its own
        /// path) or for tests.
        #[clap(long)]
        status_socket: Option<PathBuf>,
        /// Skip the startup check that aborts when another TUN
        /// interface already claims our configured address.
        /// Useful when the orphan interface is known-stale and
        /// can't be torn down (utun on macOS can't be deleted
        /// after its owner dies; only `drift-vpn cleanup` or a
        /// reboot frees it). Proceeding past the conflict means
        /// the routing-table entry for the configured subnet
        /// may end up on the stale interface, silently dropping
        /// traffic — set this flag only after `drift-vpn status`
        /// on the conflicting iface confirms it's really dead.
        #[clap(long)]
        force_cleanup: bool,
    },
    /// Generate a fresh identity keypair, write the secret
    /// to `--out`, and print the pubkey hex to stdout.
    Keygen {
        #[clap(short, long, default_value = "identity.key")]
        out: PathBuf,
    },
    /// Print the pubkey for an existing identity file.
    Show {
        #[clap(short, long)]
        identity_file: PathBuf,
    },
    /// Connect to a running daemon's status socket and print
    /// peer state, link RTTs, and counters. Operator-facing —
    /// no log-grepping required.
    Status {
        /// Path to the status socket the daemon is serving on.
        #[clap(long)]
        socket: Option<PathBuf>,
        /// Print raw JSON instead of the human-readable summary.
        #[clap(long)]
        json: bool,
    },

    /// Generate per-host drift-vpn configs from the shared
    /// drift.toml inventory managed by `drift-config`.
    Config {
        #[clap(subcommand)]
        cmd: ConfigCmd,
    },

    /// Preflight diagnostics. Reads the config, checks the host
    /// (privilege, TUN device, IP forwarding, port availability,
    /// identity file, peer endpoints), prints a pass/warn/fail
    /// report. Read-only — does not mutate state, does not need
    /// the daemon running.
    Doctor {
        /// Path to TOML config. When omitted, drift-vpn walks
        /// the same candidate paths as `drift-vpn up` (per-user
        /// XDG / macOS Application Support, then
        /// `/etc/drift-vpn/config.toml`).
        #[clap(short, long)]
        config: Option<PathBuf>,
        /// In addition to the static preflight checks, actually
        /// attempt a handshake against each configured peer /
        /// bridge. Briefly stands up a no-TUN Transport, calls
        /// connect_url + add_peer, waits up to ~5s for the
        /// session to reach Established, then tears down. Will
        /// surface "bridge unreachable" / "peer offline" /
        /// pubkey-mismatch failures that static checks miss.
        ///
        /// Read-only with respect to system state (no TUN
        /// created, no routes added). Does not need the daemon
        /// running.
        #[clap(long)]
        probe: bool,
    },

    /// Install drift-vpn as a managed system service: writes a
    /// systemd unit on Linux or a launchd plist on macOS, reloads
    /// the service manager, and (by default) enables it for boot.
    /// Requires root.
    Install {
        /// Path to the config file the service will load on
        /// startup. Doesn't need to exist yet — the service will
        /// just fail to start until it does.
        #[clap(short, long, default_value = "/etc/drift-vpn/config.toml")]
        config: PathBuf,
        /// Path to the drift-vpn binary the service will exec.
        #[clap(short, long, default_value = "/usr/local/bin/drift-vpn")]
        binary: PathBuf,
        /// Service unit name. Default is `drift-vpn` →
        /// `drift-vpn.service` on Linux, `com.drift.vpn.plist` on
        /// macOS. Set when running multiple drift-vpn daemons on
        /// one host.
        #[clap(long, default_value = "drift-vpn")]
        service_name: String,
        /// Install but don't enable for boot.
        #[clap(long)]
        no_enable: bool,
        /// Start the service immediately after install.
        #[clap(long)]
        start: bool,
        /// Print the unit that would be written and the commands
        /// that would run, then exit. Doesn't touch the
        /// filesystem or invoke systemctl/launchctl. Doesn't
        /// require root.
        #[clap(long)]
        dry_run: bool,
    },

    /// Stop, disable, and remove the drift-vpn system service
    /// previously installed by `drift-vpn install`. Requires
    /// root. Idempotent — safe to run if the service was already
    /// partially uninstalled.
    Uninstall {
        /// Service unit name (must match what was used with
        /// `install`).
        #[clap(long, default_value = "drift-vpn")]
        service_name: String,
        /// Print the actions that would run, then exit. Doesn't
        /// touch the filesystem or invoke systemctl/launchctl.
        #[clap(long)]
        dry_run: bool,
    },

    /// Generate a new identity and a signed rotation announce. The
    /// announce, signed with the OLD identity, tells peers that the
    /// OLD pubkey is being retired in favor of a NEW pubkey. Each
    /// peer pastes the new pubkey into their config after running
    /// `rotate-verify` on the announce. Phase-1: the announce is
    /// distributed out-of-band (signal, email, paste); future
    /// versions will broadcast it over established tunnels.
    Rotate {
        /// Path to the EXISTING identity file (will not be
        /// modified — archive or remove it after rotation
        /// completes everywhere).
        #[clap(short, long, default_value = "/etc/drift-vpn/identity.key")]
        r#in: PathBuf,
        /// Path to write the NEW identity file. Must not already
        /// exist. Mode 0600 on Unix.
        #[clap(short, long)]
        out: PathBuf,
        /// Optional path to write the announce blob (hex) to.
        /// If omitted, the blob is printed to stdout (the human-
        /// readable rotation summary still goes to stderr).
        #[clap(long)]
        announce_out: Option<PathBuf>,
    },

    /// Verify a rotation announce from a peer and print the new
    /// pubkey to paste into your drift-vpn config. Rejects
    /// announces with a bad signature, mismatched expected
    /// pubkey, or stale timestamp.
    RotateVerify {
        /// The announce blob — either the hex string directly, or
        /// a path to a file containing it.
        #[clap(long)]
        announce: String,
        /// The pubkey hex you currently have configured for this
        /// peer. The verify rejects the announce if its embedded
        /// `old_pub` doesn't match.
        #[clap(long)]
        expect_old_pub: String,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Add a [vpn] block to drift.toml with the chosen CIDR.
    Init {
        /// Path to drift.toml. Default: /etc/drift/drift.toml as
        /// root, otherwise <user-config>/drift/drift.toml.
        #[clap(short, long)]
        config: Option<PathBuf>,
        /// Tun network range, e.g. 10.99.0.0/24.
        #[clap(long, default_value = "10.99.0.0/24")]
        cidr: String,
        /// Tun MTU. 1340 leaves room under DRIFT's payload limit.
        #[clap(long, default_value = "1340")]
        mtu: u32,
    },
    /// Assign a tun address + role to one host in [vpn].
    Assign {
        /// Path to drift.toml.
        #[clap(short, long)]
        config: Option<PathBuf>,
        /// Host name (must already exist in [hosts.X]).
        host: String,
        /// IP inside the [vpn] cidr, e.g. 10.99.0.1.
        #[clap(long)]
        tun: String,
        /// hub | spoke | client.
        #[clap(long, default_value = "spoke")]
        role: String,
    },
    /// Generate per-host config.toml files into ./out/<host>/.
    Gen {
        /// Path to drift.toml.
        #[clap(short, long)]
        config: Option<PathBuf>,
        /// Output directory.
        #[clap(short, long, default_value = "./out")]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift_vpn=info,drift=warn".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out } => {
            let pub_hex = identity::keygen(&out).await?;
            eprintln!("wrote secret to {}", out.display());
            println!("{}", pub_hex);
        }
        Cmd::Show { identity_file } => {
            let id = identity::load(&identity_file).await?;
            println!("{}", hex::encode(id.public_bytes()));
        }
        Cmd::Up {
            config: path,
            status_socket,
            force_cleanup,
        } => {
            #[cfg(unix)]
            {
                let path = resolve_vpn_config_path(path);
                let cfg = config::Config::load(&path).await?;
                let id = identity::load(&cfg.interface.identity_file).await?;
                let sock = status_socket.unwrap_or_else(status::default_socket_path);
                daemon::run(cfg, id, sock, force_cleanup).await?;
            }
            #[cfg(not(unix))]
            {
                let _ = (path, status_socket, force_cleanup);
                anyhow::bail!(
                    "drift-vpn `up` requires a Unix-like OS for TUN/utun support \
                     (Linux + macOS today; Windows Wintun support is on the roadmap). \
                     `keygen` and `show` work cross-platform."
                );
            }
        }
        Cmd::Status { socket, json } => {
            #[cfg(unix)]
            {
                let path = socket.unwrap_or_else(status::default_socket_path);
                let report = status::fetch(&path).await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", status::render_human(&report));
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (socket, json);
                anyhow::bail!("drift-vpn status requires Unix sockets (Linux + macOS today)");
            }
        }
        Cmd::Doctor { config: path, probe } => {
            #[cfg(unix)]
            {
                let path = resolve_vpn_config_path(path);
                let all_pass = doctor::run(&path, probe).await?;
                if !all_pass {
                    std::process::exit(1);
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (path, probe);
                anyhow::bail!(
                    "drift-vpn doctor requires a Unix-like OS (Linux + macOS today)"
                );
            }
        }
        Cmd::Install {
            config,
            binary,
            service_name,
            no_enable,
            start,
            dry_run,
        } => {
            #[cfg(unix)]
            {
                install::install(install::InstallOpts {
                    config,
                    binary,
                    service_name,
                    no_enable,
                    start,
                    dry_run,
                })
                .await?;
            }
            #[cfg(not(unix))]
            {
                let _ = (config, binary, service_name, no_enable, start, dry_run);
                anyhow::bail!(
                    "drift-vpn install requires a Unix-like OS (Linux systemd or \
                     macOS launchd). For Windows, run drift-vpn in WSL2."
                );
            }
        }
        Cmd::Uninstall {
            service_name,
            dry_run,
        } => {
            #[cfg(unix)]
            {
                install::uninstall(install::UninstallOpts {
                    service_name,
                    dry_run,
                })
                .await?;
            }
            #[cfg(not(unix))]
            {
                let _ = (service_name, dry_run);
                anyhow::bail!(
                    "drift-vpn uninstall requires a Unix-like OS (Linux systemd or \
                     macOS launchd)."
                );
            }
        }
        Cmd::Rotate {
            r#in,
            out,
            announce_out,
        } => {
            rotate::rotate(rotate::RotateOpts {
                r#in,
                out,
                announce_out,
            })
            .await?;
        }
        Cmd::RotateVerify {
            announce,
            expect_old_pub,
        } => {
            rotate::rotate_verify(rotate::RotateVerifyOpts {
                announce,
                expect_old_pub,
            })
            .await?;
        }
        Cmd::Config { cmd } => match cmd {
            ConfigCmd::Init { config, cidr, mtu } => {
                let path = resolve_config_path(config)?;
                config_gen::init(&path, &cidr, mtu)?;
            }
            ConfigCmd::Assign {
                config,
                host,
                tun,
                role,
            } => {
                let path = resolve_config_path(config)?;
                config_gen::assign(&path, &host, &tun, &role)?;
            }
            ConfigCmd::Gen { config, out } => {
                let path = resolve_config_path(config)?;
                config_gen::gen(&path, &out)?;
            }
        },
    }
    Ok(())
}

/// Resolve `--config <path>` (or fall back to drift-config's
/// platform-default location) for the `config` subcommands.
fn resolve_config_path(opt: Option<PathBuf>) -> Result<PathBuf> {
    match opt {
        Some(p) => Ok(p),
        None => drift_config::io::default_path(),
    }
}

/// Resolve `--config <path>` for drift-vpn's own daemon config
/// (`up`, `doctor`). Walks a list of candidate paths and picks
/// the first that exists, falling back to the system-level
/// `/etc/drift-vpn/config.toml` so the caller gets a clear
/// "not found at <that path>" if nothing is configured anywhere.
///
/// Distinct from `resolve_config_path` (which resolves the
/// shared drift.toml inventory used by `drift-vpn config`).
fn resolve_vpn_config_path(opt: Option<PathBuf>) -> PathBuf {
    if let Some(p) = opt {
        return p;
    }
    let candidates = default_vpn_config_candidates();
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    // None exist — return the system-level path so the operator
    // sees "config not found at /etc/drift-vpn/config.toml"
    // rather than a confusing per-user path they may not even
    // have a directory for.
    candidates
        .into_iter()
        .last()
        .unwrap_or_else(|| PathBuf::from("/etc/drift-vpn/config.toml"))
}

/// Candidate paths searched by `resolve_vpn_config_path`, in
/// priority order. Per-user paths first because that's where
/// every actual deployment of drift-vpn we've debugged this
/// session kept its config; the system path is the fallback
/// for service-style installs.
fn default_vpn_config_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let home = std::env::var_os("HOME").map(PathBuf::from);

    #[cfg(target_os = "macos")]
    if let Some(h) = &home {
        out.push(h.join("Library/Application Support/drift-vpn/config.toml"));
    }

    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        out.push(PathBuf::from(xdg).join("drift-vpn/config.toml"));
    } else if let Some(h) = &home {
        out.push(h.join(".config/drift-vpn/config.toml"));
    }

    out.push(PathBuf::from("/etc/drift-vpn/config.toml"));
    out
}

#[cfg(test)]
mod resolve_vpn_config_path_tests {
    use super::*;

    #[test]
    fn explicit_path_returned_as_is() {
        let p = PathBuf::from("/some/custom/path.toml");
        assert_eq!(resolve_vpn_config_path(Some(p.clone())), p);
    }

    #[test]
    fn default_candidates_include_system_path_last() {
        let cands = default_vpn_config_candidates();
        assert!(!cands.is_empty());
        assert_eq!(
            cands.last(),
            Some(&PathBuf::from("/etc/drift-vpn/config.toml")),
            "system path must always be the final fallback"
        );
    }

    #[test]
    fn default_candidates_have_per_user_path_before_system() {
        // We don't care about absolute paths in test (HOME varies),
        // but the per-user candidate must appear BEFORE
        // /etc/drift-vpn/config.toml — that ordering is the whole
        // point of the fix.
        let cands = default_vpn_config_candidates();
        let sys = PathBuf::from("/etc/drift-vpn/config.toml");
        let sys_idx = cands.iter().position(|p| p == &sys).expect("sys path present");
        assert!(
            cands.len() > 1 && sys_idx > 0 || std::env::var_os("HOME").is_none(),
            "per-user candidate must come before the system fallback (cands = {:?})",
            cands
        );
    }
}
