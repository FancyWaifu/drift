//! `drift-vpn` — identity-routed multi-transport VPN built on
//! DRIFT. See drift-vpn/README.md for design + config docs.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod config;
mod config_gen;
mod identity;
mod metrics;
mod routing;
mod status;

// v0.12: tun/utun via the `tun` crate works on Linux + macOS;
// Windows Wintun is on the roadmap.
#[cfg(unix)]
mod daemon;

#[derive(Parser)]
#[clap(name = "drift-vpn", about = "Identity-routed multi-transport VPN over DRIFT")]
struct Cli {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Bring up the VPN. Reads a TOML config and runs the
    /// daemon in the foreground; SIGINT to stop.
    Up {
        /// Path to TOML config.
        #[clap(short, long, default_value = "/etc/drift-vpn/config.toml")]
        config: PathBuf,
        /// Override the status-socket path. Default is
        /// `/run/drift-vpn/status.sock`. Useful for running
        /// multiple daemons on one host (give each its own
        /// path) or for tests.
        #[clap(long)]
        status_socket: Option<PathBuf>,
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
        } => {
            #[cfg(unix)]
            {
                let cfg = config::Config::load(&path).await?;
                let id = identity::load(&cfg.interface.identity_file).await?;
                let sock = status_socket.unwrap_or_else(status::default_socket_path);
                daemon::run(cfg, id, sock).await?;
            }
            #[cfg(not(unix))]
            {
                let _ = (path, status_socket);
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
