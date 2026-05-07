//! `drift-vpn` — identity-routed multi-transport VPN built on
//! DRIFT. See drift-vpn/README.md for design + config docs.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod config;
mod identity;
mod metrics;
mod routing;
mod status;

#[cfg(target_os = "linux")]
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
            #[cfg(target_os = "linux")]
            {
                let cfg = config::Config::load(&path).await?;
                let id = identity::load(&cfg.interface.identity_file).await?;
                let sock = status_socket.unwrap_or_else(status::default_socket_path);
                daemon::run(cfg, id, sock).await?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (path, status_socket);
                anyhow::bail!(
                    "drift-vpn `up` is Linux-only in v0.1 (TUN device support); \
                     other commands (keygen, show) work cross-platform"
                );
            }
        }
        Cmd::Status { socket, json } => {
            #[cfg(target_os = "linux")]
            {
                let path = socket.unwrap_or_else(status::default_socket_path);
                let report = status::fetch(&path).await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", status::render_human(&report));
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (socket, json);
                anyhow::bail!("drift-vpn status is Linux-only");
            }
        }
    }
    Ok(())
}
