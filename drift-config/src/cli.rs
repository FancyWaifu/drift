//! Subcommand dispatch for `drift-config`.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Inventory + identity manager for DRIFT deployments")]
pub struct Cli {
    /// Path to drift.toml. Default: /etc/drift/drift.toml as root,
    /// otherwise <user-config>/drift/drift.toml.
    #[arg(long, short = 'c', global = true)]
    pub config: Option<PathBuf>,

    /// Path to the identity key file. Default: same dir as
    /// drift.toml, named identity.key.
    #[arg(long, short = 'i', global = true)]
    pub identity: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a fresh drift.toml with sensible defaults.
    Init(InitArgs),

    /// Generate this host's X25519 identity, register it in
    /// drift.toml under `--name`. Use this on every device that
    /// will run a DRIFT tool.
    Keygen(KeygenArgs),

    /// Manage peer entries.
    #[command(subcommand)]
    Peer(PeerCommand),

    /// Print the current inventory in human-readable form.
    Show,

    /// Sanity-check drift.toml: pubkey hex shape, endpoint URL
    /// shape, no duplicate names.
    Validate,
}

#[derive(Args)]
pub struct InitArgs {
    /// Network name (purely cosmetic, used in `show` output).
    #[arg(long, default_value = "drift-network")]
    pub name: String,
    /// Refuse to overwrite if drift.toml already exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct KeygenArgs {
    /// Local name for this host. Defaults to `hostname` output.
    #[arg(long)]
    pub name: Option<String>,
    /// Endpoint URLs other peers should use to reach this host.
    /// Repeat for multiple. Empty = pure roaming client.
    #[arg(long = "endpoint", short = 'e')]
    pub endpoints: Vec<String>,
    /// `user@host` for ssh-driven deploy of this host. Optional.
    #[arg(long)]
    pub ssh: Option<String>,
    /// Refuse to overwrite an existing identity file.
    #[arg(long)]
    pub force: bool,
}

#[derive(Subcommand)]
pub enum PeerCommand {
    /// Add a peer manually given its pubkey + endpoint(s).
    Add(PeerAddArgs),
    /// List all hosts in the inventory.
    Ls,
    /// Remove a host by name.
    Rm(PeerRmArgs),
}

#[derive(Args)]
pub struct PeerAddArgs {
    /// Local name for this peer (free-form).
    pub name: String,
    /// 64-hex X25519 pubkey.
    #[arg(long)]
    pub pubkey: String,
    /// One or more DRIFT URLs (e.g. udp://1.2.3.4:51820).
    #[arg(long = "endpoint", short = 'e')]
    pub endpoints: Vec<String>,
    /// Optional ssh target.
    #[arg(long)]
    pub ssh: Option<String>,
    /// Free-form note (stored verbatim in drift.toml).
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Args)]
pub struct PeerRmArgs {
    pub name: String,
}
