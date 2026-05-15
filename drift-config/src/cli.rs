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

    /// Generate this host's X25519 identity and register it in
    /// drift.toml as `[hosts.<name>]`. Run on every device that
    /// will use a DRIFT tool.
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
    /// Cosmetic label for this network. Only shown in
    /// `drift-config show`; nothing routes by it. Most users
    /// never need to set this — leave it at the default.
    #[arg(long, default_value = "drift-network")]
    pub network: String,
    /// Refuse to overwrite if drift.toml already exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct KeygenArgs {
    /// Local name for this host (the `[hosts.X]` key in
    /// drift.toml). Defaults to the OS hostname.
    pub host: Option<String>,
    /// Endpoint URLs other peers should use to reach this host.
    /// Repeat for multiple. Empty = pure roaming client.
    #[arg(long = "endpoint", short = 'e')]
    pub endpoints: Vec<String>,
    /// Refuse to overwrite an existing identity file.
    #[arg(long)]
    pub force: bool,
}

#[derive(Subcommand)]
pub enum PeerCommand {
    /// Add a peer manually. Three valid forms:
    ///
    ///   1. `--pubkey HEX --endpoint udp://host:port`  →  direct dial
    ///   2. `--pubkey HEX --via-bridge BRIDGE_HEX`     →  federation through a known bridge
    ///   3. `--pubkey HEX` (no endpoint, no via-bridge) →  federation-discovery
    ///      via the inventory's `default_bridge`. Requires `default_bridge`
    ///      to be set at the top of drift.toml — see `drift-config init`.
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
    /// Optional — omit for federation-discovery mode (case 3 in
    /// the parent help).
    #[arg(long = "endpoint", short = 'e')]
    pub endpoints: Vec<String>,
    /// Pubkey-hex of the bridge this peer is reachable through.
    /// When set, tools dialing this peer (drift-mosh, drift-http,
    /// …) auto-route through that bridge using DRIFT federation —
    /// no need to pass --bridge / --target-bridge on the command
    /// line. The bridge itself must also have an entry in this
    /// inventory with `endpoints`.
    ///
    /// Optional. When both `endpoints` and `via_bridge` are
    /// omitted, the entry becomes a "discovery-only" host: tools
    /// will dial the inventory's `default_bridge` with the
    /// UNKNOWN_BRIDGE_PUB sentinel and let the bridge's
    /// `peer_directory` resolve the route via federation
    /// discovery. See FEDERATION_DISCOVERY.md for the protocol.
    #[arg(long = "via-bridge")]
    pub via_bridge: Option<String>,
}

#[derive(Args)]
pub struct PeerRmArgs {
    pub name: String,
}
