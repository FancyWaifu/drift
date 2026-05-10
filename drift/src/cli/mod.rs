pub mod bridge;
pub mod contacts;
pub mod identity;
pub mod info;
pub mod keygen;
pub mod listen;
pub mod relay;
pub mod send;

use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "drift", version, about = "DRIFT encrypted transport")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Path to identity key file
    #[arg(long, global = true, default_value = "~/.drift/identity.key")]
    pub identity: String,

    /// Output format
    #[arg(long, global = true, default_value = "human")]
    pub format: OutputFormat,
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate a new identity keypair
    Keygen(KeygenArgs),
    /// Show identity info from a key file
    Info(InfoArgs),
    /// Send a message or file to a peer
    Send(SendArgs),
    /// Listen for incoming messages
    Listen(ListenArgs),
    /// Run a mesh relay node
    Relay(RelayArgs),
    /// Run this device as a multi-transport DRIFT bridge.
    /// Listen URLs come from --listen flags or, if none given,
    /// from this host's entry in the shared drift.toml inventory
    /// managed by `drift-config`.
    Bridge(BridgeArgs),
    /// Manage local contacts (petname → pubkey address book)
    Contacts(ContactsArgs),
}

#[derive(clap::Args)]
pub struct ContactsArgs {
    #[command(subcommand)]
    pub command: contacts::ContactsCommand,
}

#[derive(clap::Args)]
pub struct KeygenArgs {
    /// Output path (overrides --identity)
    #[arg(short, long)]
    pub output: Option<String>,
    /// Overwrite existing key file
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::Args)]
pub struct InfoArgs {
    /// Key file to inspect (overrides --identity)
    pub file: Option<String>,
}

#[derive(clap::Args)]
pub struct SendArgs {
    /// Target address (host:port)
    pub target: SocketAddr,
    /// Target peer's public key (hex, 64 chars)
    #[arg(long)]
    pub peer_key: String,
    /// Inline message to send
    #[arg(short, long, group = "input")]
    pub message: Option<String>,
    /// File to send (uses reliable streams)
    #[arg(short, long, group = "input")]
    pub file: Option<PathBuf>,
    /// Local bind address
    #[arg(long, default_value = "0.0.0.0:0")]
    pub bind: SocketAddr,
    /// Route through a relay
    #[arg(long)]
    pub via: Option<SocketAddr>,
    /// Deadline in milliseconds (0 = no deadline)
    #[arg(long, default_value = "0")]
    pub deadline: u16,
    /// Adapter to connect with: 1=UDP (default), 2=TCP, 3=WebSocket
    #[arg(long, default_value = "1")]
    pub adapter: u8,
}

#[derive(clap::Args)]
pub struct ListenArgs {
    /// Address to listen on
    #[arg(default_value = "0.0.0.0:9000")]
    pub bind: SocketAddr,
    /// Accept any incoming peer
    #[arg(long)]
    pub accept_any: bool,
    /// Restrict to specific peer public keys (hex, repeatable)
    #[arg(long = "peer")]
    pub peers: Vec<String>,
    /// Write received files to this directory
    #[arg(long)]
    pub output_dir: Option<PathBuf>,
    /// Transport preset
    #[arg(long, default_value = "default")]
    pub preset: TransportPreset,
}

#[derive(Clone, ValueEnum)]
pub enum TransportPreset {
    Default,
    Iot,
    Realtime,
}

#[derive(clap::Args)]
pub struct BridgeArgs {
    /// Listen URLs (repeatable). Examples:
    ///   --listen udp://0.0.0.0:51820
    ///   --listen tcp://0.0.0.0:443
    ///   --listen ws://0.0.0.0:8443
    /// If omitted, listen URLs are read from this host's
    /// `endpoints` in drift.toml.
    #[arg(long = "listen")]
    pub listen: Vec<String>,

    /// Path to drift.toml. Default: /etc/drift/drift.toml as
    /// root, or the user-config equivalent. Only consulted when
    /// --listen is empty.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Which `[hosts.<name>]` entry in drift.toml is THIS host?
    /// Default: detect from /etc/hostname or $HOSTNAME.
    #[arg(long = "host")]
    pub host_name: Option<String>,

    /// Outbound peers this bridge should also initiate sessions
    /// with. Format: `<url>@<pubkey-hex>`. Repeatable. Used to
    /// chain two bridges together so mesh routing has end-to-end
    /// visibility: bridge A `--peer udp://B:51820@<B-pub>` makes
    /// A initiate to B, which lets A's clients reach B's clients
    /// without any client knowing the other bridge.
    #[arg(long = "peer")]
    pub peers: Vec<String>,

    /// Federation peers — like `--peer`, but the resulting
    /// session also gets registered in the federation table.
    /// Bridges chain together via `--federate` and forward
    /// `PacketType::Federated` envelopes by pubkey lookup
    /// rather than via beacon-driven mesh routing. Format:
    /// `<url>@<pubkey-hex>` (same as `--peer`). Repeatable.
    #[arg(long = "federate")]
    pub federates: Vec<String>,
}

#[derive(clap::Args)]
pub struct RelayArgs {
    /// Address to listen on
    #[arg(default_value = "0.0.0.0:9000")]
    pub bind: SocketAddr,
    /// Static routes: PEERID_HEX:HOST:PORT (repeatable)
    #[arg(long = "route")]
    pub routes: Vec<String>,
    /// Show metrics every N seconds (0 = disabled)
    #[arg(long, default_value = "10")]
    pub metrics_interval: u64,
}

/// Expand ~ to home directory.
pub fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs_home() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
