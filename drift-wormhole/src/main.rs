//! drift-wormhole — file transfer over DRIFT, Magic-Wormhole-shaped.
//!
//! ```text
//!   sender:                              recipient:
//!     drift-wormhole send file.txt         drift-wormhole recv <PUB>@<HOST>:<PORT>
//!       prints PUB@host:port,                connects to that peer,
//!       waits for incoming stream            opens stream, reads file
//! ```
//!
//! Differences from real Magic Wormhole:
//!   * **Pubkey instead of codeword.** Both peers identify by
//!     32-byte X25519 pubkey instead of a SPAKE2-derived
//!     ephemeral codeword. The sender prints their pubkey;
//!     the recipient pastes it. Less "magic," but no
//!     dependency on a public rendezvous mailbox server.
//!   * **No relay required.** When both parties are reachable
//!     (LAN, exposed VPS, friend's home network with port
//!     forward, etc.) the connection is direct. Behind dual
//!     NAT, you can route through any DRIFT bridge — same as
//!     drift-http does for HTTP.
//!   * **Same wire transports.** `--bind` accepts udp:// /
//!     tcp:// / ws:// schemes, so a sender on a network that
//!     blocks UDP can still ship the file over a WebSocket.
//!
//! Identity is shared with drift-mosh, drift-http, and any
//! future DRIFT tool at `~/.config/drift/identity.key` —
//! one pubkey is your handle for every DRIFT-based thing.

mod protocol;

#[cfg(feature = "native")]
mod identity;
#[cfg(feature = "native")]
mod recv;
#[cfg(feature = "native")]
mod send;

#[cfg(feature = "portable")]
mod portable;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "drift-wormhole",
    about = "File transfer over DRIFT (Magic-Wormhole-shaped)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Send a file. Prints a one-line "recipient command" to
    /// share over chat / sms / etc.; waits for the recipient
    /// to connect and pulls the file.
    Send(SendArgs),
    /// Receive a file. Argument is the `PUB@HOST:PORT` string
    /// the sender printed.
    Recv(RecvArgs),
}

#[derive(Args)]
pub(crate) struct SendArgs {
    /// File to send.
    pub file: PathBuf,

    /// DRIFT bind address. Repeatable: pass `--bind` once per
    /// transport you want to listen on. Schemes: `udp://`,
    /// `tcp://`, `ws://`. Default UDP on an ephemeral port.
    #[clap(long, default_value = "udp://0.0.0.0:0")]
    pub bind: Vec<String>,

    /// Path to the identity key. Defaults to
    /// `$CONFIG_DIR/drift/identity.key`.
    #[clap(long)]
    pub identity_file: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct RecvArgs {
    /// Sender peer in `PUBHEX@HOST:PORT` form. Bare `host:port`
    /// → udp://; explicit scheme prefix (`udp://`, `tcp://`,
    /// `ws://`) selects the wire.
    pub peer: String,

    /// Output directory. Defaults to current directory; the
    /// file is saved using the sender's filename unless
    /// `--out` overrides.
    #[clap(long, default_value = ".")]
    pub out_dir: PathBuf,

    /// Override the saved filename.
    #[clap(long)]
    pub out: Option<String>,

    /// Path to the identity key. Defaults to
    /// `$CONFIG_DIR/drift/identity.key`.
    #[clap(long)]
    pub identity_file: Option<PathBuf>,
}

/// Native (async, tokio) entry point — the default build, all wires.
#[cfg(feature = "native")]
#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();

    let result = match cli.cmd {
        Cmd::Send(a) => send::run(a).await,
        Cmd::Recv(a) => recv::run(a).await,
    };
    if let Err(e) = result {
        eprintln!("drift-wormhole: {:#}", e);
        std::process::exit(1);
    }
    Ok(())
}

/// Portable (sync, no-tokio) entry point — `drift-proto-std`, tcp-only.
/// Selected by `--no-default-features --features portable`.
#[cfg(all(feature = "portable", not(feature = "native")))]
fn main() -> Result<()> {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Send(a) => portable::run_send(a),
        Cmd::Recv(a) => portable::run_recv(a),
    };
    if let Err(e) = result {
        eprintln!("drift-wormhole: {:#}", e);
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(feature = "native")]
fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "drift=warn,drift_wormhole=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(feature = "native")]
pub(crate) fn load_identity(path: Option<PathBuf>) -> Result<drift::identity::Identity> {
    let p = match path {
        Some(p) => p,
        None => identity::default_path()?,
    };
    identity::load_or_create(&p)
}
