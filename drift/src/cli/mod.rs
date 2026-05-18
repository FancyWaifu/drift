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
    /// Wait for the session to reach Established (handshake complete)
    /// before exiting. Without this, `drift send` exits as soon as
    /// the bytes are queued — on strict-NAT paths the HELLO_ACK may
    /// never reach back and the message is silently lost despite a
    /// 0 exit code. With `--await-ack`, drift retransmits HELLO
    /// transparently until handshake completion or `--await-timeout`
    /// expires.
    #[arg(long, default_value = "false")]
    pub await_ack: bool,
    /// How long to wait for handshake completion when `--await-ack`
    /// is set. Default 5 seconds — enough for any non-pathological
    /// WAN, fail-fast for pathological ones.
    #[arg(long, default_value = "5")]
    pub await_timeout: u64,
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

    /// Phase PQ: disable the X25519 + ML-KEM-768 hybrid
    /// handshake (escape hatch). Hybrid PQ is now the
    /// default. Set this flag if you need the legacy
    /// classical-only handshake — e.g., on a bandwidth- or
    /// CPU-constrained device, or for interop testing with
    /// peers that have intentionally turned PQ off.
    ///
    /// Classical-only servers still accept incoming hybrid
    /// HELLOs from PQ-capable clients? No — they refuse
    /// fail-closed (silent downgrade would defeat the
    /// client's PQ guarantee). Use with intent.
    ///
    /// Wire cost when hybrid is on: per-handshake HELLO +1.2
    /// KB, HELLO_ACK +1.1 KB. DATA framing unchanged.
    /// See SPEC.md §6.7.
    #[arg(long = "no-hybrid-pq", default_value_t = false)]
    pub no_hybrid_pq: bool,

    /// Phase G: federation-peer fault skip threshold. Bridges
    /// that bloom-claim a target then fail to deliver
    /// accumulate a fault counter; once a peer's count hits
    /// this threshold, it's skipped from `FindPeer` fanout
    /// until the counter decays back. `0` disables (observe-
    /// only). Default `5`.
    #[arg(long = "bridge-fault-skip-threshold", default_value_t = 5)]
    pub bridge_fault_skip_threshold: u32,

    /// Phase PQ-T.11: UDP receive-buffer size in bytes.
    /// Bridges absorbing many concurrent first-time handshakes
    /// (especially hybrid PQ HELLOs at ~1.3 KB each) need
    /// more than the ~200 KB OS default or they drop under
    /// thundering-herd reconnects. Default 4 MiB; the kernel
    /// may clamp lower (raise `sysctl net.core.rmem_max` on
    /// Linux, `kern.ipc.maxsockbuf` on macOS to lift the cap).
    #[arg(
        long = "udp-recv-buffer-bytes",
        default_value_t = 4 * 1024 * 1024
    )]
    pub udp_recv_buffer_bytes: usize,

    /// Phase PQ-T.11: first-HELLO jitter, in milliseconds.
    /// The initial handshake send is delayed by a uniformly
    /// random `0..N` ms. Disperses synchronized client
    /// reconnects after a bridge restart. Default 334 (matches
    /// WireGuard's `RekeyTimeoutJitterMaxMs`).
    ///
    /// Set to `0` to disable jitter — useful for LAN-only
    /// deployments where latency budget trumps thundering-
    /// herd robustness.
    #[arg(long = "handshake-jitter-ms", default_value_t = 334)]
    pub handshake_jitter_ms: u64,

    /// SEC.FIX.1 escape hatch — disable the open-relay guard.
    /// By default `drift bridge` drops forward requests whose
    /// source IP doesn't match an established peer (closes a
    /// reflection / amplification primitive: without it, any
    /// host on the internet can send raw UDP with a victim's
    /// dst_id and have the bridge re-emit those bytes to the
    /// victim with our IP as source).
    ///
    /// Only set this for trusted-mesh test fixtures where you
    /// genuinely need legacy open forwarding. NEVER on an
    /// internet-facing bridge.
    #[arg(long = "allow-open-relay", default_value_t = false)]
    pub allow_open_relay: bool,

    /// HTTP.OPT2 — trust X-Forwarded-For / X-Real-IP when the
    /// http:// adapter applies its per-IP connection cap. Set
    /// this when running drift bridge behind nginx, caddy, or
    /// any other reverse proxy that terminates TCP before
    /// drift sees it. Without this flag the per-IP cap thinks
    /// every connection comes from the proxy's loopback /
    /// internal IP and lets through far more than intended.
    ///
    /// IMPORTANT: only set when you actually have a trusted
    /// reverse proxy in front. If exposed directly, clients
    /// can spoof X-Forwarded-For to bypass the cap.
    #[arg(long = "trust-proxy-headers", default_value_t = false)]
    pub trust_proxy_headers: bool,

    /// HTTP.FED.STRICT — by default `drift bridge` only allows
    /// federation links over h2:// / h2s:// / webtransport://.
    /// These three are multiplexed, middlebox-friendly, and
    /// reverse-proxy-friendly — the modern federation backbone.
    /// Client connections via `--listen` still accept any wire
    /// scheme; this gate is only on outbound `--federate` URLs.
    ///
    /// Set this flag to bypass the gate and allow `--federate`
    /// over legacy schemes (udp / tcp / tls / ws / http / dns).
    /// Use only for backwards compatibility with peers that
    /// haven't upgraded yet, or for tests.
    #[arg(long = "allow-legacy-federation", default_value_t = false)]
    pub allow_legacy_federation: bool,
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
