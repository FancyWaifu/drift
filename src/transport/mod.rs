use crate::crypto::{derive_peer_id, Direction, PeerId, SessionKey};
use crate::error::{DriftError, Result};
use crate::header::{canonical_aad, Header, PacketType, AUTH_TAG_LEN, HEADER_LEN};
use crate::identity::{
    derive_session_key, random_nonce, rekey_derive, Identity, NONCE_LEN, STATIC_KEY_LEN,
};
use crate::session::{
    HandshakeState, PathProbe, Peer, PendingSend, PrevSession, SEQ_SEND_CEILING,
};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

pub const MAX_PACKET: usize = 1400;
pub const MAX_PAYLOAD: usize = MAX_PACKET - HEADER_LEN - AUTH_TAG_LEN;

// HELLO payload: client_static_pub(32) + client_ephemeral_pub(32) + client_nonce(16) = 80
const HELLO_PAYLOAD_LEN: usize = STATIC_KEY_LEN + STATIC_KEY_LEN + NONCE_LEN;
// HELLO_ACK payload: server_ephemeral_pub(32) + server_nonce(16) + auth_tag(16) = 64
const HELLO_ACK_PAYLOAD_LEN: usize = STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN;
#[cfg(unix)]
mod batch;
mod cookies;
#[cfg(unix)]
mod ecn;
mod mesh;
mod path;
mod peer_shards;
mod qlog;
mod resumption;
mod rtt;
use cookies::{CookieSecrets, COOKIE_BLOB_LEN, HELLO_WITH_COOKIE_LEN};
use mesh::{DEFAULT_MESH_TTL, MAX_INCOMING_HOP_TTL};
pub use mesh::{RouteEntry, RoutingTable, MAX_ROUTES};
use path::{
    build_path_challenge_packet, PATH_CHALLENGE_LEN, PATH_PROBE_RETRY,
};
pub use resumption::{ClientTicket, EXPORT_BLOB_LEN, TICKET_DEFAULT_TTL};
use resumption::ResumptionStore;
use peer_shards::PeerShards;
use std::collections::HashMap as StdHashMap;

/// Runtime configuration for a `Transport`. Every field has a sensible
/// default suitable for interactive apps; override before `Transport::bind`
/// for deployments with different constraints (e.g., IoT, bulk, real-time).
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Initial retry interval for handshake HELLO. Subsequent retries
    /// double each attempt (exponential backoff). Default: 50ms.
    pub handshake_retry_base_ms: u64,
    /// Maximum number of HELLO retry attempts before giving up.
    /// Default: 10 (total budget ~51s).
    pub handshake_max_attempts: u8,
    /// How often the background retry task scans peers. Default: 25ms.
    pub handshake_scan_ms: u64,
    /// Interval between BEACON emissions to established peers.
    /// Default: 2000ms. Set to a large value for battery-sensitive
    /// deployments (e.g., 60000 for IoT).
    pub beacon_interval_ms: u64,
    /// Capacity of the mpsc channel between the receive loop and the
    /// application's `recv()` method. Default: 1024.
    pub recv_channel_capacity: usize,
    /// If true, incoming HELLOs from peers NOT in the peer table are
    /// auto-registered instead of dropped. Used by directory relays
    /// and other services that accept anonymous connections. Default:
    /// false — only pre-registered peers are accepted.
    pub accept_any_peer: bool,
    /// If true, always require clients to echo a stateless DoS cookie
    /// before the server does any X25519 or peer allocation. Useful for
    /// tests and high-risk deployments. Default: false.
    pub cookie_always: bool,
    /// When the number of in-flight unauthenticated handshakes (peers
    /// in `AwaitingData`) meets or exceeds this value, the server
    /// adaptively switches to cookie mode for new HELLOs. Default:
    /// `u32::MAX` (effectively never triggers on its own).
    pub cookie_threshold: u32,
    /// Maximum age in seconds the server will accept a cookie
    /// timestamp. Keeps the fast path's replay window bounded and
    /// limits stale-cookie reuse across restarts. Default: 60s.
    pub cookie_max_age_secs: u64,
    /// How often the server rotates its cookie secret. The previous
    /// secret is retained for one extra window so in-flight cookies
    /// still validate across a rotation boundary. Default: 30s.
    pub cookie_rotate_secs: u64,
    /// Upper bound on how many total peers the transport will keep
    /// in its peer table. Only enforced against auto-registered
    /// peers (those admitted via `accept_any_peer` on an inbound
    /// HELLO) — explicit `add_peer` calls always succeed. Prevents
    /// an attacker spraying unique pubkeys from exhausting memory
    /// between eviction-reaper scans. Default: 8192.
    pub max_peers: usize,
    /// Hard cap on the number of DATA packets a peer may buffer in
    /// its pre-handshake `pending` queue. Once hit, `send_data`
    /// returns `DriftError::QueueFull` rather than buffering more.
    /// Bounds memory when a handshake is slow or stuck. Default: 256.
    pub pending_queue_cap: usize,
    /// Maximum time (in seconds) a peer is allowed to sit in
    /// `AwaitingData` state before the eviction reaper intervenes. On
    /// timeout: auto-registered peers are dropped outright, explicitly
    /// registered peers are reset to `Pending` so they can handshake
    /// again. Default: 30s. Set `u64::MAX` to disable eviction.
    pub awaiting_data_timeout_secs: u64,
    /// Enable Explicit Congestion Notification (RFC 3168). When
    /// true, all outgoing packets are marked `ECT(0)` and (on
    /// Linux) incoming `CE` marks are read out of the socket and
    /// fed into the per-peer congestion controller as a gentle
    /// backoff signal. Default: false. ECN is opt-in because the
    /// real-world benefit depends on whether middleboxes on the
    /// path bleach the codepoint — datacenters and modern
    /// transit honor it, much of the consumer internet doesn't.
    pub enable_ecn: bool,
    /// Path to a qlog-style structured event log. When set,
    /// the transport writes newline-delimited JSON events
    /// (packet sent/received, handshake complete, rekey, path
    /// migration, etc.) to this file, in a format loosely
    /// compatible with qlog tooling. Disabled by default.
    pub qlog_path: Option<std::path::PathBuf>,
    /// Interval in milliseconds between latency probe rounds.
    /// When non-zero, the transport emits a `Ping` to every
    /// direct neighbor on this cadence and uses the matching
    /// `Pong` round-trip to keep the per-neighbor RTT
    /// estimate fresh. The estimator feeds the RTT-weighted
    /// mesh-routing path-selection code. Set to 0 to disable
    /// active probing (the estimator still gets passive
    /// samples from handshakes and path probes). Default:
    /// 5000 (5s).
    pub rtt_probe_interval_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            handshake_retry_base_ms: 50,
            handshake_max_attempts: 10,
            handshake_scan_ms: 25,
            beacon_interval_ms: 2000,
            recv_channel_capacity: 1024,
            accept_any_peer: false,
            cookie_always: false,
            cookie_threshold: u32::MAX,
            cookie_max_age_secs: 60,
            cookie_rotate_secs: 30,
            awaiting_data_timeout_secs: 30,
            pending_queue_cap: 256,
            max_peers: 8192,
            enable_ecn: false,
            rtt_probe_interval_ms: 5_000,
            qlog_path: None,
        }
    }
}

impl TransportConfig {
    /// Preset tuned for battery-powered IoT deployments: infrequent
    /// beacons (60 s), slow handshake retry (500 ms base), small recv
    /// buffer.
    pub fn iot() -> Self {
        Self {
            handshake_retry_base_ms: 500,
            handshake_max_attempts: 8,
            handshake_scan_ms: 200,
            beacon_interval_ms: 60_000,
            recv_channel_capacity: 64,
            accept_any_peer: false,
            cookie_always: false,
            cookie_threshold: u32::MAX,
            cookie_max_age_secs: 60,
            cookie_rotate_secs: 30,
            awaiting_data_timeout_secs: 30,
            pending_queue_cap: 256,
            max_peers: 8192,
            enable_ecn: false,
            // IoT is battery-constrained — skip active probes
            // and rely on passive samples only.
            rtt_probe_interval_ms: 0,
            qlog_path: None,
        }
    }

    /// Preset tuned for high-frequency real-time apps (games, VoIP):
    /// fast handshake retry, small beacon interval.
    pub fn realtime() -> Self {
        Self {
            handshake_retry_base_ms: 25,
            handshake_max_attempts: 12,
            handshake_scan_ms: 10,
            beacon_interval_ms: 1000,
            recv_channel_capacity: 4096,
            accept_any_peer: false,
            cookie_always: false,
            cookie_threshold: u32::MAX,
            cookie_max_age_secs: 60,
            cookie_rotate_secs: 30,
            awaiting_data_timeout_secs: 30,
            pending_queue_cap: 256,
            max_peers: 8192,
            enable_ecn: false,
            // Real-time apps need tight, up-to-date latency
            // routing — probe aggressively.
            rtt_probe_interval_ms: 2_000,
            qlog_path: None,
        }
    }
}

/// Exponential backoff: waits `base * 2^attempts` ms between retries,
/// capped to prevent shift overflow.
fn handshake_backoff_ms(base: u64, attempts: u8) -> u64 {
    let shift = attempts.min(12) as u32;
    base << shift
}

#[derive(Debug)]
pub struct Received {
    pub peer_id: PeerId,
    pub seq: u32,
    pub supersedes: u32,
    pub payload: Vec<u8>,
    /// True if the network marked this packet as having
    /// experienced congestion (ECN `CE` codepoint, RFC 3168).
    /// Only ever set when ECN is enabled in the transport
    /// config AND the platform supports cmsg-based CE
    /// detection (currently Linux). Higher layers (the stream
    /// manager) use this to feed the congestion controller a
    /// gentle backoff signal before any actual loss occurs.
    pub ecn_ce: bool,
}

/// Runtime counters exposed via `Transport::metrics()`.
#[derive(Default)]
pub(crate) struct MetricsInner {
    pub(crate) packets_sent: AtomicU64,
    pub(crate) packets_received: AtomicU64,
    pub(crate) bytes_sent: AtomicU64,
    pub(crate) bytes_received: AtomicU64,
    pub(crate) handshakes_completed: AtomicU64,
    pub(crate) handshake_retries: AtomicU64,
    pub(crate) replays_caught: AtomicU64,
    pub(crate) deadline_dropped: AtomicU64,
    pub(crate) coalesce_dropped: AtomicU64,
    pub(crate) auth_failures: AtomicU64,
    pub(crate) forwarded: AtomicU64,
    pub(crate) beacons_sent: AtomicU64,
    pub(crate) challenges_issued: AtomicU64,
    pub(crate) cookies_accepted: AtomicU64,
    pub(crate) cookies_rejected: AtomicU64,
    pub(crate) handshakes_evicted: AtomicU64,
    pub(crate) path_probes_sent: AtomicU64,
    pub(crate) path_probes_succeeded: AtomicU64,
    pub(crate) peer_id_collisions: AtomicU64,
    pub(crate) auto_rekeys: AtomicU64,
    pub(crate) resumption_tickets_issued: AtomicU64,
    pub(crate) resumption_tickets_received: AtomicU64,
    pub(crate) resumption_attempts: AtomicU64,
    pub(crate) resumptions_completed: AtomicU64,
    pub(crate) resumption_rejects: AtomicU64,
    pub(crate) ecn_ce_received: AtomicU64,
    pub(crate) graceful_probes_initiated: AtomicU64,
    pub(crate) pings_sent: AtomicU64,
    pub(crate) pongs_sent: AtomicU64,
    pub(crate) pongs_received: AtomicU64,
    pub(crate) amplification_blocked: AtomicU64,
    pub(crate) batched_sends: AtomicU64,
    pub(crate) handshakes_inflight: std::sync::atomic::AtomicUsize,
}

/// Snapshot of transport metrics at a point in time.
#[derive(Debug, Clone, Copy)]
pub struct Metrics {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub handshakes_completed: u64,
    pub handshake_retries: u64,
    pub replays_caught: u64,
    pub deadline_dropped: u64,
    pub coalesce_dropped: u64,
    pub auth_failures: u64,
    pub forwarded: u64,
    pub beacons_sent: u64,
    pub challenges_issued: u64,
    pub cookies_accepted: u64,
    pub cookies_rejected: u64,
    pub handshakes_evicted: u64,
    pub path_probes_sent: u64,
    pub path_probes_succeeded: u64,
    pub peer_id_collisions: u64,
    pub auto_rekeys: u64,
    pub resumption_tickets_issued: u64,
    pub resumption_tickets_received: u64,
    pub resumption_attempts: u64,
    pub resumptions_completed: u64,
    pub resumption_rejects: u64,
    pub ecn_ce_received: u64,
    pub graceful_probes_initiated: u64,
    pub pings_sent: u64,
    pub pongs_sent: u64,
    pub pongs_received: u64,
    pub amplification_blocked: u64,
    pub batched_sends: u64,
}

/// Shared inner state — cloned into the background receive task.
///
/// Accessed by submodules (handshake, cookies, path, etc.) via
/// `impl Inner { ... }` blocks, so fields are visible to every
/// file in the `transport` module tree.
pub(crate) struct Inner {
    pub(crate) ifaces: crate::io::InterfaceSet,
    pub(crate) identity: Arc<Identity>,
    pub(crate) local_peer_id: PeerId,
    pub(crate) peers: Arc<PeerShards>,
    pub(crate) routes: Arc<Mutex<RoutingTable>>,
    pub(crate) metrics: MetricsInner,
    pub(crate) config: TransportConfig,
    /// Rotating secrets used to MAC stateless DoS cookies on the
    /// server side. See `handle_hello` for the adaptive check and
    /// `run_cookie_rotate_loop` for rotation.
    pub(crate) cookies: Arc<Mutex<CookieSecrets>>,
    /// Server-side resumption store: ticket id → (psk, expiry,
    /// client identity binding). Populated by
    /// `issue_resumption_ticket` after each successful
    /// handshake; consumed by `handle_resume_hello`.
    pub(crate) resumption_store: Arc<Mutex<ResumptionStore>>,
    /// Client-side per-server ticket cache: peer id → opaque
    /// resumption ticket the server gave us. Populated by
    /// `handle_resumption_ticket`; consumed by `send_resume_hello`.
    pub(crate) client_tickets: Arc<Mutex<StdHashMap<PeerId, ClientTicket>>>,
    /// Optional qlog-style event writer. `None` unless the
    /// user set `TransportConfig::qlog_path`.
    pub(crate) qlog: Option<qlog::QlogWriter>,
    /// CID → PeerId lookup for incoming short-header packets.
    /// Populated when a session reaches Established; cleared
    /// on close. The CID is derived deterministically from the
    /// session key so no extra wire exchange is needed.
    pub(crate) cid_map: Arc<Mutex<StdHashMap<u16, PeerId>>>,
    /// Reverse map: PeerId → the CID that THIS side should
    /// put in outgoing short-header packets to that peer.
    /// (This is the PEER'S rx CID, not ours.)
    pub(crate) peer_out_cid: Arc<Mutex<StdHashMap<PeerId, u16>>>,
}

pub struct Transport {
    inner: Arc<Inner>,
    rx: Mutex<mpsc::Receiver<Received>>,
    /// Kept so `add_interface` can clone it for new recv
    /// loops spawned after bind.
    recv_tx: mpsc::Sender<Received>,
}

impl Transport {
    /// Bind a new transport with the default config.
    pub async fn bind(addr: SocketAddr, identity: Identity) -> Result<Self> {
        Self::bind_with_config(addr, identity, TransportConfig::default()).await
    }

    /// Create a transport over a custom `PacketIO` adapter.
    /// Use this for non-UDP transports (TCP, serial, etc.).
    /// The caller is responsible for establishing the
    /// underlying connection first (e.g., `TcpStream::connect`).
    pub async fn bind_with_io(
        io: Arc<dyn crate::io::PacketIO>,
        identity: Identity,
        config: TransportConfig,
    ) -> Result<Self> {
        Self::bind_inner(io, identity, config).await
    }

    /// Bind a new transport with a custom config over UDP.
    pub async fn bind_with_config(
        addr: SocketAddr,
        identity: Identity,
        config: TransportConfig,
    ) -> Result<Self> {
        let udp_socket = Arc::new(UdpSocket::bind(addr).await?);
        #[cfg(unix)]
        if config.enable_ecn {
            if let Err(e) = ecn::enable_ecn(&udp_socket) {
                warn!(error = %e, "failed to enable ECN on socket");
            }
        }
        let io: Arc<dyn crate::io::PacketIO> =
            Arc::new(crate::io::UdpPacketIO::new(udp_socket));
        Self::bind_inner(io, identity, config).await
    }

    async fn bind_inner(
        io: Arc<dyn crate::io::PacketIO>,
        identity: Identity,
        config: TransportConfig,
    ) -> Result<Self> {
        let cookie_always = config.cookie_always;
        let cookie_threshold = config.cookie_threshold;
        let awaiting_data_timeout_secs = config.awaiting_data_timeout_secs;
        let accept_any_peer = config.accept_any_peer;
        let rtt_probe_interval_ms = config.rtt_probe_interval_ms;
        let recv_channel_capacity = config.recv_channel_capacity;
        let local_peer_id = identity.peer_id();
        let qlog_writer = config.qlog_path.as_deref().and_then(|p| {
            match qlog::QlogWriter::open(p) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!(error = %e, path = ?p, "failed to open qlog file; disabling");
                    None
                }
            }
        });

        let inner = Arc::new(Inner {
            ifaces: crate::io::InterfaceSet::single("default", io),
            identity: Arc::new(identity),
            local_peer_id,
            peers: Arc::new(PeerShards::default()),
            routes: Arc::new(Mutex::new(RoutingTable::default())),
            metrics: MetricsInner::default(),
            config,
            cookies: Arc::new(Mutex::new(CookieSecrets::new())),
            resumption_store: Arc::new(Mutex::new(ResumptionStore::default())),
            client_tickets: Arc::new(Mutex::new(StdHashMap::new())),
            qlog: qlog_writer,
            cid_map: Arc::new(Mutex::new(StdHashMap::new())),
            peer_out_cid: Arc::new(Mutex::new(StdHashMap::new())),
        });

        // ECN was set up by bind_with_config before calling
        // bind_inner, if the IO adapter is UDP.

        let (tx, rx) = mpsc::channel(recv_channel_capacity);
        // Spawn one recv loop per interface so all adapters
        // feed into the same processing pipeline. When a
        // second interface is added later via add_interface,
        // it gets its own recv loop spawned at that time.
        let num_ifaces = inner.ifaces.len();
        for iface_idx in 0..num_ifaces {
            let bg = inner.clone();
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                bg.run_recv_loop_for(tx_clone, iface_idx).await
            });
        }

        let beacon_bg = inner.clone();
        tokio::spawn(async move { beacon_bg.run_beacon_loop().await });

        let retry_bg = inner.clone();
        tokio::spawn(async move { retry_bg.run_handshake_retry_loop().await });

        // RTT probe loop: only spawn when the user actually
        // wants active latency measurement. Skipping it when
        // disabled saves one timer per transport.
        if rtt_probe_interval_ms > 0 {
            let rtt_bg = inner.clone();
            tokio::spawn(async move { rtt_bg.run_rtt_probe_loop().await });
        }

        // Route sweep loop: purges stale mesh routes whose
        // beacon refresh has lapsed. Always spawned — the
        // sweep is cheap and dead-route removal is a
        // correctness requirement for the RTT-weighted
        // router, not an optimization.
        let sweep_bg = inner.clone();
        tokio::spawn(async move { sweep_bg.run_route_sweep_loop().await });

        // Cookie rotation only matters when the cookie path can be
        // reached. Skip spawning the loop entirely in the default
        // fast-path config — it just wastes wake-ups.
        if cookie_always || cookie_threshold != u32::MAX {
            let cookie_bg = inner.clone();
            tokio::spawn(async move { cookie_bg.run_cookie_rotate_loop().await });
        }

        // The AwaitingData eviction reaper is only load-bearing when
        // some path (cookies or accept_any_peer) can produce stuck
        // handshakes. Don't spawn it when eviction is disabled and
        // there's no way for the state to go stale.
        if awaiting_data_timeout_secs != u64::MAX
            && (accept_any_peer
                || cookie_always
                || cookie_threshold != u32::MAX)
        {
            let evict_bg = inner.clone();
            tokio::spawn(async move { evict_bg.run_handshake_eviction_loop().await });
        }

        Ok(Self {
            inner,
            rx: Mutex::new(rx),
            recv_tx: tx,
        })
    }

    /// Attach a new packet I/O interface to this transport
    /// at runtime. Returns the interface index that will be
    /// used for any peers that handshake through this adapter.
    /// A recv loop is spawned immediately so incoming packets
    /// on the new interface are processed alongside existing
    /// ones.
    ///
    /// Use this to make a single DRIFT node bridge between
    /// UDP and TCP (or any other medium):
    ///
    /// ```ignore
    /// let transport = Transport::bind(...).await?;  // UDP on :9000
    /// let tcp = TcpStream::connect("10.0.0.5:443").await?;
    /// let tcp_io = Arc::new(TcpPacketIO::new(tcp)?);
    /// let tcp_idx = transport.add_interface("tcp", tcp_io);
    /// // Now peers can reach us via UDP OR TCP.
    /// ```
    pub fn add_interface(
        &self,
        name: impl Into<String>,
        io: Arc<dyn crate::io::PacketIO>,
    ) -> usize {
        let idx = self.inner.ifaces.add(name, io);
        // Spawn a recv loop for the new interface, feeding
        // into the same mpsc channel as the original.
        let bg = self.inner.clone();
        let tx = self.recv_tx.clone();
        tokio::spawn(async move {
            bg.run_recv_loop_for(tx, idx).await;
        });
        idx
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.ifaces.local_addr()?)
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.inner.local_peer_id
    }

    pub fn local_public(&self) -> [u8; STATIC_KEY_LEN] {
        self.inner.identity.public_bytes()
    }

    /// Returns true if the kernel actually applied the ECN
    /// outbound mark (`ECT(0)`) to this transport's socket.
    /// Configured via `TransportConfig::enable_ecn`. On
    /// platforms or kernels that don't honor the socket option,
    /// this returns false even when ECN was requested.
    pub fn is_ecn_enabled(&self) -> bool {
        #[cfg(unix)]
        {
            if let Some(fd) = self.inner.ifaces.as_raw_fd() {
                // Create a temporary reference to peek at
                // IP_TOS. This is safe because the fd is
                // owned by the Arc'd UdpPacketIO and won't
                // be closed while Inner is alive.
                let mut val: libc::c_int = 0;
                let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as _;
                let rc = unsafe {
                    libc::getsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        libc::IP_TOS,
                        &mut val as *mut _ as *mut _,
                        &mut len,
                    )
                };
                rc == 0 && (val as u8) & 0x03 == 0x02
            } else {
                false
            }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Snapshot current transport metrics. All counters are monotonic
    /// and reset only when the Transport is dropped.
    pub fn metrics(&self) -> Metrics {
        let m = &self.inner.metrics;
        Metrics {
            packets_sent: m.packets_sent.load(Ordering::Relaxed),
            packets_received: m.packets_received.load(Ordering::Relaxed),
            bytes_sent: m.bytes_sent.load(Ordering::Relaxed),
            bytes_received: m.bytes_received.load(Ordering::Relaxed),
            handshakes_completed: m.handshakes_completed.load(Ordering::Relaxed),
            handshake_retries: m.handshake_retries.load(Ordering::Relaxed),
            replays_caught: m.replays_caught.load(Ordering::Relaxed),
            deadline_dropped: m.deadline_dropped.load(Ordering::Relaxed),
            coalesce_dropped: m.coalesce_dropped.load(Ordering::Relaxed),
            auth_failures: m.auth_failures.load(Ordering::Relaxed),
            forwarded: m.forwarded.load(Ordering::Relaxed),
            beacons_sent: m.beacons_sent.load(Ordering::Relaxed),
            challenges_issued: m.challenges_issued.load(Ordering::Relaxed),
            cookies_accepted: m.cookies_accepted.load(Ordering::Relaxed),
            cookies_rejected: m.cookies_rejected.load(Ordering::Relaxed),
            handshakes_evicted: m.handshakes_evicted.load(Ordering::Relaxed),
            path_probes_sent: m.path_probes_sent.load(Ordering::Relaxed),
            path_probes_succeeded: m.path_probes_succeeded.load(Ordering::Relaxed),
            peer_id_collisions: m.peer_id_collisions.load(Ordering::Relaxed),
            auto_rekeys: m.auto_rekeys.load(Ordering::Relaxed),
            resumption_tickets_issued: m.resumption_tickets_issued.load(Ordering::Relaxed),
            resumption_tickets_received: m.resumption_tickets_received.load(Ordering::Relaxed),
            resumption_attempts: m.resumption_attempts.load(Ordering::Relaxed),
            resumptions_completed: m.resumptions_completed.load(Ordering::Relaxed),
            resumption_rejects: m.resumption_rejects.load(Ordering::Relaxed),
            ecn_ce_received: m.ecn_ce_received.load(Ordering::Relaxed),
            graceful_probes_initiated: m.graceful_probes_initiated.load(Ordering::Relaxed),
            pings_sent: m.pings_sent.load(Ordering::Relaxed),
            pongs_sent: m.pongs_sent.load(Ordering::Relaxed),
            pongs_received: m.pongs_received.load(Ordering::Relaxed),
            amplification_blocked: m.amplification_blocked.load(Ordering::Relaxed),
            batched_sends: m.batched_sends.load(Ordering::Relaxed),
        }
    }

    /// TEST HELPER: force an immediate rotation of the cookie
    /// secret. Previous becomes old-current, current becomes a
    /// fresh random. Used to exercise the across-rotation grace
    /// window without waiting for the scheduled rotation task.
    #[doc(hidden)]
    pub async fn test_rotate_cookies(&self) {
        self.inner.cookies.lock().await.rotate();
    }

    /// TEST HELPER: snapshot the routing table entry for a
    /// destination, returning `(next_hop, cost_us)` or None
    /// if no route is present. Used by the RTT-weighted
    /// routing integration test to verify the router picked
    /// the correct next-hop among competing beacon
    /// advertisements.
    #[doc(hidden)]
    pub async fn test_lookup_route(
        &self,
        dst: &PeerId,
    ) -> Option<(SocketAddr, u32)> {
        self.inner
            .routes
            .lock()
            .await
            .lookup_entry(dst)
            .map(|e| (e.next_hop, e.cost_us))
    }

    /// TEST HELPER: forcibly set `peer.next_tx_seq` to the given
    /// value. Intended only for tests that need to drive the seq
    /// counter past points that would take too long to reach via
    /// real traffic (e.g. the `SEQ_SEND_CEILING` check). Returns
    /// false if the peer is unknown.
    #[doc(hidden)]
    pub async fn test_bump_peer_seq(&self, peer_id: &PeerId, value: u32) -> bool {
        let mut peers = self.inner.peers.lock_for(peer_id).await;
        match peers.get_mut(peer_id) {
            Some(peer) => {
                peer.next_tx_seq = value;
                true
            }
            None => false,
        }
    }

    /// Current number of peers parked in `AwaitingData` — i.e.,
    /// handshakes where the server has derived a session key but
    /// has not yet seen the client's first DATA packet. Reads a
    /// single atomic, no peer-table lock.
    pub fn handshakes_in_progress(&self) -> usize {
        self.inner
            .metrics
            .handshakes_inflight
            .load(Ordering::Relaxed)
    }

    /// Register a mesh route: packets destined for `dst` should be forwarded
    /// to `next_hop_addr` instead of sent directly. The destination peer
    /// still needs to be known (add_peer) for session establishment.
    pub async fn add_route(&self, dst: PeerId, next_hop_addr: SocketAddr) {
        self.inner
            .routes
            .lock()
            .await
            .insert_static(dst, next_hop_addr);
    }

    /// Explicitly update the known remote address for a peer.
    /// Call this when the app knows the peer has moved (e.g., mobile
    /// handoff, app-level rendezvous update). The existing session is
    /// preserved — identity remains bound to the same pubkey, only the
    /// socket address changes. Returns true if the peer was found.
    pub async fn update_peer_addr(&self, peer_id: &PeerId, new_addr: SocketAddr) -> bool {
        let mut peers = self.inner.peers.lock_for(peer_id).await;
        match peers.get_mut(peer_id) {
            Some(peer) => {
                peer.addr = new_addr;
                true
            }
            None => false,
        }
    }

    /// Graceful connection migration. Asks the transport to
    /// validate `candidate_addr` as a new path to `peer` *before*
    /// the current path breaks, and swap over once validation
    /// succeeds. Use this when the OS tells you the network is
    /// about to change (wifi → cellular handoff, VPN reconnect,
    /// etc.) — by the time the old path fails, the new one is
    /// already validated and there's no traffic stall.
    ///
    /// The probe is AEAD-authenticated end-to-end, so an
    /// off-path attacker can't trick us into migrating to an
    /// address they control.
    ///
    /// Returns immediately. The actual migration completes when
    /// the matching `PathResponse` arrives — observe via
    /// `Metrics::path_probes_succeeded`. Errors:
    /// `UnknownPeer` (no such peer / not Established);
    /// `QueueFull` (an unrelated probe is already in flight).
    pub async fn probe_candidate_path(
        &self,
        peer_id: &PeerId,
        candidate_addr: SocketAddr,
    ) -> Result<()> {
        self.inner
            .probe_candidate_path(peer_id, candidate_addr)
            .await
    }

    /// Register a peer by its static X25519 public key.
    ///
    /// Semantics:
    /// - If no peer with this derived id exists, create one and
    ///   return its id.
    /// - If a peer with the same id AND the same static pubkey
    ///   already exists, idempotent no-op — returns its id.
    /// - If a peer with the same id but a DIFFERENT static pubkey
    ///   exists, returns `Err(DriftError::PeerIdCollision)`. Peer
    ///   ids are 64-bit BLAKE2b hashes, so a legitimate collision
    ///   is astronomically unlikely; this error means either a
    ///   test mix-up or a birthday-style namespace attack.
    ///
    /// Use `update_peer_addr` to change the address of an
    /// existing peer without re-handshaking.
    pub async fn add_peer(
        &self,
        peer_static_pub: [u8; STATIC_KEY_LEN],
        addr: SocketAddr,
        direction: Direction,
    ) -> Result<PeerId> {
        let id = derive_peer_id(&peer_static_pub);
        let mut peers = self.inner.peers.lock_for(&id).await;
        match peers.get(&id) {
            Some(existing) if existing.peer_static_pub != peer_static_pub => {
                self.inner
                    .metrics
                    .peer_id_collisions
                    .fetch_add(1, Ordering::Relaxed);
                warn!(peer_id = ?id, "peer id collision in add_peer; rejecting");
                Err(DriftError::PeerIdCollision)
            }
            Some(_) => Ok(id),
            None => {
                let peer = Peer::new(id, addr, peer_static_pub, direction);
                peers.insert(peer);
                Ok(id)
            }
        }
    }

    pub async fn send_data(
        &self,
        dst: &PeerId,
        payload: &[u8],
        deadline_ms: u16,
        coalesce_group: u32,
    ) -> Result<()> {
        self.inner
            .send_data(dst, payload, deadline_ms, coalesce_group)
            .await
    }

    /// Batched variant: build every DATA packet in the batch
    /// under the peer locks, then ship them to the kernel in
    /// one `sendmmsg(2)` call on Linux (or a sequential
    /// fallback on other platforms). For high-throughput
    /// senders, this cuts syscall overhead roughly N-fold
    /// versus calling `send_data` in a loop. Returns the
    /// number of packets accepted by the kernel — may be
    /// less than `items.len()` if the kernel partially sends.
    ///
    /// All targets must be established; a peer that's
    /// still mid-handshake is skipped (its payload is
    /// dropped and not counted).
    pub async fn send_data_batch(
        &self,
        items: &[(PeerId, Vec<u8>)],
    ) -> Result<usize> {
        self.inner.send_data_batch(items).await
    }

    /// Gracefully close the session with `dst`. Sends an
    /// AEAD-authenticated `Close` packet to the peer, then drops
    /// the peer locally (auto-registered) or resets its handshake
    /// state (explicit). Subsequent `send_data` to this peer will
    /// re-trigger the handshake. Returns `Err(UnknownPeer)` if
    /// the peer isn't in our table or has no live session.
    pub async fn close_peer(&self, dst: &PeerId) -> Result<()> {
        self.inner.close_peer(dst).await
    }

    /// Rekey an established session in place. Generates a fresh
    /// 32-byte salt, derives new keys from `BLAKE2b("drift-rekey-v1"
    /// ‖ old_key ‖ salt)`, sends a `RekeyRequest` to the peer
    /// (sealed with the OLD key), and installs the new keys
    /// locally. The old keys are held for a grace window on the
    /// receive side so in-flight DATA can still be decrypted.
    /// After the peer replies with `RekeyAck`, the initiator
    /// drops the old keys entirely.
    ///
    /// Used to sidestep the `SEQ_SEND_CEILING` on long-lived
    /// high-throughput sessions without forcing a full
    /// re-handshake. Returns `Err(UnknownPeer)` if the session
    /// isn't currently `Established`.
    pub async fn rekey(&self, dst: &PeerId) -> Result<()> {
        self.inner.rekey(dst).await
    }

    /// Export the resumption ticket (if any) currently held for
    /// `peer` as an opaque blob. Persist this to disk / keychain
    /// to skip the X25519 static DH on a future reconnect.
    ///
    /// **The blob carries sensitive PSK material** — store it
    /// with the same care as a private key. Returns
    /// `Err(UnknownPeer)` if no ticket is currently cached for
    /// this peer.
    pub async fn export_resumption_ticket(&self, peer: &PeerId) -> Result<Vec<u8>> {
        let tickets = self.inner.client_tickets.lock().await;
        let ticket = tickets.get(peer).ok_or(DriftError::UnknownPeer)?;
        if ticket.expiry <= std::time::SystemTime::now() {
            return Err(DriftError::UnknownPeer);
        }
        Ok(ticket.to_bytes())
    }

    /// Install a previously exported resumption ticket for
    /// `peer`. The next `send_data` to this peer will use a
    /// `ResumeHello` instead of a full HELLO. Returns
    /// `Err(AuthFailed)` if the blob is malformed or doesn't
    /// match the peer's stored static pubkey.
    pub async fn import_resumption_ticket(
        &self,
        peer: &PeerId,
        blob: &[u8],
    ) -> Result<()> {
        let ticket = ClientTicket::from_bytes(blob).ok_or(DriftError::AuthFailed)?;
        if ticket.server_id != *peer {
            return Err(DriftError::AuthFailed);
        }
        if ticket.expiry <= std::time::SystemTime::now() {
            return Err(DriftError::AuthFailed);
        }
        // Verify the ticket's bound server pubkey matches what
        // we know about this peer (if we know about them at
        // all). Allows importing tickets before add_peer; in
        // that case the static_pub binding is checked later
        // during the resumption attempt itself.
        {
            let peers = self.inner.peers.lock_for(peer).await;
            if let Some(p) = peers.get(peer) {
                if p.peer_static_pub != ticket.server_static_pub {
                    return Err(DriftError::AuthFailed);
                }
            }
        }
        self.inner
            .client_tickets
            .lock()
            .await
            .insert(*peer, ticket);
        Ok(())
    }

    /// Await the next authenticated DATA packet. Returns None if the
    /// background task has shut down (socket closed).
    pub async fn recv(&self) -> Option<Received> {
        self.rx.lock().await.recv().await
    }
}

/// How long the previous session keys stay alive after a rekey,
/// so in-flight DATA sealed under the old key can still decrypt.
/// Kept generous — two full RTTs on a typical WAN link.
const REKEY_GRACE: Duration = Duration::from_secs(2);

/// Auto-rekey trigger: once a peer's `next_tx_seq` crosses this
/// value, `send_data` will transparently rekey before sending so
/// the caller never sees `SessionExhausted`. Set to 75% of
/// `SEQ_SEND_CEILING` so there's still ~512M packets of headroom
/// to complete the rekey round-trip even if the link is slow.
const AUTO_REKEY_THRESHOLD: u32 = (SEQ_SEND_CEILING / 4) * 3;

impl Inner {
    /// Initiator-side rekey. Builds a new key from the current
    /// one + a fresh salt, installs it locally, sends a
    /// `RekeyRequest` sealed with the OLD key so the peer can
    /// do the same derivation. Seq resets on rekey because the
    /// new key gives us a fresh nonce namespace — no reuse
    /// risk.
    async fn rekey(&self, dst: &PeerId) -> Result<()> {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        // Build the RekeyRequest under the peer lock so the
        // old-key seal happens atomically with the state swap.
        let (wire, addr, new_key_bytes) = {
            let mut peers = self.peers.lock_for(dst).await;
            let peer = peers.get_mut(dst).ok_or(DriftError::UnknownPeer)?;
            let (old_tx, old_rx, old_key_bytes) = match &peer.handshake {
                HandshakeState::Established {
                    tx,
                    rx,
                    key_bytes,
                    ..
                } => (tx.clone(), rx.clone(), *key_bytes),
                _ => return Err(DriftError::UnknownPeer),
            };

            // 1. Build the RekeyRequest packet, sealed with the
            //    OLD tx key, body = 32 salt bytes.
            let seq = peer
                .next_seq_checked()
                .ok_or(DriftError::SessionExhausted)?;
            let mut header =
                Header::new(PacketType::RekeyRequest, seq, self.local_peer_id, peer.id);
            header.payload_len = (32 + AUTH_TAG_LEN) as u16;
            header.send_time_ms = peer.send_time_ms();
            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);
            let aad = canonical_aad(&hbuf);
            let mut wire = Vec::with_capacity(HEADER_LEN + 32 + AUTH_TAG_LEN);
            wire.extend_from_slice(&hbuf);
            old_tx.seal_into(
                seq,
                PacketType::RekeyRequest as u8,
                &aad,
                &salt,
                &mut wire,
            )?;

            // 2. Derive the new key and install it. Seq resets
            //    so the new (key, nonce) namespace starts at 1.
            let new_key_bytes = rekey_derive(&old_key_bytes, &salt);
            let new_tx = SessionKey::new(&new_key_bytes, Direction::Initiator);
            let new_rx = SessionKey::new(&new_key_bytes, Direction::Responder);
            peer.reset_seq();
            peer.mark_session_start();
            peer.handshake = HandshakeState::Established {
                tx: new_tx,
                rx: new_rx,
                key_bytes: new_key_bytes,
                prev: Some(PrevSession {
                    tx: old_tx,
                    rx: old_rx,
                    installed_at: Instant::now(),
                }),
            };

            (wire, peer.addr, new_key_bytes)
        };

        let iface = self.iface_for(dst).await;
        self.ifaces.send_for(iface, &wire, addr).await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(wire.len() as u64, Ordering::Relaxed);
        // Refresh CID maps for the new session key.
        self.install_cids(*dst, &new_key_bytes, true).await;
        Ok(())
    }

    /// Receiver side of the rekey handshake. Decrypt the 32-byte
    /// salt with the CURRENT rx key (which is the old one from
    /// the peer's perspective — it sealed before switching).
    /// Derive the same new key, install it locally with the old
    /// one in `prev`, and ack with a `RekeyAck` sealed under the
    /// NEW tx key so the initiator knows it's safe to drop prev.
    async fn handle_rekey_request(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let peer_id = header.src_id;

        let (ack_wire, ack_addr, new_key_bytes_rekey) = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;
            let (old_tx, old_rx, old_key_bytes) = match &peer.handshake {
                HandshakeState::Established {
                    tx,
                    rx,
                    key_bytes,
                    ..
                } => (tx.clone(), rx.clone(), *key_bytes),
                _ => return Err(DriftError::UnknownPeer),
            };

            // Decrypt body with current rx.
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            let salt_bytes = old_rx.open(
                header.seq,
                PacketType::RekeyRequest as u8,
                &aad,
                body,
            )?;
            if salt_bytes.len() != 32 {
                return Err(DriftError::PacketTooShort {
                    got: salt_bytes.len(),
                    need: 32,
                });
            }
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&salt_bytes);

            let new_key_bytes_val = rekey_derive(&old_key_bytes, &salt);
            // Responder here is the side that received the
            // request — we seal outgoing (including the ack)
            // with Responder-direction nonces, since our peer
            // will decrypt with Initiator-direction rx.
            let new_tx = SessionKey::new(&new_key_bytes_val, Direction::Responder);
            let new_rx = SessionKey::new(&new_key_bytes_val, Direction::Initiator);

            peer.reset_seq();
            peer.mark_session_start();
            peer.handshake = HandshakeState::Established {
                tx: new_tx,
                rx: new_rx,
                key_bytes: new_key_bytes_val,
                prev: Some(PrevSession {
                    tx: old_tx,
                    rx: old_rx,
                    installed_at: Instant::now(),
                }),
            };

            // Build the RekeyAck sealed with the NEW tx.
            let ack_seq = peer
                .next_seq_checked()
                .ok_or(DriftError::SessionExhausted)?;
            let mut ack_header =
                Header::new(PacketType::RekeyAck, ack_seq, self.local_peer_id, peer_id);
            ack_header.payload_len = AUTH_TAG_LEN as u16;
            ack_header.send_time_ms = peer.send_time_ms();
            let mut ack_hbuf = [0u8; HEADER_LEN];
            ack_header.encode(&mut ack_hbuf);
            let ack_aad = canonical_aad(&ack_hbuf);
            let (tx_ref, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
            let mut ack_wire = Vec::with_capacity(HEADER_LEN + AUTH_TAG_LEN);
            ack_wire.extend_from_slice(&ack_hbuf);
            tx_ref.seal_into(ack_seq, PacketType::RekeyAck as u8, &ack_aad, b"", &mut ack_wire)?;

            (ack_wire, peer.addr, new_key_bytes_val)
        };

        self.ifaces.send_for(self.iface_for(&peer_id).await, &ack_wire, ack_addr).await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(ack_wire.len() as u64, Ordering::Relaxed);
        // Refresh CID maps for the rekeyed session (Responder side).
        self.install_cids(peer_id, &new_key_bytes_rekey, false).await;
        Ok(())
    }

    /// Received a `RekeyAck` from the peer. It's sealed with the
    /// NEW key — the fact that it decrypts proves the peer has
    /// successfully installed the new keys, so we can drop our
    /// `prev` slot immediately without waiting out the grace
    /// window.
    async fn handle_rekey_ack(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let peer_id = header.src_id;
        let mut peers = self.peers.lock_for(&peer_id).await;
        let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;

        let mut hbuf = [0u8; HEADER_LEN];
        hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
        let aad = canonical_aad(&hbuf);

        // The ack is sealed with the NEW key — so use the
        // current rx (which is already the new one, since
        // `rekey` swapped it in before sending the request).
        //
        // NOTE: We deliberately do NOT drop `prev` here. Even
        // after a successful RekeyAck the peer may still have
        // OLD-key DATA packets in flight — anything it
        // transmitted between us sending RekeyRequest and it
        // receiving and processing that request. Those packets
        // need to fall back to `prev.rx` in `handle_data`.
        // `prev` expires on the grace-window timer instead.
        if let HandshakeState::Established { rx, .. } = &mut peer.handshake {
            let _ = rx.open(header.seq, PacketType::RekeyAck as u8, &aad, body)?;
        }
        Ok(())
    }

    async fn close_peer(&self, dst: &PeerId) -> Result<()> {
        // Build the Close wire packet under the peer lock, then
        // send it outside the lock so the socket.await doesn't
        // block peer-table users.
        let (bytes, addr) = {
            let mut peers = self.peers.lock_for(dst).await;
            let peer = peers.get_mut(dst).ok_or(DriftError::UnknownPeer)?;
            if !peer.handshake.is_ready_for_data() {
                return Err(DriftError::UnknownPeer);
            }
            let was_awaiting_data =
                matches!(peer.handshake, HandshakeState::AwaitingData { .. });
            let wire = build_close_packet(self.local_peer_id, peer)?;
            let addr = peer.addr;

            // Drop local state immediately — we won't accept any
            // further DATA on this session and won't retry the
            // Close if it gets lost.
            if peer.auto_registered {
                peers.remove(dst);
            } else {
                peer.handshake = HandshakeState::Pending;
                peer.pending.clear();
                peer.session_epoch = None;
                peer.probing = None;
            }
            if was_awaiting_data {
                self.metrics
                    .handshakes_inflight
                    .fetch_sub(1, Ordering::Relaxed);
            }
            (wire, addr)
        };

        self.ifaces.send_for(self.iface_for(dst).await, &bytes, addr).await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn send_data(
        &self,
        dst: &PeerId,
        payload: &[u8],
        deadline_ms: u16,
        coalesce_group: u32,
    ) -> Result<()> {
        if payload.len() > MAX_PAYLOAD {
            return Err(DriftError::PacketTooShort {
                got: MAX_PAYLOAD,
                need: payload.len(),
            });
        }

        // Auto-rekey: if the peer's tx seq is approaching the
        // wraparound ceiling, rekey transparently before sending so
        // the caller never sees `SessionExhausted`. Cheap O(1)
        // peek under the peer lock; we drop the lock before the
        // rekey round-trip to avoid holding it across an await.
        let needs_rekey = {
            let peers = self.peers.lock_for(dst).await;
            peers
                .get(dst)
                .map(|p| {
                    matches!(p.handshake, HandshakeState::Established { .. })
                        && p.next_tx_seq >= AUTO_REKEY_THRESHOLD
                })
                .unwrap_or(false)
        };
        if needs_rekey {
            self.metrics.auto_rekeys.fetch_add(1, Ordering::Relaxed);
            self.rekey(dst).await?;
        }

        // Resumption: if we have a stored ticket for this peer
        // AND the peer is currently Pending (no in-flight
        // handshake), send a ResumeHello instead of a normal
        // HELLO. This skips the X25519 static DH on both sides.
        // We only enter this branch from the Initiator side of a
        // brand-new connection — once AwaitingAck or Established,
        // the normal flow takes over.
        let try_resume = {
            let have_ticket = {
                let tickets = self.client_tickets.lock().await;
                tickets
                    .get(dst)
                    .map(|t| t.expiry > std::time::SystemTime::now())
                    .unwrap_or(false)
            };
            if have_ticket {
                let peers = self.peers.lock_for(dst).await;
                peers
                    .get(dst)
                    .map(|p| {
                        matches!(p.handshake, HandshakeState::Pending)
                            && p.direction == Direction::Initiator
                    })
                    .unwrap_or(false)
            } else {
                false
            }
        };
        if try_resume {
            // Queue the payload first so handle_resume_ack can
            // flush it when the server replies.
            {
                let mut peers = self.peers.lock_for(dst).await;
                if let Some(peer) = peers.get_mut(dst) {
                    if peer.pending.len() >= self.config.pending_queue_cap {
                        return Err(DriftError::QueueFull);
                    }
                    peer.pending.push(PendingSend {
                        payload: payload.to_vec(),
                        deadline_ms,
                        coalesce_group,
                    });
                }
            }
            return self.send_resume_hello(*dst).await;
        }

        let learned_route = self.routes.lock().await.lookup(dst);
        // Look up the outgoing CID for short-header path.
        // This is cheap (one hash-map lookup under a
        // separate lock from the peer table).
        let out_cid = self.peer_out_cid.lock().await.get(dst).copied();

        let action = {
            let mut peers = self.peers.lock_for(dst).await;
            let peer = peers.get_mut(dst).ok_or(DriftError::UnknownPeer)?;

            // Mesh-routed peers always need hop_ttl and long
            // headers so intermediate nodes can forward. For
            // direct peers, suppress learned routes once
            // Established to prevent a malicious neighbor from
            // advertising a 1-hop route and siphoning traffic.
            let mesh_next_hop = if peer.via_mesh {
                learned_route.or(Some(peer.addr))
            } else if matches!(
                peer.handshake,
                HandshakeState::Established { .. }
            ) {
                None
            } else {
                learned_route
            };

            let effective_cid = if peer.via_mesh { None } else { out_cid };

            if peer.handshake.is_ready_for_data() {
                build_data_packet_with_cid(
                    self.local_peer_id,
                    peer,
                    payload,
                    deadline_ms,
                    coalesce_group,
                    mesh_next_hop,
                    effective_cid,
                )?
            } else {
                // Fail fast if the handshake has already burned
                // through all retries — there's no point queuing
                // more data that will never be delivered.
                if let HandshakeState::AwaitingAck { attempts, .. } = &peer.handshake {
                    if *attempts >= self.config.handshake_max_attempts {
                        return Err(DriftError::HandshakeExhausted);
                    }
                }
                // Bound the pre-handshake queue. An app that keeps
                // calling send_data on a stuck peer would otherwise
                // leak memory without bound.
                if peer.pending.len() >= self.config.pending_queue_cap {
                    return Err(DriftError::QueueFull);
                }
                peer.pending.push(PendingSend {
                    payload: payload.to_vec(),
                    deadline_ms,
                    coalesce_group,
                });
                if matches!(peer.handshake, HandshakeState::Pending)
                    && peer.direction == Direction::Initiator
                {
                    build_hello(
                        self.local_peer_id,
                        peer,
                        &self.identity,
                        mesh_next_hop,
                    )
                } else {
                    SendAction::Queued
                }
            }
        };

        self.dispatch(action).await
    }

    /// Build and ship a batch of outgoing DATA packets in a
    /// single syscall (Linux `sendmmsg(2)`; sequential
    /// fallback elsewhere). Peers that aren't yet in
    /// Established state are silently skipped — this is a
    /// fast-path API for bulk senders, not a general-purpose
    /// send.
    async fn send_data_batch(
        &self,
        items: &[(PeerId, Vec<u8>)],
    ) -> Result<usize> {
        if items.is_empty() {
            return Ok(0);
        }
        // Build all the wires under single-shard locks.
        // We group items by shard to amortize lock
        // acquisition, but for simplicity fall back to
        // per-item lock_for — good enough for v1.
        let mut batch: Vec<(Vec<u8>, SocketAddr, usize)> = Vec::with_capacity(items.len());
        for (dst, payload) in items {
            if payload.len() > MAX_PAYLOAD {
                continue;
            }
            let mut peers = self.peers.lock_for(dst).await;
            let Some(peer) = peers.get_mut(dst) else {
                continue;
            };
            if !matches!(peer.handshake, HandshakeState::Established { .. }) {
                // Skip non-Established peers — the caller
                // can use `send_data` for handshake-time
                // queueing.
                continue;
            }
            if let Ok(SendAction::Data(bytes, target, iface)) = build_data_packet(
                self.local_peer_id,
                peer,
                payload,
                0,
                0,
                None,
            ) {
                batch.push((bytes, target, iface));
            }
        }

        if batch.is_empty() {
            return Ok(0);
        }

        // Hand the built batch to the platform-specific
        // sender. On Linux this is one `sendmmsg`; elsewhere
        // it's a loop of `send_to`.
        let sent = {
            let mut n = 0usize;
            for (bytes, addr, iface) in &batch {
                self.ifaces.send_for(*iface, bytes, *addr).await?;
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                n += 1;
            }
            self.metrics.batched_sends.fetch_add(1, Ordering::Relaxed);
            n
        };
        Ok(sent)
    }

    /// Populate the CID lookup maps for an established
    /// session so short-header packets can be sent and
    /// Quick lookup: which interface reaches this peer?
    /// Returns 0 (default) if the peer is unknown.
    async fn iface_for(&self, peer_id: &PeerId) -> usize {
        let peers = self.peers.lock_for(peer_id).await;
        peers.get(peer_id).map(|p| p.interface_id).unwrap_or(0)
    }

    /// received. `local_is_initiator` is true on the side
    /// that sent HELLO (the Initiator).
    async fn install_cids(
        &self,
        peer_id: PeerId,
        session_key: &[u8; 32],
        local_is_initiator: bool,
    ) {
        use crate::short_header::{derive_initiator_rx_cid, derive_responder_rx_cid};

        // My receive CID — what the peer should put in
        // short-header packets TO me.
        let my_rx_cid = if local_is_initiator {
            derive_initiator_rx_cid(session_key)
        } else {
            derive_responder_rx_cid(session_key)
        };
        // Peer's receive CID — what I put in short-header
        // packets TO the peer.
        let peer_rx_cid = if local_is_initiator {
            derive_responder_rx_cid(session_key)
        } else {
            derive_initiator_rx_cid(session_key)
        };

        self.cid_map.lock().await.insert(my_rx_cid, peer_id);
        self.peer_out_cid.lock().await.insert(peer_id, peer_rx_cid);
    }

    async fn dispatch(&self, action: SendAction) -> Result<()> {
        match action {
            SendAction::Data(bytes, addr, iface) => {
                self.ifaces.send_for(iface, &bytes, addr).await?;
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics.bytes_sent.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                if let Some(q) = &self.qlog {
                    q.log_packet_sent("Data", &addr.to_string(), bytes.len(), 0);
                }
            }
            SendAction::Hello(bytes, addr, iface) => {
                self.ifaces.send_for(iface, &bytes, addr).await?;
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics.bytes_sent.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                debug!("sent HELLO to {:?}", addr);
                if let Some(q) = &self.qlog {
                    q.log_packet_sent("Hello", &addr.to_string(), bytes.len(), 0);
                }
            }
            SendAction::Queued => {}
        }
        Ok(())
    }

    async fn run_recv_loop_for(
        self: Arc<Self>,
        tx: mpsc::Sender<Received>,
        iface_idx: usize,
    ) {
        let iface = match self.ifaces.get(iface_idx) {
            Some(io) => io.clone(),
            None => return,
        };
        let mut buf = vec![0u8; MAX_PACKET];
        loop {
            let (n, src, ecn_ce) = match iface.recv_from(&mut buf).await {
                Ok((n, src)) => (n, src, false),
                Err(e) => {
                    warn!(error = %e, "recv_from failed");
                    break;
                }
            };

            self.metrics.packets_received.fetch_add(1, Ordering::Relaxed);
            self.metrics.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
            if ecn_ce {
                self.metrics
                    .ecn_ce_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            let received_at = Instant::now();
            let data = &buf[..n];

            // qlog: emit a structured packet_received event
            // before dispatch. We peek the header type for the
            // category tag but let `process_incoming` do the
            // actual auth + dispatch.
            if let Some(q) = &self.qlog {
                if let Ok(h) = Header::decode(&data[..data.len().min(HEADER_LEN)]) {
                    q.log_packet_received(
                        format!("{:?}", h.packet_type).as_str(),
                        &src.to_string(),
                        n,
                        h.seq,
                    );
                }
            }

            // Short-header fast path: if the version nibble
            // is 0x2, this is a compact DATA packet from an
            // established direct session. Look up the CID →
            // peer, decrypt, and deliver without touching the
            // full long-header parser.
            if crate::short_header::is_short_header(data) {
                match self.process_short_header(data, src, received_at, ecn_ce).await {
                    Ok(Some(r)) => {
                        if tx.send(r).await.is_err() {
                            debug!("recv channel closed (short)");
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        if matches!(e, DriftError::AuthFailed) {
                            self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                        }
                        warn!(error = %e, ?src, "dropped invalid short-header packet");
                    }
                }
                continue;
            }

            match self.process_incoming(data, src, received_at, ecn_ce, iface_idx).await {
                Ok(Some(r)) => {
                    if tx.send(r).await.is_err() {
                        debug!("recv channel closed");
                        break;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    // Classify the error for metrics
                    match &e {
                        DriftError::Replay(_) => {
                            self.metrics.replays_caught.fetch_add(1, Ordering::Relaxed);
                        }
                        DriftError::AuthFailed => {
                            self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                        }
                        DriftError::DeadlineExpired => {
                            self.metrics.deadline_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                    warn!(error = %e, ?src, "dropped invalid packet");
                }
            }
        }
    }

    /// Fast path for short-header DATA packets. Looks up the
    /// CID in the peer map, decrypts with the matching rx
    /// key, and returns a `Received` ready for delivery.
    /// Also handles path validation: if the packet arrives
    /// from a different source than peer.addr, issues a
    /// PathChallenge just like the long-header handle_data
    /// path does.
    async fn process_short_header(
        &self,
        data: &[u8],
        src: SocketAddr,
        received_at: Instant,
        ecn_ce: bool,
    ) -> Result<Option<Received>> {
        let (cid, seq, body) = crate::short_header::decode_short(data)?;

        let peer_id = {
            let map = self.cid_map.lock().await;
            *map.get(&cid).ok_or(DriftError::UnknownPeer)?
        };

        let (payload, probe) = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;
            let (_, rx) = peer
                .handshake
                .session()
                .ok_or(DriftError::UnknownPeer)?;
            let aad = &data[..crate::short_header::SHORT_HEADER_LEN];
            let plaintext = match rx.open(seq, PacketType::Data as u8, aad, body) {
                Ok(pt) => pt,
                Err(err) => {
                    // Rekey grace: try the prev rx if current fails.
                    let mut recovered = None;
                    if let HandshakeState::Established { prev, .. } = &mut peer.handshake {
                        if let Some(p) = prev {
                            if p.installed_at.elapsed() <= REKEY_GRACE {
                                if let Ok(pt) = p.rx.open(seq, PacketType::Data as u8, aad, body) {
                                    recovered = Some(pt);
                                }
                            }
                        }
                    }
                    match recovered {
                        Some(pt) => pt,
                        None => return Err(err),
                    }
                }
            };
            peer.check_and_update_replay(seq)?;

            // Path validation: same logic as the long-header
            // handle_data path. If this short-header DATA
            // arrived from a new source, start a path probe.
            let probe = if peer.addr != src
                && matches!(peer.handshake, HandshakeState::Established { .. })
            {
                let now = Instant::now();
                let refresh = match &peer.probing {
                    None => true,
                    Some(p) if p.addr != src => true,
                    Some(p) if now.duration_since(p.started) > PATH_PROBE_RETRY => true,
                    _ => false,
                };
                if refresh {
                    let mut challenge = [0u8; PATH_CHALLENGE_LEN];
                    rand::thread_rng().fill_bytes(&mut challenge);
                    peer.probing = Some(PathProbe {
                        addr: src,
                        challenge,
                        started: now,
                    });
                    build_path_challenge_packet(
                        self.local_peer_id,
                        peer,
                        &challenge,
                    )
                    .ok()
                    .map(|bytes| (bytes, src))
                } else {
                    None
                }
            } else {
                None
            };

            peer.last_seen = received_at;
            (plaintext, probe)
        };

        if let Some((bytes, addr)) = probe {
            if let Err(e) = self.ifaces.send_for(self.iface_for(&peer_id).await, &bytes, addr).await {
                debug!(error = %e, "PathChallenge send failed (short hdr)");
            } else {
                self.metrics.path_probes_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics.bytes_sent.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
        }

        Ok(Some(Received {
            peer_id,
            seq,
            supersedes: 0,
            payload,
            ecn_ce,
        }))
    }

    async fn process_incoming(
        &self,
        data: &[u8],
        src: SocketAddr,
        received_at: Instant,
        ecn_ce: bool,
        iface_idx: usize,
    ) -> Result<Option<Received>> {
        if data.len() < HEADER_LEN {
            return Err(DriftError::PacketTooShort {
                got: data.len(),
                need: HEADER_LEN,
            });
        }
        let header = Header::decode(&data[..HEADER_LEN])?;
        let body = &data[HEADER_LEN..];

        // Mesh forwarding: any packet not addressed to us, still with hops
        // remaining, gets forwarded without inspection of the ciphertext.
        if header.dst_id != self.local_peer_id && header.hop_ttl > 1 {
            // SECURITY: cap the hop budget of incoming packets before
            // we agree to forward them. An attacker could otherwise
            // set hop_ttl to u8::MAX (255) and force us to amplify a
            // single datagram into many network hops.
            if header.hop_ttl > MAX_INCOMING_HOP_TTL {
                debug!(
                    hop_ttl = header.hop_ttl,
                    "dropping incoming packet with excessive hop_ttl"
                );
                return Ok(None);
            }
            self.forward_packet(data, &header).await?;
            return Ok(None);
        }

        match header.packet_type {
            PacketType::Hello => {
                self.handle_hello(&header, body, src, iface_idx).await?;
                Ok(None)
            }
            PacketType::HelloAck => {
                self.handle_hello_ack(&header, body).await?;
                Ok(None)
            }
            PacketType::Challenge => {
                self.handle_challenge(&header, body).await?;
                Ok(None)
            }
            PacketType::PathChallenge => {
                self.handle_path_challenge(&header, data, body, src).await?;
                Ok(None)
            }
            PacketType::PathResponse => {
                self.handle_path_response(&header, data, body, src).await?;
                Ok(None)
            }
            PacketType::Close => {
                self.handle_close(&header, data, body).await?;
                Ok(None)
            }
            PacketType::RekeyRequest => {
                self.handle_rekey_request(&header, data, body).await?;
                Ok(None)
            }
            PacketType::RekeyAck => {
                self.handle_rekey_ack(&header, data, body).await?;
                Ok(None)
            }
            PacketType::Beacon => {
                self.handle_beacon(&header, data, body, src, iface_idx).await?;
                Ok(None)
            }
            PacketType::ResumeHello => {
                self.handle_resume_hello(&header, body, src).await?;
                Ok(None)
            }
            PacketType::ResumeAck => {
                self.handle_resume_ack(&header, body).await?;
                Ok(None)
            }
            PacketType::ResumptionTicket => {
                self.handle_resumption_ticket(&header, data, body).await?;
                Ok(None)
            }
            PacketType::Ping => {
                self.handle_ping(&header, data, body, src).await?;
                Ok(None)
            }
            PacketType::Pong => {
                self.handle_pong(&header, data, body).await?;
                Ok(None)
            }
            PacketType::Data => {
                self.handle_data(&header, data, body, src, received_at, ecn_ce)
                    .await
            }
        }
    }

    /// Periodic handshake-retry emitter. Scans peers in AwaitingAck state
    /// and retransmits HELLO using the same client_nonce if enough time
    /// has elapsed. Gives up after HANDSHAKE_MAX_ATTEMPTS.
    async fn run_handshake_retry_loop(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(
            self.config.handshake_scan_ms,
        ));
        loop {
            ticker.tick().await;
            let to_retransmit: Vec<(Vec<u8>, SocketAddr, usize)> = {
                let routes = self.routes.lock().await;
                let mut peers = self.peers.lock_all().await;
                let mut out = Vec::new();
                for peer in peers.iter_mut() {
                    if let HandshakeState::AwaitingAck {
                        client_nonce,
                        ephemeral,
                        last_sent,
                        attempts,
                        cookie,
                    } = &mut peer.handshake
                    {
                        let wait = handshake_backoff_ms(
                            self.config.handshake_retry_base_ms,
                            *attempts,
                        );
                        if last_sent.elapsed() < std::time::Duration::from_millis(wait) {
                            continue;
                        }
                        if *attempts >= self.config.handshake_max_attempts {
                            continue;
                        }
                        *attempts += 1;
                        *last_sent = Instant::now();

                        let mesh = routes.lookup(&peer.id);
                        let wire = build_hello_wire(
                            self.local_peer_id,
                            peer.id,
                            &self.identity,
                            ephemeral.public_bytes(),
                            *client_nonce,
                            mesh.is_some(),
                            cookie.as_ref(),
                        );
                        let target = mesh.unwrap_or(peer.addr);
                        out.push((wire, target, peer.interface_id));
                    }
                }
                out
            };
            for (bytes, addr, iface) in to_retransmit {
                if let Err(e) = self.ifaces.send_for(iface, &bytes, addr).await {
                    warn!(error = %e, "HELLO retransmit failed");
                } else {
                    self.metrics.handshake_retries.fetch_add(1, Ordering::Relaxed);
                    self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                    self.metrics.bytes_sent.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    debug!("retransmitted HELLO to {:?}", addr);
                }
            }
        }
    }


    async fn handle_hello(
        &self,
        header: &Header,
        body: &[u8],
        src: SocketAddr,
        iface_idx: usize,
    ) -> Result<()> {
        if body.len() < HELLO_PAYLOAD_LEN {
            return Err(DriftError::PacketTooShort {
                got: body.len(),
                need: HELLO_PAYLOAD_LEN,
            });
        }
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let mut client_static_pub = [0u8; STATIC_KEY_LEN];
        client_static_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut client_ephemeral_pub = [0u8; STATIC_KEY_LEN];
        client_ephemeral_pub
            .copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN * 2]);
        let mut client_nonce = [0u8; NONCE_LEN];
        client_nonce.copy_from_slice(
            &body[STATIC_KEY_LEN * 2..STATIC_KEY_LEN * 2 + NONCE_LEN],
        );

        // SECURITY: reject obviously-weak pubkeys up front. An
        // all-zero pubkey (or any low-order point) would produce a
        // zero shared secret in `Identity::dh`, making the derived
        // session key a deterministic function of the public nonces
        // — the attacker could compute it and forge DATA packets
        // without knowing any private material. `dh_checked` below
        // catches the full low-order family via `was_contributory()`,
        // but rejecting the all-zero key here skips any X25519 work
        // on the fast path and yields a clear error.
        if client_static_pub == [0u8; STATIC_KEY_LEN]
            || client_ephemeral_pub == [0u8; STATIC_KEY_LEN]
        {
            self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            return Err(DriftError::AuthFailed);
        }

        // Adaptive DoS cookie check. Happens BEFORE any peer-table
        // allocation and BEFORE any X25519 work, so an attacker
        // spamming HELLOs from spoofed addresses only costs us the
        // Blake2b MAC compute + a single UDP send per packet.
        let cookie_required = self.cookie_required_sync();
        let has_cookie_tail = body.len() >= HELLO_WITH_COOKIE_LEN;
        if cookie_required {
            if !has_cookie_tail {
                self.send_challenge(iface_idx,
                    header.src_id,
                    src,
                    &client_static_pub,
                    &client_ephemeral_pub,
                    &client_nonce,
                )
                .await?;
                return Ok(());
            }
            let cookie_tail = &body[HELLO_PAYLOAD_LEN..HELLO_WITH_COOKIE_LEN];
            if !self
                .validate_cookie(
                    &src,
                    &client_static_pub,
                    &client_ephemeral_pub,
                    &client_nonce,
                    cookie_tail,
                )
                .await
            {
                self.metrics.cookies_rejected.fetch_add(1, Ordering::Relaxed);
                // Reply with a fresh challenge so a legitimate client
                // whose cookie expired can recover without restarting.
                self.send_challenge(iface_idx,
                    header.src_id,
                    src,
                    &client_static_pub,
                    &client_ephemeral_pub,
                    &client_nonce,
                )
                .await?;
                return Ok(());
            }
            self.metrics.cookies_accepted.fetch_add(1, Ordering::Relaxed);
        }

        let client_peer_id = derive_peer_id(&client_static_pub);

        let (ack_bytes, ack_addr) = {
            // handle_hello takes lock_all because the
            // auto-register cap check needs to count peers
            // across every shard. The hot path for already-
            // registered peers (the common case) is still
            // dominated by the single-shard accesses elsewhere.
            let mut peers = self.peers.lock_all().await;

            // Auto-registration: if the config allows accepting any peer
            // and we've never heard from this pubkey, add it to the table
            // on the fly as a responder.
            if !peers.contains(&client_peer_id) {
                if self.config.accept_any_peer {
                    // Cap auto-registered peers so a HELLO flood
                    // can't exhaust memory before the eviction
                    // reaper catches up. Explicit app-registered
                    // peers are unaffected.
                    if peers.iter().filter(|p| p.auto_registered).count()
                        >= self.config.max_peers
                    {
                        return Err(DriftError::UnknownPeer);
                    }
                    let mut new_peer = Peer::new(
                        client_peer_id,
                        src,
                        client_static_pub,
                        Direction::Responder,
                    );
                    new_peer.auto_registered = true;
                    new_peer.interface_id = iface_idx;
                    peers.insert(new_peer);
                    debug!("auto-registered new peer {:?} on iface {}", client_peer_id, iface_idx);
                } else {
                    return Err(DriftError::UnknownPeer);
                }
            }

            let peer = peers
                .get_mut(&client_peer_id)
                .ok_or(DriftError::UnknownPeer)?;

            if peer.peer_static_pub != client_static_pub {
                return Err(DriftError::AuthFailed);
            }

            // Dual-initiation tiebreaker: if we're in AwaitingAck (we sent
            // our own HELLO to this peer) and they also sent us one, the
            // side with the LOWER static public key wins the role of
            // "responder" — that side drops its outbound HELLO and accepts
            // the incoming one. The other side ignores the incoming HELLO
            // and keeps waiting for HELLO_ACK.
            if matches!(peer.handshake, HandshakeState::AwaitingAck { .. }) {
                let local_pub = self.identity.public_bytes();
                if local_pub > client_static_pub {
                    // We "win" — drop their HELLO, continue waiting for our ACK.
                    debug!("dual-init: dropping peer HELLO (local key wins)");
                    return Ok(());
                }
                // We "lose" — abandon our outbound handshake, accept theirs.
                debug!("dual-init: accepting peer HELLO (remote key wins)");
                peer.handshake = HandshakeState::Pending;
            }

            // If we're already in AwaitingData with the same client_nonce,
            // the client is retransmitting because our HELLO_ACK got lost.
            // Replay the cached reply — do NOT derive a new session key.
            if let HandshakeState::AwaitingData {
                cached_ack,
                cached_client_nonce,
                ..
            } = &peer.handshake
            {
                if *cached_client_nonce == client_nonce {
                    // SECURITY: do NOT migrate `peer.addr` on a
                    // duplicate HELLO. HELLO is unauthenticated —
                    // an attacker who captured a real HELLO off
                    // the wire could otherwise replay it from
                    // their own IP and silently redirect the
                    // server's outgoing traffic to themselves
                    // (they can't decrypt the payloads but they
                    // can drop them). Migration still works via
                    // authenticated DATA in `handle_data`. Send
                    // the cached ACK back to the ORIGINAL address
                    // we already trust.
                    let reply_addr = peer.addr;
                    debug!("replayed cached HELLO_ACK for duplicate HELLO");
                    (cached_ack.clone(), reply_addr)
                } else {
                    // Different nonce → client restarted. Fall through to
                    // regenerate. Skip the outer block manually.
                    let regen = regenerate_session(
                        &self.identity,
                        peer,
                        client_static_pub,
                        client_ephemeral_pub,
                        client_nonce,
                        self.local_peer_id,
                        client_peer_id,
                        src,
                        &self.metrics.handshakes_inflight,
                        header.hop_ttl,
                    )?;
                    regen
                }
            } else {
                let regen = regenerate_session(
                    &self.identity,
                    peer,
                    client_static_pub,
                    client_ephemeral_pub,
                    client_nonce,
                    self.local_peer_id,
                    client_peer_id,
                    src,
                    &self.metrics.handshakes_inflight,
                    header.hop_ttl,
                )?;
                regen
            }
        };

        // SECURITY: 3x amplification limit (RFC 9000 §8.1 style).
        // Before the peer's source address is validated by a
        // successful DATA round-trip, cap our outgoing
        // bytes-to-this-src at 3x the bytes we've received from
        // it. An off-path spoofer sending forged HELLOs can't
        // receive the reply, so they can't trick us into
        // amplifying their traffic toward a victim address.
        // `note_unauth_bytes_rx` was already credited by the
        // incoming HELLO body length; here we try to "spend"
        // the ack_bytes.len() against that budget.
        let amp_ok = {
            let mut peers = self.peers.lock_for(&client_peer_id).await;
            if let Some(peer) = peers.get_mut(&client_peer_id) {
                // Credit the HELLO we just received against the
                // budget, then try to spend the outgoing ack.
                peer.note_unauth_bytes_rx(body.len() + HEADER_LEN);
                peer.try_spend_unauth_budget(ack_bytes.len())
            } else {
                // Peer might have been auto-registered during
                // regenerate_session; assume budget open.
                true
            }
        };
        if !amp_ok {
            self.metrics
                .amplification_blocked
                .fetch_add(1, Ordering::Relaxed);
            debug!("dropped HELLO_ACK: would exceed 3x amplification budget");
            return Ok(());
        }

        // Reply via the same interface the HELLO arrived on.
        // This is critical for multi-interface nodes: if the
        // HELLO came in on TCP (iface 1), the ACK must go
        // out on TCP, not the default UDP (iface 0).
        self.ifaces.send_via(iface_idx, &ack_bytes, ack_addr).await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(ack_bytes.len() as u64, Ordering::Relaxed);
        debug!("sent HELLO_ACK to {:?} via iface {}", ack_addr, iface_idx);
        Ok(())
    }

    async fn handle_hello_ack(&self, header: &Header, body: &[u8]) -> Result<()> {
        if body.len() < HELLO_ACK_PAYLOAD_LEN {
            return Err(DriftError::PacketTooShort {
                got: body.len(),
                need: HELLO_ACK_PAYLOAD_LEN,
            });
        }
        let mut server_ephemeral_pub = [0u8; STATIC_KEY_LEN];
        server_ephemeral_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut server_nonce = [0u8; NONCE_LEN];
        server_nonce.copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN + NONCE_LEN]);
        let tag_start = STATIC_KEY_LEN + NONCE_LEN;
        let tag = &body[tag_start..tag_start + AUTH_TAG_LEN];

        // Client looks up the peer by src_id = the server's identity.
        let peer_id = header.src_id;
        let to_send: Vec<(Vec<u8>, SocketAddr, usize)>;
        let mut cid_key_for_install: Option<[u8; 32]> = None;
        let mesh_next_hop = self.routes.lock().await.lookup(&peer_id);
        {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;

            // Pattern match by value via std::mem::replace to consume the
            // ephemeral secret (it's not Copy).
            let old_state =
                std::mem::replace(&mut peer.handshake, HandshakeState::Pending);
            let (client_nonce, ephemeral, hello_sent_at) = match old_state {
                HandshakeState::AwaitingAck {
                    client_nonce,
                    ephemeral,
                    last_sent,
                    ..
                    // `cookie` is discarded — once HELLO_ACK lands, the
                    // handshake is done and the token is no longer useful.
                } => (client_nonce, ephemeral, last_sent),
                other => {
                    // Restore and bail.
                    peer.handshake = other;
                    debug!("HELLO_ACK in wrong state, ignoring");
                    return Ok(());
                }
            };

            // Passive RTT sample: the time from when we sent
            // the last HELLO to receiving this HELLO_ACK is
            // a clean round-trip measurement. Feed it into
            // the neighbor estimator so the routing table
            // has a valid RTT for this peer immediately,
            // before any active Ping round has even fired.
            peer.update_neighbor_rtt(Instant::now().duration_since(hello_sent_at));

            // Checked DH: a rogue server replying with an all-zero
            // or other low-order ephemeral pubkey would otherwise
            // let it force the client into a predictable session
            // key.
            let static_dh = self
                .identity
                .dh(&peer.peer_static_pub)
                .ok_or(DriftError::AuthFailed)?;
            let ephemeral_dh = ephemeral
                .dh(&server_ephemeral_pub)
                .ok_or(DriftError::AuthFailed)?;
            drop(ephemeral); // zeroize client ephemeral secret
            let session_key_bytes = derive_session_key(
                &static_dh,
                &ephemeral_dh,
                &client_nonce,
                &server_nonce,
            );

            let tx = SessionKey::new(&session_key_bytes, Direction::Initiator);
            let rx = SessionKey::new(&session_key_bytes, Direction::Responder);

            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);
            let canon = canonical_aad(&hbuf);
            let mut aad = Vec::with_capacity(HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN);
            aad.extend_from_slice(&canon);
            aad.extend_from_slice(&server_ephemeral_pub);
            aad.extend_from_slice(&server_nonce);
            rx.open(1, PacketType::HelloAck as u8, &aad, tag)?;

            peer.reset_seq();
            peer.coalesce_state.clear();
            peer.coalesce_order.clear();
            peer.mark_session_start();
            peer.handshake = HandshakeState::Established {
                tx,
                rx,
                key_bytes: session_key_bytes,
                prev: None,
            };
            if mesh_next_hop.is_some() {
                peer.via_mesh = true;
            }
            self.metrics.handshakes_completed.fetch_add(1, Ordering::Relaxed);
            debug!("handshake complete with peer {:?}", peer_id);
            if let Some(q) = &self.qlog {
                q.log_handshake_complete(&format!("{:?}", peer_id), false);
            }
            cid_key_for_install = Some(session_key_bytes);

            // Flush pending.
            let pending = std::mem::take(&mut peer.pending);
            let mut built = Vec::with_capacity(pending.len());
            for ps in pending {
                if let SendAction::Data(bytes, target, iface) = build_data_packet(
                    self.local_peer_id,
                    peer,
                    &ps.payload,
                    ps.deadline_ms,
                    ps.coalesce_group,
                    mesh_next_hop,
                )? {
                    built.push((bytes, target, iface));
                }
            }
            to_send = built;
        }

        // Install CIDs for short-header send/recv now that the
        // peer lock is released.
        if let Some(key) = &cid_key_for_install {
            self.install_cids(peer_id, key, true).await;
        }

        for (bytes, target, iface) in to_send {
            self.ifaces.send_for(iface, &bytes, target).await?;
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics.bytes_sent.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Periodically sweep the peer table for peers stuck in
    /// `AwaitingData` longer than `awaiting_data_timeout_secs`. Stale
    /// auto-registered peers are dropped outright; explicit peers are
    /// reset to `Pending` so the app can still reach them later. This
    /// bounds the in-flight handshake count that the adaptive cookie
    /// threshold watches, preventing a slow drift into permanent
    /// cookie mode.
    async fn run_handshake_eviction_loop(self: Arc<Self>) {
        if self.config.awaiting_data_timeout_secs == u64::MAX {
            return;
        }
        let scan_every =
            std::time::Duration::from_secs((self.config.awaiting_data_timeout_secs / 2).max(1));
        let mut ticker = tokio::time::interval(scan_every);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let cutoff =
                std::time::Duration::from_secs(self.config.awaiting_data_timeout_secs);
            let now = Instant::now();
            let mut evicted: u64 = 0;
            let mut to_remove: Vec<PeerId> = Vec::new();

            {
                let mut peers = self.peers.lock_all().await;
                for peer in peers.iter_mut() {
                    if !matches!(peer.handshake, HandshakeState::AwaitingData { .. }) {
                        continue;
                    }
                    let age = peer
                        .session_epoch
                        .map(|e| now.duration_since(e))
                        .unwrap_or_default();
                    if age <= cutoff {
                        continue;
                    }
                    if peer.auto_registered {
                        to_remove.push(peer.id);
                    } else {
                        peer.handshake = HandshakeState::Pending;
                        peer.pending.clear();
                        peer.session_epoch = None;
                        evicted += 1;
                    }
                }
                for id in &to_remove {
                    if peers.remove(id).is_some() {
                        evicted += 1;
                    }
                }
            }

            if evicted > 0 {
                self.metrics
                    .handshakes_evicted
                    .fetch_add(evicted, Ordering::Relaxed);
                // Every evicted peer was in AwaitingData; decrement
                // the live gauge by the same amount so cookie_required
                // and handshakes_in_progress stay accurate.
                self.metrics
                    .handshakes_inflight
                    .fetch_sub(evicted as usize, Ordering::Relaxed);
                debug!(evicted, "reaped stale AwaitingData peers");
            }
        }
    }

    async fn handle_data(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
        src: SocketAddr,
        received_at: Instant,
        ecn_ce: bool,
    ) -> Result<Option<Received>> {
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let peer_id = header.src_id;

        // Core handling under the peer lock. We collect any
        // side-effect packets that need to leave the socket
        // (a PathChallenge if a probe should fire, or flushed
        // pending DATA when a responder-direction peer
        // transitions to Established on the first inbound
        // DATA) into a local variable and emit them AFTER we
        // drop the lock.
        let (received, probe_to_send, just_established_after, flushed_pending, established_key): (
            Option<Received>,
            Option<(Vec<u8>, SocketAddr)>,
            bool,
            Vec<(Vec<u8>, SocketAddr, usize)>,
            Option<[u8; 32]>,
        ) = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;

            let (_, rx) = peer
                .handshake
                .session()
                .ok_or(DriftError::UnknownPeer)?;

            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);

            // Try the current rx first. If it fails AND a
            // rekey grace-window prev is still alive, try the
            // old rx before giving up — catches DATA that was
            // already in flight under the old key when we
            // switched.
            let payload = match rx.open(header.seq, PacketType::Data as u8, &aad, body) {
                Ok(pt) => pt,
                Err(err) => {
                    let mut recovered = None;
                    if let HandshakeState::Established { prev, .. } = &mut peer.handshake {
                        if let Some(p) = prev {
                            if p.installed_at.elapsed() <= REKEY_GRACE {
                                if let Ok(pt) = p.rx.open(
                                    header.seq,
                                    PacketType::Data as u8,
                                    &aad,
                                    body,
                                ) {
                                    recovered = Some(pt);
                                }
                            } else {
                                // Expired — drop the prev slot.
                                *prev = None;
                            }
                        }
                    }
                    match recovered {
                        Some(pt) => pt,
                        None => return Err(err),
                    }
                }
            };

            peer.check_and_update_replay(header.seq)?;

            if !peer.deadline_ok(header, received_at) {
                self.metrics.deadline_dropped.fetch_add(1, Ordering::Relaxed);
                debug!(
                    seq = header.seq,
                    deadline_ms = header.deadline_ms,
                    "dropped expired"
                );
                return Ok(None);
            }

            if !peer.coalesce_accept(header) {
                self.metrics.coalesce_dropped.fetch_add(1, Ordering::Relaxed);
                debug!(
                    seq = header.seq,
                    group = header.supersedes,
                    "dropped stale"
                );
                return Ok(None);
            }

            let mut just_established = false;
            let mut just_established_key: Option<[u8; 32]> = None;
            let mut flushed: Vec<(Vec<u8>, SocketAddr, usize)> = Vec::new();
            if matches!(peer.handshake, HandshakeState::AwaitingData { .. }) {
                if let HandshakeState::AwaitingData {
                    tx,
                    rx,
                    key_bytes,
                    ..
                } = std::mem::replace(&mut peer.handshake, HandshakeState::Pending)
                {
                    peer.handshake = HandshakeState::Established {
                        tx,
                        rx,
                        key_bytes,
                        prev: None,
                    };
                    self.metrics.handshakes_completed.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .handshakes_inflight
                        .fetch_sub(1, Ordering::Relaxed);
                    just_established = true;
                    just_established_key = Some(key_bytes);
                    if let Some(q) = &self.qlog {
                        q.log_handshake_complete(&format!("{:?}", peer_id), false);
                    }
                    // Amplification counters are no longer
                    // needed — the source address has been
                    // validated by a successful AEAD-auth'd
                    // DATA round trip, so we can send freely
                    // from here on.
                    peer.clear_unauth_counters();

                    // Flush any DATA the app queued while the
                    // responder-side handshake was still in
                    // flight. Without this, a server that
                    // calls `send_data` before receiving the
                    // client's first DATA would silently drop
                    // those packets — they'd sit in
                    // `pending` forever because nothing else
                    // triggers the flush on the responder
                    // side. Mirrors the initiator-side flush
                    // in `handle_hello_ack`.
                    let pending = std::mem::take(&mut peer.pending);
                    let flush_mesh = if peer.via_mesh {
                        Some(peer.addr)
                    } else {
                        None
                    };
                    for ps in pending {
                        if let Ok(SendAction::Data(bytes, target, iface)) = build_data_packet(
                            self.local_peer_id,
                            peer,
                            &ps.payload,
                            ps.deadline_ms,
                            ps.coalesce_group,
                            flush_mesh,
                        ) {
                            flushed.push((bytes, target, iface));
                        }
                    }
                }
            }

            // Path validation: if this DATA arrived from a source
            // different from the currently-trusted peer.addr, do
            // NOT migrate yet. Start (or refresh) a path probe to
            // the new source. Only a `PathResponse` that echoes the
            // right challenge from that same source can promote the
            // migration; an attacker who only captured packets
            // can't answer the probe.
            let probe = if peer.addr != src
                && matches!(peer.handshake, HandshakeState::Established { .. })
            {
                let now = Instant::now();
                let refresh = match &peer.probing {
                    None => true,
                    Some(p) if p.addr != src => true,
                    Some(p) if now.duration_since(p.started) > PATH_PROBE_RETRY => true,
                    _ => false,
                };
                if refresh {
                    let mut challenge = [0u8; PATH_CHALLENGE_LEN];
                    rand::thread_rng().fill_bytes(&mut challenge);
                    peer.probing = Some(PathProbe {
                        addr: src,
                        challenge,
                        started: now,
                    });
                    build_path_challenge_packet(
                        self.local_peer_id,
                        peer,
                        &challenge,
                    )
                    .ok()
                    .map(|bytes| (bytes, src))
                } else {
                    None
                }
            } else {
                None
            };

            peer.last_seen = received_at;

            (
                Some(Received {
                    peer_id,
                    seq: header.seq,
                    supersedes: header.supersedes,
                    payload,
                    ecn_ce,
                }),
                probe,
                just_established,
                flushed,
                just_established_key,
            )
        };

        // Emit any DATA we flushed from the pending queue on
        // the responder-side establishment path, outside the
        // peer lock.
        for (bytes, addr, iface) in flushed_pending {
            if let Err(e) = self.ifaces.send_for(iface, &bytes, addr).await {
                debug!(error = %e, "flushed DATA send failed");
            } else {
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
        }

        if just_established_after {
            // Install CID maps for short-header fast path
            // (Responder side).
            if let Some(key) = established_key {
                self.install_cids(peer_id, &key, false).await;
            }
            // Issue a resumption ticket so the peer can do a
            // 1-RTT reconnect next time. Best-effort: if the
            // send fails (e.g. peer addr already gone) we
            // don't fail the DATA delivery.
            if let Err(e) = self.issue_resumption_ticket(peer_id).await {
                debug!(error = ?e, "failed to issue resumption ticket");
            }
        }

        if let Some((bytes, addr)) = probe_to_send {
            if let Err(e) = self.ifaces.send_for(self.iface_for(&peer_id).await, &bytes, addr).await {
                debug!(error = %e, "PathChallenge send failed");
            } else {
                self.metrics.path_probes_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics.bytes_sent.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
        }

        Ok(received)
    }

    /// Received a `Close`. Verify the AEAD tag to prove the sender
    /// actually holds the session key, then drop the peer outright
    /// (auto-registered) or reset its handshake state (explicitly
    /// registered). Decrements `handshakes_inflight` if the peer
    /// was in AwaitingData when the close arrived.
    async fn handle_close(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let peer_id = header.src_id;
        let mut peers = self.peers.lock_for(&peer_id).await;
        let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;
        let (_, rx) = peer
            .handshake
            .session()
            .ok_or(DriftError::UnknownPeer)?;

        let mut hbuf = [0u8; HEADER_LEN];
        hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
        let aad = canonical_aad(&hbuf);
        // AEAD-authenticated: attacker can't forge a Close without
        // the session key, so this is safe to act on immediately.
        let _ = rx.open(header.seq, PacketType::Close as u8, &aad, body)?;

        let was_awaiting_data =
            matches!(peer.handshake, HandshakeState::AwaitingData { .. });
        if peer.auto_registered {
            debug!(peer_id = ?peer_id, "peer closed; removing auto-registered entry");
            peers.remove(&peer_id);
        } else {
            debug!(peer_id = ?peer_id, "peer closed; resetting explicit entry");
            peer.handshake = HandshakeState::Pending;
            peer.pending.clear();
            peer.session_epoch = None;
            peer.probing = None;
        }
        if was_awaiting_data {
            self.metrics
                .handshakes_inflight
                .fetch_sub(1, Ordering::Relaxed);
        }
        Ok(())
    }

}

/// Build a `Close` wire packet: AEAD-sealed empty body, consuming
/// one tx seq slot.
fn build_close_packet(local_peer_id: PeerId, peer: &mut Peer) -> Result<Vec<u8>> {
    let seq = peer
        .next_seq_checked()
        .ok_or(DriftError::SessionExhausted)?;
    let send_time_ms = peer.send_time_ms();
    let mut header = Header::new(PacketType::Close, seq, local_peer_id, peer.id);
    header.payload_len = AUTH_TAG_LEN as u16;
    header.send_time_ms = send_time_ms;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);
    let (tx, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
    let mut wire = Vec::with_capacity(HEADER_LEN + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(seq, PacketType::Close as u8, &aad, b"", &mut wire)?;
    Ok(wire)
}

fn build_data_packet(
    local_peer_id: PeerId,
    peer: &mut Peer,
    payload: &[u8],
    deadline_ms: u16,
    coalesce_group: u32,
    mesh_next_hop: Option<SocketAddr>,
) -> Result<SendAction> {
    build_data_packet_with_cid(
        local_peer_id,
        peer,
        payload,
        deadline_ms,
        coalesce_group,
        mesh_next_hop,
        None,
    )
}

fn build_data_packet_with_cid(
    local_peer_id: PeerId,
    peer: &mut Peer,
    payload: &[u8],
    deadline_ms: u16,
    coalesce_group: u32,
    mesh_next_hop: Option<SocketAddr>,
    out_cid: Option<u16>,
) -> Result<SendAction> {
    let seq = peer
        .next_seq_checked()
        .ok_or(DriftError::SessionExhausted)?;

    // Short-header fast path: eligible when
    //   1. We have an outgoing CID for the peer
    //   2. No mesh forwarding (direct session)
    //   3. No deadline or coalesce features active
    // This gives us 7-byte header + 16-byte tag = 23 bytes
    // vs the long header's 36 + 16 = 52 bytes.
    if let Some(cid) = out_cid {
        if mesh_next_hop.is_none() && deadline_ms == 0 && coalesce_group == 0 {
            let (tx, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
            let wire = crate::short_header::encode_short(cid, seq, tx, payload)?;
            return Ok(SendAction::Data(wire, peer.addr, peer.interface_id));
        }
    }

    // Long header: full 36 bytes, all features available.
    let send_time_ms = peer.send_time_ms();
    let mut header = Header::new(PacketType::Data, seq, local_peer_id, peer.id)
        .with_deadline(deadline_ms);
    if coalesce_group != 0 {
        header = header.with_supersedes(coalesce_group);
    }
    if mesh_next_hop.is_some() {
        header = header.with_hop_ttl(DEFAULT_MESH_TTL);
    }
    header.payload_len = payload.len() as u16;
    header.send_time_ms = send_time_ms;

    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);

    let (tx, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;

    let mut wire = Vec::with_capacity(HEADER_LEN + payload.len() + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(seq, PacketType::Data as u8, &aad, payload, &mut wire)?;

    let target = mesh_next_hop.unwrap_or(peer.addr);
    Ok(SendAction::Data(wire, target, peer.interface_id))
}

/// Run the server-side half of the handshake: derive session key
/// from both static and ephemeral DH, cache the HELLO_ACK wire
/// bytes, transition into AwaitingData, return (ack_bytes,
/// ack_addr) for the caller to send. The server generates a fresh
/// ephemeral keypair here and drops it after the DH computation
/// — forward secrecy on this side.
///
/// `inflight_gauge` is incremented iff the peer's previous state
/// was NOT already `AwaitingData`. This keeps
/// `handshakes_inflight` an accurate gauge across fresh starts
/// and dual-init regenerations without ever double-counting.
fn regenerate_session(
    identity: &Identity,
    peer: &mut Peer,
    client_static_pub: [u8; STATIC_KEY_LEN],
    client_ephemeral_pub: [u8; STATIC_KEY_LEN],
    client_nonce: [u8; NONCE_LEN],
    local_peer_id: PeerId,
    client_peer_id: PeerId,
    src: SocketAddr,
    inflight_gauge: &std::sync::atomic::AtomicUsize,
    incoming_hop_ttl: u8,
) -> Result<(Vec<u8>, SocketAddr)> {
    let was_awaiting_data =
        matches!(peer.handshake, HandshakeState::AwaitingData { .. });
    let server_nonce = random_nonce();
    let server_ephemeral = Identity::generate();
    let server_ephemeral_pub = server_ephemeral.public_bytes();

    // Use the contributory-checked DH. A non-contributory result
    // would mean the client's pubkey is a low-order / identity
    // point — someone trying to trick the server into deriving a
    // predictable session key. Fail the handshake cleanly.
    let static_dh = identity
        .dh(&client_static_pub)
        .ok_or(DriftError::AuthFailed)?;
    let ephemeral_dh = server_ephemeral
        .dh(&client_ephemeral_pub)
        .ok_or(DriftError::AuthFailed)?;
    let session_key_bytes =
        derive_session_key(&static_dh, &ephemeral_dh, &client_nonce, &server_nonce);
    // server_ephemeral drops here; StaticSecret's Zeroize impl clears it.
    drop(server_ephemeral);

    let tx = SessionKey::new(&session_key_bytes, Direction::Responder);
    let rx = SessionKey::new(&session_key_bytes, Direction::Initiator);

    peer.reset_seq();
    peer.coalesce_state.clear();
    peer.coalesce_order.clear();
    peer.mark_session_start();
    peer.addr = src;
    // A HELLO arriving with `hop_ttl > 1` was issued with
    // `with_hop_ttl(DEFAULT_MESH_TTL)` — the sender intended
    // mesh routing. The default `hop_ttl = 1` indicates a
    // direct HELLO. The old `> 0` check misfired on every
    // direct handshake and caused the beacon emitter to treat
    // direct neighbors as mesh-routed (silently skipping them
    // in the fixed filter, dropping them at the bridge's
    // forward gate before the filter existed).
    if incoming_hop_ttl > 1 {
        peer.via_mesh = true;
    }

    let mut ack_header =
        Header::new(PacketType::HelloAck, 1, local_peer_id, client_peer_id)
            .with_hop_ttl(DEFAULT_MESH_TTL);
    ack_header.payload_len = HELLO_ACK_PAYLOAD_LEN as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    ack_header.encode(&mut hbuf);

    let canon = canonical_aad(&hbuf);
    // AAD covers header + server_ephemeral_pub + server_nonce so that
    // tampering with either fails the tag.
    let mut aad = Vec::with_capacity(HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN);
    aad.extend_from_slice(&canon);
    aad.extend_from_slice(&server_ephemeral_pub);
    aad.extend_from_slice(&server_nonce);
    let tag = tx.seal(1, PacketType::HelloAck as u8, &aad, b"")?;

    let mut wire = Vec::with_capacity(HEADER_LEN + HELLO_ACK_PAYLOAD_LEN);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&server_ephemeral_pub);
    wire.extend_from_slice(&server_nonce);
    wire.extend_from_slice(&tag);

    peer.handshake = HandshakeState::AwaitingData {
        tx: tx.clone(),
        rx: rx.clone(),
        key_bytes: session_key_bytes,
        cached_ack: wire.clone(),
        cached_client_nonce: client_nonce,
    };
    if !was_awaiting_data {
        inflight_gauge.fetch_add(1, Ordering::Relaxed);
    }

    Ok((wire, src))
}

/// Build a HELLO wire packet with a pre-chosen nonce and ephemeral
/// public key. Used both for the initial handshake and for
/// retransmissions (where the same nonce + ephemeral key are reused so
/// the server can recognize the duplicate and replay the cached ACK).
fn build_hello_wire(
    local_peer_id: PeerId,
    dst_id: PeerId,
    identity: &Identity,
    ephemeral_pub: [u8; STATIC_KEY_LEN],
    client_nonce: [u8; NONCE_LEN],
    mesh: bool,
    cookie: Option<&[u8; COOKIE_BLOB_LEN]>,
) -> Vec<u8> {
    let mut header = Header::new(PacketType::Hello, 0, local_peer_id, dst_id);
    if mesh {
        header = header.with_hop_ttl(DEFAULT_MESH_TTL);
    }
    let payload_len = if cookie.is_some() {
        HELLO_WITH_COOKIE_LEN
    } else {
        HELLO_PAYLOAD_LEN
    };
    header.payload_len = payload_len as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);

    let mut wire = Vec::with_capacity(HEADER_LEN + payload_len);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&identity.public_bytes());
    wire.extend_from_slice(&ephemeral_pub);
    wire.extend_from_slice(&client_nonce);
    if let Some(c) = cookie {
        wire.extend_from_slice(c);
    }
    wire
}

fn build_hello(
    local_peer_id: PeerId,
    peer: &mut Peer,
    identity: &Identity,
    mesh_next_hop: Option<SocketAddr>,
) -> SendAction {
    let client_nonce = random_nonce();
    let ephemeral = Identity::generate();
    let ephemeral_pub = ephemeral.public_bytes();
    let wire = build_hello_wire(
        local_peer_id,
        peer.id,
        identity,
        ephemeral_pub,
        client_nonce,
        mesh_next_hop.is_some(),
        None,
    );
    peer.handshake = HandshakeState::AwaitingAck {
        client_nonce,
        ephemeral,
        last_sent: Instant::now(),
        attempts: 1,
        cookie: None,
    };
    let target = mesh_next_hop.unwrap_or(peer.addr);
    SendAction::Hello(wire, target, peer.interface_id)
}

enum SendAction {
    Data(Vec<u8>, SocketAddr, usize),
    Hello(Vec<u8>, SocketAddr, usize),
    Queued,
}
