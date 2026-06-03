use crate::crypto::{derive_peer_id, Direction, PeerId, SessionKey};
use crate::error::{DriftError, PeerError, Result};
use crate::header::{canonical_aad, Header, PacketType, AUTH_TAG_LEN, HEADER_LEN};
use crate::identity::{
    derive_session_key, random_nonce, rekey_derive, Identity, NONCE_LEN, STATIC_KEY_LEN,
};
use crate::session::{HandshakeState, PathProbe, Peer, PendingSend, PrevSession, SEQ_SEND_CEILING};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

/// Maximum size of a single DRIFT packet on the wire, in bytes.
///
/// 1400 was chosen to fit inside the path MTU that the public
/// internet actually delivers reliably (1500 Ethernet MTU minus
/// 20 B IPv4 header minus 8 B UDP header minus a 72-byte safety
/// margin for IPv6, tunneled networks, MPLS, and PPPoE
/// encapsulation). Smaller than that and we leave throughput on
/// the table for the common case; larger and we start hitting
/// PMTU black holes on real-world residential / cellular links
/// that silently drop fragmented or oversized UDP.
///
/// Iroh's QUIC stack starts at the same 1400 because the same
/// rationale applies (see `wire_iroh::INITIAL_MTU`); the
/// initial-MTU probe walks upward when path MTU discovery
/// confirms larger sizes work.
pub const MAX_PACKET: usize = 1400;

/// Maximum application-visible payload size in a single DRIFT
/// packet, after subtracting the long-header frame and the AEAD
/// auth tag. Apps that exceed this fragment at the stream layer,
/// not the packet layer.
pub const MAX_PAYLOAD: usize = MAX_PACKET - HEADER_LEN - AUTH_TAG_LEN;

// HELLO payload: client_static_pub(32) + client_ephemeral_pub(32) + client_nonce(16) = 80
const HELLO_PAYLOAD_LEN: usize = STATIC_KEY_LEN + STATIC_KEY_LEN + NONCE_LEN;
// HELLO_ACK payload: server_ephemeral_pub(32) + server_nonce(16) + auth_tag(16) = 64
const HELLO_ACK_PAYLOAD_LEN: usize = STATIC_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN;
// Phase PQ: when `FLAG_PQ_HYBRID` is set on the header, an
// ML-KEM-768 extension appends after the standard payload (and
// after any cookie tail on HELLO). The reader chains these
// fields from the header flags: base → optional cookie → optional
// PQ. See `drift::header::FLAG_PQ_HYBRID` for the wire contract.
pub(crate) const HELLO_PQ_TAIL_LEN: usize = drift_core::pq::ML_KEM_EK_LEN; // 1184
pub(crate) const HELLO_ACK_PQ_TAIL_LEN: usize = drift_core::pq::ML_KEM_CT_LEN; // 1088
#[cfg(unix)]
pub(crate) mod batch;
mod cookies;
pub mod dp_bloom;
mod federated;
mod find_peer;
pub use federated::{
    build as build_federated, build_directory, build_directory_v3, build_directory_v4,
    build_ticket, decode_ticket, encode_ticket, parse as parse_federated, parse_directory,
    parse_directory_v3, parse_directory_v4, ticket_signed_msg, verify_ticket, FederatedEnvelope,
    PresenceTicket, FED_HEADER_LEN, MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_ENTRIES_V4, TICKET_LEN,
    UNKNOWN_BRIDGE_PUB,
};
pub use find_peer::{
    build_find_peer, build_find_peer_hashed, build_peer_gone, build_peer_here, hash_target_pub,
    parse_find_peer, parse_find_peer_hashed, parse_peer_gone, parse_peer_here, FindPeer,
    FindPeerHashed, PathEntry, PeerGone, PeerHere, FIND_PEER_HASHED_DIGEST_LEN,
    FIND_PEER_HASHED_LEN, FIND_PEER_HASHED_SALT_LEN, FIND_PEER_LEN, MAX_FIND_DEADLINE_MS,
    MAX_FIND_TTL, NEG_CACHE_TTL_MS, PATH_ENTRY_LEN, PEER_GONE_LEN, PEER_HERE_HEADER_LEN,
    QUERY_DEDUP_TTL_MS,
};
#[cfg(unix)]
mod ecn;
pub(crate) mod mesh;
mod path;
mod peer_shards;
mod qlog;
mod resumption;
mod rtt;
use cookies::{CookieSecrets, COOKIE_BLOB_LEN, HELLO_WITH_COOKIE_LEN};
pub use mesh::{RouteEntry, RoutingTable, MAX_ROUTES};
use mesh::{DEFAULT_MESH_TTL, MAX_INCOMING_HOP_TTL};
use path::{build_path_challenge_packet, PATH_CHALLENGE_LEN, PATH_PROBE_RETRY};
use peer_shards::PeerShards;
use resumption::ResumptionStore;
pub use resumption::{ClientTicket, EXPORT_BLOB_LEN, TICKET_DEFAULT_TTL};
use std::collections::HashMap as StdHashMap;
use std::collections::HashSet as StdHashSet;

/// Runtime configuration for a `Transport`. Every field has a sensible
/// default suitable for interactive apps; override before `Transport::bind`
/// for deployments with different constraints (e.g., IoT, bulk, real-time).
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Initial retry interval for handshake HELLO. Subsequent
    /// retries double each attempt (exponential backoff).
    ///
    /// Default: **1000 ms** — aligned with RFC 6298 §2.1's
    /// pre-RTT-sample initial RTO (which has been the Linux
    /// kernel's TCP default since 2.6) and QUIC's PTO baseline
    /// (RFC 9002 §6.2.1).
    ///
    /// Smaller values like 50ms recover faster from a single
    /// dropped HELLO on a fast path, but trigger a
    /// retransmission storm when the HELLO is large enough
    /// to take meaningful time to transmit (e.g. hybrid PQ
    /// HELLOs at ~1.3 KB on slow links). See
    /// `docs/HANDSHAKE_RETRY_DESIGN.md`.
    ///
    /// LAN-only deployments with sub-ms RTT can override down
    /// to e.g. 50ms safely. The retry loop additionally adapts
    /// to the measured RTT once available — see the SRTT path
    /// in `run_handshake_retry_loop`.
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
    /// SEC.FIX.1: when true, drop forwarding requests whose source
    /// IP doesn't match any known peer's tracked addr. Closes the
    /// open-relay primitive (an unauthenticated host can otherwise
    /// send raw UDP with a victim's dst_id and have the bridge
    /// forward bytes to the victim with our IP as source).
    ///
    /// Default: true for `drift bridge` (set via the bridge CLI),
    /// false elsewhere. In-process mesh-chain tests that build
    /// relay chains via `add_route` without `add_peer` set this
    /// to false to keep their topology working — those scenarios
    /// trust the entire mesh and don't face open-internet input.
    pub require_src_for_forward: bool,
    /// If true, always require clients to echo a stateless DoS cookie
    /// before the server does any X25519 or peer allocation. Useful for
    /// tests and high-risk deployments. Default: false.
    pub cookie_always: bool,
    /// When the number of in-flight unauthenticated handshakes (peers
    /// in `AwaitingData`) meets or exceeds this value, the server
    /// adaptively switches to cookie mode for new HELLOs. Default:
    /// 1000 — a single client can sustain ~3 KB per half-open peer
    /// entry, so 1000 inflight = ~3 MB before cookies kick in; beyond
    /// that the server demands a stateless cookie before allocating
    /// state, naturally rate-limiting accumulation. Set `u32::MAX`
    /// to disable adaptive cookies (e.g. for tests where you want
    /// predictable timing).
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

    /// Phase E v1 minimal: disable reactive `FindPeer` entirely.
    /// Deprecated in favor of `find_peer_mode = Disabled`; kept
    /// as a bool for back-compat. When set, overrides
    /// `find_peer_mode` to `Disabled`.
    pub find_peer_disabled: bool,

    /// Phase E v2: per-bridge discovery posture. Lets operators
    /// pick a privacy stance independent of the rest of
    /// federation behavior. See `FindPeerMode` for the
    /// per-variant semantics.
    pub find_peer_mode: FindPeerMode,

    /// Phase F: announce a DP-noised bloom filter of local
    /// clients in FederationDirectory v4. When `Some(p)`, this
    /// bridge's `announce_directory` emits v4 packets carrying
    /// the filter (with one-sided noise rate `p`); federation
    /// peers cache the filter and use it to pre-filter their
    /// `FindPeer` fanout. `None` falls back to v3 announces
    /// (no filter; original behavior).
    ///
    /// Suggested values: 0.0 = plain bloom (FP only from hash
    /// collisions; max privacy loss vs DP), 0.05 (the reference
    /// noise rate) = moderate privacy / moderate extra FPs,
    /// 0.20+ = strong noise / many decoy queries / strong
    /// membership obfuscation.
    pub bloom_announce_noise: Option<f64>,

    /// Phase F: cover-traffic rate in queries-per-second.
    /// When `Some(r)`, a background task emits fire-and-forget
    /// `FindPeer` queries with random decoy target pubkeys at
    /// Poisson-distributed intervals with mean `1 / r`. The
    /// decoys are indistinguishable on-the-wire from real
    /// queries — a passive observer correlating timing with
    /// user activity sees noise floor that smothers real
    /// query patterns.
    ///
    /// Suggested values:
    /// - `None`: no cover traffic (Phase A behavior).
    /// - `Some(0.1)`: ~1 decoy every 10s. Cheap, defeats
    ///   coarse-grained traffic analysis.
    /// - `Some(1.0)`: 1 decoy per second. Stronger noise,
    ///   ~real-query-pace cover.
    /// - `Some(5.0+)`: aggressive — drowns most usage patterns
    ///   in noise, at meaningful bandwidth cost.
    ///
    /// Honors `find_peer_mode`: in `OriginateHashed` mode,
    /// decoys use `FindPeerHashed` (so even the on-the-wire
    /// shape matches real privacy-mode queries). In
    /// `Disabled` mode, no cover traffic emits.
    pub cover_traffic_rate_hz: Option<f64>,

    /// Phase G: reputation-based fanout skipping.
    ///
    /// A federation peer accumulates `bridge_faults` whenever a
    /// `FindPeer` we sent to it (because its bloom filter
    /// claimed the target) expired with no `PeerHere` reply.
    /// When a peer's fault count reaches or exceeds this
    /// threshold, the fanout step skips it entirely for
    /// subsequent queries — the bridge is treated as
    /// unreliable or dishonest.
    ///
    /// Faults decay exponentially: every
    /// `bridge_fault_decay_secs` the GC loop halves every
    /// counter and drops zeroed entries. So a transient outage
    /// doesn't permanently demote a peer, but sustained
    /// misbehavior keeps a peer cut out.
    ///
    /// `0` disables the skipping behavior (observe-only —
    /// faults still get logged, the fanout still queries the
    /// peer). Default `5` strikes a balance: a peer needs
    /// repeat-mistakes-without-recovery to get cut.
    pub bridge_fault_skip_threshold: u32,

    /// Phase G: seconds between fault-counter halvings (see
    /// `bridge_fault_skip_threshold`). Smaller = faster
    /// recovery, larger = stickier reputation. Default `30`s
    /// gives a misbehaving bridge a couple of minutes of
    /// quiet to fully decay back to zero.
    pub bridge_fault_decay_secs: u64,

    /// Phase G (FED_DISC): maximum hops a directory entry may
    /// travel through proactive re-announcement. A direct local
    /// entry has hops=0; a once-re-announced entry has hops=1;
    /// a twice-re-announced entry has hops=2; etc. Bridges
    /// don't re-emit entries with hops >= max_announce_hops.
    ///
    /// Default 4 — covers the typical homelab federation up to
    /// ~16 bridges in a linear chain, or any-size full mesh.
    /// Bridges in larger federations may set this higher;
    /// bridges with strict privacy needs may set it lower
    /// (0 = receivers don't re-emit; only the originating
    /// bridge announces its direct clients).
    ///
    /// Note: this is a *per-bridge* cap on what THIS bridge
    /// will re-emit. Each bridge in the chain enforces its
    /// own cap independently — the lowest cap along the path
    /// is the effective propagation limit. Receivers honor
    /// whatever hops value an inbound entry carries.
    pub max_announce_hops: u8,

    /// Phase PQ: enable the X25519 + ML-KEM-768 hybrid
    /// handshake. When `true`:
    ///   - This transport's outbound HELLOs carry an ML-KEM
    ///     encapsulation key (1184 bytes) and set
    ///     `FLAG_PQ_HYBRID` on the header.
    ///   - HELLO_ACKs in reply must also carry the matching
    ///     ML-KEM ciphertext and flag; the derived session
    ///     key feeds both halves through `derive_hybrid_key`,
    ///     defeating "harvest now, decrypt later" attacks even
    ///     against a future quantum adversary that breaks
    ///     X25519.
    ///   - Inbound HELLOs WITHOUT the flag are accepted via
    ///     the classical path (interop with non-PQ peers).
    ///   - Inbound HELLOs WITH the flag are accepted only if
    ///     this side ALSO has `hybrid_pq` enabled — refused
    ///     otherwise, because silently dropping to classical
    ///     would defeat the originator's PQ guarantee.
    ///
    /// Wire cost: ~+1.2 KB per HELLO and +1.1 KB per HELLO_ACK
    /// — fits comfortably below typical MTU and matches what
    /// TLS 1.3 hybrid is shipping in 2024-2025.
    pub hybrid_pq: bool,

    /// Requested UDP socket receive-buffer size, in bytes.
    /// `None` (default) keeps the OS default (~200 KB on
    /// macOS/Linux), which is fine for single-client
    /// transports but drops packets under thundering-herd
    /// reconnects on servers — especially with hybrid PQ
    /// HELLOs at ~1.3 KB each.
    ///
    /// `Some(n)` requests `SO_RCVBUF = n` via `socket2` after
    /// the UDP socket is bound. The kernel may clamp the
    /// request (see `sysctl net.core.rmem_max` on Linux,
    /// `kern.ipc.maxsockbuf` on macOS); the actual value
    /// applied is logged at info level. Failures are logged
    /// at warn and do NOT abort bind — the socket continues
    /// with whatever the kernel granted.
    ///
    /// Recommended for bridges: 4 MiB (`4 * 1024 * 1024`).
    pub udp_recv_buffer_bytes: Option<usize>,

    /// First-HELLO jitter window, in milliseconds. When
    /// non-zero, the initial handshake send is delayed by a
    /// uniformly random `0..handshake_jitter_ms` ms. Retries
    /// after the initial send use `handshake_retry_base_ms`
    /// plus exponential backoff and are NOT additionally
    /// jittered (the backoff already disperses them).
    ///
    /// Purpose: when many clients reconnect after a server
    /// restart (or many clients boot at the same time),
    /// synchronized HELLOs can overrun the server's UDP recv
    /// buffer. Spreading them by even a few hundred ms
    /// dramatically reduces drop rates.
    ///
    /// Per WireGuard's `RekeyTimeoutJitterMaxMs = 334`,
    /// a value in the 200–500 range is a sane default for
    /// clients expected to reconnect en masse. Default `0`
    /// (no jitter) preserves prior behavior.
    pub handshake_jitter_ms: u64,
}

/// Discovery-layer posture for a `Transport`. Default is `Open`
/// (Phase A behavior). Privacy-conscious deployments can pick a
/// stricter mode without disabling federation altogether.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FindPeerMode {
    /// Full Phase A/B participation: originate `FindPeer` for
    /// unknown targets, answer queries for our local clients,
    /// forward queries we can't answer to other federation peers.
    #[default]
    Open,
    /// Answer local hits, but do NOT forward queries from other
    /// bridges. Useful for "leaf" bridges that participate in
    /// federation but don't want to be discovery transit.
    NoForward,
    /// When originating a `FindPeer` for an unknown target, emit
    /// the hashed variant (`PacketType::FindPeerHashed`) so
    /// transit bridges see only `SHA-256(target || salt)`. Still
    /// answers and forwards incoming queries (both plain and
    /// hashed). See `FEDERATION_DISCOVERY.md` §5.5.
    OriginateHashed,
    /// Discovery off entirely: `UNKNOWN_BRIDGE_PUB` envelopes
    /// drop silently; incoming `FindPeer` / `FindPeerHashed`
    /// queries are dropped without reply. Clients must use
    /// explicit `via_bridge` entries.
    Disabled,
}

impl TransportConfig {
    /// Resolve the effective discovery mode. The deprecated
    /// `find_peer_disabled` boolean takes precedence when set.
    pub(crate) fn effective_find_peer_mode(&self) -> FindPeerMode {
        if self.find_peer_disabled {
            FindPeerMode::Disabled
        } else {
            self.find_peer_mode
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            // RFC 6298 §2.1 initial RTO. See the field doc.
            handshake_retry_base_ms: 1000,
            // 10 attempts × exponential backoff from 1 s
            // bottoms out around ~17 minutes of total
            // retry budget — long enough that a transient
            // network glitch doesn't strand the peer, short
            // enough that a genuinely-dead peer surfaces a
            // `HandshakeExhausted` error before users start
            // wondering. Tune down for latency-sensitive
            // clients, up for batch-style bridges.
            handshake_max_attempts: 10,
            // The handshake-retry scanner wakes up at this
            // cadence to look for peers whose retry deadline
            // has elapsed. 25 ms is two orders of magnitude
            // below typical RTT so retransmits fire within
            // one drift::transport tick of their scheduled
            // time without hammering the lock.
            handshake_scan_ms: 25,
            // 2 s default matches WireGuard's keepalive
            // cadence and gives federation directory
            // announces (every 7 s) a reliable presence
            // signal between announces. Bridges override
            // this down to 500 ms — they're the route
            // advertisers in the mesh, faster announces
            // mean faster cross-bridge convergence.
            beacon_interval_ms: 2000,
            // 1024 entries holds ~1 second of incoming
            // DATA at the K=17 federation density without
            // dropping. Slow consumers see backpressure
            // (sender's `send_data` returns `QueueFull`)
            // rather than packet loss.
            recv_channel_capacity: 1024,
            accept_any_peer: false,
            require_src_for_forward: false,
            cookie_always: false,
            // Cookie issuance kicks in when more than 1000
            // HELLOs/sec arrive — that's an order of
            // magnitude above normal connect rates but
            // small enough to catch a SYN-flood-style
            // amplification attempt before it exhausts
            // peer-table slots.
            cookie_threshold: 1000,
            // Cookies stay valid for 60 s — long enough
            // for a legitimate client to receive and replay
            // one, short enough that a replayed cookie
            // from an attacker's earlier capture won't
            // survive past one rotation window.
            cookie_max_age_secs: 60,
            // Server secret rotates every 30 s, with the
            // previous secret kept for the
            // `cookie_max_age_secs` grace window. A captured
            // cookie is unforgeable past two rotations.
            cookie_rotate_secs: 30,
            // After HELLO_ACK has been sent, we hold the
            // half-open session for 30 s waiting for the
            // first authenticated DATA. Below that window
            // a legitimate client whose first DATA was lost
            // can't recover; above it, half-open sessions
            // accumulate during a HELLO flood.
            awaiting_data_timeout_secs: 30,
            // 256 pre-handshake payloads per peer. An app
            // that keeps `send_data`-ing on a peer stuck in
            // Pending would otherwise leak memory without
            // bound. 256 × 1400 bytes ≈ 350 KB per peer
            // worst case.
            pending_queue_cap: 256,
            // 8192 peer-table slots covers a public bridge
            // serving a small federation; private bridges
            // never come close. The auto-register cap in
            // `handle_hello` enforces this; explicit
            // app-registered peers are unaffected.
            max_peers: 8192,
            enable_ecn: false,
            // RTT probe every 5 s. Drives bridge-fault
            // detection and mesh-route quality scoring.
            // Faster cadence costs unnecessary bandwidth
            // on idle links; slower means slower failover
            // when a bridge dies.
            rtt_probe_interval_ms: 5_000,
            qlog_path: None,
            find_peer_disabled: false,
            find_peer_mode: FindPeerMode::Open,
            bloom_announce_noise: None,
            cover_traffic_rate_hz: None,
            // After 5 consecutive failed forwarding attempts
            // through a federation peer, mark it bridge-faulty
            // and skip it on subsequent route decisions until
            // the decay timer expires. Matches the RFC 5681
            // congestion-control style of treating repeated
            // loss as a routing-quality signal, not a packet-
            // loss signal.
            bridge_fault_skip_threshold: 5,
            // 30-second hold on the bridge-faulty mark. Long
            // enough that a flapping bridge can't reinsert
            // itself into the routing table on its next
            // beacon; short enough that a brief network
            // glitch doesn't permanently demote a healthy
            // bridge.
            bridge_fault_decay_secs: 30,
            // Phase G (FED_DISC): covers ~16-bridge linear
            // chain or any-size full mesh. See field doc for
            // tuning guidance.
            max_announce_hops: 4,
            // Phase PQ-T.12: PQ is now ON by default. The wire
            // is interop-compatible with classical peers (a
            // PQ-enabled server still accepts classical
            // HELLOs); only the originator's outgoing HELLOs
            // carry the FLAG_PQ_HYBRID extension. Opt out via
            // `TransportConfig { hybrid_pq: false, ..default() }`
            // or, for `drift bridge`, the `--no-hybrid-pq` flag.
            //
            // Operational notes for server-side deployments:
            //   - bump `udp_recv_buffer_bytes` to 4+ MiB to
            //     absorb thundering-herd reconnects of large
            //     hybrid HELLOs (drift bridge does this by
            //     default); and
            //   - keep `handshake_jitter_ms` non-zero on
            //     clients that may reconnect en masse so
            //     synchronized HELLOs don't all arrive in the
            //     same microsecond.
            hybrid_pq: true,
            udp_recv_buffer_bytes: None,
            handshake_jitter_ms: 0,
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
            require_src_for_forward: false,
            cookie_always: false,
            cookie_threshold: 1000,
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
            find_peer_disabled: false,
            find_peer_mode: FindPeerMode::Open,
            bloom_announce_noise: None,
            cover_traffic_rate_hz: None,
            bridge_fault_skip_threshold: 5,
            bridge_fault_decay_secs: 30,
            // Phase G (FED_DISC): covers ~16-bridge linear
            // chain or any-size full mesh. See field doc for
            // tuning guidance.
            max_announce_hops: 4,
            // Phase PQ-T.12: PQ is now ON by default. The wire
            // is interop-compatible with classical peers (a
            // PQ-enabled server still accepts classical
            // HELLOs); only the originator's outgoing HELLOs
            // carry the FLAG_PQ_HYBRID extension. Opt out via
            // `TransportConfig { hybrid_pq: false, ..default() }`
            // or, for `drift bridge`, the `--no-hybrid-pq` flag.
            //
            // Operational notes for server-side deployments:
            //   - bump `udp_recv_buffer_bytes` to 4+ MiB to
            //     absorb thundering-herd reconnects of large
            //     hybrid HELLOs (drift bridge does this by
            //     default); and
            //   - keep `handshake_jitter_ms` non-zero on
            //     clients that may reconnect en masse so
            //     synchronized HELLOs don't all arrive in the
            //     same microsecond.
            hybrid_pq: true,
            udp_recv_buffer_bytes: None,
            handshake_jitter_ms: 0,
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
            require_src_for_forward: false,
            cookie_always: false,
            cookie_threshold: 1000,
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
            find_peer_disabled: false,
            find_peer_mode: FindPeerMode::Open,
            bloom_announce_noise: None,
            cover_traffic_rate_hz: None,
            bridge_fault_skip_threshold: 5,
            bridge_fault_decay_secs: 30,
            // Phase G (FED_DISC): covers ~16-bridge linear
            // chain or any-size full mesh. See field doc for
            // tuning guidance.
            max_announce_hops: 4,
            // Phase PQ-T.12: PQ is now ON by default. The wire
            // is interop-compatible with classical peers (a
            // PQ-enabled server still accepts classical
            // HELLOs); only the originator's outgoing HELLOs
            // carry the FLAG_PQ_HYBRID extension. Opt out via
            // `TransportConfig { hybrid_pq: false, ..default() }`
            // or, for `drift bridge`, the `--no-hybrid-pq` flag.
            //
            // Operational notes for server-side deployments:
            //   - bump `udp_recv_buffer_bytes` to 4+ MiB to
            //     absorb thundering-herd reconnects of large
            //     hybrid HELLOs (drift bridge does this by
            //     default); and
            //   - keep `handshake_jitter_ms` non-zero on
            //     clients that may reconnect en masse so
            //     synchronized HELLOs don't all arrive in the
            //     same microsecond.
            hybrid_pq: true,
            udp_recv_buffer_bytes: None,
            handshake_jitter_ms: 0,
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
    /// For packets that arrived as a federated envelope, this
    /// is the 32-byte pubkey of the *originating client* (not
    /// the bridge that delivered the packet to us). `peer_id`
    /// in that case will be the bridge's id. `None` for normal
    /// (non-federated) packets.
    pub federated_from: Option<[u8; 32]>,
    /// For federated packets, the 32-byte pubkey of the bridge
    /// the originating client is connected to. Lets a receiver
    /// auto-route a reply by calling `add_federated_peer(
    /// federated_from, my_bridge_handle, federated_via_bridge)`
    /// without needing the sender's bridge info out-of-band.
    pub federated_via_bridge: Option<[u8; 32]>,
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
    /// Packets dropped at the mesh-forward path because the
    /// source IP didn't match any known peer's addr. Bumped
    /// by the SEC.FIX.1 guard. Watch this to detect open-relay
    /// scan/abuse attempts.
    pub(crate) forward_unauth_drops: AtomicU64,
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
    /// Federated envelopes dropped because the envelope's
    /// `source_client_pub` / `source_bridge_pub` didn't match the
    /// session-authenticated sender. Counts identity-spoofing
    /// attempts at the source bridge.
    pub(crate) federation_spoof_drops: AtomicU64,
    /// FederationDirectory entries dropped because their attached
    /// XEdDSA presence ticket failed verification (expired, wrong
    /// signature, signed for a different bridge). Counts attempts
    /// by a federated bridge to announce pubkeys it doesn't
    /// actually hold a real session with.
    pub(crate) federation_invalid_tickets_dropped: AtomicU64,
    pub(crate) batched_sends: AtomicU64,
    /// Phase PQ: handshakes that completed using the X25519 +
    /// ML-KEM-768 hybrid path. Subset of `handshakes_completed`.
    pub(crate) hybrid_pq_handshakes_completed: AtomicU64,
    /// Phase PQ: HELLOs that arrived with `FLAG_PQ_HYBRID` but
    /// were rejected because this side has `hybrid_pq` disabled
    /// (or vice-versa: an unexpected PQ HelloAck arrived). Each
    /// rejection is silent on the wire but loud in this counter.
    pub(crate) hybrid_pq_handshakes_refused: AtomicU64,
    pub(crate) handshakes_inflight: std::sync::atomic::AtomicUsize,
    /// Packets dropped because the destination peer wasn't
    /// known to this node (handlers that require `dst_id ==
    /// local_peer_id` and the destination wasn't local, or a
    /// lookup in the peer table missed). Common cause on
    /// bridges: a control packet (ticket, beacon, rekey)
    /// addressed to a mesh peer arrived with `hop_ttl <= 1`,
    /// so the forward gate didn't route it.
    pub(crate) unknown_peer_drops: AtomicU64,
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
    /// SEC.FIX.1: forwards dropped because the source IP didn't
    /// match any established peer. Bumped on the open-relay
    /// guard path; zero on bridges with `require_src_for_forward
    /// = false`.
    pub forward_unauth_drops: u64,
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
    pub unknown_peer_drops: u64,
    pub federation_spoof_drops: u64,
    pub federation_invalid_tickets_dropped: u64,
    /// Phase PQ. Subset of `handshakes_completed` that ran the
    /// hybrid X25519 + ML-KEM-768 path.
    pub hybrid_pq_handshakes_completed: u64,
    /// Phase PQ. HELLOs refused because of a PQ posture
    /// mismatch (either direction).
    pub hybrid_pq_handshakes_refused: u64,
}

/// One outbound packet for `Transport::send_data_batch_qos`.
/// Carries the same per-packet metadata as `send_data` so
/// callers can batch without losing the deadline / coalesce
/// hints that the per-packet API exposes.
#[derive(Debug, Clone)]
pub struct BatchItem {
    pub peer: PeerId,
    pub payload: Vec<u8>,
    pub deadline_ms: u16,
    pub coalesce_group: u32,
}

/// Per-peer link-quality snapshot. Returned by
/// `Transport::peer_metrics(&PeerId)` for callers (drift-vpn,
/// applications, observability) that want to make routing or
/// failover decisions based on actual link health.
///
/// All fields are point-in-time snapshots; treat as advisory.
/// Multi-counter computations (e.g. "loss rate") should be
/// done by the caller from successive snapshots.
#[derive(Debug, Clone, Copy)]
pub struct PeerMetrics {
    /// Smoothed RTT to this peer (RFC 6298 SRTT). `None` until
    /// the first sample lands — handshake completion gives one
    /// for free, subsequent samples come from path probes,
    /// rekey RTTs, and (if enabled) the periodic Ping/Pong.
    pub srtt: Option<Duration>,
    /// Smoothed RTT variance. Roughly `mean(|sample - srtt|)`.
    /// Useful as a jitter signal — a low SRTT with high RTTVAR
    /// is a path that's mostly fast but spikes badly.
    pub rttvar: Option<Duration>,
    /// Last instant we received an authenticated packet from
    /// this peer. Compare to `Instant::now()` for staleness.
    /// A peer that hasn't been seen in 30s is probably dead
    /// even if `srtt` looks healthy.
    pub last_seen: Instant,
    /// Next sequence number we will assign to outgoing packets
    /// — i.e. one more than the count of packets we've sent
    /// under the current session keys. Resets on rekey, so this
    /// is "packets since last rekey," not lifetime.
    pub next_tx_seq: u32,
    /// Highest receive sequence we've seen from this peer in
    /// the current session — i.e. the count of unique packets
    /// they've sent us (modulo any out-of-order arrivals
    /// already counted via the replay bitmap).
    pub highest_rx_seq: u32,
    /// Whether the peer is currently in the Established state.
    /// Convenient for callers that just want a yes/no.
    pub is_established: bool,
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
    // routes, cid_map, peer_out_cid all use std::sync::Mutex
    // rather than tokio's async Mutex: their critical sections
    // are short HashMap/table ops with no await points, so the
    // async machinery (Future, registration, scheduler yield)
    // is pure overhead. Hot-path send_data acquires all three
    // — every cycle counts.
    pub(crate) routes: Arc<StdMutex<RoutingTable>>,
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
    /// Hint flag for the per-packet `try_resume` check: only
    /// flipped to `true` when at least one ticket has been
    /// stored. While `false`, `send_data` skips the entire
    /// resumption block — saves one async mutex acquire and one
    /// peer-table lookup per packet on the hot path.
    ///
    /// Allowed to be a stale `true` (e.g., after the last
    /// ticket is removed): the worst case is we pay the
    /// original check cost, which is what we'd do anyway. We
    /// never need it to be conservatively `false`, so the
    /// monotonic-set semantics are correct.
    pub(crate) has_any_ticket: std::sync::atomic::AtomicBool,
    /// Optional qlog-style event writer. `None` unless the
    /// user set `TransportConfig::qlog_path`.
    pub(crate) qlog: Option<qlog::QlogWriter>,
    /// CID → PeerId lookup for incoming short-header packets.
    /// Populated when a session reaches Established; cleared
    /// on close. The CID is derived deterministically from the
    /// session key so no extra wire exchange is needed.
    pub(crate) cid_map: Arc<StdMutex<StdHashMap<u16, PeerId>>>,
    /// Reverse map: PeerId → the CID that THIS side should
    /// put in outgoing short-header packets to that peer.
    /// (This is the PEER'S rx CID, not ours.)
    pub(crate) peer_out_cid: Arc<StdMutex<StdHashMap<PeerId, u16>>>,
    /// Session-reset notifications. Set by a higher-layer
    /// observer (typically `StreamManager`) so it can hear
    /// when a peer's authenticated session was regenerated
    /// (e.g. by a fresh HELLO from a new source IP — the
    /// "restart migration" path) and tear down per-peer
    /// state that became invalid alongside the new session
    /// keys. Optional and `Arc<StdMutex<Option<_>>>` so
    /// `Inner` doesn't pay any cost when no observer is
    /// installed.
    pub(crate) session_reset_tx: Arc<StdMutex<Option<mpsc::UnboundedSender<PeerId>>>>,
    /// Federation table — bridge-pubkey → PeerId mapping. Used by
    /// the `PacketType::Federated` handler to look up the next-hop
    /// bridge by pubkey (the only routing-relevant info in the
    /// envelope). Populated by `Transport::add_federation_peer`;
    /// every entry MUST also be present in `peers` so the lookup
    /// can be followed by a normal `send_data` to that PeerId.
    ///
    /// This is a *direct* routing table — each entry is a real
    /// pubkey-identified peer the local node has a session with —
    /// not the multi-hop mesh routes in `routes`. The federation
    /// shape is "every peer-bridge is explicitly configured,"
    /// modeled on Matrix's `.well-known/matrix/server` discovery
    /// pattern rather than DRIFT's beacon-driven mesh.
    pub(crate) federation_table: Arc<StdMutex<StdHashMap<[u8; 32], PeerId>>>,

    /// Directory of remote clients known to be reachable via one
    /// of our federation peers. Populated by
    /// `PacketType::FederationDirectory` announcements; consulted
    /// when routing a `PacketType::Federated` envelope whose
    /// `target_bridge_pub` is the all-zero sentinel
    /// (`federated::UNKNOWN_BRIDGE_PUB`) — i.e. the client doesn't
    /// know which bridge holds the target.
    ///
    /// `client_pubkey → (announcer_bridge_peer_id, last_announced_at)`
    /// with a 20 s TTL (~3× the ~7 s announce interval): entries
    /// that aren't re-announced within that window are evicted, so
    /// a client whose bridge stops announcing drops out of routing
    /// fast rather than stranding traffic at a stale next-hop.
    ///
    /// Security: only federation peers (entries in
    /// `federation_table`) can write to this table — see
    /// `handle_federation_directory`.
    pub(crate) peer_directory: Arc<StdMutex<StdHashMap<[u8; 32], (PeerId, std::time::Instant)>>>,

    /// Phase C side-table: hop count per directory entry. Kept
    /// separate from `peer_directory` so existing reader sites
    /// (which just need next-hop + freshness) don't have to be
    /// updated. Re-announcer reads this to decide which cached
    /// entries are eligible for transitive re-emission
    /// (`hops < MAX_ANNOUNCE_HOPS - 1`).
    ///
    /// Stays in lockstep with `peer_directory`: same keys, same
    /// insert/evict points. The two-map approach also keeps the
    /// hot path (`handle_federated` UNKNOWN_BRIDGE lookup) on
    /// the single-map fast path it already has.
    pub(crate) peer_directory_hops: Arc<StdMutex<StdHashMap<[u8; 32], u8>>>,

    /// Phase C side-table: presence ticket per transitive
    /// directory entry. Needed so re-announcement can attach the
    /// terminal client's *original* client-signed ticket to a
    /// transitive (pubkey, hops) pair. The terminal's ticket is
    /// the only cryptographic anchor a downstream receiver has
    /// to verify a transitive entry; without it, an unverified
    /// claim "I have a route to X" is uncheckable.
    pub(crate) peer_directory_tickets:
        Arc<StdMutex<StdHashMap<[u8; 32], federated::PresenceTicket>>>,

    /// Phase F: per-federation-peer bloom filter from their most
    /// recent FederationDirectory v4 announce. Keyed by the
    /// announcing bridge's `PeerId`. Used by
    /// `handle_federated`'s UNKNOWN_BRIDGE_PUB miss path to
    /// pre-filter `FindPeer` fanout — bridges whose filter says
    /// "definitely not" are skipped entirely, narrowing the
    /// per-lookup gossip blast radius.
    ///
    /// A bridge with no filter on file (v3-or-earlier announcer,
    /// or v4 announcer with `filter_bytes_len = 0`) is queried
    /// unconditionally — bloom is purely a NARROWING optimization
    /// for protocols that support it; absence is back-compat.
    pub(crate) peer_bloom_filters: Arc<StdMutex<StdHashMap<PeerId, dp_bloom::DpBloomFilter>>>,

    /// Phase F.8: per-federation-peer soft-fault counter. A
    /// fault is recorded when a `pending_find` times out and
    /// the bridge's bloom filter had claimed (via `contains`
    /// returning true) that it could answer. The counter is
    /// reset on a successful `PeerHere` from that bridge.
    ///
    /// v1 is observe-only: high fault counts log a warning
    /// but DON'T auto-demote from `federation_table`. The
    /// signal is for operator-side investigation; auto-action
    /// would need more data before becoming hard policy
    /// (false positives from bloom + intermittent latency
    /// would erroneously punish honest bridges).
    pub(crate) bridge_faults: Arc<StdMutex<StdHashMap<PeerId, u32>>>,

    /// Per-client presence tickets received via `PresenceTicket`
    /// packets. Keyed by the client's static pubkey (the
    /// session-authenticated sender, NOT anything the packet
    /// claims). Used by `Inner::announce_directory_entries` to
    /// build the (pubkey, ticket) pairs that go out in
    /// `FederationDirectory` announcements.
    ///
    /// Set on receive in `handle_presence_ticket`; client refreshes
    /// its ticket before expiry, replacing the stored entry.
    /// Entries are dropped passively when the client disconnects
    /// (no eviction logic — the absence of the client from
    /// `established_client_pubkeys` excludes them from the
    /// announcement anyway).
    pub(crate) presence_tickets: Arc<StdMutex<StdHashMap<[u8; 32], federated::PresenceTicket>>>,

    // ─── Federation peer discovery (FEDERATION_DISCOVERY.md §6) ──
    /// In-flight `FindPeer` queries we originated and are waiting
    /// on. Keyed by target client pubkey. When a matching `PeerHere`
    /// arrives, the `waiters` are released (the queued Federated
    /// envelopes are re-issued through the resolved bridge); on
    /// timeout, they're dropped and a negative-cache entry is set.
    ///
    /// Phase A stores opaque envelope bytes in `waiters` and re-sends
    /// them via `send_typed(PacketType::Federated)`. Multi-hop
    /// (Phase B) reuses the same coalescing — each subsequent query
    /// for the same target appends to `waiters` without firing a
    /// duplicate FindPeer.
    pub(crate) pending_finds: Arc<StdMutex<StdHashMap<[u8; 32], PendingFind>>>,

    /// `FindPeer` query IDs we've already processed, kept for
    /// `QUERY_DEDUP_TTL_MS` so repeats (loops, retransmits, broken
    /// federation topology) get silently dropped instead of
    /// triggering another round-trip. Map value is the deadline
    /// after which the entry can be GC'd. Phase A doesn't need
    /// loop-detection for 1-hop forwarding, but the bookkeeping is
    /// cheap and the same table backs Phase B's multi-hop case.
    pub(crate) recent_queries: Arc<StdMutex<StdHashMap<u64, Instant>>>,

    /// "Not found" cache for failed lookups. Holds the deadline at
    /// which the negative answer expires. Prevents a hot client
    /// path from re-issuing a `FindPeer` storm for a pubkey that
    /// no bridge in the federation hosts.
    pub(crate) neg_cache: Arc<StdMutex<StdHashMap<[u8; 32], Instant>>>,

    /// Phase B: queries we forwarded on behalf of an upstream
    /// federation peer (i.e. our local lookup missed but ttl was
    /// still > 1). When the matching `PeerHere` arrives, we look
    /// the query_id up here to know which peer to re-emit the
    /// extended-path reply to. `pending_finds` distinguishes
    /// "we originated" from "we forwarded": entries in
    /// `pending_finds` mean the former, entries in
    /// `forwarded_queries` mean the latter.
    ///
    /// Phase B does not currently age this table — entries leak
    /// for the process lifetime if no `PeerHere` ever arrives.
    /// `recent_queries` provides loop prevention; size of this
    /// map is bounded by genuine query rate in practice. Aging /
    /// LRU eviction belongs in Phase C cleanup.
    pub(crate) forwarded_queries: Arc<StdMutex<StdHashMap<u64, PeerId>>>,

    /// Rate-limited "dropped invalid packet" warn site. An attacker
    /// flooding garbage triggers one of these per packet; without a
    /// throttle the logs become unusable and CPU is wasted on
    /// formatting. Allows one emission per second, accumulating a
    /// "suppressed since last" count in between.
    pub(crate) drop_warn_throttle: LogThrottle,
}

/// One in-flight `FindPeer` query: the originator-side state a
/// bridge keeps while it waits for `PeerHere` to come back. Holds
/// the queue of `Federated` envelopes that arrived for this target
/// while the lookup was outstanding; on a successful reply the
/// queue is flushed through the resolved next-hop, and on timeout
/// the queue is dropped (clients will retry through retransmit).
pub(crate) struct PendingFind {
    pub(crate) query_id: u64,
    pub(crate) started_at: Instant,
    /// Each waiter is the parsed-then-re-serialized envelope that
    /// will be re-issued via `send_typed(PacketType::Federated)`
    /// once the lookup resolves. Stored as opaque bytes so the
    /// hot path (handle_peer_here) doesn't have to re-parse.
    pub(crate) waiters: Vec<Vec<u8>>,
    /// Phase F.8: federation peers whose v4 bloom filter said
    /// "yes, I have the target" — these are the bridges we
    /// asked. If the pending_find times out without a PeerHere,
    /// the GC loop increments `bridge_faults` for each of these
    /// peers (they advertised something they didn't deliver).
    /// Bridges with no filter on file (queried unconditionally
    /// per back-compat) are NOT in this list — we don't fault
    /// a bridge for not answering a query it never claimed it
    /// could answer.
    pub(crate) claimed_by: Vec<PeerId>,
}

/// One-emission-per-window throttle, accumulating a suppressed
/// count for the next emission. `tick_or_count()` returns
/// `Some(suppressed_count_since_last_emission)` when the caller
/// should emit, or `None` when the call should be silently
/// suppressed.
pub(crate) struct LogThrottle {
    last: StdMutex<Option<Instant>>,
    suppressed: AtomicU64,
    window: Duration,
}

impl LogThrottle {
    fn new(window: Duration) -> Self {
        Self {
            last: StdMutex::new(None),
            suppressed: AtomicU64::new(0),
            window,
        }
    }

    fn tick_or_count(&self) -> Option<u64> {
        let now = Instant::now();
        let mut guard = self.last.lock().unwrap();
        let should_emit = match *guard {
            None => true,
            Some(last) => now.duration_since(last) >= self.window,
        };
        if should_emit {
            *guard = Some(now);
            let n = self.suppressed.swap(0, Ordering::Relaxed);
            Some(n)
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

pub struct Transport {
    inner: Arc<Inner>,
    rx: Mutex<mpsc::Receiver<Received>>,
    /// Kept so `add_interface` can clone it for new recv
    /// loops spawned after bind.
    recv_tx: mpsc::Sender<Received>,
    /// Abort handles for all background tasks spawned during
    /// bind + any `add_interface` calls. Aborting on drop is
    /// what keeps a Transport from leaking its worker tasks:
    /// each task holds an `Arc<Inner>`, so without explicit
    /// abort the Inner would stay pinned in memory (and its
    /// tickers would keep firing) for the entire process
    /// lifetime.
    tasks: TaskGuard,
}

/// Owns the `JoinHandle`s for a Transport's background tasks.
/// On drop, aborts every handle so the futures are dropped,
/// their captured `Arc<Inner>` references released, and the
/// Inner freed promptly. Lives on `Transport` (not `Inner`)
/// on purpose — `Inner` is what the tasks are keeping alive,
/// so the guard has to outlive the tasks but be owned by
/// whatever drops with the user-visible handle.
#[derive(Default)]
struct TaskGuard {
    /// `Arc<Mutex<…>>` rather than a plain `Mutex` so background
    /// loops (like the `bind_url` accept loop) can keep a `Weak`
    /// reference and push their own dynamically-spawned handles
    /// here without taking a strong ref that would create a
    /// drop-cycle.
    handles: std::sync::Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl TaskGuard {
    fn push(&self, handle: tokio::task::JoinHandle<()>) {
        if let Ok(mut v) = self.handles.lock() {
            v.push(handle);
        } else {
            // Lock is poisoned only if a prior holder panicked
            // while mutating. Safest path is to abort the new
            // handle immediately so we don't silently leak.
            handle.abort();
        }
    }

    /// Hand out the inner `Arc<Mutex<…>>`. Callers should
    /// downgrade to `Weak` before storing — keeping a strong
    /// reference defeats the abort-on-drop guarantee.
    fn handles_arc(&self) -> std::sync::Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> {
        self.handles.clone()
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        // Try to acquire the inner mutex; if successful, abort
        // every handle. We can't use `get_mut()` anymore since
        // `handles` is now an Arc<Mutex<...>>.
        if let Ok(mut v) = self.handles.lock() {
            for h in v.drain(..) {
                h.abort();
            }
        }
    }
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
        let udp_socket = UdpSocket::bind(addr).await?;
        // Phase PQ-T.11.1: opt-in SO_RCVBUF tuning. Bridges
        // expecting many concurrent first-time handshakes
        // (especially hybrid PQ at ~1.3 KB each) should set
        // this to several MB to avoid kernel drops under
        // thundering-herd reconnects. See `udp_recv_buffer_bytes`
        // doc on TransportConfig.
        if let Some(want) = config.udp_recv_buffer_bytes {
            crate::io::apply_udp_recv_buffer(&udp_socket, want);
        }
        let udp_socket = Arc::new(udp_socket);
        #[cfg(unix)]
        if config.enable_ecn {
            if let Err(e) = ecn::enable_ecn(&udp_socket) {
                warn!(error = %e, "failed to enable ECN on socket");
            }
        }
        let io: Arc<dyn crate::io::PacketIO> = Arc::new(crate::io::UdpPacketIO::new(udp_socket));
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
        let qlog_writer =
            config
                .qlog_path
                .as_deref()
                .and_then(|p| match qlog::QlogWriter::open(p) {
                    Ok(w) => Some(w),
                    Err(e) => {
                        warn!(error = %e, path = ?p, "failed to open qlog file; disabling");
                        None
                    }
                });

        let inner = Arc::new(Inner {
            ifaces: crate::io::InterfaceSet::single("default", io),
            identity: Arc::new(identity),
            local_peer_id,
            peers: Arc::new(PeerShards::default()),
            routes: Arc::new(StdMutex::new(RoutingTable::default())),
            metrics: MetricsInner::default(),
            config,
            cookies: Arc::new(Mutex::new(CookieSecrets::new())),
            resumption_store: Arc::new(Mutex::new(ResumptionStore::default())),
            client_tickets: Arc::new(Mutex::new(StdHashMap::new())),
            has_any_ticket: std::sync::atomic::AtomicBool::new(false),
            qlog: qlog_writer,
            cid_map: Arc::new(StdMutex::new(StdHashMap::new())),
            peer_out_cid: Arc::new(StdMutex::new(StdHashMap::new())),
            session_reset_tx: Arc::new(StdMutex::new(None)),
            federation_table: Arc::new(StdMutex::new(StdHashMap::new())),
            peer_directory: Arc::new(StdMutex::new(StdHashMap::new())),
            peer_directory_hops: Arc::new(StdMutex::new(StdHashMap::new())),
            peer_directory_tickets: Arc::new(StdMutex::new(StdHashMap::new())),
            peer_bloom_filters: Arc::new(StdMutex::new(StdHashMap::new())),
            bridge_faults: Arc::new(StdMutex::new(StdHashMap::new())),
            presence_tickets: Arc::new(StdMutex::new(StdHashMap::new())),
            pending_finds: Arc::new(StdMutex::new(StdHashMap::new())),
            recent_queries: Arc::new(StdMutex::new(StdHashMap::new())),
            neg_cache: Arc::new(StdMutex::new(StdHashMap::new())),
            forwarded_queries: Arc::new(StdMutex::new(StdHashMap::new())),
            drop_warn_throttle: LogThrottle::new(Duration::from_secs(1)),
        });

        // ECN was set up by bind_with_config before calling
        // bind_inner, if the IO adapter is UDP.

        let (tx, rx) = mpsc::channel(recv_channel_capacity);
        let tasks = TaskGuard::default();

        // Spawn one recv loop per interface so all adapters
        // feed into the same processing pipeline. When a
        // second interface is added later via add_interface,
        // it gets its own recv loop spawned at that time.
        let num_ifaces = inner.ifaces.len();
        for iface_idx in 0..num_ifaces {
            let bg = inner.clone();
            let tx_clone = tx.clone();
            tasks.push(tokio::spawn(async move {
                bg.run_recv_loop_for(tx_clone, iface_idx).await
            }));
        }

        let beacon_bg = inner.clone();
        tasks.push(tokio::spawn(
            async move { beacon_bg.run_beacon_loop().await },
        ));

        let retry_bg = inner.clone();
        tasks.push(tokio::spawn(async move {
            retry_bg.run_handshake_retry_loop().await
        }));

        // RTT probe loop: only spawn when the user actually
        // wants active latency measurement. Skipping it when
        // disabled saves one timer per transport.
        if rtt_probe_interval_ms > 0 {
            let rtt_bg = inner.clone();
            tasks.push(tokio::spawn(
                async move { rtt_bg.run_rtt_probe_loop().await },
            ));
        }

        // Route sweep loop: purges stale mesh routes whose
        // beacon refresh has lapsed. Always spawned — the
        // sweep is cheap and dead-route removal is a
        // correctness requirement for the RTT-weighted
        // router, not an optimization.
        let sweep_bg = inner.clone();
        tasks.push(tokio::spawn(async move {
            sweep_bg.run_route_sweep_loop().await
        }));

        // Background sweep for federation-discovery state.
        // Bounded memory growth for `pending_finds`,
        // `recent_queries`, `neg_cache`, `forwarded_queries` —
        // see `run_find_peer_gc_loop`.
        let gc_bg = inner.clone();
        tasks.push(tokio::spawn(
            async move { gc_bg.run_find_peer_gc_loop().await },
        ));

        // Phase F: cover-traffic decoy queries. Only spawned
        // when the operator opts in via
        // `TransportConfig::cover_traffic_rate_hz`.
        if inner.config.cover_traffic_rate_hz.is_some() {
            let cover_bg = inner.clone();
            tasks.push(tokio::spawn(async move {
                cover_bg.run_cover_traffic_loop().await
            }));
        }

        // Cookie rotation only matters when the cookie path can be
        // reached. Skip spawning the loop entirely in the default
        // fast-path config — it just wastes wake-ups.
        if cookie_always || cookie_threshold != u32::MAX {
            let cookie_bg = inner.clone();
            tasks.push(tokio::spawn(async move {
                cookie_bg.run_cookie_rotate_loop().await
            }));
        }

        // The AwaitingData eviction reaper is only load-bearing when
        // some path (cookies or accept_any_peer) can produce stuck
        // handshakes. Don't spawn it when eviction is disabled and
        // there's no way for the state to go stale.
        if awaiting_data_timeout_secs != u64::MAX
            && (accept_any_peer || cookie_always || cookie_threshold != u32::MAX)
        {
            let evict_bg = inner.clone();
            tasks.push(tokio::spawn(async move {
                evict_bg.run_handshake_eviction_loop().await
            }));
        }

        Ok(Self {
            inner,
            rx: Mutex::new(rx),
            recv_tx: tx,
            tasks,
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
        self.tasks.push(tokio::spawn(async move {
            bg.run_recv_loop_for(tx, idx).await;
        }));
        idx
    }

    /// Bind a `Transport` from a URL like `udp://0.0.0.0:9100`
    /// or `tcp://0.0.0.0:9100`. The scheme picks the adapter,
    /// the address part picks where to listen.
    ///
    /// For single-shot listeners (UDP), the returned `PacketIO`
    /// is used as the Transport's primary interface. For
    /// multi-shot listeners (TCP, WebSocket), the Transport is
    /// constructed with a `MemPacketIO` placeholder primary and
    /// an accept-loop runs in the background, attaching each
    /// inbound connection as a new interface via
    /// `add_interface`. Application code is identical regardless
    /// of which transport is in use — that's the plug-and-play
    /// promise.
    ///
    /// Returns the bound URL (with the resolved port for `:0`
    /// inputs) so the caller can print it in their banner.
    pub async fn bind_url(
        url: &str,
        identity: Identity,
        config: TransportConfig,
    ) -> Result<(Self, String)> {
        let (scheme, addr_str) = url
            .find("://")
            .map(|i| (&url[..i], &url[i + 3..]))
            .unwrap_or(("udp", url));
        let scheme = scheme.to_string();
        // Phase PQ-T.11.1: special-case udp:// so we can apply
        // SO_RCVBUF via UdpListenerIO::bind_with_recv_buffer
        // before handing off to bind_inner. Other adapters
        // (tcp, ws, tls, http, dns, webtransport) don't expose
        // a single socket whose recv buffer would matter at
        // bind time — they create per-connection sockets later.
        let mut listener: Box<dyn crate::io::Listener> = if scheme == "udp"
            && config.udp_recv_buffer_bytes.is_some()
        {
            let addr = crate::io::parse_ip_addr(addr_str)
                .await
                .map_err(DriftError::Io)?;
            let udp =
                crate::io::UdpListenerIO::bind_with_recv_buffer(addr, config.udp_recv_buffer_bytes)
                    .await
                    .map_err(DriftError::Io)?;
            Box::new(udp) as Box<dyn crate::io::Listener>
        } else {
            crate::io::make_listener(url)
                .await
                .map_err(DriftError::Io)?
        };
        let bound_addr = listener.local_addr().map_err(DriftError::Io)?;
        let bound_url = format!("{}://{}", scheme, bound_addr);

        if listener.is_multi() {
            // Multi-shot adapter (TCP, WS, …): primary is a
            // MemPacketIO placeholder so Transport has something
            // to satisfy its "needs an iface to be born"
            // contract. The placeholder never sees traffic; real
            // peers arrive on the interfaces the accept loop
            // attaches.
            let (mem_primary, _mem_dead) = crate::io::MemPacketIO::pair();
            let primary: Arc<dyn crate::io::PacketIO> = Arc::new(mem_primary);
            let transport = Self::bind_inner(primary, identity, config).await?;
            // Spawn the accept loop. On Drop, Transport.tasks
            // aborts this handle, which drops the loop's local
            // state. Recv loops registered for individual TCP
            // interfaces live in Transport.tasks already.
            let tx = transport.recv_tx.clone();
            let inner = transport.inner.clone();
            let tasks_weak = std::sync::Arc::downgrade(&(transport.tasks.handles_arc()));
            transport.tasks.push(tokio::spawn(async move {
                let mut listener = listener;
                loop {
                    match listener.accept().await {
                        Ok(io) => {
                            let idx = inner.ifaces.add("multi-accept", io);
                            let bg = inner.clone();
                            let tx_clone = tx.clone();
                            let recv_handle =
                                tokio::spawn(
                                    async move { bg.run_recv_loop_for(tx_clone, idx).await },
                                );
                            // Track the recv-loop handle so it
                            // gets aborted when the Transport
                            // drops. Weak so we don't keep the
                            // TaskGuard alive past Transport's
                            // own lifetime.
                            if let Some(handles) = tasks_weak.upgrade() {
                                if let Ok(mut v) = handles.lock() {
                                    v.push(recv_handle);
                                } else {
                                    recv_handle.abort();
                                    break;
                                }
                            } else {
                                recv_handle.abort();
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = ?e, "listener accept failed; backing off");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }));
            Ok((transport, bound_url))
        } else {
            // Single-shot adapter (UDP): the listener's one
            // PacketIO becomes the Transport's primary
            // interface directly.
            let io = listener.accept().await.map_err(DriftError::Io)?;
            let transport = Self::bind_inner(io, identity, config).await?;
            Ok((transport, bound_url))
        }
    }

    /// Client-side counterpart to `bind_url`. Resolves a peer
    /// URL like `udp://host:9100` or `tcp://host:9100` and
    /// returns a `Transport` already wired up to reach that
    /// peer, plus the resolved `SocketAddr` to pass into
    /// `add_peer`.
    pub async fn connect_url(
        url: &str,
        identity: Identity,
        config: TransportConfig,
    ) -> Result<(Self, SocketAddr)> {
        let (io, addr) = crate::io::make_connector(url)
            .await
            .map_err(DriftError::Io)?;
        let transport = Self::bind_inner(io, identity, config).await?;
        Ok((transport, addr))
    }

    /// Add a second (third, …) listener to a live Transport.
    /// Useful when you want one server reachable on multiple
    /// transports simultaneously — e.g. UDP for fast clients
    /// AND TCP for clients behind UDP-blocking firewalls.
    ///
    /// For single-shot listeners (UDP), the listener's one
    /// `PacketIO` is attached immediately via `add_interface`.
    /// For multi-shot listeners (TCP, WS, …), an accept loop
    /// runs in the background and attaches each inbound
    /// connection as a new interface.
    ///
    /// Returns the resolved bound URL (with `:0` ports filled
    /// in) so the caller can include it in startup banners.
    pub async fn add_listener(&self, url: &str) -> Result<String> {
        let (scheme, _) = url
            .find("://")
            .map(|i| (&url[..i], &url[i + 3..]))
            .unwrap_or(("udp", url));
        let scheme = scheme.to_string();
        let mut listener = crate::io::make_listener(url)
            .await
            .map_err(DriftError::Io)?;
        let bound_addr = listener.local_addr().map_err(DriftError::Io)?;
        let bound_url = format!("{}://{}", scheme, bound_addr);

        if listener.is_multi() {
            let tx = self.recv_tx.clone();
            let inner = self.inner.clone();
            let tasks_weak = std::sync::Arc::downgrade(&self.tasks.handles_arc());
            let label = format!("{}-listen", scheme);
            self.tasks.push(tokio::spawn(async move {
                let mut listener = listener;
                loop {
                    match listener.accept().await {
                        Ok(io) => {
                            let idx = inner.ifaces.add(label.clone(), io);
                            let bg = inner.clone();
                            let tx_clone = tx.clone();
                            let recv_handle =
                                tokio::spawn(
                                    async move { bg.run_recv_loop_for(tx_clone, idx).await },
                                );
                            if let Some(handles) = tasks_weak.upgrade() {
                                if let Ok(mut v) = handles.lock() {
                                    v.push(recv_handle);
                                } else {
                                    recv_handle.abort();
                                    break;
                                }
                            } else {
                                recv_handle.abort();
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = ?e, "listener accept failed; backing off");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }));
        } else {
            let io = listener.accept().await.map_err(DriftError::Io)?;
            self.add_interface(format!("{}-listen", scheme), io);
        }
        Ok(bound_url)
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

    /// Look up the X25519 pubkey for a known peer by its
    /// 8-byte peer_id. Returns `None` if no peer with that
    /// id is registered. Useful for application-level code
    /// (drift-mosh, drift-http, …) that knows the peer_id
    /// from a stream's `peer()` accessor and wants to record
    /// the full pubkey in a contacts file.
    pub async fn peer_public(&self, peer_id: &PeerId) -> Option<[u8; STATIC_KEY_LEN]> {
        let peers = self.inner.peers.lock_for(peer_id).await;
        peers.get(peer_id).map(|p| p.peer_static_pub)
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
            forward_unauth_drops: m.forward_unauth_drops.load(Ordering::Relaxed),
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
            unknown_peer_drops: m.unknown_peer_drops.load(Ordering::Relaxed),
            federation_spoof_drops: m.federation_spoof_drops.load(Ordering::Relaxed),
            federation_invalid_tickets_dropped: m
                .federation_invalid_tickets_dropped
                .load(Ordering::Relaxed),
            hybrid_pq_handshakes_completed: m
                .hybrid_pq_handshakes_completed
                .load(Ordering::Relaxed),
            hybrid_pq_handshakes_refused: m.hybrid_pq_handshakes_refused.load(Ordering::Relaxed),
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
    pub async fn test_lookup_route(&self, dst: &PeerId) -> Option<(SocketAddr, u32)> {
        self.inner
            .routes
            .lock()
            .unwrap()
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
            .unwrap()
            .insert_static(dst, next_hop_addr);
    }

    /// Explicitly update the known remote address for a peer.
    /// Call this when the app knows the peer has moved (e.g., mobile
    /// handoff, app-level rendezvous update). The existing session is
    /// preserved — identity remains bound to the same pubkey, only the
    /// socket address changes. Returns true if the peer was found.
    pub async fn update_peer_addr(&self, peer_id: &PeerId, new_addr: SocketAddr) -> bool {
        let old_addr: Option<SocketAddr> = {
            let mut peers = self.inner.peers.lock_for(peer_id).await;
            match peers.get_mut(peer_id) {
                Some(peer) => {
                    let old = peer.addr;
                    peer.addr = new_addr;
                    Some(old)
                }
                None => None,
            }
        };
        match old_addr {
            Some(old) => {
                self.inner
                    .peers
                    .note_addr_changed(*peer_id, old, new_addr)
                    .await;
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

    /// Cross-interface variant of `probe_candidate_path`. Sends
    /// the PathChallenge via `iface_idx` instead of the peer's
    /// currently registered interface. On a matching
    /// PathResponse arriving on the same iface, the peer
    /// migrates to BOTH the new addr AND the new outbound iface
    /// — so subsequent send_data flows over the validated path.
    ///
    /// drift-vpn uses this for cross-scheme failover: when UDP
    /// is blocked, the supervisor opens a TCP connector to the
    /// peer's TCP endpoint, attaches it as a new interface via
    /// `add_interface`, and probes through it.
    pub async fn probe_candidate_path_via(
        &self,
        peer_id: &PeerId,
        candidate_addr: SocketAddr,
        iface_idx: usize,
    ) -> Result<()> {
        self.inner
            .probe_candidate_path_via(peer_id, candidate_addr, iface_idx)
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
        let inserted_at: Option<SocketAddr> = {
            let mut peers = self.inner.peers.lock_for(&id).await;
            match peers.get(&id) {
                Some(existing) if existing.peer_static_pub != peer_static_pub => {
                    self.inner
                        .metrics
                        .peer_id_collisions
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(peer_id = ?id, "peer id collision in add_peer; rejecting");
                    return Err(DriftError::PeerIdCollision);
                }
                Some(_) => None,
                None => {
                    let peer = Peer::new(id, addr, peer_static_pub, direction);
                    peers.insert(peer);
                    Some(addr)
                }
            }
        };
        // SEC.FIX.1 fast-gate: maintain the addr_index after the
        // shard guard drops. See peer_shards.rs for the lock-
        // ordering and stale-positive analysis.
        if let Some(addr) = inserted_at {
            self.inner.peers.note_inserted(id, addr).await;
        }
        Ok(id)
    }

    /// Register a peer that has no known direct address — it
    /// will be reached only via mesh forwarding through another
    /// peer. Sets `via_mesh = true` up front so `send_data`
    /// consults the mesh routing table on every call instead
    /// of attempting a direct send to a placeholder addr.
    ///
    /// Used by drift-vpn's hub-and-spoke topology: a spoke that
    /// can't accept incoming connections (mobile, behind NAT)
    /// gets registered this way; the hub peer that connects to
    /// both ends advertises a route via beacons; once the hub
    /// learns the mesh path, traffic flows transparently.
    ///
    /// Until a route is learned, `send_data` will return
    /// `UnknownPeer` because there's no path. That's correct —
    /// just like sending to a peer whose direct addr is offline
    /// at startup.
    pub async fn add_mesh_peer(
        &self,
        peer_static_pub: [u8; STATIC_KEY_LEN],
        direction: Direction,
    ) -> Result<PeerId> {
        let id = derive_peer_id(&peer_static_pub);
        // 0.0.0.0:0 is a non-routable placeholder that the
        // mesh router will replace via `learned_route` lookups
        // every send_data call.
        let placeholder: SocketAddr = "0.0.0.0:0".parse().expect("constant addr parses");
        let inserted_at: Option<SocketAddr> = {
            let mut peers = self.inner.peers.lock_for(&id).await;
            match peers.get(&id) {
                Some(existing) if existing.peer_static_pub != peer_static_pub => {
                    self.inner
                        .metrics
                        .peer_id_collisions
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(peer_id = ?id, "peer id collision in add_mesh_peer; rejecting");
                    return Err(DriftError::PeerIdCollision);
                }
                Some(_) => None,
                None => {
                    let mut peer = Peer::new(id, placeholder, peer_static_pub, direction);
                    peer.via_mesh = true;
                    peers.insert(peer);
                    Some(placeholder)
                }
            }
        };
        if let Some(addr) = inserted_at {
            self.inner.peers.note_inserted(id, addr).await;
        }
        Ok(id)
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

    // ─── Federated routing ──────────────────────────────────────
    //
    // Federation is a *non-mesh* relay model: bridges talk directly
    // to each other by explicit configuration (no beacon-driven
    // route discovery), and clients pubkey-address a far-side peer
    // via `(target_bridge_pub, target_client_pub)`. Modeled on
    // Matrix / XMPP server-to-server federation.

    /// Register a peer bridge for federation. The bridge must
    /// already have been added as a regular peer via `add_peer`
    /// (this method just maps its 32-byte pubkey to its PeerId
    /// for the federation envelope lookup).
    pub fn register_federation_peer(&self, bridge_pub: [u8; 32], bridge_peer_id: PeerId) {
        let mut t = self.inner.federation_table.lock().unwrap();
        t.insert(bridge_pub, bridge_peer_id);
    }

    /// Establish an outbound federation link to another bridge over
    /// an arbitrary transport (UDP/TCP/WS/TLS/…).  Unlike `add_peer`
    /// — which assumes the existing primary interface can reach the
    /// remote — this method actually *connects* using the URL's
    /// scheme, attaches the resulting connection as a new interface
    /// on this transport, and pins the peer's `interface_id` to it.
    ///
    /// This is what bridges should call for every `--federate <url>`
    /// flag: it works for connection-oriented transports (TCP, TLS,
    /// WS) where you can't legitimately send through a listener
    /// socket. For UDP, it falls back to the equivalent of the old
    /// "reuse primary socket" path by attaching the connector's
    /// UDP socket as an additional interface — slightly less
    /// efficient than reusing the primary for UDP-only deployments
    /// but symmetric, simpler, and harmless.
    ///
    /// Returns the `PeerId` of the federation peer, which is also
    /// recorded in the federation table for cross-bridge envelope
    /// forwarding.
    pub async fn connect_federate(
        &self,
        url: &str,
        target_pubkey: [u8; STATIC_KEY_LEN],
    ) -> Result<PeerId> {
        let (io, addr) = crate::io::make_connector(url)
            .await
            .map_err(DriftError::Io)?;
        let scheme = url.find("://").map(|i| &url[..i]).unwrap_or("udp");
        let iface_idx = self.add_interface(format!("{}-federate-out", scheme), io);
        let peer_id = self
            .add_peer(target_pubkey, addr, Direction::Initiator)
            .await?;
        // Pin the peer's outbound interface to the newly-attached
        // connector, since interface 0 (the primary) may be a TCP
        // listener placeholder or a different scheme's socket.
        {
            let mut peers = self.inner.peers.lock_for(&peer_id).await;
            if let Some(p) = peers.get_mut(&peer_id) {
                p.interface_id = iface_idx;
            }
        }
        self.register_federation_peer(target_pubkey, peer_id);
        Ok(peer_id)
    }

    /// Register a remote client peer reachable via federation.
    /// After this call, normal `send_data(&peer_id, ...)` to
    /// the returned id transparently wraps payloads in a
    /// `PacketType::Federated` envelope and ships them via
    /// `via_bridge`. The receiver's `Transport::recv()` will
    /// yield a `Received` whose `peer_id` matches what this
    /// method returns, so existing tools (drift-mosh,
    /// drift-wormhole, drift-http, …) that use the send_data /
    /// recv API work over federation without any changes —
    /// federation is a routing concern, not an app concern.
    ///
    /// Caller contract:
    /// * `via_bridge` must already be in the peer table and
    ///   have an Established session (the local bridge link).
    /// * `target_bridge_pub` is the pubkey of the *remote*
    ///   bridge the target client is connected to; goes into
    ///   the envelope's `target_bridge_pub` slot for the local
    ///   bridge's federation-table lookup.
    /// * `target_client_pub` is the remote client's pubkey.
    ///
    /// Returns the `PeerId` to use in `send_data`. Insertion
    /// is idempotent: a second call with the same pubkey
    /// returns the same id without disturbing existing state.
    pub async fn add_federated_peer(
        &self,
        target_client_pub: [u8; 32],
        via_bridge: PeerId,
        target_bridge_pub: [u8; 32],
    ) -> Result<PeerId> {
        let id = derive_peer_id(&target_client_pub);
        let placeholder: SocketAddr = "0.0.0.0:0".parse().expect("constant addr parses");
        let inserted_at: Option<SocketAddr> = {
            let mut peers = self.inner.peers.lock_for(&id).await;
            match peers.get_mut(&id) {
                Some(existing) if existing.peer_static_pub != target_client_pub => {
                    self.inner
                        .metrics
                        .peer_id_collisions
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(DriftError::PeerIdCollision);
                }
                Some(existing) => {
                    existing.federated_via = Some(via_bridge);
                    existing.federated_target_bridge_pub = Some(target_bridge_pub);
                    None
                }
                None => {
                    // Federated peers don't have a direct DRIFT
                    // session with us — the bridge handles all
                    // crypto-bearing forwarding. We leave handshake
                    // in the default `Pending` state; `send_data`
                    // recognizes `federated_via.is_some()` and
                    // short-circuits to the federated path BEFORE
                    // any handshake-state check, so the placeholder
                    // session state is never read.
                    let mut peer =
                        Peer::new(id, placeholder, target_client_pub, Direction::Initiator);
                    peer.federated_via = Some(via_bridge);
                    peer.federated_target_bridge_pub = Some(target_bridge_pub);
                    peers.insert(peer);
                    Some(placeholder)
                }
            }
        };
        if let Some(addr) = inserted_at {
            self.inner.peers.note_inserted(id, addr).await;
        }
        Ok(id)
    }

    /// Send a federated payload to `target_client_pub` via the
    /// remote bridge `target_bridge_pub`. The payload is wrapped
    /// in a `PacketType::Federated` envelope and shipped to the
    /// local bridge `via_bridge_peer` — that bridge forwards to
    /// the target bridge (per its federation table), which
    /// delivers to the target client.
    ///
    /// End-to-end semantics: bridges only see the envelope (which
    /// has pubkeys + an opaque payload). The payload itself is
    /// whatever the application wants — for DRIFT client-to-client
    /// crypto, the application supplies an AEAD-sealed inner
    /// DRIFT packet.
    pub async fn send_federated(
        &self,
        via_bridge_peer: &PeerId,
        target_bridge_pub: [u8; 32],
        target_client_pub: [u8; 32],
        payload: &[u8],
    ) -> Result<()> {
        // Federated envelopes carry a 98-byte header on top of
        // the user payload (32+32+32+2). Subtract that from
        // MAX_PAYLOAD to get the real per-call ceiling.
        let max_user_payload = MAX_PAYLOAD.saturating_sub(federated::FED_HEADER_LEN);
        if payload.len() > max_user_payload {
            return Err(DriftError::PayloadTooLarge {
                got: max_user_payload,
                cap: payload.len(),
            });
        }
        let source_client_pub = self.inner.identity.public_bytes();
        // The bridge we're going through IS our source bridge,
        // by definition. Look up its pubkey for the envelope.
        let source_bridge_pub = {
            let peers = self.inner.peers.lock_for(via_bridge_peer).await;
            peers
                .get(via_bridge_peer)
                .map(|p| p.peer_static_pub)
                .ok_or(PeerError::NotRegistered)?
        };
        let envelope = federated::build(
            &target_bridge_pub,
            &target_client_pub,
            &source_bridge_pub,
            &source_client_pub,
            payload,
        );
        // Reuse the regular DATA send path but tag the packet
        // type as Federated. send_data wraps payload as Data;
        // here we go through a specialized path so the outer
        // packet's `packet_type` byte is Federated.
        self.inner
            .send_typed(via_bridge_peer, PacketType::Federated, &envelope)
            .await
    }

    /// Number of currently-registered federation peers. For
    /// observability and tests.
    pub fn federation_peer_count(&self) -> usize {
        self.inner.federation_table.lock().unwrap().len()
    }

    /// Returns true if the given bridge pubkey is currently in the
    /// federation table. For tests + observability — production
    /// code shouldn't need to introspect routing tables directly.
    #[doc(hidden)]
    pub fn federation_table_contains(&self, bridge_pub: &[u8; 32]) -> bool {
        self.inner
            .federation_table
            .lock()
            .unwrap()
            .contains_key(bridge_pub)
    }

    /// Announce a list of locally-connected client pubkeys to every
    /// peer in our federation table. Used by `drift bridge`'s
    /// directory-announce task: every N seconds the bridge gathers
    /// the pubkeys of its currently-connected clients (peers in
    /// the peer table that aren't themselves federation bridges)
    /// and ships them via `PacketType::FederationDirectory` to
    /// each fed peer.
    ///
    /// Receiving bridges record `client_pub → (sender_peer_id, now)`
    /// in their peer directory; entries expire after 60 s without
    /// re-announcement. Clients can then send `Federated` envelopes
    /// with `target_bridge_pub = UNKNOWN_BRIDGE_PUB` and let any
    /// transit bridge resolve via its directory.
    ///
    /// `client_pubs` is chunked into `MAX_DIRECTORY_ENTRIES`-sized
    /// packets so a single announcement always fits comfortably
    /// under MAX_PAYLOAD. The function returns after all chunks
    /// have been queued; failures to individual peers are logged
    /// and otherwise ignored (one fed peer being unreachable
    /// shouldn't prevent the others from receiving the update).
    pub async fn announce_directory(&self, entries: &[([u8; 32], federated::PresenceTicket)]) {
        let peers: Vec<PeerId> = self
            .inner
            .federation_table
            .lock()
            .unwrap()
            .values()
            .copied()
            .collect();
        if peers.is_empty() {
            return;
        }

        // Phase C: build a snapshot of transitively-known entries
        // eligible for re-announcement. An entry can be
        // re-announced with hops+1 only if hops+1 <
        // MAX_ANNOUNCE_HOPS — i.e. current hops < MAX_ANNOUNCE_HOPS - 1.
        // For each transitive entry we also need the announcer
        // PeerId so we can apply split-horizon (don't tell B
        // about a client we learned from B).
        let transitive: Vec<([u8; 32], federated::PresenceTicket, u8, PeerId)> = {
            // Phase G: read cap from per-bridge config rather
            // than the previous hardcoded MAX_ANNOUNCE_HOPS=2.
            // Receivers honor whatever hops value an inbound
            // entry carries; this cap only governs what we
            // re-emit.
            let hops_cap = self.inner.config.max_announce_hops;
            let dir = self.inner.peer_directory.lock().unwrap();
            let hops_map = self.inner.peer_directory_hops.lock().unwrap();
            let tickets = self.inner.peer_directory_tickets.lock().unwrap();
            let mut out = Vec::new();
            for (client_pub, (announcer_pid, _)) in dir.iter() {
                let hops = match hops_map.get(client_pub) {
                    Some(&h) if h + 1 < hops_cap => h,
                    _ => continue,
                };
                if let Some(ticket) = tickets.get(client_pub) {
                    out.push((*client_pub, ticket.clone(), hops + 1, *announcer_pid));
                }
            }
            out
        };

        // Phase F: build the bloom filter once per announce
        // cycle if configured. The same filter goes out to every
        // federation peer (no per-recipient bloom — it'd defeat
        // the privacy point of having ONE consistent view of
        // "what hashes match this bridge's local clients").
        //
        // We hash the direct entries' pubkeys plus the transitive
        // ones (across all announcers) — the filter represents
        // "any client reachable via me", which is what receivers
        // actually want to test against.
        let bloom: Option<dp_bloom::DpBloomFilter> =
            self.inner.config.bloom_announce_noise.map(|noise| {
                let mut salt = [0u8; dp_bloom::BLOOM_SALT_LEN];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
                let mut f = dp_bloom::DpBloomFilter::default_for_size(salt);
                for (pk, _) in entries {
                    f.insert(pk);
                }
                for (pk, _, _, _) in &transitive {
                    f.insert(pk);
                }
                f.add_dp_noise(noise);
                f
            });
        let cap = if bloom.is_some() {
            federated::MAX_DIRECTORY_ENTRIES_V4
        } else {
            federated::MAX_DIRECTORY_ENTRIES
        };

        // For each federation peer, build a v3-or-v4 payload
        // combining:
        //   - direct entries (hops=0), always included
        //   - transitive entries (hops+1), filtered by split-horizon
        //     (skip entries we learned FROM this peer).
        //   - bloom filter (v4 only), attached to the FIRST chunk.
        for peer_id in &peers {
            let mut combined: Vec<([u8; 32], federated::PresenceTicket, u8)> =
                entries.iter().map(|(p, t)| (*p, t.clone(), 0u8)).collect();
            for (pub_, ticket, new_hops, announcer) in &transitive {
                if *announcer == *peer_id {
                    continue; // split horizon
                }
                combined.push((*pub_, ticket.clone(), *new_hops));
            }
            let chunks: Vec<Vec<u8>> = if let Some(b) = &bloom {
                if combined.is_empty() {
                    vec![federated::build_directory_v4(&[], Some(b))]
                } else {
                    let mut out = Vec::new();
                    let mut first = true;
                    for chunk in combined.chunks(cap) {
                        let bloom_for_chunk = if first {
                            first = false;
                            Some(b)
                        } else {
                            None
                        };
                        out.push(federated::build_directory_v4(chunk, bloom_for_chunk));
                    }
                    out
                }
            } else if combined.is_empty() {
                vec![federated::build_directory_v3(&[])]
            } else {
                combined
                    .chunks(cap)
                    .map(federated::build_directory_v3)
                    .collect()
            };
            for chunk in &chunks {
                if let Err(e) = self
                    .inner
                    .send_typed(peer_id, PacketType::FederationDirectory, chunk)
                    .await
                {
                    debug!(
                        error = %e,
                        peer = ?peer_id,
                        "directory: announce send failed"
                    );
                }
            }
        }
    }

    /// Snapshot the pubkeys of all currently-Established peers
    /// that are NOT themselves federation bridges. This is what
    /// `drift bridge` advertises in its directory announcements:
    /// "these are the clients I host." Excludes peers in
    /// `federation_table` so a bridge doesn't accidentally tell
    /// its federation peers "I host bridge X" and create a
    /// route-back-to-self loop.
    pub async fn established_client_pubkeys(&self) -> Vec<[u8; 32]> {
        let fed_pubs: std::collections::HashSet<[u8; 32]> = self
            .inner
            .federation_table
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect();
        let mut out = Vec::new();
        let peers = self.inner.peers.lock_all().await;
        for p in peers.iter() {
            if matches!(
                p.handshake,
                drift_core::session::HandshakeState::Established { .. }
            ) && !fed_pubs.contains(&p.peer_static_pub)
            {
                out.push(p.peer_static_pub);
            }
        }
        out
    }

    /// Snapshot the (pubkey, presence-ticket) pairs for every
    /// Established non-federation peer that has emitted a valid
    /// presence ticket to us. This is what `drift bridge`
    /// hands to `announce_directory` — only pubkeys we actually
    /// have cryptographic attestation for go out in the
    /// FederationDirectory packet.
    ///
    /// Clients that haven't sent us a ticket yet are silently
    /// omitted (they'll appear once they do). This excludes
    /// "freeloader" clients that won't sign tickets — but in
    /// practice every DRIFT client that talks to a bridge calls
    /// `register_presence_to` for its bridge during startup,
    /// so the omission is a non-event in the legitimate case.
    pub async fn established_client_entries(&self) -> Vec<([u8; 32], federated::PresenceTicket)> {
        let fed_pubs: std::collections::HashSet<[u8; 32]> = self
            .inner
            .federation_table
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect();
        let mut pubs = Vec::new();
        let peers = self.inner.peers.lock_all().await;
        for p in peers.iter() {
            if matches!(
                p.handshake,
                drift_core::session::HandshakeState::Established { .. }
            ) && !fed_pubs.contains(&p.peer_static_pub)
            {
                pubs.push(p.peer_static_pub);
            }
        }
        drop(peers);
        let tickets = self.inner.presence_tickets.lock().unwrap();
        pubs.into_iter()
            .filter_map(|pk| tickets.get(&pk).cloned().map(|t| (pk, t)))
            .collect()
    }

    /// Sign and emit a presence ticket to `bridge` so it can
    /// announce us in its FederationDirectory. Returns once the
    /// ticket has been queued for send; the bridge stores the
    /// ticket on receipt and immediately becomes able to attest
    /// to our presence on its next directory tick.
    ///
    /// `lifetime_ms` controls how long the bridge can use the
    /// ticket before it expires. 10 minutes (600_000 ms) is a
    /// reasonable default — long enough that minor clock skew
    /// between client and verifier doesn't matter, short enough
    /// that a stolen ticket becomes useless quickly.
    ///
    /// Callers should re-invoke this periodically (typically at
    /// lifetime_ms / 2) to refresh the bridge's stored copy.
    pub async fn register_presence_to(&self, bridge: &PeerId, lifetime_ms: u64) -> Result<()> {
        let bridge_pub = {
            let peers = self.inner.peers.lock_for(bridge).await;
            peers
                .get(bridge)
                .map(|p| p.peer_static_pub)
                .ok_or(PeerError::NotRegistered)?
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let expiry_ms = now_ms.saturating_add(lifetime_ms);

        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let mut nonce_extra = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_extra);

        let signed_msg = federated::ticket_signed_msg(&bridge_pub, expiry_ms, &nonce);
        let sig = self.inner.identity.xeddsa_sign(&signed_msg, &nonce_extra);
        let ticket = federated::PresenceTicket {
            expiry_ms,
            nonce,
            sig,
        };
        let wire = federated::encode_ticket(&ticket);
        self.inner
            .send_typed(bridge, PacketType::PresenceTicket, &wire)
            .await
    }

    /// Number of currently-known entries in the peer directory.
    /// For observability + tests.
    pub fn peer_directory_count(&self) -> usize {
        self.inner.peer_directory.lock().unwrap().len()
    }

    /// Returns true if the given client pubkey is currently in our
    /// peer directory (without expiry check). Used by tests.
    #[doc(hidden)]
    pub fn peer_directory_contains(&self, client_pub: &[u8; 32]) -> bool {
        self.inner
            .peer_directory
            .lock()
            .unwrap()
            .contains_key(client_pub)
    }

    /// Number of in-flight `FindPeer` queries we've originated.
    /// Used by Phase A integration tests.
    #[doc(hidden)]
    pub fn pending_finds_count(&self) -> usize {
        self.inner.pending_finds.lock().unwrap().len()
    }

    /// Returns true if a `FindPeer` query is in flight for the
    /// given client. Used by Phase A integration tests.
    #[doc(hidden)]
    pub fn pending_finds_contains(&self, client_pub: &[u8; 32]) -> bool {
        self.inner
            .pending_finds
            .lock()
            .unwrap()
            .contains_key(client_pub)
    }

    /// Number of "not found" entries currently cached. Used by
    /// Phase A integration tests to verify negative-cache behavior.
    #[doc(hidden)]
    /// Number of recently-seen FindPeer query_ids. Phase F
    /// cover-traffic test asserts this populates as decoys
    /// arrive at recipient bridges.
    #[doc(hidden)]
    pub fn recent_queries_count(&self) -> usize {
        self.inner.recent_queries.lock().unwrap().len()
    }

    /// Phase F.8: fault counter for a specific federation
    /// peer. Returns 0 if no faults have been recorded.
    #[doc(hidden)]
    pub fn bridge_fault_count(&self, peer: &PeerId) -> u32 {
        self.inner
            .bridge_faults
            .lock()
            .unwrap()
            .get(peer)
            .copied()
            .unwrap_or(0)
    }

    pub fn neg_cache_count(&self) -> usize {
        self.inner.neg_cache.lock().unwrap().len()
    }

    /// Test-only escape hatch: ship arbitrary bytes through an
    /// established session, tagged as `PacketType::Federated`.
    /// Normal callers must use `send_federated`, which forces
    /// `source_client_pub` to the local identity. This method
    /// exists so adversarial-federation tests can construct
    /// envelopes with forged fields and verify the protocol's
    /// defenses (or document the lack of them).
    ///
    /// Doc-hidden + `__debug` prefix so it doesn't appear in
    /// the regular API surface or rust-analyzer autocomplete.
    #[doc(hidden)]
    pub async fn __debug_send_federated_envelope(
        &self,
        via_bridge_peer: &PeerId,
        envelope: &[u8],
    ) -> Result<()> {
        self.inner
            .send_typed(via_bridge_peer, PacketType::Federated, envelope)
            .await
    }

    /// Test-only: ship a raw FederationDirectory payload to a peer.
    /// Lets tests exercise the directory layer's semantics
    /// (first-write-wins, idempotent-set, evict-on-failure)
    /// without spinning up the 7 s announce ticker.
    #[doc(hidden)]
    pub async fn __debug_send_directory_announcement(
        &self,
        via_bridge_peer: &PeerId,
        payload: &[u8],
    ) -> Result<()> {
        self.inner
            .send_typed(via_bridge_peer, PacketType::FederationDirectory, payload)
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
    pub async fn send_data_batch(&self, items: &[(PeerId, Vec<u8>)]) -> Result<usize> {
        self.inner.send_data_batch(items).await
    }

    /// Batched variant with per-item QoS hints. Same syscall
    /// economics as `send_data_batch` but each item carries
    /// its own `deadline_ms` and `coalesce_group` so callers
    /// (drift-vpn's classifier) don't lose feature parity with
    /// the per-packet `send_data` API when they switch to
    /// batching.
    pub async fn send_data_batch_qos(&self, items: &[BatchItem]) -> Result<usize> {
        self.inner.send_data_batch_qos(items).await
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

    /// Whether `peer` currently has an Established session
    /// (data can flow without further handshake). Returns
    /// `false` for unknown peers, Pending peers, mid-handshake
    /// peers, and peers with sessions that have been reset.
    /// Cheap — one peer-table lookup under the per-shard lock.
    pub async fn peer_is_established(&self, peer: &PeerId) -> bool {
        let peers = self.inner.peers.lock_for(peer).await;
        peers
            .get(peer)
            .map(|p| {
                matches!(
                    p.handshake,
                    drift_core::session::HandshakeState::Established { .. }
                )
            })
            .unwrap_or(false)
    }

    /// Current addr the transport will send to for `peer`.
    /// `None` if the peer is unknown. Used by happy-eyeballs
    /// callers to verify a session was established at the
    /// addr they probed (vs. the transport auto-updating the
    /// peer's addr based on an incoming HELLO from elsewhere).
    pub async fn peer_addr(&self, peer: &PeerId) -> Option<SocketAddr> {
        let peers = self.inner.peers.lock_for(peer).await;
        peers.get(peer).map(|p| p.addr)
    }

    /// Per-peer link-quality snapshot. `None` if the peer is
    /// unknown. See `PeerMetrics` for field semantics.
    ///
    /// Intended for callers driving routing or failover (e.g.
    /// drift-vpn deciding to switch endpoints because RTT
    /// degraded). One peer-table lookup under a per-shard lock.
    pub async fn peer_metrics(&self, peer: &PeerId) -> Option<PeerMetrics> {
        let peers = self.inner.peers.lock_for(peer).await;
        let p = peers.get(peer)?;
        Some(PeerMetrics {
            srtt: p.neighbor_srtt,
            rttvar: p.neighbor_rttvar,
            last_seen: p.last_seen,
            next_tx_seq: p.next_tx_seq,
            highest_rx_seq: p.highest_rx_seq,
            is_established: matches!(
                p.handshake,
                drift_core::session::HandshakeState::Established { .. }
            ),
        })
    }

    /// Reset a peer's session state without notifying the remote.
    /// Differs from `close_peer` in two ways:
    ///
    /// 1. Works in *any* state — pre-handshake, mid-handshake,
    ///    or established. `close_peer` requires
    ///    `is_ready_for_data()`.
    /// 2. Doesn't send a `Close` packet. Useful when the wire
    ///    we'd send it on is broken (e.g., we're about to
    ///    migrate transports) or when we want to silently
    ///    re-handshake at the current `peer.addr` (e.g., the
    ///    addr just changed via `update_peer_addr` and the
    ///    in-flight HELLO is going to the wrong place).
    ///
    /// Preserved across the reset: `addr`, `peer_static_pub`,
    /// `direction`, `interface_id`, `auto_registered`,
    /// `via_mesh`. Cleared: handshake state, session keys,
    /// sequence counters, CID maps, replay bitmap, coalesce
    /// state, pending sends, RTT samples, resumption-in-flight
    /// state, path-validation probes.
    ///
    /// After `restart_handshake`, the next `send_data` to this
    /// peer will trigger a fresh HELLO toward the (possibly
    /// updated) `peer.addr`.
    ///
    /// Returns `Err(UnknownPeer)` if the peer isn't in our
    /// table.
    pub async fn restart_handshake(&self, dst: &PeerId) -> Result<()> {
        self.inner.restart_handshake(dst).await
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
        let ticket = tickets
            .get(peer)
            .ok_or(PeerError::ResumptionTicketNotFound)?;
        if ticket.expiry <= std::time::SystemTime::now() {
            return Err(PeerError::ResumptionTicketNotFound.into());
        }
        Ok(ticket.to_bytes())
    }

    /// Install a previously exported resumption ticket for
    /// `peer`. The next `send_data` to this peer will use a
    /// `ResumeHello` instead of a full HELLO. Returns
    /// `Err(AuthFailed)` if the blob is malformed or doesn't
    /// match the peer's stored static pubkey.
    pub async fn import_resumption_ticket(&self, peer: &PeerId, blob: &[u8]) -> Result<()> {
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
        self.inner.client_tickets.lock().await.insert(*peer, ticket);
        self.inner
            .has_any_ticket
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Await the next authenticated DATA packet. Returns None if the
    /// background task has shut down (socket closed).
    pub async fn recv(&self) -> Option<Received> {
        self.rx.lock().await.recv().await
    }

    /// Install a session-reset listener. Returns a receiver that
    /// fires the peer id whenever that peer's authenticated
    /// session was regenerated by a fresh HELLO (typical
    /// trigger: client process restarted and reconnected from a
    /// new source IP). Higher layers — most importantly
    /// `StreamManager` — use this to drop per-peer state
    /// (stream tables, congestion gauges, next-id counters)
    /// that no longer matches the new session.
    ///
    /// At most one listener at a time; calling this again
    /// replaces the previous receiver. Intended to be called
    /// once, by `StreamManager::bind`. Failing to install a
    /// listener is fine — the channel is optional and
    /// transport behavior is unchanged.
    pub fn take_session_reset_listener(&self) -> mpsc::UnboundedReceiver<PeerId> {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut slot) = self.inner.session_reset_tx.lock() {
            *slot = Some(tx);
        }
        rx
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
            let peer = peers.get_mut(dst).ok_or(PeerError::NotRegistered)?;
            let (old_tx, old_rx, old_key_bytes) = match &peer.handshake {
                HandshakeState::Established {
                    tx, rx, key_bytes, ..
                } => (tx.clone(), rx.clone(), key_bytes.clone()),
                _ => return Err(PeerError::SessionNotEstablished.into()),
            };

            // 1. Build the RekeyRequest packet, sealed with the
            //    OLD tx key, body = 32 salt bytes.
            let seq = peer.next_seq_checked()?;
            let mut header = peer.make_header(PacketType::RekeyRequest, seq, self.local_peer_id);
            header.payload_len = (32 + AUTH_TAG_LEN) as u16;
            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);
            let aad = canonical_aad(&hbuf);
            let mut wire = Vec::with_capacity(HEADER_LEN + 32 + AUTH_TAG_LEN);
            wire.extend_from_slice(&hbuf);
            old_tx.seal_into(seq, PacketType::RekeyRequest as u8, &aad, &salt, &mut wire)?;

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
                key_bytes: new_key_bytes.clone(),
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
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;

        let (ack_wire, ack_addr, new_key_bytes_rekey) = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (old_tx, old_rx, old_key_bytes) = match &peer.handshake {
                HandshakeState::Established {
                    tx, rx, key_bytes, ..
                } => (tx.clone(), rx.clone(), key_bytes.clone()),
                _ => return Err(PeerError::SessionNotEstablished.into()),
            };

            // Decrypt body with current rx.
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            let salt_bytes = old_rx.open(header.seq, PacketType::RekeyRequest as u8, &aad, body)?;
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
                key_bytes: new_key_bytes_val.clone(),
                prev: Some(PrevSession {
                    tx: old_tx,
                    rx: old_rx,
                    installed_at: Instant::now(),
                }),
            };

            // Build the RekeyAck sealed with the NEW tx.
            let ack_seq = peer.next_seq_checked()?;
            let mut ack_header =
                peer.make_header(PacketType::RekeyAck, ack_seq, self.local_peer_id);
            ack_header.payload_len = AUTH_TAG_LEN as u16;
            let mut ack_hbuf = [0u8; HEADER_LEN];
            ack_header.encode(&mut ack_hbuf);
            let ack_aad = canonical_aad(&ack_hbuf);
            let (tx_ref, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let mut ack_wire = Vec::with_capacity(HEADER_LEN + AUTH_TAG_LEN);
            ack_wire.extend_from_slice(&ack_hbuf);
            tx_ref.seal_into(
                ack_seq,
                PacketType::RekeyAck as u8,
                &ack_aad,
                b"",
                &mut ack_wire,
            )?;

            (ack_wire, peer.addr, new_key_bytes_val)
        };

        self.ifaces
            .send_for(self.iface_for(&peer_id).await, &ack_wire, ack_addr)
            .await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(ack_wire.len() as u64, Ordering::Relaxed);
        // Refresh CID maps for the rekeyed session (Responder side).
        self.install_cids(peer_id, &new_key_bytes_rekey, false)
            .await;
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
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;
        let mut peers = self.peers.lock_for(&peer_id).await;
        let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;

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
        let (bytes, addr, removed) = {
            let mut peers = self.peers.lock_for(dst).await;
            let peer = peers.get_mut(dst).ok_or(PeerError::NotRegistered)?;
            if !peer.handshake.is_ready_for_data() {
                return Err(PeerError::SessionNotReady.into());
            }
            let was_awaiting_data = matches!(peer.handshake, HandshakeState::AwaitingData { .. });
            let wire = build_close_packet(self.local_peer_id, peer)?;
            let addr = peer.addr;

            // Drop local state immediately — we won't accept any
            // further DATA on this session and won't retry the
            // Close if it gets lost.
            let removed = if peer.auto_registered {
                peers.remove(dst);
                true
            } else {
                peer.handshake = HandshakeState::Pending;
                peer.pending.clear();
                peer.session_epoch = None;
                peer.probing = None;
                false
            };
            if was_awaiting_data {
                self.metrics
                    .handshakes_inflight
                    .fetch_sub(1, Ordering::Relaxed);
            }
            (wire, addr, removed)
        };
        if removed {
            self.peers.note_removed(dst, addr).await;
        }

        self.ifaces
            .send_for(self.iface_for(dst).await, &bytes, addr)
            .await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn restart_handshake(&self, dst: &PeerId) -> Result<()> {
        // Reset the peer entry to a fresh state. We preserve
        // identity-bound + routing-bound fields (`addr`,
        // `peer_static_pub`, `direction`, `interface_id`,
        // `auto_registered`, `via_mesh`) and clear everything
        // else (handshake state, session keys, sequence
        // counters, replay bitmap, coalesce state, pending
        // sends, RTT samples, resumption-in-flight, path
        // probes, unauth byte counters).
        let was_awaiting_data;
        {
            let mut peers = self.peers.lock_for(dst).await;
            let peer = peers.get_mut(dst).ok_or(PeerError::NotRegistered)?;
            was_awaiting_data = matches!(peer.handshake, HandshakeState::AwaitingData { .. });

            let preserved_addr = peer.addr;
            let preserved_pub = peer.peer_static_pub;
            let preserved_dir = peer.direction;
            let preserved_iface = peer.interface_id;
            let preserved_auto = peer.auto_registered;
            let preserved_via_mesh = peer.via_mesh;

            let mut fresh =
                drift_core::session::Peer::new(*dst, preserved_addr, preserved_pub, preserved_dir);
            fresh.interface_id = preserved_iface;
            fresh.auto_registered = preserved_auto;
            fresh.via_mesh = preserved_via_mesh;
            *peer = fresh;
        }

        // Drop CID-map entries. `cid_map` is the inbound-CID →
        // peer_id index; we don't keep a per-peer reverse list
        // so we sweep the whole map removing entries pointing
        // at this peer. `peer_out_cid` is per-peer.
        {
            let mut cid_map = self.cid_map.lock().unwrap();
            cid_map.retain(|_cid, pid| pid != dst);
        }
        {
            let mut peer_out_cid = self.peer_out_cid.lock().unwrap();
            peer_out_cid.remove(dst);
        }

        // Drop the cached resumption ticket for this peer. Without
        // this, the next `send_data` would pick `ResumeHello`
        // (because a ticket is on file) and the remote — which
        // may have lost all state in the very scenario we're
        // recovering from — would reject the resumed handshake
        // and just drop our packets. Force a full HELLO instead.
        {
            let mut tickets = self.client_tickets.lock().await;
            tickets.remove(dst);
        }

        if was_awaiting_data {
            self.metrics
                .handshakes_inflight
                .fetch_sub(1, Ordering::Relaxed);
        }

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

        // Federated-peer short-circuit: if this peer was added
        // via `add_federated_peer`, route the payload through
        // the configured bridge instead of trying to send
        // directly. The bridge holds the only DRIFT session
        // (between us and it); send_typed handles the AEAD
        // for that hop. The bridge will then forward the
        // envelope to the target client via its federation
        // table (Matrix-style direct pubkey routing, not the
        // beacon-driven mesh path).
        let federated_route = {
            let peers = self.peers.lock_for(dst).await;
            peers.get(dst).and_then(|p| {
                if let (Some(via), Some(target_bridge)) =
                    (p.federated_via, p.federated_target_bridge_pub)
                {
                    Some((via, target_bridge, p.peer_static_pub))
                } else {
                    None
                }
            })
        };
        if let Some((via_bridge, target_bridge_pub, target_client_pub)) = federated_route {
            // Same payload-size ceiling as send_federated.
            let max_user_payload = MAX_PAYLOAD.saturating_sub(federated::FED_HEADER_LEN);
            if payload.len() > max_user_payload {
                return Err(DriftError::PayloadTooLarge {
                    got: max_user_payload,
                    cap: payload.len(),
                });
            }
            // Honor the deadline / coalesce QoS by stamping them
            // into… nope, federated payloads are opaque to bridges.
            // Higher-layer QoS would need to ride inside the
            // payload itself for the receiver to see it. For now
            // we silently ignore deadline_ms / coalesce_group on
            // federated sends; documented limitation.
            let _ = (deadline_ms, coalesce_group);
            let source_client_pub = self.identity.public_bytes();
            // Source bridge pubkey = the bridge we're routing
            // through. Look it up from the peer table.
            let source_bridge_pub = {
                let peers = self.peers.lock_for(&via_bridge).await;
                peers
                    .get(&via_bridge)
                    .map(|p| p.peer_static_pub)
                    .ok_or(PeerError::NotRegistered)?
            };
            let envelope = federated::build(
                &target_bridge_pub,
                &target_client_pub,
                &source_bridge_pub,
                &source_client_pub,
                payload,
            );
            return self
                .send_typed(&via_bridge, PacketType::Federated, &envelope)
                .await;
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
        // Hot-path short-circuit: most apps never use resumption,
        // so `has_any_ticket` stays false forever and we skip the
        // mutex+peer-lookup pair entirely. The flag is a strict
        // hint — a stale `true` just falls through to the original
        // check, which is correct.
        let try_resume = if !self
            .has_any_ticket
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            false
        } else {
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

        let learned_route = self.routes.lock().unwrap().lookup(dst);
        // Look up the outgoing CID for short-header path.
        // This is cheap (one hash-map lookup under a
        // separate lock from the peer table).
        let out_cid = self.peer_out_cid.lock().unwrap().get(dst).copied();

        let action = {
            let mut peers = self.peers.lock_for(dst).await;
            let peer = peers.get_mut(dst).ok_or(PeerError::NotRegistered)?;

            // Mesh-routed peers always need hop_ttl and long
            // headers so intermediate nodes can forward. For
            // direct peers, suppress learned routes once
            // Established to prevent a malicious neighbor from
            // advertising a 1-hop route and siphoning traffic.
            let mesh_next_hop = if peer.via_mesh {
                learned_route.or(Some(peer.addr))
            } else if matches!(peer.handshake, HandshakeState::Established { .. }) {
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
                        self.config.hybrid_pq,
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
    async fn send_data_batch(&self, items: &[(PeerId, Vec<u8>)]) -> Result<usize> {
        // Adapter for the QoS-less form: zero out the QoS
        // fields and delegate. We avoid an allocation per item
        // by building BatchItem in-place rather than cloning
        // the payload — the caller owns the Vec, we move it.
        let qos: Vec<BatchItem> = items
            .iter()
            .map(|(peer, payload)| BatchItem {
                peer: *peer,
                payload: payload.clone(),
                deadline_ms: 0,
                coalesce_group: 0,
            })
            .collect();
        self.send_data_batch_qos(&qos).await
    }

    async fn send_data_batch_qos(&self, items: &[BatchItem]) -> Result<usize> {
        if items.is_empty() {
            return Ok(0);
        }
        // First pass: split federated peers out of the batched
        // path. They take the federation short-circuit in single
        // `send_data` (envelope-wrap + ship via the bridge's
        // session) — that logic isn't in `build_data_packet`, so
        // batched build would skip them and silently drop their
        // traffic. One syscall per federated packet is acceptable:
        // federated peers are a minority, and the bridge is the
        // bottleneck anyway.
        // Build federation classification with ONE shard lock
        // per unique peer (was N — same hot-loop issue as the
        // build loop below).
        let mut federated_set: StdHashSet<PeerId> = StdHashSet::new();
        let mut seen: StdHashSet<PeerId> = StdHashSet::new();
        for it in items {
            if !seen.insert(it.peer) {
                continue;
            }
            let peers = self.peers.lock_for(&it.peer).await;
            if peers
                .get(&it.peer)
                .map(|p| p.federated_via.is_some())
                .unwrap_or(false)
            {
                federated_set.insert(it.peer);
            }
        }
        let mut federated_items: Vec<&BatchItem> = Vec::new();
        let mut direct_items: Vec<&BatchItem> = Vec::with_capacity(items.len());
        for it in items {
            if federated_set.contains(&it.peer) {
                federated_items.push(it);
            } else {
                direct_items.push(it);
            }
        }

        let mut sent_fed = 0usize;
        for it in &federated_items {
            if self
                .send_data(&it.peer, &it.payload, it.deadline_ms, it.coalesce_group)
                .await
                .is_ok()
            {
                sent_fed += 1;
            }
        }

        if direct_items.is_empty() {
            return Ok(sent_fed);
        }

        // Build all the wires for direct peers. Group items by
        // peer_id so we take ONE shard lock per peer regardless
        // of batch size; previous code locked the shard N times
        // for an N-item batch all going to the same peer, which
        // was the dominant lock-acquire path under iperf-style
        // saturation. Common case (drift-vpn point-to-point) has
        // exactly one peer in by_peer — the HashMap is sized
        // accordingly and the per-batch allocation is tiny.
        let mut by_peer: StdHashMap<PeerId, Vec<&BatchItem>> = StdHashMap::with_capacity(4);
        for it in &direct_items {
            if it.payload.len() > MAX_PAYLOAD {
                continue;
            }
            by_peer.entry(it.peer).or_default().push(it);
        }

        let mut batch: Vec<(Vec<u8>, SocketAddr, usize)> = Vec::with_capacity(direct_items.len());
        for (peer_id, items) in &by_peer {
            let mut peers = self.peers.lock_for(peer_id).await;
            let Some(peer) = peers.get_mut(peer_id) else {
                continue;
            };
            if !matches!(peer.handshake, HandshakeState::Established { .. }) {
                continue;
            }
            let mesh_next_hop = if peer.via_mesh { Some(peer.addr) } else { None };
            for it in items {
                if let Ok(SendAction::Data(bytes, target, iface)) = build_data_packet(
                    self.local_peer_id,
                    peer,
                    &it.payload,
                    it.deadline_ms,
                    it.coalesce_group,
                    mesh_next_hop,
                ) {
                    batch.push((bytes, target, iface));
                }
            }
        }

        if batch.is_empty() {
            return Ok(0);
        }

        // Group by interface so all packets going to the
        // same listener get one syscall. The common case has
        // a single interface (the primary UDP listener), so
        // this typically yields one sendmmsg for the entire
        // batch. Multi-interface deployments (post-failover,
        // mixed-scheme) get one sendmmsg per active interface.
        let mut by_iface: StdHashMap<usize, Vec<(Vec<u8>, SocketAddr)>> = StdHashMap::new();
        for (bytes, addr, iface) in batch {
            by_iface.entry(iface).or_default().push((bytes, addr));
        }

        let mut sent_total = 0usize;
        let mut bytes_total: u64 = 0;
        for (iface, group) in by_iface {
            let bytes_in_group: u64 = group.iter().map(|(b, _)| b.len() as u64).sum();
            let n = self.ifaces.send_batch_for(iface, &group).await?;
            sent_total += n;
            bytes_total += bytes_in_group;
            for (buf, _) in group {
                drift_core::pool::return_wire_buf(buf);
            }
        }
        self.metrics
            .packets_sent
            .fetch_add(sent_total as u64, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(bytes_total, Ordering::Relaxed);
        self.metrics.batched_sends.fetch_add(1, Ordering::Relaxed);
        Ok(sent_total + sent_fed)
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

        self.cid_map.lock().unwrap().insert(my_rx_cid, peer_id);
        self.peer_out_cid
            .lock()
            .unwrap()
            .insert(peer_id, peer_rx_cid);
    }

    /// Send a `PacketType::Federated` packet to a peer. The peer
    /// must already be in `HandshakeState::Established` (the call
    /// fails with `UnknownPeer` otherwise — federation forwards
    /// happen on top of live sessions, never as the first packet).
    async fn send_typed(
        &self,
        dst: &PeerId,
        packet_type: PacketType,
        payload: &[u8],
    ) -> Result<()> {
        // Only Federated and FederationDirectory ride this path;
        // other packet types have their own builders (Data via
        // send_data, Hello via the handshake state machine, etc.).
        // Be explicit so a future caller doesn't accidentally
        // route the wrong type through here.
        if !matches!(
            packet_type,
            PacketType::Federated
                | PacketType::FederationDirectory
                | PacketType::PresenceTicket
                | PacketType::FindPeer
                | PacketType::PeerHere
                | PacketType::PeerGone
                | PacketType::FindPeerHashed
        ) {
            return Err(DriftError::DecodeError);
        }
        let action = {
            let mut peers = self.peers.lock_for(dst).await;
            let peer = peers.get_mut(dst).ok_or(PeerError::NotRegistered)?;
            if !matches!(peer.handshake, HandshakeState::Established { .. }) {
                return Err(PeerError::SessionNotEstablished.into());
            }
            build_typed_packet(self.local_peer_id, peer, packet_type, payload)?
        };
        self.dispatch(action).await
    }

    /// Decrypt + route a `PacketType::Federated` envelope.
    /// Three-way dispatch on the envelope's pubkey fields:
    ///
    /// 1. `target_client_pub == self.local_pubkey` →
    ///    deliver to the application as a `Received` with
    ///    `federated_from = Some(source_client_pub)`. This is
    ///    the recipient-client branch.
    /// 2. `target_bridge_pub == self.local_pubkey` →
    ///    we're the destination bridge. Look up the target
    ///    client by deriving `PeerId` from its pubkey, and
    ///    forward the envelope on the local-client session.
    /// 3. Otherwise → look up `target_bridge_pub` in the
    ///    federation table; forward via that peer-bridge's
    ///    session if known, else drop.
    async fn handle_federated(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
        _src: SocketAddr,
        _received_at: Instant,
        ecn_ce: bool,
    ) -> Result<Option<Received>> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;

        // Decrypt with the Federated type tag in AAD.
        let payload_bytes = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            rx.open(header.seq, PacketType::Federated as u8, &aad, body)?
        };

        let env = federated::parse(&payload_bytes)?;
        let our_pub = self.identity.public_bytes();

        // ── SECURITY: authenticate the envelope's `source_*` claims ──
        //
        // The outer DRIFT packet's session crypto authenticates
        // *who handed us this envelope* (header.src_id). The four
        // pubkeys inside the envelope are application-supplied
        // bytes; without a check here, any client of an
        // `accept_any_peer` bridge could ship envelopes claiming
        // to originate from any pubkey and route them to anyone.
        //
        // Threat model: bridges in our federation_table are part
        // of the TCB and may set source_* freely (that's literally
        // why they're in the table — to relay client traffic). A
        // direct client connected to us must name themselves as
        // the source. The check only applies when we're acting
        // as a bridge (case 2 or 3 below); when we're the
        // destination CLIENT (case 1), the sender is necessarily
        // our bridge (we connected to them, no one else can route
        // Federated traffic to us), and the bridge's attestation
        // is the only source-identity proof possible — same trust
        // model as a client of any Matrix/XMPP homeserver.
        if env.target_client_pub != our_pub {
            let sender_pub = {
                let peers = self.peers.lock_for(&peer_id).await;
                peers
                    .get(&peer_id)
                    .map(|p| p.peer_static_pub)
                    .ok_or(PeerError::NotRegistered)?
            };
            let sender_is_trusted_bridge = self
                .federation_table
                .lock()
                .unwrap()
                .contains_key(&sender_pub);
            if !sender_is_trusted_bridge {
                // Sender is a client (or an unknown bridge — same
                // trust level). Their envelopes must name themselves
                // as the source client AND name us as the source
                // bridge (we're the only bridge they're connected
                // to from our point of view).
                if env.source_client_pub != sender_pub || env.source_bridge_pub != our_pub {
                    self.metrics
                        .federation_spoof_drops
                        .fetch_add(1, Ordering::Relaxed);
                    debug!(
                        sender = ?sender_pub,
                        claimed_client = ?env.source_client_pub,
                        claimed_bridge = ?env.source_bridge_pub,
                        "federated: dropped envelope with forged source fields"
                    );
                    return Err(DriftError::AuthFailed);
                }
            }
        }

        // (1) Final delivery to us as a client.
        if env.target_client_pub == our_pub {
            // Set peer_id to the *originating client's* id (not
            // the bridge that delivered to us). This is what
            // makes federation transparent to existing tools:
            // drift-mosh, drift-wormhole, etc. all use
            // `pkt.peer_id` as the identity of who sent them
            // bytes. With federation, that identity is the
            // remote client, even though the bridge actually
            // handed us the envelope on the wire.
            let source_peer_id = derive_peer_id(&env.source_client_pub);

            // Auto-register the source as a federated peer when
            // accept_any_peer is set. Mirrors how an inbound
            // HELLO with accept_any_peer=true auto-adds a direct
            // peer: the server can reply via send_data(...) to
            // the same peer_id and the federation short-circuit
            // routes the response back through the bridge that
            // delivered the original packet. Without this,
            // server-style apps (drift-mosh-server, etc.) would
            // need to manually call add_federated_peer on every
            // first-contact, which defeats the "federation is
            // transparent" promise for the recv-and-reply case.
            //
            // `peer_id` (the outer-packet src) IS our local
            // bridge — the one that delivered this envelope —
            // so it's also the correct `via_bridge` for the
            // reply path.
            let fed_inserted_at: Option<SocketAddr> = if self.config.accept_any_peer {
                let mut peers = self.peers.lock_for(&source_peer_id).await;
                match peers.get_mut(&source_peer_id) {
                    Some(existing) => {
                        // Refresh the reply path on every case-1
                        // receipt, not just the first. Without this,
                        // a client that roams to a different bridge
                        // (e.g. their on-ramp bridge restarted, or
                        // they're now reaching us via a different
                        // federation peer) gets stuck: subsequent
                        // replies go to the stale `federated_via`
                        // and black-hole.
                        //
                        // Security: the sender of an inbound
                        // federated envelope is always our own
                        // bridge (we connected to it). Whatever
                        // `source_bridge_pub` they attest in the
                        // envelope is, by definition, the trust
                        // we extend to that bridge — same model as
                        // a Matrix/XMPP client trusting its
                        // homeserver's S2S routing. A malicious
                        // federated bridge CAN steer reply traffic
                        // by sending a single envelope claiming
                        // source_client_pub=victim. That hazard
                        // existed before this fix too: the first
                        // arrival (None match below) already
                        // pinned victim→attacker. Fixing it
                        // properly requires XEdDSA presence
                        // tickets (deferred).
                        existing.federated_via = Some(peer_id);
                        existing.federated_target_bridge_pub = Some(env.source_bridge_pub);
                        None
                    }
                    None => {
                        let placeholder: SocketAddr = "0.0.0.0:0".parse().expect("constant parses");
                        let mut p = Peer::new(
                            source_peer_id,
                            placeholder,
                            env.source_client_pub,
                            Direction::Responder,
                        );
                        p.federated_via = Some(peer_id);
                        p.federated_target_bridge_pub = Some(env.source_bridge_pub);
                        p.auto_registered = true;
                        peers.insert(p);
                        Some(placeholder)
                    }
                }
            } else {
                None
            };
            if let Some(addr) = fed_inserted_at {
                self.peers.note_inserted(source_peer_id, addr).await;
            }

            return Ok(Some(Received {
                peer_id: source_peer_id,
                seq: header.seq,
                supersedes: 0,
                payload: env.payload.to_vec(),
                ecn_ce,
                federated_from: Some(env.source_client_pub),
                federated_via_bridge: Some(env.source_bridge_pub),
            }));
        }

        // (2) + (3) collapsed — directory-lookup routing.
        //
        // The previous separate case-2 ("target_bridge_pub == our_pub
        // → deliver locally; drop on miss") had a transit-hop bug
        // that surfaced as soon as proactive announces propagated
        // beyond one hop (Phase F in FEDERATION_DISCOVERY.md):
        //
        //   - Bridge B re-announces client X (originally announced
        //     by bridge C) to bridge A. A's peer_directory now has
        //     X → (B's_peer_id, ts).
        //   - A later forwards a packet for X via the directory:
        //     case-3 rewrites target_bridge_pub = B_pub, sends to B.
        //   - B receives, sees target_bridge_pub == our_pub → case-2
        //     local-delivery → MISS (X isn't on B, X is on C). The
        //     old code logged "failed to deliver to local client"
        //     and dropped silently.
        //
        // The fix is structural: treat `target_bridge_pub == our_pub`
        // AND `target_bridge_pub == UNKNOWN_BRIDGE_PUB` the same way
        // — try local delivery first, fall through to directory
        // lookup on miss. The directory entry's announcer_pub
        // becomes the rewritten target_bridge_pub, and B's directory
        // (which has X → C) forwards to C. C local-delivers.
        //
        // (Auto-register removed in the same earlier change that
        //  introduced the source-authentication check above.
        //  Federation requires *symmetric* --federate config on
        //  both bridges, matching Matrix / XMPP server-to-server
        //  trust. See drift-config/README.md.)
        // Phase F (FED_DISC): treat THREE conditions as "needs
        // routing via directory lookup":
        //   (a) UNKNOWN_BRIDGE_PUB sentinel — client doesn't know
        //       the target bridge (original case 3).
        //   (b) target_bridge_pub == our_pub but client isn't
        //       local — we're a transit hop for a re-announced
        //       entry (the Phase F transit bug fix).
        //   (c) target_bridge_pub is some specific OTHER bridge
        //       not in our federation_table — happens on REPLY
        //       traffic when the destination is multiple hops
        //       away through bridges we don't directly federate
        //       with (e.g. local-client on b1 replies to a remote
        //       client whose bridge b3 isn't in b1's federation
        //       table). Previously dropped with "no route to
        //       target bridge"; now we consult the directory and
        //       forward via whichever of our federation peers
        //       has announced the target client.
        // The `unknown` (= "needs directory lookup") predicate
        // covers three conditions:
        //   (a) UNKNOWN_BRIDGE_PUB sentinel — the client doesn't
        //       know which bridge hosts the target.
        //   (b) target_bridge_pub == our_pub — we may be a transit
        //       hop for a re-announced entry. We try local
        //       delivery first, then fall through to directory
        //       lookup if the client isn't actually local.
        //   (c) target_bridge_pub names a bridge that isn't in
        //       our federation_table — happens on REPLY traffic
        //       when the destination is reachable only via a
        //       multi-hop chain through bridges we don't directly
        //       federate with. (Concretely: local-client on b1
        //       replies to a remote client whose bridge b3 isn't
        //       in b1's federation table. We should consult the
        //       directory / fall back to FindPeer rather than
        //       drop.)
        //
        // Negating (a or b or c) gives us "target IS a known
        // federation peer we can directly route to" — the fast
        // path.
        let fed_table_has_target = env.target_bridge_pub != federated::UNKNOWN_BRIDGE_PUB
            && env.target_bridge_pub != our_pub
            && self
                .federation_table
                .lock()
                .unwrap()
                .contains_key(&env.target_bridge_pub);
        let unknown = !fed_table_has_target;
        let (next_hop, resolved_bridge_pub) = if unknown {
            // First check: do WE host this client locally? A
            // single-bridge federation with no remote peers has
            // an empty peer_directory but its presence_tickets
            // table will still have local-client entries. Without
            // this check, every UNKNOWN_BRIDGE_PUB envelope for a
            // local client would miss the directory and trigger
            // a FindPeer fan-out that no peer can answer.
            //
            // When we find a local match, treat it exactly like
            // case-2 (target_bridge_pub == our_pub): derive the
            // local client's peer_id from its pubkey and deliver
            // on the local session.
            let local_pid = derive_peer_id(&env.target_client_pub);
            let local_hit = self
                .peers
                .lock_for(&local_pid)
                .await
                .get(&local_pid)
                .map(|p| {
                    matches!(p.handshake, HandshakeState::Established { .. })
                        && p.peer_static_pub == env.target_client_pub
                })
                .unwrap_or(false);
            if local_hit {
                (Some(local_pid), our_pub)
            } else {
                // Directory lookup. Evict the entry if it's older
                // than DIRECTORY_TTL — let the announcement layer
                // refresh it. Bridges announce every ~7 s, so 20 s
                // gives ~3 announce intervals of slack before we
                // call a silent bridge dead.
                const DIRECTORY_TTL: std::time::Duration = std::time::Duration::from_secs(20);
                let mut dir = self.peer_directory.lock().unwrap();
                let now = std::time::Instant::now();
                let entry = dir.get(&env.target_client_pub).copied();
                if let Some((pid, t)) = entry {
                    if now.duration_since(t) > DIRECTORY_TTL {
                        dir.remove(&env.target_client_pub);
                        (None, env.target_bridge_pub)
                    } else {
                        // Look up the announcer's pubkey so we can
                        // rewrite the envelope's target_bridge_pub.
                        let pubs = self.federation_table.lock().unwrap();
                        let announcer_pub =
                            pubs.iter()
                                .find_map(|(p, id)| if *id == pid { Some(*p) } else { None });
                        drop(pubs);
                        match announcer_pub {
                            Some(pub_) => (Some(pid), pub_),
                            // Announcer left the fed table since the
                            // entry was recorded — stale; drop.
                            None => {
                                dir.remove(&env.target_client_pub);
                                (None, env.target_bridge_pub)
                            }
                        }
                    }
                } else {
                    (None, env.target_bridge_pub)
                }
            } // close `if local_hit { … } else { …` opened above
        } else {
            let nh = self
                .federation_table
                .lock()
                .unwrap()
                .get(&env.target_bridge_pub)
                .copied();
            (nh, env.target_bridge_pub)
        };
        if let Some(next_peer) = next_hop {
            let re_envelope = federated::build(
                &resolved_bridge_pub,
                &env.target_client_pub,
                &env.source_bridge_pub,
                &env.source_client_pub,
                env.payload,
            );
            if let Err(e) = self
                .send_typed(&next_peer, PacketType::Federated, &re_envelope)
                .await
            {
                debug!(
                    error = %e,
                    target = ?resolved_bridge_pub,
                    "federated: failed to forward to peer bridge"
                );
                // Send failure to the resolved next-hop is a
                // strong signal that bridge is unreachable —
                // session torn down, OS routing blackholed, etc.
                // Drop every directory entry attributed to it so
                // the next dial doesn't fall into the same hole.
                // The next announce from a still-alive announcer
                // (or recovery of this one) repopulates within
                // the announce interval (~7 s).
                let mut dir = self.peer_directory.lock().unwrap();
                dir.retain(|_, (pid, _)| *pid != next_peer);
            }
        } else if unknown {
            // Phase E: dispatch by configured discovery mode.
            let mode = self.config.effective_find_peer_mode();
            match mode {
                FindPeerMode::Disabled => {
                    debug!(
                        target_client = ?env.target_client_pub,
                        "federated: find_peer disabled — dropping UNKNOWN_BRIDGE_PUB envelope"
                    );
                    return Ok(None);
                }
                FindPeerMode::Open | FindPeerMode::NoForward | FindPeerMode::OriginateHashed => {
                    // Originate normally below. NoForward affects
                    // receive-side behavior, not the originator
                    // side. OriginateHashed flips the wire format
                    // we emit (handled below).
                }
            }
            // Phase A directory-lookup miss path: instead of
            // dropping silently, originate a `FindPeer` query to
            // every federation peer and queue the envelope for
            // re-issue when `PeerHere` arrives.
            //
            // Coalescing rules:
            //   1. If we have a `neg_cache` hit (recent failed
            //      lookup), drop this packet. Same target won't be
            //      requeried until the negative entry expires.
            //   2. If `pending_finds` already has a fresh entry
            //      (started_at + DEADLINE > now), append this
            //      envelope to the existing waiter queue — only
            //      one `FindPeer` per target in flight.
            //   3. Else: create a new `pending_finds` entry, queue
            //      this envelope, emit `FindPeer` to every
            //      federation peer.
            let now_inst = std::time::Instant::now();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            // Negative-cache check.
            {
                let mut neg = self.neg_cache.lock().unwrap();
                if let Some(&expires_at) = neg.get(&env.target_client_pub) {
                    if now_inst < expires_at {
                        debug!(
                            target_client = ?env.target_client_pub,
                            "federated: neg-cached lookup miss, dropping"
                        );
                        return Ok(None);
                    }
                    // Expired — fall through and re-query.
                    neg.remove(&env.target_client_pub);
                }
            }
            // Build a re-serializable envelope for the waiter
            // queue. Storing the bytes (rather than a borrow)
            // means we don't have to keep `body` alive across the
            // pending-find lifetime.
            let waiter_bytes = federated::build(
                &env.target_bridge_pub,
                &env.target_client_pub,
                &env.source_bridge_pub,
                &env.source_client_pub,
                env.payload,
            );
            let deadline =
                now_inst + std::time::Duration::from_millis(find_peer::MAX_FIND_DEADLINE_MS);
            let (should_emit_find, query_id) = {
                let mut pending = self.pending_finds.lock().unwrap();
                if let Some(entry) = pending.get_mut(&env.target_client_pub) {
                    if entry.started_at
                        + std::time::Duration::from_millis(find_peer::MAX_FIND_DEADLINE_MS)
                        > now_inst
                    {
                        // In-flight; coalesce.
                        entry.waiters.push(waiter_bytes);
                        (false, entry.query_id)
                    } else {
                        // Stale entry — replace and re-fire.
                        let mut qid_bytes = [0u8; 8];
                        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut qid_bytes);
                        let qid = u64::from_be_bytes(qid_bytes);
                        *entry = PendingFind {
                            query_id: qid,
                            started_at: now_inst,
                            waiters: vec![waiter_bytes],
                            claimed_by: Vec::new(),
                        };
                        (true, qid)
                    }
                } else {
                    let mut qid_bytes = [0u8; 8];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut qid_bytes);
                    let qid = u64::from_be_bytes(qid_bytes);
                    pending.insert(
                        env.target_client_pub,
                        PendingFind {
                            query_id: qid,
                            started_at: now_inst,
                            waiters: vec![waiter_bytes],
                            claimed_by: Vec::new(), // populated from fanout below
                        },
                    );
                    (true, qid)
                }
            };
            let _ = deadline;
            if should_emit_find {
                let our_pub = self.identity.public_bytes();
                // Snapshot federation peers (drop the lock before
                // awaiting send_typed — never hold a sync mutex
                // across an await point).
                let all_fed_peers: Vec<PeerId> = self
                    .federation_table
                    .lock()
                    .unwrap()
                    .values()
                    .copied()
                    .collect();

                // Phase F: pre-filter the fanout list using each
                // peer's cached bloom filter. A peer with a
                // filter that says "definitely not here" gets
                // skipped entirely — the gossip blast radius
                // shrinks from "every federation peer" to "only
                // peers whose filter passed for this target".
                //
                // Peers with NO filter on file (v3-or-earlier
                // announcers, or v4 with empty filter) are
                // queried unconditionally — bloom is a pure
                // narrowing optimization, never a strict gate.
                let fed_peers_bloom: Vec<PeerId> = {
                    let bf = self.peer_bloom_filters.lock().unwrap();
                    all_fed_peers
                        .iter()
                        .copied()
                        .filter(|pid| match bf.get(pid) {
                            Some(filter) => filter.contains(&env.target_client_pub),
                            None => true, // no filter cached → query
                        })
                        .collect()
                };

                // Phase G.3: reputation-based skipping. Drop
                // peers whose fault counter is at or above the
                // configured threshold. A bridge that has
                // repeatedly bloom-claimed targets without
                // delivering them gets cut out of fanout until
                // its counter decays back below the threshold
                // (Phase G.2). `threshold = 0` disables the
                // check entirely (back to bloom-only behavior).
                let fed_peers: Vec<PeerId> = {
                    let threshold = self.config.bridge_fault_skip_threshold;
                    if threshold == 0 {
                        fed_peers_bloom.clone()
                    } else {
                        let faults = self.bridge_faults.lock().unwrap();
                        fed_peers_bloom
                            .iter()
                            .copied()
                            .filter(|pid| faults.get(pid).copied().unwrap_or(0) < threshold)
                            .collect()
                    }
                };
                if fed_peers.len() < fed_peers_bloom.len() {
                    debug!(
                        target_client = ?env.target_client_pub,
                        before = fed_peers_bloom.len(),
                        after = fed_peers.len(),
                        "FindPeer: reputation skipped high-fault peers"
                    );
                }
                if fed_peers.len() < all_fed_peers.len() {
                    debug!(
                        target_client = ?env.target_client_pub,
                        before = all_fed_peers.len(),
                        after = fed_peers.len(),
                        "FindPeer: bloom filters narrowed fanout"
                    );
                }
                if fed_peers.is_empty() {
                    debug!(
                        target_client = ?env.target_client_pub,
                        "FindPeer: every federation peer's bloom said 'no'; dropping query"
                    );
                    // Treat as neg-cache hit to avoid re-firing
                    // for every queued waiter. Short TTL so a
                    // post-rotation filter that now contains
                    // the target picks up promptly.
                    self.neg_cache.lock().unwrap().insert(
                        env.target_client_pub,
                        now_inst + std::time::Duration::from_millis(find_peer::NEG_CACHE_TTL_MS),
                    );
                    // Drop any queued waiters for this target —
                    // they'd just sit until their own deadline.
                    self.pending_finds
                        .lock()
                        .unwrap()
                        .remove(&env.target_client_pub);
                    return Ok(None);
                }

                // Phase F.8: record which bridges' filters
                // CLAIMED to have the target (filter said yes
                // AND we have a filter on file). Bridges queried
                // unconditionally (no filter) are NOT recorded as
                // claimants — we only fault a bridge for failing
                // a claim it actually made.
                let claimants: Vec<PeerId> = {
                    let bf = self.peer_bloom_filters.lock().unwrap();
                    fed_peers
                        .iter()
                        .copied()
                        .filter(|pid| {
                            bf.get(pid)
                                .map(|f| f.contains(&env.target_client_pub))
                                .unwrap_or(false)
                        })
                        .collect()
                };
                if !claimants.is_empty() {
                    let mut pending = self.pending_finds.lock().unwrap();
                    if let Some(entry) = pending.get_mut(&env.target_client_pub) {
                        entry.claimed_by = claimants;
                    }
                }
                let (payload, pkt_type, mode_label) = if matches!(
                    self.config.effective_find_peer_mode(),
                    FindPeerMode::OriginateHashed
                ) {
                    let mut salt = [0u8; find_peer::FIND_PEER_HASHED_SALT_LEN];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
                    let target_hash = find_peer::hash_target_pub(&env.target_client_pub, &salt);
                    let q = find_peer::FindPeerHashed {
                        salt,
                        target_hash,
                        query_id,
                        ttl: find_peer::MAX_FIND_TTL,
                        originator_bridge: our_pub,
                        originator_query_at_ms: now_ms,
                    };
                    (
                        find_peer::build_find_peer_hashed(&q),
                        PacketType::FindPeerHashed,
                        "hashed",
                    )
                } else {
                    let q = find_peer::FindPeer {
                        target_client_pub: env.target_client_pub,
                        query_id,
                        ttl: find_peer::MAX_FIND_TTL,
                        originator_bridge: our_pub,
                        originator_query_at_ms: now_ms,
                    };
                    (
                        find_peer::build_find_peer(&q),
                        PacketType::FindPeer,
                        "plain",
                    )
                };
                for peer in &fed_peers {
                    if let Err(e) = self.send_typed(peer, pkt_type, &payload).await {
                        debug!(
                            error = %e,
                            ?peer,
                            mode = mode_label,
                            "FindPeer: failed to emit to federation peer"
                        );
                    }
                }
                debug!(
                    target_client = ?env.target_client_pub,
                    query_id,
                    federation_peers = fed_peers.len(),
                    mode = mode_label,
                    "FindPeer: originated lookup"
                );
            }
        } else {
            debug!(
                target = ?env.target_bridge_pub,
                "federated: no route to target bridge, dropping"
            );
        }
        Ok(None)
    }

    /// Process a `PacketType::FederationDirectory` packet from a
    /// peer bridge. Decrypts under the sender's session keys,
    /// verifies the sender is in our federation_table (so an
    /// arbitrary client can't populate the directory), and
    /// records each announced client pubkey under the sender's
    /// peer_id with the current timestamp.
    ///
    /// Stale entries (>60 s without re-announcement) are evicted
    /// inline at lookup time in `handle_federated` case (3).
    async fn handle_federation_directory(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;

        // Decrypt with the FederationDirectory type tag in AAD.
        let payload_bytes = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            rx.open(
                header.seq,
                PacketType::FederationDirectory as u8,
                &aad,
                body,
            )?
        };

        // Only trusted bridges may announce. A client that
        // somehow sends a FederationDirectory packet here would
        // pass the AEAD check (they have an Established session
        // with us) but their pubkey wouldn't be in the federation
        // table — and accepting their advertisement would let
        // any client of an accept_any_peer bridge inject arbitrary
        // routing entries, the same hole we closed for the
        // Federated case-2 auto-register.
        let sender_pub = {
            let peers = self.peers.lock_for(&peer_id).await;
            peers
                .get(&peer_id)
                .map(|p| p.peer_static_pub)
                .ok_or(PeerError::NotRegistered)?
        };
        let sender_is_bridge = self
            .federation_table
            .lock()
            .unwrap()
            .contains_key(&sender_pub);
        if !sender_is_bridge {
            self.metrics
                .federation_spoof_drops
                .fetch_add(1, Ordering::Relaxed);
            debug!(
                sender = ?sender_pub,
                "directory: dropped announcement from non-bridge peer"
            );
            return Err(DriftError::AuthFailed);
        }

        // Phase F: parse v4 (also accepts v3 and v2; v3/v2
        // come back with `bloom = None`). v3's hops field is
        // preserved; v4 additionally yields the announcer's
        // DP-bloom-filtered local-clients set, which we cache
        // for FindPeer fanout narrowing.
        let (entries, bloom) = federated::parse_directory_v4(&payload_bytes)?;
        // Update / clear the bloom filter for this announcer.
        // An announcer that switches from v4-with-bloom to
        // v3-or-v4-without-bloom should have the cached entry
        // dropped so we don't keep filtering on stale data.
        {
            let mut bf = self.peer_bloom_filters.lock().unwrap();
            match bloom {
                Some(b) => {
                    bf.insert(peer_id, b);
                }
                None => {
                    bf.remove(&peer_id);
                }
            }
        }

        // ── Per-entry verification ──
        //
        // For DIRECTLY-announced entries (hops=0), the ticket is
        // signed by `client_pub` for `sender_pub` — the standard
        // presence ticket check. For TRANSITIVE entries (hops>0),
        // the ticket was signed by the client for the TERMINAL
        // bridge (path[0] of the original PeerHere chain), not
        // for the announcing bridge. We can't re-verify the
        // terminal-bridge binding from this packet alone — we
        // accept it as a routing hint and rely on:
        //   (a) the announcer being in our federation_table
        //       (trust gate at line 3395)
        //   (b) the cap on transitive hops (MAX_ANNOUNCE_HOPS)
        //   (c) bridge-self-signed hop attestations (later phase).
        //
        // Drop bad entries individually rather than rejecting the
        // whole announcement.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let our_pub = self.identity.public_bytes();
        let we_host_locally: std::collections::HashSet<[u8; 32]> = self
            .presence_tickets
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect();
        let mut new_set: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut accepted: Vec<([u8; 32], federated::PresenceTicket, u8)> = Vec::new();
        for (client_pub, ticket, hops) in entries {
            if client_pub == our_pub {
                continue;
            }
            // Anti-loop: ignore transitive claims about clients
            // we host locally. We're the ground truth for them.
            if we_host_locally.contains(&client_pub) {
                continue;
            }
            // For direct claims, verify the standard presence
            // ticket binding (client_pub signed for sender_pub).
            // Transitive claims skip this check — see comment above.
            if hops == 0
                && federated::verify_ticket(&client_pub, &sender_pub, &ticket, now_ms).is_err()
            {
                self.metrics
                    .federation_invalid_tickets_dropped
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    announcer = ?sender_pub,
                    claimed_client = ?client_pub,
                    "directory: dropped direct entry with invalid presence ticket"
                );
                continue;
            }
            new_set.insert(client_pub);
            accepted.push((client_pub, ticket, hops));
        }
        let now = std::time::Instant::now();
        let mut dir = self.peer_directory.lock().unwrap();

        // ── Idempotent-set semantics (issue 3, implicit retraction) ──
        //
        // Each FederationDirectory packet from a bridge is the
        // COMPLETE current set of that bridge's clients, not a
        // delta. Prune entries we previously recorded under this
        // announcer that aren't in the new set — that's how a
        // client disconnecting from its bridge stops attracting
        // traffic in <7 s (the announce interval) instead of
        // waiting out the 20 s stale-entry TTL.
        //
        // Implementation note: the prune walks all entries which
        // is O(n_dir). For deployments with thousands of clients
        // this would want a reverse index (announcer → pubkeys);
        // for now the linear scan is fine.
        dir.retain(|client_pub, (announcer_pid, _)| {
            *announcer_pid != peer_id || new_set.contains(client_pub)
        });
        drop(dir);
        // Mirror prune on Phase C side-tables.
        {
            let dir = self.peer_directory.lock().unwrap();
            let live_keys: std::collections::HashSet<[u8; 32]> = dir.keys().copied().collect();
            drop(dir);
            self.peer_directory_hops
                .lock()
                .unwrap()
                .retain(|k, _| live_keys.contains(k));
            self.peer_directory_tickets
                .lock()
                .unwrap()
                .retain(|k, _| live_keys.contains(k));
        }

        // ── First-write-wins for cross-announcer conflicts (issue 2) ──
        //
        // If bridge B and bridge C both claim client X, B's
        // earlier announcement wins for the lifetime of B's
        // claim. A malicious federated peer racing to claim
        // pubkeys it doesn't host can no longer hijack durable
        // routing: the legitimate bridge's prior entry blocks
        // the impostor. The race window is bounded by the 20 s
        // TTL (or sooner via send-failure eviction below) — i.e.
        // an attacker only wins for pubkeys whose legitimate
        // bridge has already gone silent.
        //
        // Phase C wrinkle: we also write the per-entry hops and
        // ticket into side-tables. If first-write-wins blocks the
        // peer_directory write, we likewise leave the existing
        // hops/ticket entries alone — they're keyed by client_pub
        // and we ALREADY have them under a different announcer.
        let mut dir = self.peer_directory.lock().unwrap();
        let mut hops_map = self.peer_directory_hops.lock().unwrap();
        let mut tickets_map = self.peer_directory_tickets.lock().unwrap();
        for (pub_, ticket, hops) in accepted {
            use std::collections::hash_map::Entry;
            match dir.entry(pub_) {
                Entry::Vacant(e) => {
                    e.insert((peer_id, now));
                    hops_map.insert(pub_, hops);
                    tickets_map.insert(pub_, ticket);
                }
                Entry::Occupied(mut e) => {
                    if e.get().0 == peer_id {
                        e.get_mut().1 = now;
                        hops_map.insert(pub_, hops);
                        tickets_map.insert(pub_, ticket);
                    }
                    // else: first-write-wins — silently ignore.
                }
            }
        }
        Ok(())
    }

    /// Receive-side handler for `PacketType::PresenceTicket`.
    ///
    /// Verifies the carried ticket against the sender's static
    /// pubkey and our own (since the ticket must be signed for
    /// THIS bridge). On success, stores it in `presence_tickets`
    /// keyed by the sender's pubkey, replacing any older copy.
    /// Failures (bad sig, expired, ticket signed for a different
    /// bridge) are dropped silently — emitting a metric on every
    /// adversarial probe attempt would give a noisy oracle.
    async fn handle_presence_ticket(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;

        // Decrypt with the PresenceTicket type tag in AAD.
        let payload_bytes = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            rx.open(header.seq, PacketType::PresenceTicket as u8, &aad, body)?
        };

        let sender_pub = {
            let peers = self.peers.lock_for(&peer_id).await;
            peers
                .get(&peer_id)
                .map(|p| p.peer_static_pub)
                .ok_or(PeerError::NotRegistered)?
        };

        let ticket = federated::decode_ticket(&payload_bytes)?;
        let our_pub = self.identity.public_bytes();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        federated::verify_ticket(&sender_pub, &our_pub, &ticket, now_ms)?;

        self.presence_tickets
            .lock()
            .unwrap()
            .insert(sender_pub, ticket);
        Ok(())
    }

    // ─── Federation peer discovery (FEDERATION_DISCOVERY.md §6) ──

    /// Receive-side handler for `PacketType::FindPeer`. Only
    /// federated bridges may query us — clients can't trigger a
    /// search of our local-clients table (information disclosure).
    /// On a direct hit (we host the target as a local client AND
    /// hold their presence ticket), reply with `PeerHere`. Phase A
    /// drops 1-hop misses; Phase B recurses through the rest of
    /// the federation. With `find_peer_disabled` set, the whole
    /// handler short-circuits — no reply, no forward.
    async fn handle_find_peer(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        if matches!(
            self.config.effective_find_peer_mode(),
            FindPeerMode::Disabled
        ) {
            // Drop incoming queries silently — we don't
            // participate in discovery.
            return Ok(());
        }
        let peer_id = header.src_id;
        let payload_bytes = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            rx.open(header.seq, PacketType::FindPeer as u8, &aad, body)?
        };
        // Source-auth: only federation bridges may query.
        let sender_pub = {
            let peers = self.peers.lock_for(&peer_id).await;
            peers
                .get(&peer_id)
                .map(|p| p.peer_static_pub)
                .ok_or(PeerError::NotRegistered)?
        };
        let sender_is_bridge = self
            .federation_table
            .lock()
            .unwrap()
            .contains_key(&sender_pub);
        if !sender_is_bridge {
            debug!(
                ?sender_pub,
                "FindPeer: sender not in federation_table; dropping"
            );
            return Err(DriftError::AuthFailed);
        }

        let query = find_peer::parse_find_peer(&payload_bytes)?;

        // Dedup — drop replays / loops.
        let now_inst = std::time::Instant::now();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        {
            let mut recent = self.recent_queries.lock().unwrap();
            if let Some(&expires) = recent.get(&query.query_id) {
                if now_inst < expires {
                    debug!(query_id = query.query_id, "FindPeer: duplicate; dropping");
                    return Ok(());
                }
                recent.remove(&query.query_id);
            }
            let ttl_inst =
                now_inst + std::time::Duration::from_millis(find_peer::QUERY_DEDUP_TTL_MS);
            recent.insert(query.query_id, ttl_inst);
        }

        // Deadline check.
        if query
            .originator_query_at_ms
            .saturating_add(find_peer::MAX_FIND_DEADLINE_MS)
            < now_ms
        {
            debug!(
                query_id = query.query_id,
                "FindPeer: past deadline; dropping"
            );
            return Ok(());
        }

        // Direct-hit check: do we host the target as a local
        // (non-federation) client with a valid presence ticket?
        let our_pub = self.identity.public_bytes();
        let ticket_opt = {
            let tickets = self.presence_tickets.lock().unwrap();
            tickets.get(&query.target_client_pub).cloned()
        };
        let target_is_local = if let Some(ref t) = ticket_opt {
            // Ticket must be unexpired AND signed for THIS bridge.
            federated::verify_ticket(&query.target_client_pub, &our_pub, t, now_ms).is_ok()
        } else {
            false
        };
        // Also confirm we have an established session for them —
        // a leftover ticket from a now-disconnected client must not
        // produce a positive answer.
        let has_session = if target_is_local {
            self.session_established_with_pubkey(&query.target_client_pub)
                .await
        } else {
            false
        };

        if target_is_local && has_session {
            let ticket = ticket_opt.expect("verified above");
            let reply = find_peer::PeerHere {
                target_client_pub: query.target_client_pub,
                query_id: query.query_id,
                path: vec![find_peer::PathEntry {
                    bridge_pub: our_pub,
                    ticket,
                }],
            };
            let wire = find_peer::build_peer_here(&reply);
            // Reply goes back to the bridge that sent us the
            // query (which for Phase A is the originator).
            if let Err(e) = self.send_typed(&peer_id, PacketType::PeerHere, &wire).await {
                debug!(error = %e, "FindPeer: failed to send PeerHere reply");
            } else {
                debug!(
                    target = ?query.target_client_pub,
                    query_id = query.query_id,
                    "FindPeer: replied PeerHere (local hit)"
                );
            }
            return Ok(());
        }

        // Phase E NoForward: bridges in this mode answer local
        // hits only — they refuse to be discovery transit. The
        // local-hit path above already returned if we matched;
        // reaching this point means it was a miss, so we drop
        // without forwarding.
        if matches!(
            self.config.effective_find_peer_mode(),
            FindPeerMode::NoForward
        ) {
            debug!(
                target = ?query.target_client_pub,
                query_id = query.query_id,
                "FindPeer: NoForward mode — dropping miss without recurse"
            );
            return Ok(());
        }
        // Phase B: local miss with ttl > 1 — forward to every
        // federation peer except the one who sent us this query.
        // Record (query_id, sender_peer_id) so the eventual
        // PeerHere can be routed back to the upstream that
        // forwarded to us.
        if query.ttl > 1 {
            let onward = find_peer::FindPeer {
                ttl: query.ttl - 1,
                ..query.clone()
            };
            let payload = find_peer::build_find_peer(&onward);
            let fed_peers: Vec<PeerId> = self
                .federation_table
                .lock()
                .unwrap()
                .values()
                .copied()
                .filter(|pid| *pid != peer_id)
                .collect();
            if fed_peers.is_empty() {
                debug!(
                    query_id = query.query_id,
                    "FindPeer: no other federation peers to forward to; dropping"
                );
                return Ok(());
            }
            // Insert BEFORE awaiting send_typed — the
            // forwarded_queries entry must be visible by the
            // time the PeerHere comes back (which can race
            // with the await point).
            self.forwarded_queries
                .lock()
                .unwrap()
                .insert(query.query_id, peer_id);
            for fed in &fed_peers {
                if let Err(e) = self.send_typed(fed, PacketType::FindPeer, &payload).await {
                    debug!(
                        error = %e,
                        ?fed,
                        "FindPeer: forward leg failed"
                    );
                }
            }
            debug!(
                target = ?query.target_client_pub,
                query_id = query.query_id,
                ttl = onward.ttl,
                fanout = fed_peers.len(),
                "FindPeer: forwarded (Phase B multi-hop)"
            );
            return Ok(());
        }

        // ttl exhausted with no local hit — silent drop.
        debug!(
            target = ?query.target_client_pub,
            query_id = query.query_id,
            "FindPeer: ttl exhausted with no local hit; dropping"
        );
        Ok(())
    }

    /// Receive-side handler for `PacketType::FindPeerHashed`.
    /// Same dispatch shape as `handle_find_peer`, but the target
    /// pubkey arrives as `SHA-256(target || salt)`. We scan our
    /// local presence tickets, hashing each client_pub under the
    /// query's salt, and reply with `PeerHere` (carrying the real
    /// matched pubkey) on a hit. Forwards on miss exactly like
    /// the plain variant, propagating the hash unchanged.
    async fn handle_find_peer_hashed(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        if matches!(
            self.config.effective_find_peer_mode(),
            FindPeerMode::Disabled
        ) {
            return Ok(());
        }
        let peer_id = header.src_id;
        let payload_bytes = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            rx.open(header.seq, PacketType::FindPeerHashed as u8, &aad, body)?
        };
        let sender_pub = {
            let peers = self.peers.lock_for(&peer_id).await;
            peers
                .get(&peer_id)
                .map(|p| p.peer_static_pub)
                .ok_or(PeerError::NotRegistered)?
        };
        let sender_is_bridge = self
            .federation_table
            .lock()
            .unwrap()
            .contains_key(&sender_pub);
        if !sender_is_bridge {
            return Err(DriftError::AuthFailed);
        }
        let query = find_peer::parse_find_peer_hashed(&payload_bytes)?;

        // Dedup.
        let now_inst = std::time::Instant::now();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        {
            let mut recent = self.recent_queries.lock().unwrap();
            if let Some(&expires) = recent.get(&query.query_id) {
                if now_inst < expires {
                    return Ok(());
                }
                recent.remove(&query.query_id);
            }
            recent.insert(
                query.query_id,
                now_inst + std::time::Duration::from_millis(find_peer::QUERY_DEDUP_TTL_MS),
            );
        }
        if query
            .originator_query_at_ms
            .saturating_add(find_peer::MAX_FIND_DEADLINE_MS)
            < now_ms
        {
            return Ok(());
        }

        // Local-hit scan: for each presence ticket we hold,
        // compute the same hash under the query's salt and
        // compare. Linear in local-client count — fine for the
        // sizes a single bridge holds in practice.
        let candidate: Option<([u8; 32], federated::PresenceTicket)> = {
            let tickets = self.presence_tickets.lock().unwrap();
            tickets.iter().find_map(|(client_pub, t)| {
                let h = find_peer::hash_target_pub(client_pub, &query.salt);
                if h == query.target_hash {
                    Some((*client_pub, t.clone()))
                } else {
                    None
                }
            })
        };

        if let Some((client_pub, ticket)) = candidate {
            // Confirm the candidate's session is still alive
            // AND the ticket binds to our bridge — the same
            // gates handle_find_peer applies.
            let our_pub = self.identity.public_bytes();
            let ticket_ok =
                federated::verify_ticket(&client_pub, &our_pub, &ticket, now_ms).is_ok();
            if ticket_ok && self.session_established_with_pubkey(&client_pub).await {
                let reply = find_peer::PeerHere {
                    target_client_pub: client_pub,
                    query_id: query.query_id,
                    path: vec![find_peer::PathEntry {
                        bridge_pub: our_pub,
                        ticket,
                    }],
                };
                let wire = find_peer::build_peer_here(&reply);
                if let Err(e) = self.send_typed(&peer_id, PacketType::PeerHere, &wire).await {
                    debug!(error = %e, "FindPeerHashed: failed to send PeerHere reply");
                } else {
                    debug!(
                        query_id = query.query_id,
                        "FindPeerHashed: replied PeerHere (hash-matched local client)"
                    );
                }
                return Ok(());
            }
        }

        // NoForward suppresses transit even for hashed queries.
        if matches!(
            self.config.effective_find_peer_mode(),
            FindPeerMode::NoForward
        ) {
            return Ok(());
        }

        // Recurse forward, preserving the hashed wire format —
        // transit bridges still don't see the raw target_pub.
        if query.ttl > 1 {
            let onward = find_peer::FindPeerHashed {
                ttl: query.ttl - 1,
                ..query.clone()
            };
            let payload = find_peer::build_find_peer_hashed(&onward);
            let fed_peers: Vec<PeerId> = self
                .federation_table
                .lock()
                .unwrap()
                .values()
                .copied()
                .filter(|pid| *pid != peer_id)
                .collect();
            if fed_peers.is_empty() {
                return Ok(());
            }
            self.forwarded_queries
                .lock()
                .unwrap()
                .insert(query.query_id, peer_id);
            for fed in &fed_peers {
                if let Err(e) = self
                    .send_typed(fed, PacketType::FindPeerHashed, &payload)
                    .await
                {
                    debug!(error = %e, ?fed, "FindPeerHashed: forward leg failed");
                }
            }
        }
        Ok(())
    }

    /// Receive-side handler for `PacketType::PeerHere`. Verifies
    /// the ticket chain, caches the route in `peer_directory`,
    /// and flushes any queued `pending_finds` waiters through the
    /// resolved next-hop.
    async fn handle_peer_here(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;
        let payload_bytes = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            rx.open(header.seq, PacketType::PeerHere as u8, &aad, body)?
        };
        // Source-auth: only federation bridges may reply.
        let sender_pub = {
            let peers = self.peers.lock_for(&peer_id).await;
            peers
                .get(&peer_id)
                .map(|p| p.peer_static_pub)
                .ok_or(PeerError::NotRegistered)?
        };
        let sender_is_bridge = self
            .federation_table
            .lock()
            .unwrap()
            .contains_key(&sender_pub);
        if !sender_is_bridge {
            debug!(
                ?sender_pub,
                "PeerHere: sender not in federation_table; dropping"
            );
            return Err(DriftError::AuthFailed);
        }

        let reply = find_peer::parse_peer_here(&payload_bytes)?;
        if reply.path.is_empty() {
            return Err(DriftError::DecodeError);
        }

        // Verify the terminal-bridge ticket. The ticket in
        // path[0] is signed by target_client for path[0].bridge_pub
        // (the standard XEdDSA presence ticket).
        let terminal = &reply.path[0];
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if federated::verify_ticket(
            &reply.target_client_pub,
            &terminal.bridge_pub,
            &terminal.ticket,
            now_ms,
        )
        .is_err()
        {
            debug!(
                target = ?reply.target_client_pub,
                bridge = ?terminal.bridge_pub,
                "PeerHere: terminal ticket failed verification; dropping"
            );
            return Err(DriftError::AuthFailed);
        }
        // Verify each intermediate hop's self-signed attestation.
        // path[1..] entries are signed by their own bridge_pub
        // over (HOP_DOMAIN_TAG || bridge_pub || query_id ||
        // expiry || nonce). A malicious forwarder can't forge a
        // path entry for a bridge that didn't participate.
        for (i, hop) in reply.path.iter().enumerate().skip(1) {
            if find_peer::verify_hop_attestation(
                &hop.bridge_pub,
                reply.query_id,
                &hop.ticket,
                now_ms,
            )
            .is_err()
            {
                debug!(
                    target = ?reply.target_client_pub,
                    hop_index = i,
                    bridge = ?hop.bridge_pub,
                    "PeerHere: intermediate hop attestation failed verification; dropping"
                );
                return Err(DriftError::AuthFailed);
            }
        }

        // Cache the route. Next-hop is the federation peer that
        // delivered this reply. For multi-hop replies the next-hop
        // is still the immediate sender — the path encodes the
        // chain for *future* forwarders, not for our local
        // peer_directory which only needs the next-hop pointer.
        {
            let mut dir = self.peer_directory.lock().unwrap();
            dir.insert(
                reply.target_client_pub,
                (peer_id, std::time::Instant::now()),
            );
        }

        // Phase F.8: a successful PeerHere from this bridge
        // means it actually delivered on whatever it had
        // claimed. Reset its fault counter so an honest bridge
        // that previously timed out on one query (network blip,
        // not malicious) doesn't accumulate stale blame.
        self.bridge_faults.lock().unwrap().remove(&peer_id);

        // Phase B: distinguish "we originated" from "we forwarded".
        // pending_finds has an entry iff we issued the original
        // FindPeer; forwarded_queries has an entry iff we forwarded
        // someone else's. Mutually exclusive.
        let pending_opt = self
            .pending_finds
            .lock()
            .unwrap()
            .remove(&reply.target_client_pub);
        if let Some(pending) = pending_opt {
            if pending.query_id != reply.query_id {
                let mut p = self.pending_finds.lock().unwrap();
                p.insert(reply.target_client_pub, pending);
                debug!(
                    target = ?reply.target_client_pub,
                    "PeerHere: query_id mismatch with pending entry; dropping"
                );
                return Ok(());
            }
            for waiter_bytes in pending.waiters {
                let env = match federated::parse(&waiter_bytes) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let re_envelope = federated::build(
                    &terminal.bridge_pub,
                    &env.target_client_pub,
                    &env.source_bridge_pub,
                    &env.source_client_pub,
                    env.payload,
                );
                if let Err(e) = self
                    .send_typed(&peer_id, PacketType::Federated, &re_envelope)
                    .await
                {
                    debug!(error = %e, "PeerHere: failed to flush waiter");
                }
            }
            debug!(
                target = ?reply.target_client_pub,
                query_id = reply.query_id,
                "PeerHere: cached + flushed waiters (originator path)"
            );
            return Ok(());
        }

        // Phase B forwarder path: we forwarded this query for
        // someone else. Append our bridge to the path and re-emit
        // back along the chain.
        let upstream_opt = self
            .forwarded_queries
            .lock()
            .unwrap()
            .remove(&reply.query_id);
        if let Some(upstream_peer) = upstream_opt {
            // Append our hop. Phase B uses a zero-padded "stub"
            // ticket for the intermediate entry — Phase C will
            // replace this with a bridge-self-signed hop
            // attestation. Receivers only verify path[0]
            // (terminal) cryptographically in Phase B.
            if reply.path.len() >= find_peer::MAX_FIND_TTL as usize {
                debug!(
                    query_id = reply.query_id,
                    "PeerHere: path already at MAX_FIND_TTL; dropping forward"
                );
                return Ok(());
            }
            // Build a real hop attestation signed by our own
            // XEdDSA key. Expiry: 60 s — short enough that a
            // stolen attestation has limited value, long enough
            // that clock skew doesn't reject honest replies.
            let our_pub = self.identity.public_bytes();
            let attestation_expiry = now_ms.saturating_add(60_000);
            let mut nonce = [0u8; 24];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
            let mut nonce_extra = [0u8; 64];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_extra);
            let identity = self.identity.clone();
            let attestation = find_peer::build_hop_attestation(
                &our_pub,
                reply.query_id,
                attestation_expiry,
                nonce,
                |msg| identity.xeddsa_sign(msg, &nonce_extra),
            );
            let mut extended_path = reply.path.clone();
            extended_path.push(find_peer::PathEntry {
                bridge_pub: our_pub,
                ticket: attestation,
            });
            let onward = find_peer::PeerHere {
                target_client_pub: reply.target_client_pub,
                query_id: reply.query_id,
                path: extended_path,
            };
            let wire = find_peer::build_peer_here(&onward);
            if let Err(e) = self
                .send_typed(&upstream_peer, PacketType::PeerHere, &wire)
                .await
            {
                debug!(error = %e, "PeerHere: failed to forward upstream");
            } else {
                debug!(
                    target = ?reply.target_client_pub,
                    query_id = reply.query_id,
                    new_path_len = onward.path.len(),
                    "PeerHere: forwarded upstream with extended path"
                );
            }
            return Ok(());
        }

        // No matching pending or forwarded query — either a
        // duplicate reply (we already processed it) or a reply
        // for a query we never originated/forwarded. Cache stays
        // populated (already inserted above) so future traffic
        // benefits; the unsolicited-reply itself drops.
        debug!(
            target = ?reply.target_client_pub,
            query_id = reply.query_id,
            "PeerHere: no matching pending or forwarded query (cached anyway)"
        );
        Ok(())
    }

    /// Receive-side handler for `PacketType::PeerGone`. A federation
    /// bridge tells us "client X disconnected from me, flush any
    /// cache entry pointing through me." We only evict if our
    /// cache's next-hop is the emitting bridge — PeerGone from
    /// bridge A must not evict a route through bridge B.
    async fn handle_peer_gone(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;
        let payload_bytes = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            rx.open(header.seq, PacketType::PeerGone as u8, &aad, body)?
        };
        let sender_pub = {
            let peers = self.peers.lock_for(&peer_id).await;
            peers
                .get(&peer_id)
                .map(|p| p.peer_static_pub)
                .ok_or(PeerError::NotRegistered)?
        };
        let sender_is_bridge = self
            .federation_table
            .lock()
            .unwrap()
            .contains_key(&sender_pub);
        if !sender_is_bridge {
            debug!(
                ?sender_pub,
                "PeerGone: sender not in federation_table; dropping"
            );
            return Err(DriftError::AuthFailed);
        }
        let gone = find_peer::parse_peer_gone(&payload_bytes)?;
        // Anti-spoof: PeerGone's bridge_pub must match the
        // sender's authenticated pubkey.
        if gone.bridge_pub != sender_pub {
            debug!(
                claimed = ?gone.bridge_pub,
                actual = ?sender_pub,
                "PeerGone: spoofed bridge_pub; dropping"
            );
            return Err(DriftError::AuthFailed);
        }
        // Evict only if our cached next-hop is the emitter.
        let evicted = {
            let mut dir = self.peer_directory.lock().unwrap();
            if let Some(&(cached_pid, _)) = dir.get(&gone.client_pub) {
                if cached_pid == peer_id {
                    dir.remove(&gone.client_pub);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        debug!(
            client = ?gone.client_pub,
            bridge = ?gone.bridge_pub,
            evicted,
            "PeerGone: processed"
        );
        Ok(())
    }

    /// Background GC for federation-discovery state. Periodically
    /// prunes expired entries from `pending_finds`,
    /// `recent_queries`, `neg_cache`, and `forwarded_queries`.
    /// Without this loop these maps grow unboundedly across a long-
    /// lived bridge process — every cold-path lookup adds a row.
    /// The aging policy mirrors the protocol constants:
    ///
    /// | Map                | Lifetime per entry           |
    /// |--------------------|-------------------------------|
    /// | `pending_finds`    | `MAX_FIND_DEADLINE_MS` (2 s)  |
    /// | `recent_queries`   | `QUERY_DEDUP_TTL_MS` (10 s)   |
    /// | `neg_cache`        | `NEG_CACHE_TTL_MS` (5 s)      |
    /// | `forwarded_queries`| `MAX_FIND_DEADLINE_MS` (2 s)  |
    ///
    /// The sweep ticks once per second — fine-grained enough to
    /// keep memory bounded without burning CPU on what is, after
    /// all, four small HashMaps.
    pub(crate) async fn run_find_peer_gc_loop(self: std::sync::Arc<Self>) {
        let period = std::time::Duration::from_secs(1);
        let mut ticker = tokio::time::interval(period);
        let gc_started_at = std::time::Instant::now();
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = std::time::Instant::now();
            let pf_dead = std::time::Duration::from_millis(find_peer::MAX_FIND_DEADLINE_MS);
            // Phase F.8: when reaping expired pending_finds,
            // fault each claimant bridge (the bridge advertised
            // it could answer the query but didn't deliver).
            // Collect first, mutate `bridge_faults` after we
            // drop the pending_finds lock — avoids holding two
            // mutexes at once.
            let mut fault_blame: Vec<PeerId> = Vec::new();
            let pf_purged = {
                let mut pf = self.pending_finds.lock().unwrap();
                let before = pf.len();
                pf.retain(|_, p| {
                    let alive = now.duration_since(p.started_at) < pf_dead;
                    if !alive {
                        fault_blame.extend(p.claimed_by.iter().copied());
                    }
                    alive
                });
                before.saturating_sub(pf.len())
            };
            if !fault_blame.is_empty() {
                let mut faults = self.bridge_faults.lock().unwrap();
                for pid in fault_blame {
                    let counter = faults.entry(pid).or_insert(0);
                    *counter += 1;
                    if *counter == 5 || *counter == 25 || (*counter).is_multiple_of(100) {
                        // Log at meaningful inflection points
                        // rather than every fault. Demotion is
                        // applied at fanout time
                        // (`bridge_fault_skip_threshold`); the GC
                        // loop just maintains the counter.
                        tracing::warn!(
                            ?pid,
                            faults = *counter,
                            "federation peer accumulated repeated bloom-claim faults — \
                             check whether this bridge is honest (advertised pubkeys \
                             it can't actually deliver) or unreliable"
                        );
                    }
                }
            }
            // Phase G.2: exponential decay of fault counters.
            // Faults arrive on the pending_find deadline cadence
            // (one fault per blame every 2s+ when a bridge is
            // actively misbehaving), so the decay has to be much
            // slower than the GC tick (1s) or counters can never
            // climb. Halve every `bridge_fault_decay_secs` —
            // slow enough that a steady stream of faults
            // accumulates past the threshold within seconds,
            // fast enough that a once-bad bridge recovers within
            // a couple of minutes of good behavior.
            let decay_secs = self.config.bridge_fault_decay_secs;
            if decay_secs > 0 {
                let cycles_since_start = now.saturating_duration_since(gc_started_at).as_secs();
                if cycles_since_start > 0 && cycles_since_start.is_multiple_of(decay_secs) {
                    let mut faults = self.bridge_faults.lock().unwrap();
                    faults.retain(|_, counter| {
                        *counter >>= 1;
                        *counter > 0
                    });
                }
            }
            // recent_queries values are `Instant` deadlines.
            let rq_purged = {
                let mut rq = self.recent_queries.lock().unwrap();
                let before = rq.len();
                rq.retain(|_, expires| *expires > now);
                before.saturating_sub(rq.len())
            };
            // neg_cache values are `Instant` deadlines.
            let nc_purged = {
                let mut nc = self.neg_cache.lock().unwrap();
                let before = nc.len();
                nc.retain(|_, expires| *expires > now);
                before.saturating_sub(nc.len())
            };
            // forwarded_queries doesn't carry its own deadline —
            // use recent_queries (same query_id key) as the
            // source of truth. A forwarded query whose query_id
            // has been GC'd from recent_queries is past its
            // dedup window AND past its forward deadline.
            let fq_purged = {
                let recent: std::collections::HashSet<u64> = self
                    .recent_queries
                    .lock()
                    .unwrap()
                    .keys()
                    .copied()
                    .collect();
                let mut fq = self.forwarded_queries.lock().unwrap();
                let before = fq.len();
                fq.retain(|qid, _| recent.contains(qid));
                before.saturating_sub(fq.len())
            };
            if pf_purged + rq_purged + nc_purged + fq_purged > 0 {
                debug!(
                    pf = pf_purged,
                    rq = rq_purged,
                    nc = nc_purged,
                    fq = fq_purged,
                    "find_peer GC: swept expired entries"
                );
            }
        }
    }

    /// Phase F: cover-traffic loop. Emits fire-and-forget
    /// `FindPeer` (or `FindPeerHashed`, depending on mode)
    /// queries with random decoy targets at Poisson-distributed
    /// intervals. The decoys are indistinguishable on-the-wire
    /// from real queries — a passive observer correlating
    /// query timing with user activity sees a noise floor that
    /// makes real query patterns much harder to extract.
    ///
    /// Decoys do NOT touch `pending_finds`. They're emitted as
    /// raw `send_typed` calls with a one-shot query_id; whether
    /// or not a `PeerHere` ever arrives, no waiter queue is
    /// drained. This keeps the cover-traffic state cost flat
    /// (independent of emit rate).
    pub(crate) async fn run_cover_traffic_loop(self: std::sync::Arc<Self>) {
        let rate = match self.config.cover_traffic_rate_hz {
            Some(r) if r > 0.0 => r,
            _ => return,
        };
        // Exponential waits give Poisson process arrivals. The
        // mean inter-arrival time is 1/rate seconds.
        loop {
            // Sample wait ~ Exp(rate). For uniform U in (0,1],
            // wait = -ln(U) / rate.
            let wait_secs: f64 = {
                use rand::Rng;
                let u: f64 = rand::thread_rng().gen_range(1e-12..1.0_f64);
                -u.ln() / rate
            };
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait_secs)).await;

            // Skip the emit if discovery is disabled entirely.
            if matches!(
                self.config.effective_find_peer_mode(),
                FindPeerMode::Disabled
            ) {
                continue;
            }
            self.emit_cover_query().await;
        }
    }

    /// Emit one decoy query. Picks a random federation peer
    /// (refusing to fire if there are none — nothing to send
    /// noise to). Generates a random 32-byte target and a fresh
    /// query_id. Honors the configured FindPeerMode: in
    /// `OriginateHashed` mode emits `FindPeerHashed` so even the
    /// wire shape matches real privacy-mode queries.
    async fn emit_cover_query(&self) {
        let fed_peers: Vec<PeerId> = self
            .federation_table
            .lock()
            .unwrap()
            .values()
            .copied()
            .collect();
        if fed_peers.is_empty() {
            return;
        }
        // Pick one random federation peer per decoy. A decoy
        // sent to ALL peers would be a giveaway — real queries
        // are filtered through blooms and typically reach only
        // a subset. Sending to one peer keeps the decoy's
        // fan-out pattern statistically similar.
        let peer_idx: usize = {
            use rand::Rng;
            rand::thread_rng().gen_range(0..fed_peers.len())
        };
        let peer = fed_peers[peer_idx];

        let our_pub = self.identity.public_bytes();
        let mut decoy_target = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut decoy_target);
        let mut qid_bytes = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut qid_bytes);
        let query_id = u64::from_be_bytes(qid_bytes);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let (payload, pkt_type) = if matches!(
            self.config.effective_find_peer_mode(),
            FindPeerMode::OriginateHashed
        ) {
            let mut salt = [0u8; find_peer::FIND_PEER_HASHED_SALT_LEN];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            let target_hash = find_peer::hash_target_pub(&decoy_target, &salt);
            let q = find_peer::FindPeerHashed {
                salt,
                target_hash,
                query_id,
                ttl: find_peer::MAX_FIND_TTL,
                originator_bridge: our_pub,
                originator_query_at_ms: now_ms,
            };
            (
                find_peer::build_find_peer_hashed(&q),
                PacketType::FindPeerHashed,
            )
        } else {
            let q = find_peer::FindPeer {
                target_client_pub: decoy_target,
                query_id,
                ttl: find_peer::MAX_FIND_TTL,
                originator_bridge: our_pub,
                originator_query_at_ms: now_ms,
            };
            (find_peer::build_find_peer(&q), PacketType::FindPeer)
        };

        if let Err(e) = self.send_typed(&peer, pkt_type, &payload).await {
            // Silent at debug level — cover traffic failures
            // are not user-visible and don't affect real query
            // behavior.
            debug!(
                error = %e,
                ?peer,
                "cover traffic: emit failed (non-fatal)"
            );
        }
    }

    /// Helper: do we have an Established session with `pubkey`?
    /// Used by `handle_find_peer` to confirm a presence ticket
    /// hasn't outlived its underlying session.
    async fn session_established_with_pubkey(&self, pubkey: &[u8; 32]) -> bool {
        let peers = self.peers.lock_all().await;
        for p in peers.iter() {
            if p.peer_static_pub == *pubkey
                && matches!(p.handshake, HandshakeState::Established { .. })
            {
                return true;
            }
        }
        false
    }

    async fn dispatch(&self, action: SendAction) -> Result<()> {
        match action {
            SendAction::Data(bytes, addr, iface) => {
                self.ifaces.send_for(iface, &bytes, addr).await?;
                let n = bytes.len();
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add(n as u64, Ordering::Relaxed);
                if let Some(q) = &self.qlog {
                    q.log_packet_sent("Data", &addr.to_string(), n, 0);
                }
                drift_core::pool::return_wire_buf(bytes);
            }
            SendAction::Hello(bytes, addr, iface) => {
                // Phase PQ-T.11.3: first-HELLO jitter.
                // Only the FIRST HELLO comes through SendAction::Hello —
                // retransmits go directly through the retry loop, which
                // already spreads them via exponential backoff. So this
                // delay applies once per fresh handshake, exactly when
                // synchronized reconnects need spreading out.
                let jitter_ms = self.config.handshake_jitter_ms;
                if jitter_ms > 0 {
                    use rand::Rng;
                    let delay = rand::thread_rng().gen_range(0..jitter_ms);
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                }
                self.ifaces.send_for(iface, &bytes, addr).await?;
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                debug!("sent HELLO to {:?}", addr);
                if let Some(q) = &self.qlog {
                    q.log_packet_sent("Hello", &addr.to_string(), bytes.len(), 0);
                }
            }
            SendAction::Queued => {}
        }
        Ok(())
    }

    async fn run_recv_loop_for(self: Arc<Self>, tx: mpsc::Sender<Received>, iface_idx: usize) {
        let iface = match self.ifaces.get(iface_idx) {
            Some(io) => io.clone(),
            None => return,
        };
        // 64 KiB so UDP_GRO can coalesce up to ~45 MTU-sized
        // datagrams into one recvmsg. Non-UDP adapters and
        // pre-5.0 Linux UDP still get one packet per call —
        // the extra slack is cheap.
        let mut buf = vec![0u8; 64 * 1024];
        let mut segs: Vec<(usize, usize, std::net::SocketAddr)> = Vec::with_capacity(32);
        loop {
            segs.clear();
            if let Err(e) = iface.recv_from_batch(&mut buf, &mut segs).await {
                // Recv error means the underlying I/O died —
                // for connection-oriented adapters (TCP, TLS,
                // WS) this is end-of-connection. Drop our
                // reference by removing the slot so the socket
                // actually closes. The primary interface (idx
                // 0) backs the whole Transport's send path —
                // log and break without removal so a UDP
                // socket hiccup doesn't permanently disable
                // the transport.
                if iface_idx != 0 {
                    self.ifaces.remove(iface_idx);
                }
                warn!(error = %e, iface_idx, "recv_from failed; evicting interface");
                break;
            }
            for &(off, n, src) in segs.iter() {
                // GRO doesn't surface per-segment ECN; the
                // kernel exposes a TOS/ECN cmsg but our parser
                // only looks at UDP_GRO today. Treat as
                // ecn_ce=false until we wire IP_TOS/IPV6_TCLASS.
                let ecn_ce = false;
                self.metrics
                    .packets_received
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_received
                    .fetch_add(n as u64, Ordering::Relaxed);
                if ecn_ce {
                    self.metrics.ecn_ce_received.fetch_add(1, Ordering::Relaxed);
                }
                let received_at = Instant::now();
                let data = &buf[off..off + n];

                // qlog: emit a structured packet_received event
                // before dispatch. We peek the header type for
                // the category tag but let `process_incoming`
                // do the actual auth + dispatch.
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
                // peer, decrypt, and deliver without touching
                // the full long-header parser.
                if crate::short_header::is_short_header(data) {
                    match self
                        .process_short_header(data, src, received_at, ecn_ce)
                        .await
                    {
                        Ok(Some(r)) => {
                            if tx.send(r).await.is_err() {
                                debug!("recv channel closed (short)");
                                return;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            if matches!(e, DriftError::AuthFailed) {
                                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                            }
                            if let Some(suppressed) = self.drop_warn_throttle.tick_or_count() {
                                let (pkt_diag, peer_diag, hs_diag) =
                                    self.auth_fail_diag(data).await;
                                warn!(
                                    error = %e,
                                    ?src,
                                    pkt = %pkt_diag,
                                    peer = %peer_diag,
                                    state = %hs_diag,
                                    suppressed,
                                    "dropped invalid short-header packet"
                                );
                            }
                        }
                    }
                    continue;
                }

                match self
                    .process_incoming(data, src, received_at, ecn_ce, iface_idx)
                    .await
                {
                    Ok(Some(r)) => {
                        if tx.send(r).await.is_err() {
                            debug!("recv channel closed");
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        match &e {
                            DriftError::Crypto(drift_core::error::CryptoError::Replay {
                                ..
                            }) => {
                                self.metrics.replays_caught.fetch_add(1, Ordering::Relaxed);
                            }
                            DriftError::AuthFailed => {
                                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                            }
                            DriftError::DeadlineExpired => {
                                self.metrics
                                    .deadline_dropped
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            DriftError::Peer(_) => {
                                self.metrics
                                    .unknown_peer_drops
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                        if let Some(suppressed) = self.drop_warn_throttle.tick_or_count() {
                            let (pkt_diag, peer_diag, hs_diag) = self.auth_fail_diag(data).await;
                            warn!(
                                error = %e,
                                ?src,
                                pkt = %pkt_diag,
                                peer = %peer_diag,
                                state = %hs_diag,
                                suppressed,
                                "dropped invalid packet"
                            );
                        }
                    }
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
            let map = self.cid_map.lock().unwrap();
            *map.get(&cid).ok_or(PeerError::NotRegistered)?
        };

        let (payload, probe) = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let aad = &data[..crate::short_header::SHORT_HEADER_LEN];
            let plaintext = match rx.open(seq, PacketType::Data as u8, aad, body) {
                Ok(pt) => pt,
                Err(err) => {
                    // Rekey grace: try the prev rx if current fails.
                    let mut recovered = None;
                    if let HandshakeState::Established { prev: Some(p), .. } = &mut peer.handshake {
                        if p.installed_at.elapsed() <= REKEY_GRACE {
                            if let Ok(pt) = p.rx.open(seq, PacketType::Data as u8, aad, body) {
                                recovered = Some(pt);
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
                    build_path_challenge_packet(self.local_peer_id, peer, &challenge)
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
            if let Err(e) = self
                .ifaces
                .send_for(self.iface_for(&peer_id).await, &bytes, addr)
                .await
            {
                debug!(error = %e, "PathChallenge send failed (short hdr)");
            } else {
                self.metrics
                    .path_probes_sent
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
        }

        Ok(Some(Received {
            peer_id,
            seq,
            supersedes: 0,
            payload,
            ecn_ce,
            federated_from: None,
            federated_via_bridge: None,
        }))
    }

    /// Best-effort packet inspection for the rate-limited
    /// "dropped invalid packet" warn sites. Returns
    /// `(pkt_diag, peer_diag, hs_diag)` to add diagnostic
    /// context. Throttled callers only — does a cid_map lookup
    /// and one peer-shard lock.
    async fn auth_fail_diag(&self, data: &[u8]) -> (String, String, String) {
        if crate::short_header::is_short_header(data) {
            if let Ok((cid, seq, _)) = crate::short_header::decode_short(data) {
                let pid_opt = {
                    let map = self.cid_map.lock().unwrap();
                    map.get(&cid).copied()
                };
                if let Some(pid) = pid_opt {
                    let peers = self.peers.lock_for(&pid).await;
                    let hs = peers.get(&pid).map_or("missing", |p| match &p.handshake {
                        HandshakeState::Pending => "pending",
                        HandshakeState::AwaitingAck { .. } => "awaiting_ack",
                        HandshakeState::AwaitingData { .. } => "awaiting_data",
                        HandshakeState::Established { prev, .. } => {
                            if prev.is_some() {
                                "established+prev"
                            } else {
                                "established"
                            }
                        }
                    });
                    let cached_addr = peers
                        .get(&pid)
                        .map(|p| p.addr.to_string())
                        .unwrap_or_default();
                    return (
                        format!("short:cid=0x{:04x}:seq={}", cid, seq),
                        format!("known:{}:cached={}", hex::encode(pid), cached_addr),
                        hs.to_string(),
                    );
                }
                return (
                    format!("short:cid=0x{:04x}:seq={}", cid, seq),
                    "unknown_cid".to_string(),
                    "n/a".to_string(),
                );
            }
        }
        if data.len() >= HEADER_LEN {
            if let Ok(h) = Header::decode(&data[..HEADER_LEN]) {
                return (
                    format!("long:{:?}:seq={}", h.packet_type, h.seq),
                    format!(
                        "src={}:dst={}",
                        hex::encode(h.src_id),
                        hex::encode(h.dst_id)
                    ),
                    "n/a".to_string(),
                );
            }
        }
        ("undecodable".to_string(), "?".to_string(), "?".to_string())
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
            // SECURITY (SEC.FIX.1): pass the source addr to
            // forward_packet so it can gate forwarding by source
            // when `require_src_for_forward` is set (default on
            // for `drift bridge`). Without this gate, an
            // unauthenticated UDP packet with `dst_id` = some
            // peer reachable through us (via either the routing
            // table or our peer table) would be re-emitted by us
            // to that peer with our IP as source — open relay.
            self.forward_packet_with_src(data, &header, src).await?;
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
                self.handle_path_challenge(&header, data, body, src, iface_idx)
                    .await?;
                Ok(None)
            }
            PacketType::PathResponse => {
                self.handle_path_response(&header, data, body, src, iface_idx)
                    .await?;
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
                self.handle_beacon(&header, data, body, src, iface_idx)
                    .await?;
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
            PacketType::Federated => {
                self.handle_federated(&header, data, body, src, received_at, ecn_ce)
                    .await
            }
            PacketType::FederationDirectory => {
                self.handle_federation_directory(&header, data, body)
                    .await?;
                Ok(None)
            }
            PacketType::PresenceTicket => {
                self.handle_presence_ticket(&header, data, body).await?;
                Ok(None)
            }
            PacketType::FindPeer => {
                self.handle_find_peer(&header, data, body).await?;
                Ok(None)
            }
            PacketType::PeerHere => {
                self.handle_peer_here(&header, data, body).await?;
                Ok(None)
            }
            PacketType::PeerGone => {
                self.handle_peer_gone(&header, data, body).await?;
                Ok(None)
            }
            PacketType::FindPeerHashed => {
                self.handle_find_peer_hashed(&header, data, body).await?;
                Ok(None)
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
            // Snapshot routes into a plain HashMap before
            // taking the async peers lock — std::sync::MutexGuard
            // isn't Send, so we can't hold `routes` across the
            // `peers.lock_all().await` below.
            let route_snapshot: StdHashMap<PeerId, SocketAddr> = {
                let routes = self.routes.lock().unwrap();
                routes
                    .entries()
                    .into_iter()
                    .filter_map(|(id, _metric, _cost)| routes.lookup(&id).map(|addr| (id, addr)))
                    .collect()
            };
            let to_retransmit: Vec<(Vec<u8>, SocketAddr, usize)> = {
                let mut peers = self.peers.lock_all().await;
                let mut out = Vec::new();
                for peer in peers.iter_mut() {
                    // Snapshot pending_resumption before we
                    // take &mut on peer.handshake — we need
                    // both simultaneously (one to pick wire
                    // type, one to bump attempts).
                    let resumption_ctx = peer.pending_resumption.clone();
                    // Phase PQ-T.10: if a previous session
                    // gave us a real RTT sample for this peer,
                    // use the RFC 6298 §2.4 formula instead of
                    // the static `handshake_retry_base_ms`
                    // default. Floor at 200ms (DRIFT-specific
                    // — RFC 6298's 1s floor is conservative
                    // for transcontinental TCP, not our
                    // typical paths). Drops "initial" 1s
                    // default to RTT-aware on rekey / second
                    // handshake without giving up the
                    // first-contact safety margin.
                    let effective_base_ms = match peer.neighbor_srtt {
                        Some(srtt) => {
                            let srtt_ms = srtt.as_millis() as u64;
                            (4 * srtt_ms).max(200)
                        }
                        None => self.config.handshake_retry_base_ms,
                    };
                    if let HandshakeState::AwaitingAck {
                        client_nonce,
                        ephemeral,
                        last_sent,
                        attempts,
                        cookie,
                        pq,
                    } = &mut peer.handshake
                    {
                        let wait = handshake_backoff_ms(effective_base_ms, *attempts);
                        if last_sent.elapsed() < std::time::Duration::from_millis(wait) {
                            continue;
                        }
                        if *attempts >= self.config.handshake_max_attempts {
                            continue;
                        }
                        *attempts += 1;
                        *last_sent = Instant::now();

                        let mesh = route_snapshot.get(&peer.id).copied();
                        // If this AwaitingAck was entered via a
                        // ResumeHello (pending_resumption set),
                        // retransmit as ResumeHello — not HELLO.
                        // Otherwise a single ResumeHello drop
                        // silently downgrades the client to a
                        // cold handshake and wastes the ticket.
                        let wire = if let Some(res) = &resumption_ctx {
                            build_resume_hello_wire(
                                self.local_peer_id,
                                peer.id,
                                ephemeral.public_bytes(),
                                *client_nonce,
                                res.ticket_id,
                                mesh.is_some(),
                            )
                        } else {
                            // Re-emit the same ML-KEM ek bytes
                            // for the retransmit so the server,
                            // if it eventually responds, produces
                            // a ciphertext we can decapsulate
                            // with the stashed dk.
                            let pq_ek = pq.as_ref().map(|(ek, _)| ek.as_slice());
                            build_hello_wire(
                                self.local_peer_id,
                                peer.id,
                                &self.identity,
                                ephemeral.public_bytes(),
                                *client_nonce,
                                mesh.is_some(),
                                cookie.as_ref(),
                                pq_ek,
                            )
                        };
                        let target = mesh.unwrap_or(peer.addr);
                        // Mesh-only peer awaiting a learned
                        // route: skip the retransmit. Once a
                        // beacon arrives and the route table is
                        // populated, the next send_data will
                        // pick up `mesh = Some(...)` and we
                        // emit a fresh HELLO with a real target.
                        if target.ip().is_unspecified() {
                            continue;
                        }
                        out.push((wire, target, peer.interface_id));
                    }
                }
                out
            };
            for (bytes, addr, iface) in to_retransmit {
                if let Err(e) = self.ifaces.send_for(iface, &bytes, addr).await {
                    warn!(error = %e, "HELLO retransmit failed");
                } else {
                    self.metrics
                        .handshake_retries
                        .fetch_add(1, Ordering::Relaxed);
                    self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .bytes_sent
                        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
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
            return Err(PeerError::WrongDestination.into());
        }
        let mut client_static_pub = [0u8; STATIC_KEY_LEN];
        client_static_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut client_ephemeral_pub = [0u8; STATIC_KEY_LEN];
        client_ephemeral_pub.copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN * 2]);
        let mut client_nonce = [0u8; NONCE_LEN];
        client_nonce.copy_from_slice(&body[STATIC_KEY_LEN * 2..STATIC_KEY_LEN * 2 + NONCE_LEN]);

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

        // Phase PQ: extract the ML-KEM encap key when the
        // client signaled `FLAG_PQ_HYBRID`. We reject HELLOs
        // that request PQ when this side has `hybrid_pq`
        // disabled — silent fallback to classical would defeat
        // the originator's harvest-now-decrypt-later guarantee.
        // The ek lives at the very tail of the body, after any
        // cookie that may also be present.
        let pq_requested = (header.flags & drift_core::header::FLAG_PQ_HYBRID) != 0;
        if pq_requested && !self.config.hybrid_pq {
            let cpid = derive_peer_id(&client_static_pub);
            tracing::warn!(
                client_peer_id = ?cpid,
                ?src,
                "rejected HELLO with FLAG_PQ_HYBRID — \
                 this server has hybrid_pq disabled; \
                 client must retry without the flag"
            );
            self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .hybrid_pq_handshakes_refused
                .fetch_add(1, Ordering::Relaxed);
            return Err(DriftError::AuthFailed);
        }
        let pq_client_ek: Option<Vec<u8>> = if pq_requested {
            if body.len() < HELLO_PAYLOAD_LEN + HELLO_PQ_TAIL_LEN {
                return Err(DriftError::PacketTooShort {
                    got: body.len(),
                    need: HELLO_PAYLOAD_LEN + HELLO_PQ_TAIL_LEN,
                });
            }
            let ek_start = body.len() - HELLO_PQ_TAIL_LEN;
            Some(body[ek_start..].to_vec())
        } else {
            None
        };

        // Adaptive DoS cookie check. Happens BEFORE any peer-table
        // allocation and BEFORE any X25519 work, so an attacker
        // spamming HELLOs from spoofed addresses only costs us the
        // Blake2b MAC compute + a single UDP send per packet.
        //
        // Phase PQ: the PQ ek (1184 B) sits at the body tail and
        // can make a non-cookie HELLO look long enough to falsely
        // satisfy a simple `body.len() >= HELLO_WITH_COOKIE_LEN`
        // check. Strip the PQ tail before deciding cookie
        // presence — the cookie lives between the base and the
        // PQ ek (see SPEC.md §6.7).
        let cookie_required = self.cookie_required_sync();
        let body_minus_pq =
            body.len()
                .saturating_sub(if pq_requested { HELLO_PQ_TAIL_LEN } else { 0 });
        let has_cookie_tail = body_minus_pq >= HELLO_WITH_COOKIE_LEN;
        if cookie_required {
            if !has_cookie_tail {
                self.send_challenge(
                    iface_idx,
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
                self.metrics
                    .cookies_rejected
                    .fetch_add(1, Ordering::Relaxed);
                // Reply with a fresh challenge so a legitimate client
                // whose cookie expired can recover without restarting.
                self.send_challenge(
                    iface_idx,
                    header.src_id,
                    src,
                    &client_static_pub,
                    &client_ephemeral_pub,
                    &client_nonce,
                )
                .await?;
                return Ok(());
            }
            self.metrics
                .cookies_accepted
                .fetch_add(1, Ordering::Relaxed);
        }

        let client_peer_id = derive_peer_id(&client_static_pub);

        // Track whether THIS HELLO caused us to call
        // `regenerate_session` for a peer that already had an
        // Established session. That's the "restart migration"
        // signal — the stream layer needs it to wipe the now-
        // stale per-peer state (stream slots, next-id counters,
        // congestion gauges) before the new session's OPENs
        // arrive and silently collide with the old keys.
        let mut session_was_reset = false;
        // SEC.FIX.1 addr_index maintenance: track whether this
        // HELLO caused us to insert a new peer or migrate an
        // existing peer's addr. Apply the index update AFTER
        // the lock_all guard drops, so we never hold all shard
        // mutexes across the addr_index await.
        let mut new_inserted_addr: Option<SocketAddr> = None;
        let mut migrated_from: Option<SocketAddr> = None;
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
                    if peers.iter().filter(|p| p.auto_registered).count() >= self.config.max_peers {
                        return Err(PeerError::NotRegistered.into());
                    }
                    let mut new_peer =
                        Peer::new(client_peer_id, src, client_static_pub, Direction::Responder);
                    new_peer.auto_registered = true;
                    new_peer.interface_id = iface_idx;
                    peers.insert(new_peer);
                    new_inserted_addr = Some(src);
                    debug!(
                        "auto-registered new peer {:?} on iface {}",
                        client_peer_id, iface_idx
                    );
                } else {
                    return Err(PeerError::NotRegistered.into());
                }
            }

            let peer = peers
                .get_mut(&client_peer_id)
                .ok_or(PeerError::NotRegistered)?;

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
                    // No session_reset signal here — `AwaitingData`
                    // means no DATA has flowed yet, so the stream
                    // layer has nothing for this peer to wipe.
                    let old_addr = peer.addr;
                    let result = regenerate_session(
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
                        iface_idx,
                        pq_client_ek.as_deref(),
                    )?;
                    if old_addr != src && new_inserted_addr.is_none() {
                        migrated_from = Some(old_addr);
                    }
                    result
                }
            } else {
                // Only an `Established` peer had real
                // application-layer state (streams, congestion)
                // built on top of its old keys — that's the
                // "restart migration" case where the stream
                // layer has stale entries that must go before
                // the new session's first OPEN can land.
                // Pending / AwaitingAck never reached the
                // stream layer at all.
                session_was_reset = matches!(peer.handshake, HandshakeState::Established { .. });
                let old_addr = peer.addr;
                let result = regenerate_session(
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
                    iface_idx,
                    pq_client_ek.as_deref(),
                )?;
                if old_addr != src && new_inserted_addr.is_none() {
                    migrated_from = Some(old_addr);
                }
                result
            }
        };
        // SEC.FIX.1 addr_index maintenance, applied after the
        // lock_all guard dropped at the closing `};` above.
        if let Some(addr) = new_inserted_addr {
            self.peers.note_inserted(client_peer_id, addr).await;
        }
        if let Some(old) = migrated_from {
            self.peers.note_addr_changed(client_peer_id, old, src).await;
        }

        // Notify the session-reset listener (if installed) AFTER
        // dropping the peer lock so the observer can grab its
        // own locks freely.
        if session_was_reset {
            if let Ok(slot) = self.session_reset_tx.lock() {
                if let Some(tx) = slot.as_ref() {
                    let _ = tx.send(client_peer_id);
                }
            }
        }

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
        self.ifaces
            .send_via(iface_idx, &ack_bytes, ack_addr)
            .await?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(ack_bytes.len() as u64, Ordering::Relaxed);
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
        // Phase PQ: if the server signaled `FLAG_PQ_HYBRID`,
        // the body has an ML-KEM-768 ciphertext appended after
        // the standard auth tag. Extract it; the decapsulation
        // happens later inside the peer-lock block once we have
        // the stashed dk.
        let server_pq = (header.flags & drift_core::header::FLAG_PQ_HYBRID) != 0;
        let pq_ct: Option<&[u8]> = if server_pq {
            let need = HELLO_ACK_PAYLOAD_LEN + HELLO_ACK_PQ_TAIL_LEN;
            if body.len() < need {
                return Err(DriftError::PacketTooShort {
                    got: body.len(),
                    need,
                });
            }
            let ct_start = HELLO_ACK_PAYLOAD_LEN;
            Some(&body[ct_start..ct_start + HELLO_ACK_PQ_TAIL_LEN])
        } else {
            None
        };
        let mut server_ephemeral_pub = [0u8; STATIC_KEY_LEN];
        server_ephemeral_pub.copy_from_slice(&body[..STATIC_KEY_LEN]);
        let mut server_nonce = [0u8; NONCE_LEN];
        server_nonce.copy_from_slice(&body[STATIC_KEY_LEN..STATIC_KEY_LEN + NONCE_LEN]);
        let tag_start = STATIC_KEY_LEN + NONCE_LEN;
        let tag = &body[tag_start..tag_start + AUTH_TAG_LEN];

        // Client looks up the peer by src_id = the server's identity.
        let peer_id = header.src_id;
        // Definite assignment verified by the compiler: the inner
        // block either hits the early `return Ok(())` (no use) or
        // assigns via the `Established` path before falling out.
        let cid_key_for_install: Option<drift_core::Zeroizing<[u8; 32]>>;
        // Track how many bytes we shipped from the flush so we
        // can update the metric after releasing the lock — lock
        // is held during the sends themselves to serialize with
        // any concurrent `close_peer` (otherwise a Close can
        // race ahead of the pending DATAs and the server tears
        // down the AwaitingData peer before the first DATA
        // arrives, silently dropping it).
        let mut flushed_bytes = 0u64;
        let mut flushed_packets = 0u64;
        let mut to_send: Vec<(usize, Vec<u8>, std::net::SocketAddr)> = Vec::new();
        let mesh_next_hop = self.routes.lock().unwrap().lookup(&peer_id);
        {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;

            // Pattern match by value via std::mem::replace to consume the
            // ephemeral secret (it's not Copy).
            let old_state = std::mem::replace(&mut peer.handshake, HandshakeState::Pending);
            let (client_nonce, ephemeral, hello_sent_at, pq_dk_opt) = match old_state {
                HandshakeState::AwaitingAck {
                    client_nonce,
                    ephemeral,
                    last_sent,
                    pq,
                    ..
                    // `cookie` is discarded — once HELLO_ACK lands, the
                    // handshake is done and the token is no longer useful.
                } => (
                    client_nonce,
                    ephemeral,
                    last_sent,
                    pq.map(|(_ek, dk)| dk),
                ),
                other => {
                    // Restore and bail.
                    peer.handshake = other;
                    debug!("HELLO_ACK in wrong state, ignoring");
                    return Ok(());
                }
            };

            // Phase PQ: the client and server must agree on
            // PQ vs classical. Mismatch is a protocol error.
            //   - We asked for PQ (pq_dk_opt.is_some()) but
            //     server replied without the flag → silent
            //     downgrade attempt; refuse.
            //   - We did NOT ask for PQ but server replied with
            //     the flag → server-side state corruption or
            //     a forged ACK; refuse.
            if pq_dk_opt.is_some() != server_pq {
                tracing::warn!(
                    client_pq = pq_dk_opt.is_some(),
                    server_pq,
                    "PQ posture mismatch in HELLO_ACK — refusing handshake"
                );
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .hybrid_pq_handshakes_refused
                    .fetch_add(1, Ordering::Relaxed);
                return Err(DriftError::AuthFailed);
            }

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

            // Phase PQ: decapsulate the server's ML-KEM
            // ciphertext (if any) with the stashed dk and
            // derive the hybrid session key. A bogus ct (wrong
            // length, decap failure) returns None → reject
            // the whole handshake. The dk drops after this
            // block, zeroing itself.
            let session_key_bytes = if let (Some(dk), Some(ct)) = (pq_dk_opt, pq_ct) {
                let mlkem_ss = dk.decapsulate(ct).ok_or(DriftError::AuthFailed)?;
                let key = drift_core::pq::derive_hybrid_key(
                    &static_dh,
                    &ephemeral_dh,
                    &mlkem_ss,
                    &client_nonce,
                    &server_nonce,
                );
                drift_core::Zeroizing::new(key)
            } else {
                derive_session_key(&static_dh, &ephemeral_dh, &client_nonce, &server_nonce)
            };

            let tx = SessionKey::new(&session_key_bytes, Direction::Initiator);
            let rx = SessionKey::new(&session_key_bytes, Direction::Responder);

            let mut hbuf = [0u8; HEADER_LEN];
            header.encode(&mut hbuf);
            let canon = canonical_aad(&hbuf);
            // Phase PQ: when hybrid, the AAD must mirror the
            // server's — header + server_eph_pub + server_nonce
            // + server_mlkem_ct. If anyone tampered with the ct
            // we got a different mlkem_ss → different session
            // key → AEAD open() below fails.
            let mut aad = Vec::with_capacity(
                HEADER_LEN + STATIC_KEY_LEN + NONCE_LEN + pq_ct.map(|c| c.len()).unwrap_or(0),
            );
            aad.extend_from_slice(&canon);
            aad.extend_from_slice(&server_ephemeral_pub);
            aad.extend_from_slice(&server_nonce);
            if let Some(ct) = pq_ct {
                aad.extend_from_slice(ct);
            }
            rx.open(1, PacketType::HelloAck as u8, &aad, tag)?;

            peer.reset_seq();
            peer.coalesce_state.clear();
            peer.coalesce_order.clear();
            peer.mark_session_start();
            peer.handshake = HandshakeState::Established {
                tx,
                rx,
                key_bytes: session_key_bytes.clone(),
                prev: None,
            };
            if mesh_next_hop.is_some() {
                peer.via_mesh = true;
            }
            self.metrics
                .handshakes_completed
                .fetch_add(1, Ordering::Relaxed);
            if server_pq {
                self.metrics
                    .hybrid_pq_handshakes_completed
                    .fetch_add(1, Ordering::Relaxed);
            }
            debug!("handshake complete with peer {:?}", peer_id);
            if let Some(q) = &self.qlog {
                q.log_handshake_complete(&format!("{:?}", peer_id), false);
            }
            cid_key_for_install = Some(session_key_bytes);

            // Build the to-send list (Data wire bytes + iface +
            // target) WHILE STILL HOLDING the peer lock. This
            // serializes pending-drain with any concurrent
            // close_peer mutation. We release the lock BEFORE
            // doing the sendmsg syscalls because (a) parking_lot
            // guards are !Send and can't cross await, (b) the
            // ordering guarantee (DATAs hit the wire before
            // any app-issued Close) is preserved: app code
            // doesn't see handle_helloack complete until this
            // function returns, and we send before returning.
            let pending = std::mem::take(&mut peer.pending);
            for ps in pending {
                if let SendAction::Data(bytes, target, iface) = build_data_packet(
                    self.local_peer_id,
                    peer,
                    &ps.payload,
                    ps.deadline_ms,
                    ps.coalesce_group,
                    mesh_next_hop,
                )? {
                    to_send.push((iface, bytes, target));
                }
            }
        }

        // Lock released — issue the syscalls.
        for (iface, bytes, target) in to_send.drain(..) {
            let n = bytes.len() as u64;
            self.ifaces.send_for(iface, &bytes, target).await?;
            flushed_packets += 1;
            flushed_bytes += n;
        }

        // Install CIDs for short-header send/recv now that the
        // peer lock is released. Safe to do after the flush —
        // CID lookups are only needed by subsequent send_data
        // calls, which can't race with handle_helloack's own
        // flush because that's finished.
        if let Some(key) = &cid_key_for_install {
            self.install_cids(peer_id, key, true).await;
        }

        if flushed_packets > 0 {
            self.metrics
                .packets_sent
                .fetch_add(flushed_packets, Ordering::Relaxed);
            self.metrics
                .bytes_sent
                .fetch_add(flushed_bytes, Ordering::Relaxed);
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
            let cutoff = std::time::Duration::from_secs(self.config.awaiting_data_timeout_secs);
            let now = Instant::now();
            let mut evicted: u64 = 0;
            // SEC.FIX.1: track (id, addr) for each peer we evict
            // so we can update the addr_index after the lock_all
            // guard drops. Storing addrs alongside ids — capturing
            // them later via lock_for would race against any
            // concurrent peer mutation.
            let mut to_remove: Vec<(PeerId, SocketAddr)> = Vec::new();

            {
                let mut peers = self.peers.lock_all().await;
                for peer in peers.iter_mut() {
                    // Reap stale peers in EITHER half-open state:
                    //   * AwaitingData = server saw HELLO, replied
                    //     HELLO_ACK, client never sent first DATA.
                    //     Original eviction case.
                    //   * AwaitingAck = client sent HELLO, server
                    //     never replied. Common when an outbound
                    //     federation link (--federate h2s://X@P)
                    //     points at a dead peer; without this the
                    //     peer entry sits in AwaitingAck for the
                    //     life of the process, retransmitting HELLO
                    //     and consuming both memory and a HELLO/s
                    //     of outbound traffic.
                    //
                    // For AwaitingAck we use `last_sent` from the
                    // AwaitingAck state itself for age, since
                    // session_epoch isn't set until the session
                    // reaches Established.
                    let stale_age = match &peer.handshake {
                        HandshakeState::AwaitingData { .. } => peer
                            .session_epoch
                            .map(|e| now.duration_since(e))
                            .unwrap_or_default(),
                        HandshakeState::AwaitingAck { last_sent, .. } => {
                            now.duration_since(*last_sent)
                        }
                        _ => continue,
                    };
                    if stale_age <= cutoff {
                        continue;
                    }
                    if peer.auto_registered {
                        to_remove.push((peer.id, peer.addr));
                    } else {
                        peer.handshake = HandshakeState::Pending;
                        peer.pending.clear();
                        peer.session_epoch = None;
                        evicted += 1;
                    }
                }
                for (id, _addr) in &to_remove {
                    if peers.remove(id).is_some() {
                        evicted += 1;
                    }
                }
            }
            // SEC.FIX.1 addr_index maintenance, after lock_all drops.
            for (id, addr) in &to_remove {
                self.peers.note_removed(id, *addr).await;
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
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;

        // Core handling under the peer lock. We collect any
        // side-effect packets that need to leave the socket
        // (a PathChallenge if a probe should fire, or flushed
        // pending DATA when a responder-direction peer
        // transitions to Established on the first inbound
        // DATA) into a local variable and emit them AFTER we
        // drop the lock.
        #[allow(clippy::type_complexity)]
        let (received, probe_to_send, just_established_after, flushed_pending, established_key): (
            Option<Received>,
            Option<(Vec<u8>, SocketAddr)>,
            bool,
            Vec<(Vec<u8>, SocketAddr, usize)>,
            Option<drift_core::Zeroizing<[u8; 32]>>,
        ) = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;

            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;

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
                                if let Ok(pt) =
                                    p.rx.open(header.seq, PacketType::Data as u8, &aad, body)
                                {
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
                self.metrics
                    .deadline_dropped
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    seq = header.seq,
                    deadline_ms = header.deadline_ms,
                    "dropped expired"
                );
                return Ok(None);
            }

            if !peer.coalesce_accept(header) {
                self.metrics
                    .coalesce_dropped
                    .fetch_add(1, Ordering::Relaxed);
                debug!(seq = header.seq, group = header.supersedes, "dropped stale");
                return Ok(None);
            }

            let mut just_established = false;
            let mut just_established_key: Option<drift_core::Zeroizing<[u8; 32]>> = None;
            let mut flushed: Vec<(Vec<u8>, SocketAddr, usize)> = Vec::new();
            if matches!(peer.handshake, HandshakeState::AwaitingData { .. }) {
                if let HandshakeState::AwaitingData {
                    tx,
                    rx,
                    key_bytes,
                    was_hybrid_pq,
                    ..
                } = std::mem::replace(&mut peer.handshake, HandshakeState::Pending)
                {
                    peer.handshake = HandshakeState::Established {
                        tx,
                        rx,
                        key_bytes: key_bytes.clone(),
                        prev: None,
                    };
                    self.metrics
                        .handshakes_completed
                        .fetch_add(1, Ordering::Relaxed);
                    if was_hybrid_pq {
                        self.metrics
                            .hybrid_pq_handshakes_completed
                            .fetch_add(1, Ordering::Relaxed);
                    }
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
                    let flush_mesh = if peer.via_mesh { Some(peer.addr) } else { None };
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
                    build_path_challenge_packet(self.local_peer_id, peer, &challenge)
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
                    federated_from: None,
                    federated_via_bridge: None,
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
            if let Err(e) = self
                .ifaces
                .send_for(self.iface_for(&peer_id).await, &bytes, addr)
                .await
            {
                debug!(error = %e, "PathChallenge send failed");
            } else {
                self.metrics
                    .path_probes_sent
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
        }

        Ok(received)
    }

    /// Received a `Close`. Verify the AEAD tag to prove the sender
    /// actually holds the session key, then drop the peer outright
    /// (auto-registered) or reset its handshake state (explicitly
    /// registered). Decrements `handshakes_inflight` if the peer
    /// was in AwaitingData when the close arrived.
    async fn handle_close(&self, header: &Header, full_packet: &[u8], body: &[u8]) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(PeerError::WrongDestination.into());
        }
        let peer_id = header.src_id;
        // Block-scoped peer-table mutation so the !Send
        // parking_lot guard ends lexically before any await.
        // Explicit `drop(peers)` is not enough for Rust's async
        // non-Send analysis — must close the lexical scope.
        let (disconnected_pub, was_awaiting_data, removed_addr) = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(PeerError::NotRegistered)?;
            let (_, rx) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;

            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            // AEAD-authenticated: attacker can't forge a Close
            // without the session key, so this is safe to act
            // on immediately.
            let _ = rx.open(header.seq, PacketType::Close as u8, &aad, body)?;

            // Capture the disconnecting peer's pubkey before we
            // mutate their entry — needed for PeerGone emission
            // below.
            let disconnected_pub = peer.peer_static_pub;
            // And their tracked addr, for the SEC.FIX.1
            // addr_index maintenance below.
            let peer_addr = peer.addr;

            let was_awaiting_data = matches!(peer.handshake, HandshakeState::AwaitingData { .. });
            let removed_addr = if peer.auto_registered {
                debug!(peer_id = ?peer_id, "peer closed; removing auto-registered entry");
                peers.remove(&peer_id);
                Some(peer_addr)
            } else {
                debug!(peer_id = ?peer_id, "peer closed; resetting explicit entry");
                peer.handshake = HandshakeState::Pending;
                peer.pending.clear();
                peer.session_epoch = None;
                peer.probing = None;
                None
            };
            (disconnected_pub, was_awaiting_data, removed_addr)
        };
        if let Some(addr) = removed_addr {
            self.peers.note_removed(&peer_id, addr).await;
        }
        if was_awaiting_data {
            self.metrics
                .handshakes_inflight
                .fetch_sub(1, Ordering::Relaxed);
        }

        // PeerGone emission: if the disconnected peer was a local
        // client (not a federation bridge) AND we had a presence
        // ticket for them (i.e., we'd been announcing them in our
        // FederationDirectory), tell every federation peer to
        // evict their cached route through us.
        let is_federation_bridge = self
            .federation_table
            .lock()
            .unwrap()
            .contains_key(&disconnected_pub);
        let had_presence_ticket = self
            .presence_tickets
            .lock()
            .unwrap()
            .remove(&disconnected_pub)
            .is_some();
        if !is_federation_bridge && had_presence_ticket {
            self.emit_peer_gone(&disconnected_pub).await;
        }
        Ok(())
    }

    /// Broadcast `PeerGone` to every federation peer. Called when
    /// a local client disconnects so federation peers can evict
    /// their cached route immediately rather than waiting on the
    /// next idempotent-set FederationDirectory announce (~7 s).
    async fn emit_peer_gone(&self, client_pub: &[u8; 32]) {
        let our_pub = self.identity.public_bytes();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let payload = find_peer::build_peer_gone(&find_peer::PeerGone {
            client_pub: *client_pub,
            emitted_at_ms: now_ms,
            bridge_pub: our_pub,
        });
        let fed_peers: Vec<PeerId> = self
            .federation_table
            .lock()
            .unwrap()
            .values()
            .copied()
            .collect();
        for peer in &fed_peers {
            if let Err(e) = self.send_typed(peer, PacketType::PeerGone, &payload).await {
                debug!(error = %e, ?peer, "PeerGone: failed to emit");
            }
        }
        debug!(
            client = ?client_pub,
            n = fed_peers.len(),
            "PeerGone: emitted to federation"
        );
    }
}

/// Build a `Close` wire packet: AEAD-sealed empty body, consuming
/// one tx seq slot.
fn build_close_packet(local_peer_id: PeerId, peer: &mut Peer) -> Result<Vec<u8>> {
    let seq = peer.next_seq_checked()?;
    let mut header = peer.make_header(PacketType::Close, seq, local_peer_id);
    header.payload_len = AUTH_TAG_LEN as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);
    let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
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
    let seq = peer.next_seq_checked()?;

    // Short-header fast path: eligible when
    //   1. We have an outgoing CID for the peer
    //   2. No mesh forwarding (direct session)
    //   3. No deadline or coalesce features active
    // This gives us 7-byte header + 16-byte tag = 23 bytes
    // vs the long header's 36 + 16 = 52 bytes.
    if let Some(cid) = out_cid {
        if mesh_next_hop.is_none() && deadline_ms == 0 && coalesce_group == 0 {
            let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;
            let wire = crate::short_header::encode_short(cid, seq, tx, payload)?;
            return Ok(SendAction::Data(wire, peer.addr, peer.interface_id));
        }
    }

    // Long header: full 36 bytes, all features available.
    let send_time_ms = peer.send_time_ms();
    let mut header =
        Header::new(PacketType::Data, seq, local_peer_id, peer.id).with_deadline(deadline_ms);
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

    let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;

    let mut wire = drift_core::pool::take_wire_buf(HEADER_LEN + payload.len() + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(seq, PacketType::Data as u8, &aad, payload, &mut wire)?;

    let target = mesh_next_hop.unwrap_or(peer.addr);
    Ok(SendAction::Data(wire, target, peer.interface_id))
}

/// Build a `PacketType::Federated` outbound wire packet. Mirrors
/// the long-header path of `build_data_packet_with_cid` but with
/// the type byte set to `Federated`, no deadline / coalesce / CID
/// (federation always uses the long header so the recv side has
/// the explicit src/dst IDs needed to thread the envelope back to
/// `process_incoming`'s Federated handler).
fn build_typed_packet(
    local_peer_id: PeerId,
    peer: &mut Peer,
    packet_type: PacketType,
    payload: &[u8],
) -> Result<SendAction> {
    let seq = peer.next_seq_checked()?;
    let send_time_ms = peer.send_time_ms();
    let mut header = Header::new(packet_type, seq, local_peer_id, peer.id);
    header.payload_len = payload.len() as u16;
    header.send_time_ms = send_time_ms;

    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);
    let aad = canonical_aad(&hbuf);

    let (tx, _) = peer.handshake.session().ok_or(PeerError::SessionNotReady)?;

    let mut wire = Vec::with_capacity(HEADER_LEN + payload.len() + AUTH_TAG_LEN);
    wire.extend_from_slice(&hbuf);
    tx.seal_into(seq, packet_type as u8, &aad, payload, &mut wire)?;

    Ok(SendAction::Data(wire, peer.addr, peer.interface_id))
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
#[allow(clippy::too_many_arguments)]
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
    iface_idx: usize,
    pq_client_ek: Option<&[u8]>,
) -> Result<(Vec<u8>, SocketAddr)> {
    let was_awaiting_data = matches!(peer.handshake, HandshakeState::AwaitingData { .. });
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

    // Phase PQ: if the client supplied an ML-KEM-768 encap key,
    // encapsulate it and weave the resulting shared secret into
    // the session-key derivation via `derive_hybrid_key`. The
    // ciphertext ships back in HELLO_ACK so the client can
    // decapsulate. Reject malformed ek (wrong length, decap
    // failure) with AuthFailed — same disposition as a bad
    // X25519 contribution.
    let (session_key_bytes, server_mlkem_ct) = if let Some(ek) = pq_client_ek {
        let (ct, mlkem_ss) =
            drift_core::pq::server_encapsulate(ek).ok_or(DriftError::AuthFailed)?;
        let key = drift_core::pq::derive_hybrid_key(
            &static_dh,
            &ephemeral_dh,
            &mlkem_ss,
            &client_nonce,
            &server_nonce,
        );
        (drift_core::Zeroizing::new(key), Some(ct))
    } else {
        (
            derive_session_key(&static_dh, &ephemeral_dh, &client_nonce, &server_nonce),
            None,
        )
    };
    // server_ephemeral drops here; StaticSecret's Zeroize impl clears it.
    drop(server_ephemeral);

    let tx = SessionKey::new(&session_key_bytes, Direction::Responder);
    let rx = SessionKey::new(&session_key_bytes, Direction::Initiator);

    peer.reset_seq();
    peer.coalesce_state.clear();
    peer.coalesce_order.clear();
    peer.mark_session_start();
    peer.addr = src;
    // Keep `peer.interface_id` in sync with the interface the
    // fresh handshake actually arrived on. Without this, an
    // existing peer who reconnects from a new adapter (client
    // process exited, reconnected from a new TCP ephemeral port
    // or switched medium) would leave the outbound interface_id
    // pointing at the previous — now-dead — interface, and
    // every reply from us would be silently dropped at
    // send_for while the inbound path worked fine.
    peer.interface_id = iface_idx;
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

    let mut ack_header = Header::new(PacketType::HelloAck, 1, local_peer_id, client_peer_id)
        .with_hop_ttl(DEFAULT_MESH_TTL);
    if server_mlkem_ct.is_some() {
        ack_header.flags |= drift_core::header::FLAG_PQ_HYBRID;
    }
    let ack_payload_len =
        HELLO_ACK_PAYLOAD_LEN + server_mlkem_ct.as_ref().map(|ct| ct.len()).unwrap_or(0);
    ack_header.payload_len = ack_payload_len as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    ack_header.encode(&mut hbuf);

    let canon = canonical_aad(&hbuf);
    // AAD covers header + server_ephemeral_pub + server_nonce +
    // (when hybrid) server_mlkem_ct so that tampering with any
    // of them fails the tag. The ML-KEM ciphertext is plaintext
    // on the wire — it has to be, the client needs to
    // decapsulate it — but its integrity is bound by the tag
    // derived from the hybrid key, so a man-in-the-middle who
    // edits the ct flips the client's derived key and the AEAD
    // open() fails cleanly.
    let mut aad = Vec::with_capacity(
        HEADER_LEN
            + STATIC_KEY_LEN
            + NONCE_LEN
            + server_mlkem_ct.as_ref().map(|ct| ct.len()).unwrap_or(0),
    );
    aad.extend_from_slice(&canon);
    aad.extend_from_slice(&server_ephemeral_pub);
    aad.extend_from_slice(&server_nonce);
    if let Some(ct) = &server_mlkem_ct {
        aad.extend_from_slice(ct);
    }
    let tag = tx.seal(1, PacketType::HelloAck as u8, &aad, b"")?;

    let mut wire = Vec::with_capacity(HEADER_LEN + ack_payload_len);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&server_ephemeral_pub);
    wire.extend_from_slice(&server_nonce);
    wire.extend_from_slice(&tag);
    if let Some(ct) = &server_mlkem_ct {
        wire.extend_from_slice(ct);
    }

    peer.handshake = HandshakeState::AwaitingData {
        tx: tx.clone(),
        rx: rx.clone(),
        key_bytes: session_key_bytes,
        cached_ack: wire.clone(),
        cached_client_nonce: client_nonce,
        was_hybrid_pq: server_mlkem_ct.is_some(),
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
#[allow(clippy::too_many_arguments)]
fn build_hello_wire(
    local_peer_id: PeerId,
    dst_id: PeerId,
    identity: &Identity,
    ephemeral_pub: [u8; STATIC_KEY_LEN],
    client_nonce: [u8; NONCE_LEN],
    mesh: bool,
    cookie: Option<&[u8; COOKIE_BLOB_LEN]>,
    pq_ek: Option<&[u8]>,
) -> Vec<u8> {
    let mut header = Header::new(PacketType::Hello, 0, local_peer_id, dst_id);
    if mesh {
        header = header.with_hop_ttl(DEFAULT_MESH_TTL);
    }
    if pq_ek.is_some() {
        header.flags |= drift_core::header::FLAG_PQ_HYBRID;
    }
    let base_len = if cookie.is_some() {
        HELLO_WITH_COOKIE_LEN
    } else {
        HELLO_PAYLOAD_LEN
    };
    let payload_len = base_len + pq_ek.map(|ek| ek.len()).unwrap_or(0);
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
    if let Some(ek) = pq_ek {
        wire.extend_from_slice(ek);
    }
    wire
}

/// Rebuild a `ResumeHello` wire packet for the retransmit
/// loop. Mirrors `send_resume_hello` but skips the peer-table
/// mutation: the `AwaitingAck` state (ephemeral + client_nonce)
/// and the `pending_resumption` (ticket_id + psk) already live
/// on the peer from the first send — we're just re-emitting
/// the same bytes after a timeout.
fn build_resume_hello_wire(
    local_peer_id: PeerId,
    dst_id: PeerId,
    client_eph_pub: [u8; STATIC_KEY_LEN],
    client_nonce: [u8; NONCE_LEN],
    ticket_id: [u8; crate::transport::resumption::TICKET_ID_LEN],
    mesh: bool,
) -> Vec<u8> {
    use crate::transport::resumption::RESUME_HELLO_BODY_LEN;
    let mut header = Header::new(PacketType::ResumeHello, 0, local_peer_id, dst_id);
    if mesh {
        header = header.with_hop_ttl(DEFAULT_MESH_TTL);
    }
    header.payload_len = RESUME_HELLO_BODY_LEN as u16;
    let mut hbuf = [0u8; HEADER_LEN];
    header.encode(&mut hbuf);

    let mut wire = Vec::with_capacity(HEADER_LEN + RESUME_HELLO_BODY_LEN);
    wire.extend_from_slice(&hbuf);
    wire.extend_from_slice(&ticket_id);
    wire.extend_from_slice(&client_eph_pub);
    wire.extend_from_slice(&client_nonce);
    wire
}

fn build_hello(
    local_peer_id: PeerId,
    peer: &mut Peer,
    identity: &Identity,
    mesh_next_hop: Option<SocketAddr>,
    hybrid_pq: bool,
) -> SendAction {
    // Mesh-only peer with no route yet: peer.addr is the
    // 0.0.0.0:0 placeholder that `add_mesh_peer` set, and no
    // mesh route has been learned via beacons. Sending a HELLO
    // to 0.0.0.0:0 would just fail with EINVAL on every retry.
    // Stay in Pending; a later send_data will retry once the
    // mesh route table has an entry.
    let target_pre = mesh_next_hop.unwrap_or(peer.addr);
    if target_pre.ip().is_unspecified() {
        return SendAction::Queued;
    }

    let client_nonce = random_nonce();
    let ephemeral = Identity::generate();
    let ephemeral_pub = ephemeral.public_bytes();
    // Phase PQ: generate an ML-KEM-768 keypair when the
    // hybrid handshake is enabled. The ek bytes get embedded
    // in the HELLO; the dk stays in the AwaitingAck state so
    // we can decapsulate the server's ciphertext on
    // HELLO_ACK arrival.
    let pq = if hybrid_pq {
        Some(drift_core::pq::client_generate_keypair())
    } else {
        None
    };
    let wire = build_hello_wire(
        local_peer_id,
        peer.id,
        identity,
        ephemeral_pub,
        client_nonce,
        mesh_next_hop.is_some(),
        None,
        pq.as_ref().map(|(ek, _)| ek.as_slice()),
    );
    peer.handshake = HandshakeState::AwaitingAck {
        client_nonce,
        ephemeral,
        last_sent: Instant::now(),
        attempts: 1,
        cookie: None,
        pq,
    };
    let target = mesh_next_hop.unwrap_or(peer.addr);
    SendAction::Hello(wire, target, peer.interface_id)
}

enum SendAction {
    Data(Vec<u8>, SocketAddr, usize),
    Hello(Vec<u8>, SocketAddr, usize),
    Queued,
}
