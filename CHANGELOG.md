# Changelog

All notable changes to DRIFT, the identity-based transport.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each entry includes the merged-PR number so consumers can find the
diff, and groups changes by the user-visible surface they affect
(Bridge, Federation, Wires, Tooling, …) rather than by internal
crate. A change that touches multiple surfaces appears under each.

## [Unreleased]

### Bridge / Federation

- **iroh is now the default federation wire** for `drift bridge`. The
  `--federate` allowlist is reordered to put `iroh://` / `iroh-n0://`
  first; h2s / h2 / webtransport remain preferred fallbacks. UDP/TCP
  federation still needs `--allow-legacy-federation`. (#13)
- **Fixed federation-directory propagation gap.** After
  `connect_federate` succeeded, bridges sat in `HandshakeState::Pending`
  with no traffic until the 2-second keep-alive ticker fired — but the
  FederationDirectory announcer started at +1 s and silently dropped its
  first announce. Bridges now send a one-byte warmup right after
  `connect_federate` to establish the session before the directory
  loop runs. Affects every wire, not just iroh. (#18)
- **Bridge spec parsing handles URLs with internal `@`.** The
  `--bridge` / `--peer` / `--target-bridge` parsers used `split_once('@')`
  which broke for `iroh://<id>@<host:port>@<pub>` shapes. Switched to
  `rsplit_once('@')`; works for both legacy and new URL formats. (#14)

### Wires — iroh

- **`iroh-n0://` scheme** added (N0 preset with PKARR DNS discovery
  + n0 relay fallback). Privacy trade-off — bridge pubkey gets
  published to `dns.iroh.link`; loud warn at bind time. (#6)
- **Iroh identity auto-binds to bridge identity** unless
  `DRIFT_IROH_SECRET_HEX` is set. Same 32-byte secret feeds both
  curves (X25519 for DRIFT, ed25519 for iroh); the iroh `EndpointId`
  is logged at bind so operators can share it. (#7)
- **Pre-bind sysctl check for `net.core.rmem_max`.** Bridge refuses
  to bind iroh listeners if the kernel UDP receive buffer is below
  4 MiB; warns if below the 128 MiB recommended value. Surfaces a
  silent-drop failure mode that previously needed K-large traffic
  to hit. (#8)
- **Map-based peer-addr dedup.** Replaced SipHash-truncated
  `EndpointId → SocketAddr` synthesis (24-bit collision window
  at ~4096 endpoints) with a `HashMap<EndpointId, SocketAddr>`
  that allocates 192.0.2.0/24 slots sequentially. ~16M collision-
  free assignments. (#12)
- **500 ms per-path keep-alive** in `QuicTransportConfig` so the
  Backup path stays alive through iroh's 15 s `PATH_MAX_IDLE_TIMEOUT`
  even when iroh's `biased_rtt_path_selector` switches selection
  to an ephemeral NAT-traversal path. Fixes cross-host LAN federation
  stability — pre-fix the connection died at 30 s–3 min, post-fix
  the 30-minute soak runs clean. (#17)
- **Three regression tests** for the two bugs we hit in K=17:
  MTU floor (`INITIAL_MTU >= 1400`), preset-mismatch detection,
  and `SHARED_ENDPOINT` sharing across binds. Each fault-injected
  to confirm it catches the bug it's named for. (#9)
- **Iroh pinned exactly** at `=1.0.0-rc.1` with an inline upgrade
  checklist in `Cargo.toml`. Cargo.lock is gitignored, so the
  spec is the only thing preventing a silent rc.2 / 1.0 upgrade.
  (#11)

### Tooling

- **K=17 long-soak monitor** (`drift-bench/scripts/k17-soak.sh`)
  watches an already-up federation for 24 h, snapshots RSS / FDs /
  loopback bytes / auth_failures every 5 min, emits a TSV + a
  PASS/WARN/FAIL verdict. Catches slow leaks that 5-min sweeps miss.
  (#10)
- **Soak script busybox-compatible** so it runs on the router-bridge
  itself: `MIN_PIDS` env gate (default 17, single-bridge soaks set 2),
  for-loop pidfile count instead of `find -maxdepth`, parameter-
  expansion split instead of `read < <(...)` process substitution.
  (#15)

### API surface

- **Phase 5 of public-API lock-down: small crates bundle (33
  items).** drift-bench, drift-wormhole, drift-mosh, drift-http,
  drift-git audited. The five small crates have zero
  cross-workspace consumers (nothing depends on them as a lib),
  so every `pub` item that isn't used by the crate's own bins
  is a dead leak. Bin-only crates (drift-bench, drift-wormhole)
  had every top-level `pub` fn/struct/enum/const demoted to
  `pub(crate)` — 16 + 12 = 28 items. lib+bin crates
  (drift-mosh, drift-http, drift-git) only got items their own
  bins don't import demoted: drift-mosh = 0 (every pub item is
  consumed by drift-mosh-server/client/drift_mosh bins),
  drift-http = 2 (`identity::config_dir`, `identity::load_default`),
  drift-git = 3 (`PROTO_TAG`, `FRAME_DATA`, `FRAME_EOD` —
  unused frame-type constants).
- **Phase 4 of public-API lock-down: drift-core sweep.** Three
  changes: (1) the `fec` module — Reed-Solomon-over-XOR forward
  error correction that had been dead code in the workspace
  since before slice 1 — is removed entirely (no consumer
  anywhere); (2) the `time` module is demoted to `pub(crate)`
  with its `SystemTime` + `UNIX_EPOCH` exports dropped (only
  `Duration` and `Instant` are used inside drift-core); (3) the
  top-level convenience re-exports in `drift-core/src/lib.rs`
  are trimmed from 13 items to 4 (`derive_peer_id`, `PeerId`,
  `Identity`, `Zeroizing`) — `Direction`, `SessionKey`,
  `KEY_LEN`, `PEER_ID_LEN`, `DriftError`, `Result`, `Header`,
  `PacketType`, `HEADER_LEN`, `STATIC_KEY_LEN` had zero external
  consumers through `drift_core::*` and remain reachable via
  their module paths. The drift crate's `lib.rs` was updated to
  re-export those from module paths instead.
- **Phase 3 of public-API lock-down: 9 items removed from the
  top-level `drift::*` re-export surface.** This phase audits
  `drift/src/lib.rs` itself — the *intentional* public surface
  — and trims items with zero external consumers through the
  `drift::*` path. Removed: three module re-exports (`drift::fec`,
  `drift::pq`, `drift::time`) and six top-level convenience
  re-exports (`drift::KEY_LEN`, `drift::PEER_ID_LEN`,
  `drift::STATIC_KEY_LEN`, `drift::Metrics`, `drift::Received`,
  `drift::FindPeerMode`). Every removed item remains reachable
  via its containing module's path (e.g. `drift::crypto::KEY_LEN`,
  `drift::transport::Metrics`, `drift_core::time`). One internal
  consumer of `drift::Received` (in `drift-ffi`) was updated to
  use `drift::transport::Received` directly.
- **Phase 2 of public-API lock-down: 21 items in
  `drift::{io, streams, wire_*}` demoted to `pub(crate)`.**
  Continues the lock-down work from PR #35. Audit method
  unchanged: grep workspace for cross-crate imports, keep
  anything externally consumed (drift-git, drift-http,
  drift-wormhole, drift-vpn, tests, examples, fuzz targets),
  demote everything else. Items locked down:
  `streams::StreamId` (only `Stream`+`StreamManager` are
  externally consumed via drift-http/drift-git/drift-wormhole);
  `io::{InterfaceSet, UdpListenerIO, TcpListenerIO, WsListenerIO,
  TlsPacketIO, TlsListenerIO, ListenerFactory, ConnectorFactory,
  SchemeRegistration, registered_schemes}` (10 items — apps use
  `make_listener`/`make_connector` via URL strings, not the
  concrete types);
  `wire_dns::{MAX_FRAG_PAYLOAD, DnsListenerIO}` (the four
  fragmentation helpers stayed `pub` for the `doh_smoke`
  example);
  `wire_h2::{H2StreamPacketIO, H2ListenerIO}`,
  `wire_http::{HttpPacketIO, HttpListenerIO, HttpClientPacketIO}`,
  `wire_onion::OnionPacketIO`,
  `wire_webrtc::WebRtcListenerIO`,
  `wire_webtransport::WebTransportListenerIO` (concrete adapter
  types reachable through the scheme registry). Three
  `InterfaceSet` helpers (`live_count`, `is_empty`,
  `send_default`) and one `TcpListenerIO::set_per_ip_cap` are
  marked `#[allow(dead_code)]` rather than removed — they're
  polished internal-API surface that downstream code may want
  to reach for.
- **Phase 1 of public-API lock-down: `drift::transport::*`
  re-export shrunk by 37 items.** Following the design memo at
  `docs/API_LOCKDOWN_DESIGN.md`, this PR removes items from the
  `drift::transport::*` public surface that no external consumer
  (tests, examples, fuzz, app crates) actually uses. Items
  remain reachable from sibling modules inside the
  `transport` module via direct paths (`federated::Foo`,
  `find_peer::Foo`, etc.); they just no longer leak through the
  crate boundary. Removed: 9 federated items
  (`build_directory_v3`, `decode_ticket`, `parse_directory_v3`,
  `parse_directory_v4`, `ticket_signed_msg`, `verify_ticket`,
  `FederatedEnvelope`, `MAX_DIRECTORY_ENTRIES_V4`, `TICKET_LEN`),
  all 24 `find_peer` items (none had external consumers),
  `mesh::RouteEntry`, and 3 resumption items (`ClientTicket`,
  `EXPORT_BLOB_LEN`, `TICKET_DEFAULT_TTL` — apps use
  `Transport::{export,import}_resumption_ticket` which take raw
  `Vec<u8>` blobs). No behavior change; downstream apps using
  the documented `drift::Transport` API are unaffected.

### Error types

- **Slice 8: final umbrella collapse.** Completes the structured-
  error-types arc started in slice 1. Adds `Codec(CodecError)`
  and `Session(SessionError)` wrapper variants to `DriftError`
  via `#[from]`, migrates the 15 remaining
  `DriftError::PacketTooShort` produce sites and 2 `AuthFailed`
  sites in `drift-core::crypto` (`SessionKey::open` and friends)
  to typed sub-error variants. Drops 9 dead flat variants:
  `PacketTooShort`, `UnknownType`, `UnsupportedVersion`,
  `LengthMismatch`, `DecodeError` (all → `Codec(_)`), `AuthFailed`
  (→ `Crypto(_)`), `QueueFull`, `HandshakeExhausted`,
  `SessionExhausted` (all → `Session(_)`). After this slice
  `DriftError` consists of exactly four sub-error wrappers
  (`Codec`, `Crypto`, `Session`, `Peer`) plus four cross-layer
  leaves (`Io`, `DeadlineExpired`, `PeerIdCollision`,
  `PayloadTooLarge`). Five test assertions across
  `pending_queue_cap.rs`, `resource_limits.rs`, `seq_ceiling.rs`,
  `resumption.rs` updated from flat-variant matches to wrapper
  destructuring (`DriftError::Session(SessionError::QueueFull)`,
  `DriftError::Codec(CodecError::Malformed)`, etc.). The two
  recv-loop metric arms in `run_recv_loop_for` migrated to match
  `DriftError::Crypto(CryptoError::AeadAuthFailed)` instead of
  the now-gone flat `AuthFailed`. `drift-ffi::map_err` updated
  to destructure the wrappers. Public API impact: any external
  consumer matching on the flat variants must switch to
  wrapper-destructuring; the result codes from `drift-ffi` are
  unchanged.
- **Slice 7: AuthFailed migration to typed sub-error variants.**
  Migrates the 31 remaining `DriftError::AuthFailed` produce
  sites to typed sub-errors and introduces three new variants
  to express semantics the existing types didn't cover:
  `CryptoError::KeyExchangeFailed` (X25519 low-order pubkey,
  ML-KEM encap/decap, PQ posture mismatch),
  `PeerError::TicketExpired` (presence + resumption ticket TTL
  exhaustion), and `PeerError::SenderNotInFederationTable`
  (incoming federation packet from a non-allowlisted bridge).
  Distribution: ~14 sites → `CryptoError` (KeyExchangeFailed
  ×9, SignatureInvalid ×5), 1 site → `CryptoError::AeadAuthFailed`
  via the bulk-replaced `.ok_or` chains, 11 sites → `PeerError`
  (SenderNotInFederationTable ×6, TicketExpired ×3,
  ResumptionTicketNotFound ×2), 1 site → `CodecError::Malformed`
  (malformed ticket blob), plus the `rotation::verify_against`
  identity-mismatch case → `CryptoError::SignatureInvalid`.
  Two consumer match arms in `run_recv_loop_for` updated to
  bump `auth_failures` on `DriftError::Crypto(_)` (covers all
  crypto-layer failures: signature, AEAD, key exchange) instead
  of the legacy flat `AuthFailed`. Two resumption tests updated
  to assert on the new typed variants. The flat `DriftError::AuthFailed`
  variant is now producerless and will be dropped in a final
  slice along with the other dead flat variants.
- **Slice 6: mechanical migration of session + codec flat
  variant producers.** Migrates the 32 remaining straightforward
  flat-variant produce sites: 28 × `DriftError::DecodeError` in
  `find_peer.rs` / `federated.rs` / `mod.rs` → `CodecError::Malformed`
  (wrapped into `DriftError::Codec(_)` via `?`), 3 × `DriftError::QueueFull`
  in `path.rs` and `mod.rs` → `SessionError::QueueFull`, 1 ×
  `DriftError::HandshakeExhausted` in `mod.rs` →
  `SessionError::HandshakeExhausted`. Public behavior unchanged
  because `From<CodecError>` and `From<SessionError>` still map
  to the legacy flat variants — the migration is purely a
  site-level annotation that each producer declares its protocol
  layer. After this slice, the only remaining flat-variant
  producer category is the 30 `DriftError::AuthFailed` sites,
  which need per-site analysis (some are crypto-layer, some are
  app-level federation authn, some are resumption-ticket
  validation) and ship in a follow-up slice.
- **Slice 5: umbrella collapse (first step).** Drops the flat
  `DriftError::UnknownPeer` and `DriftError::Replay(u32)`
  variants (zero direct producers remained after slices 2 and 4)
  and replaces them with `Crypto(CryptoError)` and
  `Peer(PeerError)` wrapper variants using `#[from]`. The
  `?` conversion now produces the wrapper variant directly, so
  matching on the inner enum (`DriftError::Peer(PeerError::NotRegistered)`
  etc.) gives callers finer-grained handling than the old flat
  umbrella. Public-API impact: three consumer match arms
  updated in `transport::run_recv_loop_for` (the
  `unknown_peer_drops` and `replays_caught` metric branches),
  `drift-ffi::map_err` (the `DRIFT_ERR_UNKNOWN_PEER` mapping
  now matches `Peer(_)`), and `tests/graceful_migration.rs`
  (assertion updated to
  `matches!(err, DriftError::Peer(PeerError::NotRegistered))`).
  The flat `AuthFailed`, `HandshakeExhausted`, `QueueFull`,
  and `DecodeError` variants still exist because 30+ unmigrated
  direct producers still emit them; follow-up slices migrate
  those producers and drop the last flat variants.
- **`multipath::probe_path` no longer misuses `UnknownPeer`.**
  When a path-probe deadline expired with no response,
  `MultipathClient::probe_path` returned
  `DriftError::UnknownPeer` — but the peer is perfectly well
  known; the *path* timed out. Returns `DriftError::DeadlineExpired`
  now, matching the actual condition. The only consumer
  (`probe_all`'s `.is_ok()` check) is unaffected; direct callers
  of `probe_path` who were matching on the variant were
  observing a misnamed error and now see the correct one.
  Flagged during the slice 4 peer-error sub-series as a real
  misuse rather than a typed-error refactor.
- **Slice 4f: peer-layer migration in `drift::transport::mod`.**
  Migrates the 65 produce sites of `DriftError::UnknownPeer` in
  the transport core module to the appropriate `PeerError`
  variants. Distribution:
  32 × `NotRegistered` (peer-table lookups, bridge-pubkey
  lookups, CID-map lookup, auto-register max_peers cap, and the
  `!accept_any_peer` reject branch in `handle_hello`),
  16 × `SessionNotReady` (`peer.handshake.session()` derive
  misses across every recv/send path, plus the
  `!is_ready_for_data()` guard in `close_peer`),
  12 × `WrongDestination` (incoming dst_id mismatch in
  `handle_*` for rekey, federated, federation_directory,
  presence_ticket, find_peer, find_peer_hashed, peer_here,
  peer_gone, hello, data, close),
  3 × `SessionNotEstablished` (rekey's stricter
  `HandshakeState::Established` match arms in `rekey` and
  `handle_rekey_request`, plus the `send_typed` Established
  check),
  2 × `ResumptionTicketNotFound` (the `export_resumption_ticket`
  store-miss and expired-ticket branches).
  The single `DriftError::UnknownPeer` *consumer* (match arm in
  `run_recv_loop_for` for the `unknown_peer_drops` metric) is
  intentionally left alone — `From<PeerError>` preserves the
  umbrella, so the metric still triggers correctly. Public
  behavior unchanged. Concludes the per-file 4b–4f sub-series;
  slice 5 can now collapse `DriftError::UnknownPeer` since no
  returner is left.
- **Slice 4e: peer-layer migration in `resumption.rs`.** Migrates
  the 13 produce sites of `DriftError::UnknownPeer` in
  `drift::transport::resumption` (1-RTT session resumption via
  PSK) to the appropriate `PeerError` variants:
  6 × `NotRegistered` (peer-table lookups across
  `issue_resumption_ticket`, `send_resume_hello`,
  `handle_resume_hello`, `handle_resume_ack`),
  2 × `SessionNotReady` (session-key derive misses in
  `issue_resumption_ticket` tx side and `handle_resumption_ticket`
  rx side),
  2 × `WrongDestination` (incoming ResumptionTicket / ResumeHello
  addressed to a different peer id),
  2 × `ResumptionTicketNotFound` (client ticket store miss AND
  expired-ticket-evicted in `send_resume_hello` — the first slice
  4 sites to use this variant, which `PeerError` was designed
  for in 4a),
  1 × `SessionNotEstablished` (the stricter Established-state
  guard in `issue_resumption_ticket` that needs `key_bytes`).
  The 7 `DriftError::PacketTooShort` / `DriftError::AuthFailed`
  sites (codec / crypto layer) stay on the umbrella.
- **Slice 4d: peer-layer migration in `path.rs`.** Migrates the 10
  produce sites of `DriftError::UnknownPeer` in
  `drift::transport::path` (path-validation challenge/response for
  peer migration) to the appropriate `PeerError` variants:
  4 × `SessionNotReady` (session-key lookups in
  `build_path_challenge_packet`, `build_path_response_packet`,
  `handle_path_challenge`, `handle_path_response`),
  3 × `NotRegistered` (peer-table lookup misses in
  `probe_candidate_path_via`, `handle_path_challenge`,
  `handle_path_response`),
  2 × `WrongDestination` (Challenge/Response addressed to a
  different peer id),
  1 × `SessionNotEstablished` (the stricter
  `!matches!(peer.handshake, HandshakeState::Established { .. })`
  guard in `probe_candidate_path_via` — first slice-4 site to use
  this variant).
  The `DriftError::QueueFull` site (probe to a different in-flight
  candidate) and `DriftError::PacketTooShort` site (codec) stay
  on the umbrella. `From<PeerError>` preserves the public error
  surface.
- **Slice 4c: peer-layer migration in `rtt.rs`.** Migrates the 8
  produce sites of `DriftError::UnknownPeer` in
  `drift::transport::rtt` (RTT-probe Ping/Pong handling) to the
  appropriate `PeerError` variants: 4 × `SessionNotReady`
  (session-key lookup misses in `emit_pings`, `handle_ping` for
  both rx and tx, `handle_pong`), 2 × `WrongDestination`
  (Ping/Pong addressed to a different peer id), 2 ×
  `NotRegistered` (incoming src_id absent from the peer table).
  `From<PeerError>` preserves the umbrella mapping so the public
  error surface is unchanged. The `DriftError::PacketTooShort`
  site in `handle_ping` (codec-layer) remains untouched.
- **Slice 4b: peer-layer migration in `mesh.rs`.** Migrates the 4
  produce sites of `DriftError::UnknownPeer` in `drift::transport::mesh`
  to the appropriate `PeerError` variants: BEACON emit's
  `peer.handshake.session()` failure → `SessionNotReady`,
  BEACON ingest's dst_id mismatch → `WrongDestination`,
  BEACON ingest's peer-table lookup miss → `NotRegistered`,
  BEACON ingest's session-key derive miss → `SessionNotReady`.
  Each call site now declares which of the five semantic
  conditions it represents instead of collapsing into the flat
  `UnknownPeer`. Public behavior unchanged (`From<PeerError>`
  preserves the umbrella mapping).
- **Slice 4a: peer / federation (start of sub-series).** Introduces
  `drift_core::error::PeerError` to split what used to be the flat
  `DriftError::UnknownPeer` umbrella into five distinct semantic
  conditions that produce sites in `drift::transport::*` were
  silently conflating: `NotRegistered` (peer not in table),
  `SessionNotReady` (peer in table, handshake hasn't derived
  keys), `SessionNotEstablished` (keys derived but not fully
  Established — stricter), `WrongDestination` (incoming packet's
  dst_id isn't us — distinct from "unknown peer" because here
  it's the *destination* that's wrong, not the source), and
  `ResumptionTicketNotFound` (client ticket store miss / expired).
  This PR establishes the type and migrates `cookies.rs` (1 site,
  the `WrongDestination` case). There are ~102 produce sites
  across 7 files in total; subsequent slices 4b–4f migrate the
  remaining files one at a time (mesh.rs, rtt.rs, path.rs,
  resumption.rs, mod.rs). `From<PeerError> for DriftError`
  collapses every variant back to `DriftError::UnknownPeer` for
  back-compat; slice 5 will eventually drop the flat variant.
- **Slice 3: session lifecycle.** Introduces
  `drift_core::error::SessionError` with the three terminal
  session states the flat `DriftError` covered separately:
  `SessionExhausted` (seq counter at AEAD-nonce safety ceiling),
  `HandshakeExhausted` (retry budget gone), `QueueFull` (pending-
  send queue at capacity). `Peer::next_seq_checked` — the only
  pure-session-lifecycle producer in drift-core — moves from
  `Option<u32>` to `Result<u32, SessionError>` so the ~9 transport
  call sites that previously did
  `.next_seq_checked().ok_or(DriftError::SessionExhausted)?`
  collapse to plain `.next_seq_checked()?`. `From<SessionError>
  for DriftError` keeps every transitive caller working unchanged
  — `cargo test` confirms `seq_ceiling.rs`'s
  `matches!(err, DriftError::SessionExhausted)` assertion still
  passes. `HandshakeExhausted` and `QueueFull` are still produced
  inline inside cross-layer transport sends (`drift::transport`)
  and stay on `DriftError` until later slices split those sends.
- **Slice 1 of layered per-protocol-concern error types.** Introduces
  `drift_core::error::CodecError` for wire-codec failures alongside
  the existing flat `DriftError`. Pure-codec functions
  (`PacketType::from_u8`, `Header::decode`, `decode_short`,
  `RotationAnnounce::decode`) now return `Result<T, CodecError>`
  instead of `Result<T, DriftError>`. `From<CodecError> for DriftError`
  preserves backward compat: every transitive caller using `?`
  works unchanged. Callers wanting layer-specific handling can
  now match on `CodecError` variants directly instead of
  reasoning about which `DriftError` variants a parser can produce.
  Slice 2 (crypto layer / `CryptoError`), slice 3 (session
  lifecycle / `SessionError`), slice 4 (peer + federation /
  `PeerError`), and slice 5 (consolidate `DriftError` to umbrella-
  only) ship as their own PRs.
- **Slice 2: crypto layer.** Introduces `drift_core::error::CryptoError`
  with three distinct variants where the flat `DriftError` had two:
  `AeadAuthFailed` and `SignatureInvalid` (both used to collapse
  into `DriftError::AuthFailed`) plus `Replay { seq }` (previously
  the tuple `DriftError::Replay(u32)`). Pure-crypto functions
  (`xeddsa::verify`, `Session::check_and_update_replay`) now return
  `Result<(), CryptoError>` instead of `Result<(), DriftError>`,
  so the type signature documents that they can only fail with a
  crypto-layer reason — not codec, not IO. Callers that handle
  XEdDSA-signature failure and AEAD-tag-mismatch differently no
  longer have to string-match on `Display` output. `From<CryptoError>
  for DriftError` preserves the legacy umbrella mapping, so every
  transitive caller using `?` keeps working unchanged. `SessionKey::open`
  (which produces both a codec error and an AEAD-auth error from
  the same call site) and `rotation::verify_against` (which mixes
  identity-mismatch and signature-verify) intentionally stay on
  `DriftError` until a later slice splits them into composable
  single-concern primitives.

### drift-vpn

- **`resolve_endpoint` now parses iroh:// URLs.** Strips the leading
  `<endpoint_id>@` before parsing host:port, errors cleanly on
  iroh-n0:// (which has no host:port — discovery resolves at dial
  time). Low practical impact (the actual dial path goes through
  `Transport::connect_federate` which already handles iroh), but
  closes the placeholder-address fallback bug. (#16)

## How to read this file

- **Unreleased** lists changes that have landed on `main` but
  haven't been tagged into a versioned release yet.
- Versioned sections (`## [0.x.y]`) list changes between releases
  in reverse chronological order.
- Each entry leads with the user-visible effect, then explains the
  rationale or the bug being fixed. PR numbers in parens link to
  the diff + the original discussion.

## How to add to this file

When you land a PR with a user-visible change (anything an
operator would notice — bug fixes, default changes, new features,
behavior changes, CLI surface), add a bullet to `## [Unreleased]`
under the appropriate section. Don't add entries for purely
internal refactors that don't change behavior.

If a category isn't listed under Unreleased yet, add it. Common
sections: **Bridge / Federation**, **Wires — &lt;name&gt;**,
**Tooling**, **drift-vpn**, **drift-mosh**, **drift-wormhole**,
**drift-http**, **drift-git**, **Security**, **Breaking**.

Breaking changes (anything that would force a downstream user to
adjust their config, code, or deployment) go under a top-level
`### Breaking` section. Include the migration path inline.
