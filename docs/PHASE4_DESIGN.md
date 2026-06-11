# Phase 4: `drift::Transport` consumes `drift-proto`

**Status: COMPLETE. Slices 1–2, 3a/3b/3b-decrypt, 3c-ack, 3c-regen, 3c-cookie, and 4 (perf certification) are all done — the DATA path, BOTH handshake crypto cores (client `process_hello_ack` + server `regenerate_session`), and the cookie validate/challenge primitives are single-source in `drift_proto`. Slice 4 found NO dead code to delete: the per-slice strangler-fig discipline removed each old block inline as the transport swapped over, so deletion happened continuously rather than as a deferred big-bang. The transport's remaining per-peer functions are thin wrappers that hold genuinely driver-specific side effects (sharded locks, the `handshakes_inflight` gauge, `SendAction` wrapping, federation envelope assembly) — that is the intended end state, not residue. The in-`lock_all` HELLO orchestration (dual-init / cached-ACK / auto-register) stays driver-specific by design — it is sharding concurrency, not protocol. Perf gate (pre-phase-4 `875e1f8` → post `020c59a`): cross-wire loopback throughput flat (UDP −0.12%, h2s/iroh within jitter), criterion AEAD/header micro flat-to-faster. The full-fleet K=17 soak is the one remaining optional certification; its marginal value is low here since phase 4 added no allocations and made no federation-path changes.**

Phase 4 is the last and highest-risk phase of the sans-IO arc
(`SANSIO_DESIGN.md`). Phases 1–3 + 5 already delivered the
portability payoff: the engine runs the full protocol, and
drift-wasm + drift-redox adopted it. Phase 4 is purely about
**single source of truth** — eliminating the duplicated protocol
logic that still lives in `transport/mod.rs` so future protocol
changes happen in one place, not two kept-in-sync copies.

Because the target is frozen, battle-tested, deployed code (the
router bridge and the LXC fleet run it), phase 4 is done in small,
individually-safe slices with explicit safety proofs — never a
big-bang rewrite.

## The hard part: the concurrency mismatch

`drift_proto::Endpoint` is a single `&mut self` state machine: one
peer map, driven by one caller, no internal locking. That's ideal
for a browser tab, a Redox shell, or a CLI client.

`drift::Transport` shards its peer table across many locks
(`peer_shards.rs`) precisely so a **bridge** handling hundreds of
peers doesn't serialize every packet on one mutex. A naive "wrap a
single `Endpoint` behind a global lock" would be a real throughput
regression for bridges — and the published benchmarks would catch
it.

So a full "Transport is a thin driver around one Endpoint" is the
*wrong* end state. The right end state factors the protocol into
two layers:

```
drift_proto::wire      — pure, stateless byte builders/parsers
drift_proto::handlers  — per-peer logic: (&Config, &Identity,
                         &mut Peer, &mut CookieState, packet)
                         -> Vec<Action>, no I/O, no peer-map, no locks
        ↑                         ↑
   Endpoint (single-threaded   Transport (sharded, multi-threaded
   driver: owns peer map,      driver: owns sharded peer map,
   queues, wasm/redox)         recv loops, tokio, bridges)
```

Both drivers call the **same** handler functions; the protocol
logic exists once. The Endpoint stays a thin single-threaded
driver; the Transport keeps its sharded concurrency model and calls
the handlers per-peer under its existing per-shard locks. Neither
driver's concurrency model changes — only *where the protocol logic
lives* does.

## Slice plan (each its own PR, each independently safe)

| Slice | Scope | Risk | Safety proof |
|---|---|---|---|
| **1** ✅ | **Shared wire-format layer (done).** Extracted drift-proto's pure stateless `build_hello_wire` / `build_resume_hello_wire` + cookie helpers (`cookie_input`, `addr_bytes`, `ct_eq`) + size constants into a public `drift_proto::wire` module. `Endpoint` calls it; the transport deleted its private copies and the duplicated constants (`HELLO_PAYLOAD_LEN`, the PQ tails, the cookie sizes) and now re-exports/delegates to `wire`. drift-proto promoted from dev- to regular dependency of drift. Net −174 lines from the existing files. `build_close_packet` deferred to slice 2 (it seals, so it needs a live key — not purely stateless). | Low | A one-time byte-identity test (`wire_parity_proof`) asserted the transport's pre-existing private builders produced output byte-for-byte identical to `drift_proto::wire`'s across a full parameter sweep (classical/mesh/cookie/PQ; v4+v6), then was deleted with the private builders. Permanent guards: drift-proto's `wire` KATs + the `proto_interop` cross-impl suite + all cookie/PQ/resumption/attack suites green. |
| **2** ✅ | **Session-keyed frame builders (done).** New `drift_proto::frame` module owns `build_close_packet` (operates on the shared `drift_core::session::Peer`) and `build_hello_ack_wire` (the HELLO_ACK byte assembly, pure given the server's handshake material + responder tx key). Both `Endpoint` and `Transport` call them; the transport's private `build_close_packet` is deleted and its `regenerate_session` ack-assembly block (~40 lines) collapses to one call. Net −84 lines. The **DATA-send path** (`build_data_packet`) is deferred to slice 3 — it carries a pooled-buffer optimization (`drift_core::pool::take_wire_buf`), the short-header CID fast path, and returns each driver's own action type (`SendAction` vs `Transmit`), so it can't be cleanly shared without the driver/handler split, and its hot-path perf needs the slice-4 bench gate. | Low–Med | Both packets are **AEAD-sealed**, so any byte divergence breaks tag verification — the `proto_interop` suite (engine ↔ transport, both roles, classical + PQ, Close both directions) is an exact byte-identity guard, plus `frame` structural KATs + an AAD self-consistency round-trip. dual_init / restart_handshake / reconnect_cycle exercise `regenerate_session`. |
| **3** | Extract the per-peer packet **handlers** (`handle_hello`, `handle_hello_ack`, `handle_data`, cookie gate, rekey, resumption) into `drift_proto::handlers` as free functions over `(&Config, &Identity, &mut Peer, &mut CookieState, …)`. `Endpoint` and the transport both call them. Includes the deferred DATA-send path (`build_data_packet`) with a buffer-out-param so the transport keeps its pooled buffer. This is where the real de-braiding happens. | High | Each handler ported with a byte-identity / behavior-equivalence test before the transport switches to it; interop suite is the cross-impl guard; DATA path gets the bench gate. |
| **4** ✅ | **Closure + perf certification (done).** Audit found **no dead protocol code to delete** — slices 1–3 removed each old block inline as they swapped over, so `transport/mod.rs` already keeps only the sharded driver (locks, recv loops, peer table, federation, mesh) plus thin wrappers around the shared kernels that hold driver-specific side effects. The compiler reports zero dead-code/unused warnings. The perf gate (the real deliverable) certifies the cumulative arc throughput-neutral. | Low | Cross-wire loopback throughput (`drift-bench/scripts/run-wire-throughput.sh`, udp/h2s/iroh × 3) + criterion micro (`cargo bench --bench throughput`), baseline `875e1f8` vs current. K=17 fleet soak optional (no fed-path/allocation change). |

Slices 1–2 are mechanical and byte-provable. Slice 3 is the
genuinely hard one — see the dedicated design below. Slice 4 is
cleanup gated on the bench matrix.

## Slice 3 design — sharing the handlers

A recon pass over the transport (`handle_hello`, `handle_hello_ack`,
`handle_data`, `process_short_header`, `send_data`, the cookie gate)
established two facts that make handler-sharing possible at all:

1. **Both crates already use the same `drift_core::session::Peer`.**
   The transport stores it in a sharded async-locked table; the
   engine stores it in a plain `HashMap`. All *per-peer* protocol
   state — seq counters, handshake state, session keys, replay
   window, pending queue — lives inside that shared struct.
2. **Handlers mutate only `&mut Peer` and read shared context;
   side effects are returned as actions, executed by the caller.**
   This is *already* the engine's model (it returns
   `Transmit`/`Event`). The transport does the same in effect — it
   builds wire bytes under the peer lock, then sends them after
   releasing it.

So the target shape is a set of free functions:

```rust
fn handle_X(ctx: &HandlerCtx, peer: &mut Peer, pkt: …) -> Result<Actions>
```

- `ctx` is read-only shared state: `identity`, `local_peer_id`,
  config flags, and a **snapshot** of the cookie secrets (taken
  before the peer lock, so the handler stays synchronous and
  lock-free w.r.t. the global cookie mutex).
- `peer: &mut Peer` is the only mutable state — no cross-peer races,
  so it composes with the transport's per-shard lock unchanged.
- `Actions` is what the caller must do: bytes to send + where, CID
  installs, metric bumps, events. The engine drains them into its
  `transmits`/`events` queues; the transport executes them after
  releasing the peer lock (sends, `install_cids`, atomics) — exactly
  its current post-lock sequence.

**The concurrency model does not change.** The transport keeps its
sharded locks, its lock ordering, and its await-outside-locks
discipline. The one wrinkle the recon found — `handle_hello` calls
`send_challenge`/`validate_cookie` *while holding* `lock_all`, which
touch the cookie mutex + socket — is resolved by snapshotting the
cookie secrets into `ctx` before the lock and returning the
challenge bytes as an action (the transport already releases the
lock before the real send; only the secret read moves earlier).

**Transport-only concerns stay in the transport wrapper**, never in
the shared handler: addr-index maintenance (SEC.FIX.1), the
`handshakes_inflight` gauge, federation (`PeerGone`, directory),
path validation/migration probes, mesh route lookups. The shared
handler emits a neutral action; the transport's wrapper layers its
extras around it.

### Increments (each its own PR)

Slice 3 is too large and too close to deployed code for one PR, so
it lands in increments, smallest-risk first:

- **3a — DATA-send sealing core (done).** Shared the
  `build_data_packet` logic (short-header CID fast path + long
  header) as `drift_proto::frame::seal_data_wire(local, &mut Peer,
  payload, deadline, coalesce, out_cid, mesh) -> Vec<u8>`, returning
  just the wire bytes. Each driver wraps: the transport in
  `SendAction::Data(bytes, target, iface)` (mesh-next-hop or peer
  addr, on the tracked interface), the engine in `Transmit { dst:
  peer.addr }`. The shared core uses `drift_core::pool::take_wire_buf`
  for the long path, so the transport keeps its buffer-pool
  optimization. The engine's two send paths (inline `encode_short` +
  `build_data_packet`) and the transport's `build_data_packet_with_cid`
  collapse into this one function; the transport's now-orphaned
  `mesh::DEFAULT_MESH_TTL` is removed (the canonical constant is
  `drift_core::session::DEFAULT_MESH_TTL`). Byte-identical,
  allocation-identical code move (AEAD-sealed → interop + datagram +
  stream_reliability + congestion + sharding_contention are the
  byte-exact guard); structural KAT for the short/long/mesh decision.
- **3b — receive-path state transition (done).** The
  recon found the deadline / coalesce / replay checks are *already*
  shared (they're `drift_core::session::Peer` methods both call), so
  the only genuinely-duplicated receive logic is (i) the rekey-grace
  decrypt fallback and (ii) the `AwaitingData → Established`
  transition. 3b shares (ii) as
  `drift_proto::frame::complete_server_transition(&mut Peer) ->
  Option<ServerEstablished>`: the state swap, clearing the
  amplification counters, and draining the pending queue, returning
  the session key (for CID install), the PQ flag (for the metric),
  and the queued DATA (for the caller to flush in its own action
  type). The transport keeps its metrics / qlog / post-lock CID +
  ticket; the engine keeps its `Connected` event + ticket. Behavior
  is exercised on every server handshake, so `proto_interop` (+
  dual_init / restart_handshake / two_process / metrics) is the
  guard. The decrypt-grace fallback (i) is **deferred**: the
  transport authenticates the raw on-wire header byte 29 in the AAD
  while the engine re-encodes it (a security-relevant strictness
  difference), so sharing it must standardize on the raw-bytes AAD —
  its own careful step.
- **3b-decrypt — rekey-grace decrypt (done).** Shared the
  duplicated-4-ways rekey-grace decrypt fallback as
  `drift_proto::frame::open_data_with_grace` (long header) +
  `open_short_data_with_grace` (short header): try the current rx,
  then the pre-rekey `prev.rx` if the grace window is open, clearing
  `prev` on expiry. `REKEY_GRACE` is now one constant in `frame`. Two
  divergences were standardized: (1) the AAD now uses the **raw
  on-wire header** (the transport's strict behavior — the engine
  formerly re-encoded, silently un-authenticating the reserved byte;
  threaded the raw header into the engine's `on_data`); (2) the
  transport's short path now **clears expired `prev`** like the long
  path (it previously leaked the stale slot until the next eviction).
  Guard: `proto_interop` (rekey both directions) + `rekey_under_load`
  (256k packets across a rekey) + the engine's grace accept/expiry
  loopback test + a `frame` test pinning the raw-AAD strictness
  (a flipped reserved byte must fail the tag) + the receive-path
  attack suites.
- **3c-ack — client HELLO_ACK kernel (done).** Shared the
  client-side `handle_hello_ack` core as
  `drift_proto::frame::process_hello_ack(peer, identity, header,
  server_eph, server_nonce, server_pq, pq_ct, tag, now) ->
  HelloAckResult`: consume the `AwaitingAck` state, PQ posture check,
  static + ephemeral DH (+ ML-KEM decapsulation when hybrid), key
  derivation, RTT sample, AEAD ACK-tag verify, `AwaitingAck →
  Established` transition + pending drain. Returns
  `Ignored` / `PostureMismatch` / `Established { key_bytes, server_pq,
  pending }` so each caller applies its own metrics (the transport
  bumps auth-failure / hybrid-refused on mismatch and
  completed / hybrid-completed on success; the engine just emits
  `Connected`), mesh-route flag, CID install, and pending flush.
  No AAD subtlety here — both drivers already re-encoded the HELLO_ACK
  header. Lower-risk than the server side (client path is a single
  `lock_for`, no cookie-send-while-locked). Guard: `proto_interop`
  (both client roles, classical + PQ — the AEAD ACK tag makes any
  divergence fatal), `attack_pq_downgrade` (the PostureMismatch
  path), `dual_init`, `hybrid_pq`, `reconnect_cycle`, `resumption`,
  `two_process`.
- **3c-regen — server `regenerate_session` (done).** Shared the
  server key-derivation core as
  `drift_proto::frame::regenerate_session(...) -> RegenOutcome
  { ack_wire, was_awaiting_data }` — the mirror of
  `process_hello_ack`: server-ephemeral gen, static + ephemeral DH,
  ML-KEM encapsulation, key derivation, the (already-shared) HELLO_ACK
  assembly, and the `AwaitingData` install + seq/coalesce reset +
  addr/iface/via_mesh stamping. The transport drives its
  `handshakes_inflight` gauge from `was_awaiting_data`; the engine
  passes `iface_idx = 0` (the field it never reads). **Recon
  correction:** the cookie gate runs *before* `lock_all`, not inside
  it, so the feared cookie-secret-snapshot restructure is unnecessary
  — the gate is already lock-free w.r.t. the peer table. Guard:
  `proto_interop` (the client AEAD ACK-tag verify makes any server
  divergence fatal) + dos_cookie / hybrid_pq / scale_handshakes /
  restart_handshake / metric_accuracy.
- **3c-cookie — cookie gate (done).** Shared the two remaining pure,
  security-critical cookie primitives into `drift_proto::wire`:
  `validate_cookie(current, previous, src, static, eph, nonce, tail,
  max_age_secs, now_unix) -> bool` (length + freshness + current/
  previous-secret MAC check, constant-time) and
  `build_challenge_wire(local, client, timestamp, mac) -> Vec<u8>`
  (the CHALLENGE datagram). Both callers snapshot their secrets and
  pass `now` in, keeping `wire` clock-free: the transport
  (`cookies.rs::send_challenge` / `validate_cookie`) reads
  `current`/`previous` under its async cookie lock; the engine
  (`endpoint.rs::queue_challenge` / `validate_cookie`) reads them from
  `self.cookies`. The cookie *gate trigger* (`cookie_required`) stays
  driver-specific — it's a counting policy over local state (the
  transport's atomic inflight gauge vs the engine's peer-table scan),
  not protocol bytes. New KATs pin both functions
  (`challenge_wire_layout`, `validate_cookie_current_previous_and_rejections`);
  end-to-end guard is dos_cookie / cookie_rotation_boundary /
  attack_cookie_nonce_replay / attack_slowloris / hybrid_pq_cookie_path
  / proto_interop. The in-`lock_all` HELLO orchestration (dual-init
  tiebreak, cached-ACK duplicate replay, cross-shard auto-register cap)
  remains driver-specific by design — it is sharding concurrency, not
  protocol, and has no engine analogue.
- **4 — closure + perf certification (done).** A dead-code audit
  (compiler `dead_code`/`unused` lints + a manual sweep of every
  private `fn`/`const`/`use`/re-export in `transport/`) found **nothing
  to delete**: every remaining item has a live caller, and the
  transport's per-peer functions are now thin wrappers that forward to
  the `drift_proto` kernels while holding genuinely driver-specific
  side effects (the sharded peer-table locks, the `handshakes_inflight`
  atomic in `regenerate_session`, the `SendAction` wrapping in
  `build_data_packet_with_cid`, and the federation-envelope assembly in
  `build_typed_packet` — which has no `drift_proto` analogue yet). This
  confirms the strangler-fig discipline worked: each of slices 1–3
  deleted its orphaned block at swap time, so there was never a
  deferred graveyard. The one code change in this slice is making
  `run-wire-throughput.sh`'s binary path env-overridable so a
  baseline-vs-current comparison can point at each build in place.
  **Perf result** (baseline `875e1f8` = parent of slice 1, vs current
  `020c59a` = whole arc; 1 KB payload, 10 s, loopback, median of 3):

  | wire | baseline goodput | current goodput | Δ |
  |---|---|---|---|
  | udp | 1491.5 Mbps | 1489.7 Mbps | −0.12% |
  | h2s | 2759.3 Mbps | 2799.6 Mbps | +1.5% |
  | iroh | 827.2 Mbps | 807.2 Mbps | −2.4% |

  UDP (the most deterministic wire) is flat; h2s/iroh deltas are within
  loopback run-to-run jitter and non-directional. Criterion micro
  (`aead/*`, `header/*`) is flat-to-faster — but note those are
  `drift_core` crypto/header primitives that phase 4 never touched, so
  the cross-wire throughput is the authoritative gate, not the micro.
  No regression, as expected from byte-identical moves. The full-fleet
  K=17 soak (federation leak/liveness over hours) is the only remaining
  optional certification; phase 4 changed no federation path and added
  no allocations, so its marginal value here is low.

### Perf gate

The DATA path is the hottest code. 3a is a code move that produces
byte-identical output with the same allocation strategy, so no
regression is expected by construction — but the **full cross-wire
bench matrix** (`bench/bench-matrix.sh`) + a K=17 soak is the
authoritative gate and runs at slice 4 before the dead code is
deleted, per the project's wire-agnostic bench methodology. (The
`cargo bench --bench throughput` criterion suite is an AEAD/header
microbench that does not exercise `build_data_packet`, so it is not
the relevant gate for this change.)

## Safety methodology

- **Byte-identity, not just compatibility.** The interop tests prove
  the engine and transport *interoperate* (each parses the other),
  which does **not** prove their builders emit identical bytes — the
  parsers read by field offset. So before any swap, a dedicated test
  asserts `transport::build_X(args) == drift_proto::wire::build_X(args)`
  byte-for-byte. Only then is deleting the transport's copy a proven
  wire no-op.
- **Frozen-code discipline.** Each slice is the minimum change that
  removes one duplicated concern, fully covered by tests, reversible.
  No concurrency-model change until slice 3, which gets its own
  design pass.
- **Perf is a gate.** Slice 4 doesn't merge without the bench matrix
  and a K=17 soak showing no regression vs. the published numbers.
