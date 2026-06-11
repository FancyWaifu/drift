# Phase 4: `drift::Transport` consumes `drift-proto`

**Status: slice 1 (shared wire-format layer) DONE. Slices 2–4 pending.**

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
| **2** | Share the DATA + HELLO_ACK builders (`build_data_packet`, `regenerate_session` core). Harder: the transport's variants carry bookkeeping (CID fast-path, inflight gauge, iface) and return its `SendAction` enum. Extract the pure core, keep the bookkeeping in the transport wrapper. | Med | Byte-identity test as in slice 1; KAT vectors. |
| **3** | Extract the per-peer packet **handlers** (`handle_hello`, `handle_hello_ack`, `handle_data`, cookie gate, rekey, resumption) into `drift_proto::handlers` as free functions over `(&Config, &Identity, &mut Peer, &mut CookieState, …)`. `Endpoint` and the transport both call them. This is where the real de-braiding happens. | High | Each handler ported with a byte-identity / behavior-equivalence test before the transport switches to it; interop suite is the cross-impl guard. |
| **4** | Delete the transport's now-dead private protocol code; `transport/mod.rs` keeps only the sharded driver (locks, recv loops, peer table, federation, mesh). Re-run the full bench matrix to confirm no perf regression. | Med | Bench matrix (`bench/bench-matrix.sh` + criterion) per the wire-agnostic methodology; K=17 soak. |

Slices 1–2 are mechanical and byte-provable. Slice 3 is the
genuinely hard one and will be re-scoped (and re-confirmed) once 1–2
land. Slice 4 is cleanup gated on the bench matrix.

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
