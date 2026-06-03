# Public API lock-down — design memo

## The opportunity

Public API surface by crate:

| Crate          | pub items | SLOC   |
|----------------|-----------|--------|
| drift          | **196**   | 24,645 |
| drift-core     | 100       | 3,929  |
| drift-vpn      | 46        | 7,813  |
| drift-config   | 34        | 785    |
| drift-mosh     | 20        | 2,817  |
| drift-bench    | 16        | 1,337  |
| drift-http     | 15        | 1,516  |
| drift-git      | 14        | 1,113  |
| drift-wormhole | 12        | 741    |
| drift-ffi      | 4         | 505    |

drift's 196 `pub` items is the elephant: 7 pub items per 1,000
lines. By contrast, iroh's `iroh` crate at comparable maturity
exposes around 60 top-level items for ~25k lines — a
3× difference in surface density.

Why this matters: **anything `pub` is an implicit promise to
external callers.** Renaming, removing, or changing the
signature of a `pub` item is a breaking change. Internal
helpers that leaked into the `pub` namespace lock us into
back-compat for every internal refactor.

A grep of the top offenders:

  * `drift/src/transport/find_peer.rs`: 29 pub items —
    federation lookup machinery, almost all of which is internal
    to `transport::*` and never re-exported from `drift::lib`.
  * `drift/src/transport/federated.rs`: 22 pub items —
    same story. Wire codecs, ticket-verification helpers.
  * `drift/src/lib.rs`: 28 pub items — the *intended* top-level
    surface. This is the canonical interface; everything else
    should ideally be pub-crate.
  * `drift/src/io.rs`, `drift/src/cli/mod.rs`,
    `drift/src/streams.rs`, etc.: 20+ each.

The pattern is: code added as `pub fn` to be callable from a
sibling module ends up exported through the crate root by
default, because Rust's default `pub` is workspace-wide.

## The fix: `pub(crate)` as the default, `pub` as the
## intentional surface

The lock-down has two passes:

  1. **Pass A (mechanical):** anything not re-exported from
     `lib.rs` AND not used by an external crate becomes
     `pub(crate)` or `pub(super)`. Tools: `cargo deny`-style
     dead-pub linting plus manual grep for cross-crate uses.
  2. **Pass B (judgment):** for the items that legitimately
     need to cross crate boundaries, decide: do they belong in
     the public re-export surface (`lib.rs`), or are they pub-
     for-workspace-sibling-only (in which case `pub(crate)` on
     the source + an explicit `pub use` in `lib.rs` if needed)?

iroh's approach is essentially this: `pub` items live behind a
`prelude` re-export module, everything else is `pub(crate)`.
Cross-crate uses go through the prelude.

## Per-crate plan

### drift (largest, highest value) — 3 PRs

The drift crate is the externally-facing transport API. ~25 of
its 196 pub items are actually app-relevant (`Transport`,
`PeerId`, `Identity`, `TransportConfig`, the four sub-error
types, etc.). The remaining ~170 are wire codecs, internal
helpers, and test plumbing that leaked.

  * **PR 1 — transport/* lockdown:** convert
    `transport::find_peer::*`, `transport::federated::*`,
    `transport::cookies::*`, `transport::rotation::*`,
    `transport::resumption::*` (the `pub fn` codecs and
    verify helpers, NOT the `Transport` methods) from `pub` to
    `pub(crate)`. ~70 items. Pure mechanical refactor.
  * **PR 2 — io/streams/wire lockdown:** `io.rs`,
    `streams.rs`, `wire_*.rs`. ~40 items. Same treatment.
  * **PR 3 — lib.rs as the canonical surface:** audit every
    `pub use` re-export. Anything in the public surface that
    isn't documented and used by drift-vpn / drift-mosh /
    drift-http etc. gets pulled. ~25 → ~15 target.

### drift-core — 1 PR

100 pub items for 4k lines is reasonable but auditable.
Likely 30-40% of those are internal sub-module helpers (e.g.
`pq::server_encapsulate` is called from `drift::transport::mod`
but doesn't belong on the public surface). One PR walks
through and tightens.

### drift-vpn — 1 PR (defer)

46 pub items for 7.8k lines is ratio-wise *good* (6 per k SLOC).
drift-vpn is also the app-facing entry point for the killer
tool. Less urgent — defer until after drift / drift-core to
avoid churning the consumer surface twice.

### Smaller crates — bundle into 1 PR

drift-mosh (20), drift-bench (16), drift-http (15), drift-git
(14), drift-wormhole (12), drift-ffi (4) — all small enough to
audit and lock down in one combined PR. Total ~80 items;
realistic to land in a day.

## What we should NOT do

* **Don't break `drift-ffi`.** The C ABI consumers can't be
  audited and must continue to see exactly the items they see
  today. Lock down everything else around it instead.
* **Don't introduce a `prelude` module yet.** Iroh has one but
  it's the convention people overreach for. First minimize the
  surface; *then* if there's still a coherent "common app
  imports" set, group them.
* **Don't try to be clever with `#[doc(hidden)]`.** That hides
  items from rustdoc but they're still `pub`, still a
  back-compat surface. Use real visibility modifiers.
* **Don't lock down the test surface.** `#[cfg(test)]` and
  integration tests in `tests/` need pub access to the items
  they exercise. Either keep those pub (acceptable) or add
  `#[cfg(any(test, feature = "test-internals"))]` gates.

## Phased rollout

  * **Phase 1 (1 PR, ~half day):** drift transport/* lockdown
    (PR 1 above). Highest impact, lowest risk. ~70 items
    flipped to pub(crate). Mechanical.
  * **Phase 2 (1 PR, ~half day):** drift io/streams/wire/cli
    lockdown (PR 2). Same shape as phase 1.
  * **Phase 3 (1 PR, ~1 day):** drift `lib.rs` audit — the
    intentional public surface. Judgment-heavy.
  * **Phase 4 (1 PR, ~half day):** drift-core sweep.
  * **Phase 5 (1 PR, ~1 day):** small crates bundle —
    drift-mosh, drift-bench, drift-http, drift-git,
    drift-wormhole.
  * **Phase 6 (optional, deferred):** drift-vpn. Wait until at
    least one other tool ships against the locked-down surface
    so we know what's actually missing.

Total: 5 PRs, ~3 days of work. Each one is a single concern,
reviewable in 15 minutes, and adds zero behavior change. The
diff in each is almost entirely `s/pub /pub(crate) /` plus
occasional `use` adjustments where a now-private item was being
imported from the wrong path.

## Measurable target

Post-lockdown numbers we should aim for:

  * drift: 196 → ~50 pub items
  * drift-core: 100 → ~60
  * Other crates: ~10–20% reduction each

If the final numbers are far off these targets, that's a signal
to look harder — either we missed items that should be locked
down, or the original surface was already tighter than the raw
count suggested.

## Risk

Low across the board. Every flipped item is build-verified
across the workspace; if a sibling crate was depending on a
`pub` item we lock down, the build fails locally and we either
restore it as `pub` (with a comment noting it's load-bearing) or
move it explicitly into the intentional surface. No runtime
behavior changes.

The one watch-out: don't lock down anything that downstream
consumers (drift-vpn deployments, drift-mosh sessions) might
depend on transitively. Use `cargo tree --workspace` to map
inter-crate dependencies before each PR; any item flipped
out of `pub` that's reachable from a sibling crate has to
either stay pub or get an explicit re-export.
