# Federation Multi-Hop Forwarding Fix — Implementation Plan

## Context

The federation discovery system in `drift::transport` has been
implemented in five phases (A through E v2) per
`FEDERATION_DISCOVERY.md`. Unit tests for all phases pass. But the
2026-05-19 docker topology sweep (harness since removed)
exposed that the LIVE `drift bridge` subcommand only delivers
to direct 1-hop peers — exactly the count of one-hop pairs in
each topology, identical across h2/h2s/webtransport wires.

Investigation traced this to a forwarding bug in
`handle_federated` case 3 (the directory-lookup fallback): the
directory entry stores the IMMEDIATE announcer's peer_id, and
case 3 rewrites `target_bridge_pub` to the announcer's pubkey
rather than the ORIGINAL bridge that hosts the client. The
receiving announcer treats this as a local-delivery (case 2),
misses, and silently drops the packet.

Two phases close this:

  - **Phase F**: case-2 falls through to case-3 on local miss
  - **Phase G**: configurable `MAX_ANNOUNCE_HOPS` (default 4)

After both land, the docker pentagon sweep should produce 20/20
across mesh / ring / star / chain × all three wires (currently
20/10/8/8 due to the 1-hop limit).

## Phase F: Case-2 fallback on local miss

### What changes

In `drift/src/transport/mod.rs::handle_federated`, restructure the
case 1 / case 2 / case 3 branching so that case 2's local-delivery
failure falls through to case 3 (directory lookup) instead of
dropping. Currently the code reads (approximately):

```rust
if env.target_bridge_pub == UNKNOWN_BRIDGE_PUB {
    // case 3 — directory lookup
} else if env.target_bridge_pub == our_pub {
    // case 2 — deliver locally; drop on miss  ← BUG
} else {
    // forward to known bridge
}
```

Target shape:

```rust
let unknown = env.target_bridge_pub == UNKNOWN_BRIDGE_PUB;
let try_directory_lookup = unknown ||
    env.target_bridge_pub == our_pub;   // ← new condition

if env.target_bridge_pub == our_pub {
    // try local first
    if let Some(local) = try_deliver_locally(...) {
        return Ok(());
    }
    // fall through to case 3 — we may be a transit hop
    // for a re-announced entry
}

if try_directory_lookup {
    // existing case-3 logic: peer_directory[X] → announcer →
    // rewrite target_bridge_pub → forward
}
// else: case 2 (known bridge, not us) forward via fed table
```

### Test coverage

Add `drift/tests/federation_discovery.rs::live_ring_multi_hop_chain`:

```
Topology in-process: 5 bridges in a ring (b1-b2-b3-b4-b5-b1).
Each bridge has 2 federation peers (its ring neighbors).
Attach 5 clients (c1..c5), one per bridge.

For each (ci, cj) pair where i != j:
  - Wait for announce convergence (≤ 14 s on 7 s ticker).
  - ci sends a Federated envelope to its local bridge
    with target_client_pub=cj_pub, target_bridge_pub=ZERO.
  - Assert cj's transport receives the payload within 2 s.

Expected: 20/20 deliveries (5 × 4 ordered pairs).
```

This test fails on current main and passes after the Phase F fix.

### Files to touch

  - `drift/src/transport/mod.rs::handle_federated` — restructure
    case branching as sketched above
  - `drift/tests/federation_discovery.rs` — new live ring test
    (~80 lines, follows the pattern of
    `find_peer_multi_hop_chain` but uses real packet flow rather
    than `__debug_send_federated_envelope`)
  - `FEDERATION_DISCOVERY.md` — flip Phase F from PLANNED to DONE
    with checkmarks

### Estimated effort

Two to four hours. The branching restructure is small; the test
needs care to avoid Docker (just in-process Transports
federating over a loopback udp socket or via a memory pipe).

## Phase G: Configurable `MAX_ANNOUNCE_HOPS`

### What changes

In `drift/src/transport/federated.rs`, the constant:

```rust
pub const MAX_ANNOUNCE_HOPS: u8 = 2;
```

becomes a configurable parameter on `TransportConfig`:

```rust
pub struct TransportConfig {
    // … existing fields …
    /// Maximum number of hops a directory entry may travel
    /// through proactive re-announcement. Default 4 — covers
    /// the typical homelab federation up to ~16 bridges in a
    /// linear chain, or any-size full mesh. Bridges in larger
    /// federations may set this higher; bridges with strict
    /// privacy needs may set it lower (0 = only direct entries
    /// propagate; receivers don't re-emit).
    pub max_announce_hops: u8,
}
```

Default `4` (was hardcoded 2). Threaded through to
`announce_directory` at the gate:

```rust
let hops_cap = self.inner.config.max_announce_hops;
// in transitive entry filter:
Some(&h) if h + 1 < hops_cap => h,
```

CLI surface on `drift bridge`:

```
--max-announce-hops <N>
    Maximum hops a directory entry may travel via proactive
    re-announcement. Default 4. Higher values let federation
    directory information reach deeper into chain / tree
    topologies at the cost of larger per-bridge state and more
    announce traffic. Bridges configure this independently;
    receivers honor whatever hop value an inbound entry
    carries.
```

### Test coverage

Extend `live_ring_multi_hop_chain` (from Phase F) with a chain
topology too:

```
Topology: b1-b2-b3-b4-b5 (linear).
Test that c1 reaches c5 (4-hop path).
With max_announce_hops=4 (new default), expected: 20/20.
With max_announce_hops=2 (legacy), expected: 8/20 chain pairs
  (only directly-adjacent bridges' clients reachable).
```

### Files to touch

  - `drift/src/transport/federated.rs` — change const to
    associated value, update doc comment
  - `drift/src/transport/mod.rs::announce_directory` — read cap
    from config
  - `drift/src/transport/config.rs` (or wherever
    `TransportConfig` lives) — add field, default 4
  - `drift/src/cli/mod.rs` — add CLI arg
  - `drift/src/cli/bridge.rs` — plumb arg → config
  - `drift/tests/federation_discovery.rs` — chain test variant
  - `FEDERATION_DISCOVERY.md` — flip Phase G from PLANNED to
    DONE

### Estimated effort

One to two hours. Mechanical config plumbing.

## Verification

After Phase F + G land, the docker sweep (harness since removed)
was re-run. Recorded outcome:

| Topology | Pre-fix | Post-fix |
| -------- | ------- | -------- |
| mesh     | 14-18/20 (wire jitter) | 14-18/20 (wire jitter; unchanged — already worked) |
| ring     | 10/20 | 20/20 |
| star     | 8/20  | 20/20 |
| chain    | 8/20  | 20/20 |

Mesh's wire-jitter spread should be unchanged — the bug fix
doesn't affect 1-hop topologies. Webtransport's 14/20 vs
h2s's 18/20 is the Docker Desktop UDP-stack issue from earlier,
orthogonal to this work.

## Out of scope (for these phases)

  - **Loop detection in announce propagation.** Current code
    has split-horizon ("don't tell B about a client we learned
    from B") which prevents 2-hop cycles. Higher-cycle loops
    (A→B→C→A) need a per-announce `path: [PeerId; N]` extension
    to prevent. Defer until we observe loops in the wild.
  - **`PathDiscovery` Reticulum-style hop tickets.** The current
    `peer_directory_tickets` table proves "X is a client of
    some bridge in the chain" but not "the announce path was
    legitimate." For trusted federations (operators chose
    peers), this is fine. For zero-trust, need per-hop signing.
  - **Faster convergence than 7 s.** Plenty for steady state;
    expensive to tighten without rate-limiting. Defer.

## Rollback story

Phase F is structurally additive (a fallback path). If it
introduces subtle regressions, revert is `git revert <commit>`
with no protocol implications — no wire-format changes, no
state-table changes.

Phase G adds a config knob with backward-compatible default.
Operators on the old hardcoded `MAX_ANNOUNCE_HOPS=2` behavior
can set `--max-announce-hops 2` explicitly. No on-wire changes.
