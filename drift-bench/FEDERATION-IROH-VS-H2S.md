# DRIFT federation — iroh vs h2s comparison

Tests run on real Linux (Proxmox LXCs, x86_64 musl) on 2026-05-29.
The question: does the iroh wire hold up for actual drift bridge
federation, vs the established h2s wire?

## Test 1 — 2-bridge federation (45 s window)

drift-1 ↔ drift-2 over the LAN, both bridges initiate to each
other (symmetric `--federate`).

| Wire | Handshake established | BEACONs sent | Auth failures | Invalid packets |
|---|---|---|---|---|
| iroh | 115 ms after listener bind | 89 + 92 = **181** | 0 | 0 |
| h2s  | sub-second              | 89 + 89 = **178** | 0 | 0 |

**Verdict:** Tied. Both wires reach steady-state federation
cleanly. iroh's faster establishment is in the noise band of
control-plane traffic timing. Both bridges in both runs
exchange BEACONs at the expected 2/s/peer cadence with zero
authentication errors.

This is what we wanted: iroh **works** for 2-bridge federation,
no worse than h2s.

## Test 2 — K=3 federation triangle (45 s window)

drift-1, drift-2, drift-3 each `--federate` to the other two.
6 directed federation edges. This is the density at which
the original HTTP.FED.STRICT motivation (UDP mutual-init races
at K≥5 pentagon) starts to appear in less-extreme form.

### Aggregated results

| Wire | Handshakes complete | BEACONs total | dual-init events | Auth fails | Invalid packets |
|---|---|---|---|---|---|
| iroh | 3 (all 3 mutual links) | **356** | 2 | 0 | 0 |
| h2s  | 3 (all 3 mutual links) | **534** | 0 | 0 | 0 |

### BEACON destinations per bridge (the diagnostic table)

iroh K=3 — **4 of 6 directed edges active**:
| from | → bridge1 | → bridge2 | → bridge3 |
|---|---|---|---|
| bridge1 | — | 89 ✓ | 89 ✓ |
| bridge2 | 89 ✓ | — | **0 ✗** |
| bridge3 | 89 ✓ | **0 ✗** | — |

h2s K=3 — **all 6 directed edges active**:
| from | → bridge1 | → bridge2 | → bridge3 |
|---|---|---|---|
| bridge1 | — | 89 ✓ | 89 ✓ |
| bridge2 | 89 ✓ | — | 89 ✓ |
| bridge3 | 89 ✓ | 89 ✓ | — |

### What this means

**iroh has a real regression at K=3+ federation density.** The
`bridge2 ↔ bridge3` link establishes a session (both sides log
`handshake complete with peer ...`), but only one direction
sends BEACONs. The opposite direction doesn't.

The pattern that triggers it: **both bridges initiate the
federation link simultaneously**, and dual-init resolution
fires (`dual-init: dropping peer HELLO (local key wins)` on
the loser side). The dual-init handler unifies the two
ambiguous connections into one DRIFT session, but the mesh-
routing federation_table only records the winning direction
— the losing-side bridge doesn't get a federation_table entry
for the same peer, so no BEACONs flow from its end.

**h2s doesn't hit this.** TCP connections are inherently
unique (one socket pair = one stream), so simultaneous
initiates produce two TCP connections that DRIFT treats as
two separate paths, and BEACONs flow on both. No dual-init
session merging, no asymmetric mesh-routing state.

### This is not the K5 pentagon UDP race

HTTP.FED.STRICT was originally added because the K=5 pentagon
test at higher federation density exposed **UDP mutual-init
races** — naked UDP HELLOs colliding because UDP has no
connection-establishment handshake. Iroh runs over UDP but
uses QUIC's negotiated streams, so it doesn't reproduce the
original race. **It exposes a different bug at K=3 density**
— the interaction between iroh's bidirectional Connection
abstraction and DRIFT's dual-init session-table is wrong.

## Implications (updated post-fix)

**iroh and h2s are now equivalent for federation at K=3** —
all 6 directed edges active on both wires, zero auth failures,
matching BEACON cadence. The "h2s is more reliable" caveat
from before only applied to the pre-fix iroh adapter.

iroh remains a valid federation wire choice, with the same
tradeoffs as documented in `RESULTS-2026-05-27.md` Phase 4:

- **Throughput overhead** (~50% efficiency vs native iroh
  streams) — the cross-wire portability tax.
- **Middlebox compatibility** (iroh is UDP/QUIC; h2s is
  HTTPS-shaped) — pick based on what your federation links
  actually traverse.
- **Operator-config burden** (`DRIFT_IROH_SECRET_HEX` env
  var, fixed UDP port, longer URL format) — works once you
  know it, not self-documenting.

## Fix: process-wide shared iroh `Endpoint` (status: FIXED)

After researching iroh's own documentation, found this in
the `Endpoint` rustdoc:

> It is recommended to only create a single instance per
> application. This ensures all the connections made share
> the same peer-to-peer connections to other iroh endpoints.

That was the root cause. My original adapter created:
- one `Endpoint` for the listener (in `IrohListenerIO::bind`)
- one new `Endpoint` per outbound dial (in
  `connect_iroh_client`)

Because each `Endpoint` is independent, iroh's built-in
**per-peer connection deduplication** could never fire across
the listener and the connector. When bridge2 accepted bridge3's
incoming connection AND simultaneously dialed bridge3 itself,
both succeeded and produced two independent Connections (since
they lived on two independent Endpoints). DRIFT's session-layer
dual-init handler then merged them into one session, but the
federation_table only recorded one direction.

The fix: a `tokio::sync::OnceCell<Endpoint>` that holds the
process-wide singleton. Both `IrohListenerIO::bind` and
`connect_iroh_client` now go through `shared_endpoint(hint)`,
which lazily initializes the singleton with the listener's
bind hint and returns clones for subsequent calls. With a
single Endpoint, iroh's per-peer dedup works as designed:
when bridge2's listener already has an accepted Connection
from bridge3, bridge2's dial to bridge3 reuses that same
Connection instead of opening a second one.

### Result — same K=3 test, with the shared-Endpoint fix

iroh K=3 — **all 6 of 6 directed edges active**:
| from | → bridge1 | → bridge2 | → bridge3 |
|---|---|---|---|
| bridge1 | — | 89 ✓ | 89 ✓ |
| bridge2 | 90 ✓ | — | **90 ✓** |
| bridge3 | 90 ✓ | **90 ✓** | — |

Aggregate: **538 BEACONs total** vs h2s's 536. iroh is
now indistinguishable from h2s on the K=3 BEACON matrix.

Two dual_init events still fire in the iroh log — DRIFT's
dual-init session-merge runs at the protocol layer regardless
of how iroh deduplicates at the transport layer — but with
the shared Endpoint, both bridges end up with the SAME single
Connection in their session table, so the federation_table
entry gets populated correctly on both sides and mesh routing
fires symmetrically.

Raw post-fix evidence: `drift-bench/fed-k3-iroh-k3-b{1,2,3}-fixed.log`.

This is the architecturally correct fix per iroh's own
guidance, not a workaround. It would also have been needed
eventually for relay-mode federation (where each `Endpoint`
maintains its own relay connection — having multiple per
process would be wasteful).

## Reproduce

```bash
# 2-bridge federation comparison
bash drift-bench/scripts/fed-compare-2bridge.sh

# K=3 triangle federation comparison
bash drift-bench/scripts/fed-compare-k3.sh
```

Both scripts SSH into the LXCs through a router proxy
command (`104.166.196.243` → `192.168.50.{52,168,253}`).
Adjust the host IPs and SSH chain for your topology.

Raw bridge logs from this run are committed alongside this
doc as `drift-bench/fed-2bridge-{iroh,h2s}-b{1,2}.log` and
`drift-bench/fed-k3-{iroh,h2s}-k3-b{1,2,3}.log`.
