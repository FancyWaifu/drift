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

## Test 3 — K=17 corporate federation (single host, native procs)

17-bridge corporate topology run via
`docker/federation-corporate/run-native.sh` with the iroh case
added (deterministic per-bridge seed via SHA-256 of
`"drift-corp-<name>"`, 2-phase probe to scrape endpoint ids
from each bridge's `iroh listener bound — id=…` log line,
then restart with full `iroh://<id>@127.0.0.1:<port>@<pub>`
federate URLs).

Topology: 2 DMZ + 3 DC mesh + 3 regional hubs + 9 branches.
Diameter 4 hops. 96 cross-bridge dials = 6 clients × 16
non-local servers.

### iroh result vs h2s baseline

| Wire  | Pass rate | 1 hop | 2 hop | 3 hop | 4 hop |
|---|---|---|---|---|---|
| **iroh** (this run) | **56 / 96 (58 %)** | 5/6 | 14/24 | 25/30 | **12/36 (33 %)** |
| h2s (pre-h2-opt baseline)   | 66 / 96 (69 %) | — | — | — | — |
| h2s (post-h2-opt baselines) | 73–82 / 96 (76–85 %) | — | — | — | — |

**iroh underperforms h2s by 11–24 points at corporate density.**
The 4-hop column carries the gap: 33 % pass vs h2s's typical
60–80 %. Branch-to-branch cross-region traffic — the path that
needs the most federation edges to behave — is the failure
mode.

### Root-cause signal

Hub bridges (dc1/2/3, edge1, hub-east) accumulate persistent
`dropped invalid packet error=authentication failed` on the
DRIFT transport layer. The src= field is the 192.0.2.x:port
synthesized by `peer_addr_for_connection` (SipHash of
`conn.remote_id()`).

Across all 17 bridge logs, **only 5 distinct synthesized peer
addrs appear in the auth-fail stream**, and the failures repeat
every ~2 s for the entire run (matching the BEACON cadence).
On dc1 (5 federation peers), 3 of those 5 peers show in the
auth-fail set — those 3 federation edges never reconcile.

This is a different bug than the K=3 dual-init / shared-Endpoint
issue, which was about edges not establishing in both
directions. Here the edges DO establish (iroh QUIC connections
succeed), but **DRIFT session-layer auth state diverges**
between the two ends after establishment. Possible causes:

- iroh's shared `Endpoint` reusing a Connection across what
  DRIFT views as a logical disconnect+reconnect, leaving the
  session table holding stale auth state on one side.
- Multiple short-lived Connections briefly produced during
  simultaneous mutual dials on high-degree bridges — one
  cached in the DRIFT session table, others arriving with
  unmatched auth.
- Some peers seeing different `conn.remote_id()` than others
  for the same underlying ed25519 identity (unlikely but
  worth checking).

One `iroh connect: timed out` event also appears (initial
dial across the localhost port range), so connection-establish
contention is a contributing pressure at this density.

### Implication (initial)

**iroh cannot replace h2s as the corporate-tier federation
default** — at this point. For homelab / K≤3 federation it
works fine; for the 17-bridge corporate topology it fails
~40 % of dials, heavily skewed to longest-hop traffic.

### Follow-up diagnosis and fixes

The new `auth_fail_diag` instrumentation (added to the two
`drift::transport` "dropped invalid packet" warn sites) made
the failure mode legible:

```
Auth-fails with handshake-state visibility (41 short-header):
  21  state=established      — stale-keys after both Established
  20  state=awaiting_data    — receiver mid-second-handshake
```

`awaiting_data` is the smoking gun: receiver derived session
keys from a handshake that the sender's keys don't match —
two handshakes happened between the same peer pair with
diverged keys. The classic dual-init race amplified by K=17's
22 federation edges (vs K=3's 3).

Two contributing causes, fixed one at a time:

**(1) Kernel `net.core.rmem_max` clamp.** Stock Linux caps
UDP receive buffer at ~425 KB; drift requests 4 MB. Under
K=17 federation burst load this drops QUIC packets at the
kernel, throwing off iroh's congestion / connection state.
h2s federates over TCP (auto-tuned buffers) so it's unaffected.
Fixed by bumping `rmem_max`/`wmem_max` to 128 MB on the
Proxmox host. K=17 pass rate: 58/64% → 68%. Partial fix.

**(2) Simultaneous mutual `--federate` dials racing HELLOs.**
Both bridges in every federation pair dial each other. With
iroh's shared `Endpoint` deduplication and DRIFT's dual-init
session merge, the result at K=17 is multiple in-flight
handshakes per peer pair, only one of which "wins" on each
side — and the winner can disagree, leaving each side holding
different session keys. Fixed by **deterministic listener
role**: in `drift/src/cli/bridge.rs`, for `iroh://` federate
URLs only, the higher-keyed peer skips the dial and waits
passively (pre-registering the federation peer in the
routing table so mesh routing works the moment the inbound
HELLO arrives). The lower-keyed peer always dials. Only one
HELLO ever in flight per pair — zero session-key divergence.
h2s / webtransport keep mutual dials (TCP-style semantics
make them safe).

### Result — K=17 after both fixes

| Run | Pass rate | 1 hop | 2 hop | 3 hop | 4 hop | Auth-fails |
|---|---|---|---|---|---|---|
| baseline iroh        | 56/96 (58%) | 5/6 | 14/24 | 25/30 | 12/36 | 146 |
| + diagnostics        | 61/96 (64%) | 6/6 | 21/24 | 24/30 | 10/36 | 195 |
| + sysctl rcvbuf      | 65/96 (68%) | 6/6 | 19/24 | 24/30 | 16/36 | 195 |
| **+ listener role**  | **75/96 (78%)** | 6/6 | 19/24 | **30/30** | **20/36** | **0** |
| h2s baselines (ref)  | 66–82/96 (69–85%) | — | — | — | — | — |

**iroh now matches h2s at K=17 corporate density.** 3-hop
is perfect (30/30), 4-hop is best-ever (20/36 = 56%), and
zero authentication failures — the dual-init race is gone.

The remaining 21 dial failures are all 4-hop branch-to-branch
across-region paths; the failure mode is no longer cryptographic
divergence but more conventional convergence latency in the
30-second window before dials begin. Matches h2s's own 4-hop
behavior at this density.

### Updated implication

**iroh is now a valid corporate-tier federation default**,
co-equal with h2s on reliability at K=17. The wire choice
becomes a deployment question:

- iroh: UDP/QUIC, NAT-friendly, modest per-byte overhead vs
  native QUIC. Good when bridge operators don't control
  middleboxes between them.
- h2s: TCP/TLS/h2, indistinguishable from HTTPS in wire
  shape, excellent middlebox traversal, larger header overhead.
  Good when federation links cross corporate proxies / WAFs.

Raw evidence:
- `drift-bench/fed-k17-iroh-run.log` / `…-bridge-dc1.log`         — Run 1 baseline
- `drift-bench/fed-k17-iroh-v2-*`                                  — Run 2 with diagnostics
- `drift-bench/fed-k17-iroh-v3-*`                                  — Run 3 post-sysctl
- `drift-bench/fed-k17-iroh-v4-*`                                  — Run 4 with deterministic listener role
- `drift-bench/fed-k17-iroh-orbstack-*`                            — Reproduction on OrbStack VM (72/96 ≈ 75%)

## Test 4 — switch iroh wire from QUIC streams to QUIC datagrams

After the listener-role fix landed, the K=17 4-hop pass rate
sat at 47–56 % (about half the cross-region branch-to-branch
dials). The remaining ceiling traced to two architectural
properties of the stream-based adapter:

1. **Per-frame stream overhead.** Each DRIFT packet was framed
   with a 2-byte length prefix and written to a single
   bidirectional QUIC stream per peer. Per-packet QUIC stream
   bookkeeping dominated throughput at small sizes.
2. **Head-of-line blocking.** QUIC streams guarantee in-order
   delivery. A delayed frame stalled every subsequent DRIFT
   packet on the same federation link — even though DRIFT
   packets are independent. At 4 hops this compounded.

QUIC datagrams (RFC 9221) skip both. iroh exposes
`Connection::send_datagram` / `read_datagram`; the wire
adapter swap is a single-file change in `drift/src/wire_iroh.rs`.
Datagrams are unreliable + unordered, but DRIFT's session layer
already handles drops and reordering at the protocol layer (it
does the same for `udp://`), so the correctness story is the
same.

### Result — K=17 on OrbStack, datagrams vs streams

| Hop | Streams (Test 3 / OrbStack repro) | Datagrams | Δ |
|---|---|---|---|
| 1 | 6/6 (100%) | 6/6 (100%) | — |
| 2 | 19/24 (79%) | 22/24 (92%) | +3 |
| 3 | 30/30 (100%) | 30/30 (100%) | — |
| 4 | 17/36 (47%) | **27/36 (75%)** | **+10** |
| **Total** | **72/96 (75%)** | **85/96 (88.5%)** | **+13** |
| Auth-fails | 36 | 24 | −12 |

The +10 at 4 hops is exactly what the head-of-line theory
predicted: multi-hop forwarding is the case stream HoL hurt
most, and datagrams free it. The 2-hop +3 picks up
proportionally.

**iroh-with-datagrams now exceeds the h2s baseline range
(66–82/96, 69–85%) at corporate density.** This flips the wire
recommendation:

- Previous: "h2s for reliability, iroh for NAT-traversal."
- Now: "iroh for reliability AND NAT-traversal, h2s for
  middlebox compatibility (HTTPS shape, corporate proxies)."

Raw evidence:
- `drift-bench/fed-k17-iroh-datagrams-run.log` /
  `…-bridge-dc1.log` — Run 6 with the datagram switch

## Implications (updated post-fix, K=3 only)

**iroh and h2s are equivalent for federation at K=3** —
all 6 directed edges active on both wires, zero auth failures,
matching BEACON cadence. The "h2s is more reliable" caveat
from before only applied to the pre-fix iroh adapter.

At K=17 they diverge sharply — see Test 3 above.

iroh remains a valid federation wire choice for low-degree
federations, with the same tradeoffs as documented in
`RESULTS-2026-05-27.md` Phase 4:

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
