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

## Implications

For pair-wise federation: iroh is a fine choice.

For K≥3 federation topology: **h2s is the more reliable wire**
for now. Use iroh only between specific bridge pairs that
don't mutual-initiate (one side is `--federate`, the other
side just `--listen`), or accept half-duplex BEACON flow on
mutual-init pairs (federation still works for routing, just
sub-optimal mesh visibility).

## Fixing the K=3 regression

Two paths:

1. **Don't dual-init on iroh.** Add a "we already have an
   accepted session from this peer; don't open one ourselves"
   guard in `connect_federate`'s outbound path when the wire
   is iroh. Lower-effort, narrowly-scoped.

2. **Fix the dual-init handler to populate both
   federation_table entries.** When the loser's HELLO is
   dropped in favor of the winner's, the loser still needs
   to record the merged session in its federation_table so
   mesh routing fires. Lower-blast-radius but more
   architectural.

Either approach unblocks K≥3 iroh federation. Filing as a
known issue; the artifacts in `drift-bench/fed-k3-iroh-*`
have the per-bridge log evidence.

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
