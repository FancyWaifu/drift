# Federation topology × wire matrix

Empirical result from `bash sweep.sh` on a Docker Desktop / macOS
host. 5-bridge networks; each bridge has a (server, client) pair
attached; 20 cross-bridge dials per topology (every client → every
non-local server). Convergence wait 45 s, AttachAck timeout 20 s.

## Post-fix (commits `0c88962` + `8df7a57`, 2026-05-20)

|              | h2s         | h2          | webtransport |
| ------------ | ----------- | ----------- | ------------ |
| **mesh** (K5, 10 edges)             | **20 / 20** | **20 / 20** | **20 / 20** |
| **ring**  (5-cycle, 5 edges)        | **20 / 20** | **20 / 20** | **20 / 20** |
| **star**  (hub b1, 4 edges)         | **20 / 20** | **20 / 20** | **20 / 20** |
| **chain** (b1-b2-b3-b4-b5, 4 edges) | **20 / 20** | **20 / 20** | **20 / 20** |

**240 / 240 cross-bridge dials, every topology × every wire.**

## Pre-fix (snapshot at 2026-05-19, kept for comparison)

|              | h2s         | h2          | webtransport |
| ------------ | ----------- | ----------- | ------------ |
| **mesh** (K5, 10 edges) | 18 / 20 | 18 / 20 | 14 / 20 |
| **ring**  (5-cycle, 5 edges)        | **10 / 20** | **10 / 20** | **10 / 20** |
| **star**  (hub b1, 4 edges)         |  **8 / 20** |  **8 / 20** |  **8 / 20** |
| **chain** (b1-b2-b3-b4-b5, 4 edges) |  **8 / 20** |  **8 / 20** |  **8 / 20** |

## What was actually broken (resolved 2026-05-20)

The 2026-05-19 sweep produced the pass counts shown in the
"Pre-fix" table — pass numbers that exactly matched the count
of 1-hop pairs in each topology. Initial read was "drift
federation is 1-hop only." That turned out to be wrong: the
multi-hop machinery (FindPeer / PeerHere / multi-hop announces)
was implemented and unit-tested, but THREE bugs in the
integration prevented it from delivering end-to-end:

1. **case-2 transit-hop bug** in `handle_federated`. When a
   bridge B re-announced an entry it learned from another
   bridge C, packets forwarded back to B (with
   `target_bridge_pub = B_pub`) would hit B's "local delivery"
   path, miss the local-client check, and drop. Fix: collapse
   case 2 and case 3 — local-delivery on hit, directory lookup
   on miss. Commit `0c88962`, FEDERATION_DISCOVERY.md Phase F-1.

2. **out-of-fed-table targets dropped** for REPLY traffic.
   When a server on bridge b1 replied to a client behind
   bridge b3, but b3 wasn't in b1's federation_table (ring /
   chain topology), b1 saw a specific target it couldn't route
   to and dropped with "no route to target bridge". Fix:
   broaden the `unknown` predicate to also catch out-of-fed
   targets — they fall through to directory lookup + FindPeer
   too. Same commit, same phase.

3. **drift-mosh-client didn't register presence** with its
   on-ramp bridge. Consequence: the bridge couldn't include
   the client in its FederationDirectory announces NOR answer
   FindPeer queries about it (both gate on a presence ticket).
   The dial direction worked (client → server), but the reply
   couldn't find the client back. Fix: client now calls
   `register_presence_to(60s)` after the bridge HELLO. Same
   commit, FEDERATION_DISCOVERY.md Phase F-2.

4. **`MAX_ANNOUNCE_HOPS` was hardcoded to 2** — covered K5
   ring (max shortest-path 2) but not K5 chain (max
   shortest-path 4). Fix: promote to a `TransportConfig` field
   with default 4, exposed as `drift bridge
   --max-announce-hops <N>`. Same commit, Phase G.

Net effect on the docker sweep: 60% → 100% pass rate, with no
remaining wire-specific or topology-specific failures.

## Architectural shape (post-fix)

Drift's federation IS Reticulum-shaped, as the tagline
implies: proactive announces with hop tracking propagate
directory entries up to `max_announce_hops` hops out, and a
reactive FindPeer / PeerHere flow covers the long tail when
proactive propagation hasn't reached a target yet.

* For small federations (≤16 bridges in a chain, any-size
  full mesh): the default `max_announce_hops=4` is enough —
  proactive announces alone cover every cross-bridge pair.
* For larger or sparser topologies: either bump
  `max_announce_hops` higher, or rely on FindPeer to cover
  the gap. FindPeer has a `MAX_FIND_TTL=4` cap so it traverses
  up to 4 federation hops looking for a target — that's
  independent of the announce cap and lets sparsely-announced
  bridges still resolve each other.

The 1-hop limit conclusion in the pre-fix snapshot was a
characterization of the BUG, not the design. The bug is now
gone.
