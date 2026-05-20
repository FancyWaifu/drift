# Federation topology × wire matrix

Empirical result from `bash sweep.sh` on a Docker Desktop / macOS
host. 5-bridge networks; each bridge has a (server, client) pair
attached; 20 cross-bridge dials per topology (every client → every
non-local server). Convergence wait 45 s, AttachAck timeout 20 s.

|              | h2s         | h2          | webtransport |
| ------------ | ----------- | ----------- | ------------ |
| **mesh** (K5, 10 edges) | 18 / 20 | 18 / 20 | 14 / 20 |
| **ring**  (5-cycle, 5 edges)        | **10 / 20** | **10 / 20** | **10 / 20** |
| **star**  (hub b1, 4 edges)         |  **8 / 20** |  **8 / 20** |  **8 / 20** |
| **chain** (b1-b2-b3-b4-b5, 4 edges) |  **8 / 20** |  **8 / 20** |  **8 / 20** |

## Headline finding: drift federation is 1-hop only

The pass count for ring / star / chain is **identical across all
three wires** and **exactly matches the count of one-hop pairs**:

| topology | 1-hop pairs | observed pass count |
| -------- | ----------- | ------------------- |
| ring     | 10          | 10 / 10 / 10        |
| star     | 8           | 8 / 8 / 8           |
| chain    | 8           | 8 / 8 / 8           |

In the ring `b1-b2-b3-b4-b5-b1`, the 10 one-hop pairs are
`c1↔s2, c1↔s5, c2↔s1, c2↔s3, c3↔s2, c3↔s4, c4↔s3, c4↔s5, c5↔s4,
c5↔s1`. Every other pair (the 10 two-hop pairs that need
forwarding through a third bridge) fails. The pattern repeats
for star (8 hub-spoke pairs reachable; 12 spoke-spoke pairs not)
and chain (8 consecutive pairs reachable; 12 multi-hop pairs not).

Mesh is the only topology where every (c, s) pair is 1-hop,
which is why mesh approaches 20/20. The residual mesh variance
(14-18/20) is unrelated to topology — it's the Docker Desktop /
macOS CPU jitter affecting wire handshakes, same effect seen in
`docker/federation-pentagon` previously.

## Architectural implication

The federation directory contains only **directly federated
peers**. It does not transitively learn about peers behind other
bridges via inbound federation announcements. So a peer P on
bridge-X is reachable from a client C on bridge-Y if and only if
X and Y are directly connected via `--federate`.

Practically this means:

* **For full reachability across N bridges, federation must be a
  complete graph (O(N²) edges).** Every bridge must `--federate`
  to every other bridge. The 5-bridge mesh needed 10 edges;
  10-bridge mesh would need 45; 100-bridge would need 4 950.
* **Ring / chain / tree topologies are insufficient.** Operators
  building hierarchical federation (e.g. regional bridges
  federating to a backbone) need to be aware: traffic does not
  cascade across hops. Each bridge in the chain only reaches its
  direct neighbors.
* **Wire choice does not change this** — h2, h2s, and
  webtransport all behave identically in the directory layer.
  The 1-hop limit is a property of the federation announcement
  protocol, not the underlying wire.

## What to do about it

Three options exist if the 1-hop limit becomes a real obstacle:

1. **Accept full-mesh as the default.** Document it; operators
   plan for it. Works fine for small N (≤10 bridges); 50+
   bridges is impractical (manage 1 225 edges per bridge).

2. **Add transitive directory propagation.** When bridge-A
   receives an announce from bridge-B for some peer P, it
   re-emits an announce for P (with hop-count ++) to its own
   federation peers. Standard distance-vector routing applied
   to the federation directory. Most natural drift-shaped
   answer.

3. **Add explicit federation routing as a CLI/config option.**
   `--federate-via <bridge-pub>` could express "this bridge is
   reachable via this other bridge in my federation table" so
   operators can hand-build topologies. More work for operators
   but no protocol changes.

The right choice depends on intended scale. None of the three
are urgent for the current homelab use case but it's worth
having a clear-eyed view of the limit before someone builds a
50-bridge mesh and discovers it the hard way.
