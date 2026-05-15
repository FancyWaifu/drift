# Federation Discovery — Design + Implementation

**Status:** Phases A, B, C, D, **E v1 + E v2** all implemented, plus intermediate hop signing and background GC. Bloom-filter probing remains deferred (acknowledged trade-offs).
Extends `SPEC.md §10`.

This document proposes the protocol additions needed so a DRIFT client can reach any peer in the federation **without** specifying a `via_bridge` in `drift.toml`. Today the client must know which bridge holds the target; tomorrow, any bridge in the federation can resolve and forward.

---

## 1. Problem

A `drift.toml` entry today looks like:

```toml
[hosts.bob]
pubkey      = "ab12…cd34"
via_bridge  = "426b…bfc025"   # ← client must know which bridge Bob is on
```

This is brittle:
- Bob can't move between bridges without every client editing their config.
- Roaming peers (laptop home → phone on cellular, same identity) can't be reached transparently.
- Onboarding a new client requires out-of-band knowledge of the federation topology.

We want this:

```toml
[hosts.bob]
pubkey = "ab12…cd34"           # via_bridge optional; bridges resolve via discovery
```

---

## 2. What already exists (§10)

DRIFT's wire format is ahead of the routing logic. The following are already implemented:

| Mechanism | Purpose | Status |
|---|---|---|
| `UNKNOWN_BRIDGE_PUB` sentinel (§10.1) | Client signals "I don't know which bridge holds the target" | Wire-level |
| `PresenceTicket` (§10.2) | XEdDSA-signed proof "client X authorizes bridge Y to announce them" | Wire + verify |
| `FederationDirectory v2` (§10.3) | Bridge-to-bridge announce of `(client_pub, ticket)` entries | Wire + receive |
| `PresenceTicket` packet (§10.4) | Client → bridge ticket emission | Implemented |
| First-write-wins + source-auth | Anti-hijack rules on directory writes | Enforced |

Together these implement a **proactive, 1-hop announce model**: bridge A tells every bridge it federates with "these clients are at me, with these tickets." A client on a bridge that directly federates with A can resolve any client on A via the cached directory.

The gap is everything beyond one hop.

---

## 3. What's missing

The user's proposed flow:

> A bridge will ask "Do I have this user?" If no, "Does anyone have this user?" is sent out to its connected bridges, and it'll keep asking until it found the client. Then it forms a route to them or caches that route.

Three concrete protocol gaps:

1. **Multi-hop propagation.** FederationDirectory only announces *directly connected clients*, not learned routes. A → B → C: B knows about A's clients, but C doesn't.

2. **Reactive lookup.** Discovery is announce-driven. A client appearing on bridge A is invisible to bridge C until the next announce cycle (~7s) plus propagation. We have no "ask now" path.

3. **Negative caching + path failure.** No mechanism to express "I asked, nobody has X" or "the route via B is broken; flush it."

---

## 4. Proposal

Add two new packet types and one extension to FederationDirectory:

| New | PacketType | Direction | Purpose |
|---|---|---|---|
| `FindPeer` | 22 | bridge ↔ bridge | "Does any federated bridge host pubkey X?" |
| `PeerHere` | 23 | bridge ↔ bridge | "I host X (or I learned a path to X), here's a signed ticket chain" |
| `PeerGone` | 24 | bridge → federation | "Client X just disconnected from me; flush caches" |
| ext to `FederationDirectory v2` | 20 | bridge ↔ bridge | Optional `hops` field per entry (transitive learned routes) |

Together they implement a recursive lookup with multi-hop propagation. Cache results so the second lookup for the same peer is free. Disconnects propagate instantly via `PeerGone` instead of waiting on the next idempotent-set announce.

---

## 5. Wire formats

### 5.1 `FindPeer` (PacketType 22)

Sent inside an AEAD-sealed body, like other federation messages.

```
[0..32]    target_client_pub  (32 — the pubkey we're looking for)
[32..40]   query_id           (u64 BE — random, used for loop detection + reply correlation)
[40..41]   ttl                (u8 — hops remaining; decremented at each forwarder)
[41..73]   originator_bridge  (32 — the bridge that started the query; reply routes here)
[73..81]   originator_query_at_ms (u64 BE — for deadline enforcement)
```

Total: **81 bytes**.

Constants:

| Constant | Value | Rationale |
|---|---|---|
| `MAX_FIND_TTL` | `4` | Federations beyond 4 hops are unlikely; bounds blast radius |
| `MAX_FIND_DEADLINE_MS` | `2000` | Hard cap so stale queries get dropped |
| `QUERY_DEDUP_TTL_MS` | `10_000` | How long a bridge remembers seen `query_id`s |

### 5.2 `PeerHere` (PacketType 23)

```
[0..32]    target_client_pub      (32 — the pubkey this is a response for)
[32..40]   query_id               (u64 BE — matches the FindPeer)
[40..41]   path_len               (u8 — number of hops in the path chain, 1..=MAX_FIND_TTL)
[41..]     path_entries           (path_len * 128 bytes; same shape as Directory entry)

Each path_entry (128 bytes):
  [0..32]    bridge_pub             (which bridge in the chain)
  [32..128]  ticket                 (96-byte XEdDSA presence ticket — see §10.2.1)
```

The `path_entries` are ordered **from terminal to origin** — index 0 is the bridge that actually has the client; index `path_len - 1` is the bridge that signed the reply for the originator.

Total: `41 + path_len * 128` bytes. At `MAX_FIND_TTL = 4`: max 553 bytes.

### 5.3 `PeerGone` (PacketType 24)

Sent by a bridge to every federation peer the moment a local client disconnects (transport close, session timeout, or explicit logout). Lets receivers evict cached routing immediately instead of waiting for the next idempotent-set announce cycle.

```
[0..32]   client_pub      (32 — the disconnected client)
[32..40]  emitted_at_ms   (u64 BE — wall-clock at emission; receivers use this to break ties if two PeerGone for the same client arrive interleaved with announces)
[40..72]  bridge_pub      (32 — emitting bridge; redundant with the federation transport's source but carried inside the AEAD for forward-compat with eventual multi-hop forwarding)
```

Total: **72 bytes**.

Reception rules:
1. Source must be in `federation_table` (same source-auth gate as Directory).
2. Receiver evicts the matching `peer_directory` entry **only if** the cached entry's `terminal_bridge == bridge_pub` from the PeerGone. PeerGone from bridge X cannot evict a route through bridge Y.
3. If the receiver has an in-flight `PeerHere` cache with a stale tiebreaker (i.e., `learned_at > emitted_at_ms`), it keeps the cache — the client moved to a new bridge after the gone-event, and the newer route wins.
4. PeerGone is **not** forwarded beyond direct federation peers in Phase A. (Multi-hop propagation lands with the rest of multi-hop in Phase B.)

### 5.4 `FederationDirectory v2` extension — optional `hops` field

Instead of a separate "learned-route announcement," extend Directory entries with a single hop counter to advertise *transitively-known* peers. To stay wire-compatible with existing v2 implementations, this becomes v3:

```
[0]       version  (u8) = 3
[1]       reserved (u8) = 0
[2..4]    count    (u16 BE — number of entries)
[4..]     entries  (count * 129-byte entries)

Each entry (129 bytes):
  [0..32]    client_pub  (32)
  [32..128]  ticket      (96 — issued by client_pub for the bridge AT HOP 0 of the path)
  [128..129] hops        (u8 — 0 = directly connected, 1..N = transitively known via N hops)
```

v3 receivers fall back to treating v2 announcements as v3 entries with `hops = 0`.

---

## 6. Algorithms

### 6.1 Client → local bridge (unchanged)

Client builds a `Federated` packet with `target_bridge_pub = UNKNOWN_BRIDGE_PUB`. Local bridge sees the sentinel and enters the directory-lookup path below.

### 6.2 Bridge: directory-lookup path

```
fn handle_unknown_bridge(target_client: [u8; 32], envelope: &FederatedEnvelope) -> Action {
    // 1. Local directory — fastest case
    if let Some(entry) = self.peer_directory.get(&target_client) {
        if verify_ticket(&target_client, &entry.next_hop_bridge, &entry.ticket, now()).is_ok() {
            return Action::ForwardTo(entry.next_hop_bridge);
        }
        // expired ticket — fall through to re-query
        self.peer_directory.remove(&target_client);
    }

    // 2. Pending query — coalesce
    if let Some(pending) = self.pending_finds.get_mut(&target_client) {
        pending.waiters.push(envelope.clone());
        return Action::Hold;
    }

    // 3. Originate a FindPeer
    let q = FindPeer {
        target_client_pub: target_client,
        query_id: csprng_u64(),
        ttl: MAX_FIND_TTL,
        originator_bridge: self.bridge_pub,
        originator_query_at_ms: now_ms(),
    };
    self.pending_finds.insert(target_client, Pending {
        query_id: q.query_id,
        waiters: vec![envelope.clone()],
        started_at: now_ms(),
    });
    for fed_peer in self.federation_table.iter() {
        self.send_find_peer(fed_peer, &q);
    }
    Action::Hold
}
```

### 6.3 Bridge: receive `FindPeer`

```
fn handle_find_peer(q: FindPeer, from_fed_peer: BridgeId) -> Option<PeerHere> {
    // Loop detection
    if self.recent_queries.contains(&q.query_id) {
        return None;
    }
    self.recent_queries.insert_with_ttl(q.query_id, QUERY_DEDUP_TTL_MS);

    // Deadline
    if now_ms() > q.originator_query_at_ms + MAX_FIND_DEADLINE_MS {
        return None;
    }

    // Direct hit
    if let Some(local) = self.local_clients.get(&q.target_client_pub) {
        let ticket = local.current_ticket();
        let path = vec![PathEntry { bridge_pub: self.bridge_pub, ticket }];
        let reply = PeerHere { target_client_pub: q.target_client_pub, query_id: q.query_id, path };
        self.send_peer_here(from_fed_peer, &reply);
        return Some(reply);
    }

    // Indirect hit — we already learned a route
    if let Some(entry) = self.peer_directory.get(&q.target_client_pub) {
        // Re-emit using the cached path
        return Some(reply_from_cache(entry, q.query_id));
    }

    // Recurse
    if q.ttl > 1 {
        let onward = FindPeer { ttl: q.ttl - 1, ..q };
        for fed_peer in self.federation_table.iter().filter(|p| **p != from_fed_peer) {
            self.send_find_peer(fed_peer, &onward);
        }
    }

    // Reply will (or won't) arrive asynchronously — no-op for now
    None
}
```

### 6.4 Bridge: receive `PeerHere`

```
fn handle_peer_here(reply: PeerHere, from_fed_peer: BridgeId) {
    // Verify the path: each ticket must verify against the bridge_pub at hop 0
    let terminal_bridge = reply.path[0].bridge_pub;
    if verify_ticket(&reply.target_client_pub, &terminal_bridge, &reply.path[0].ticket, now_ms()).is_err() {
        self.metrics.invalid_peer_here.inc();
        return;
    }

    // Cache the route — next_hop is the federation peer that delivered this reply
    let hops = reply.path.len() as u8 - 1;
    self.peer_directory.insert(reply.target_client_pub, DirectoryEntry {
        next_hop_bridge: from_fed_peer,
        terminal_bridge,
        ticket: reply.path[0].ticket.clone(),
        hops,
        learned_at: now_ms(),
    });

    // Flush any pending waiters for this peer
    if let Some(pending) = self.pending_finds.remove(&reply.target_client_pub) {
        for env in pending.waiters {
            self.forward_federated(env, from_fed_peer);
        }
    }

    // Optionally re-emit upstream if we're a forwarder (not the originator)
    if reply.query_id matches an upstream query {
        let onward_path = reply.path.with_added_hop(self.bridge_pub, self.current_local_ticket_for(...));
        self.send_peer_here(upstream_peer, &PeerHere { path: onward_path, ..reply });
    }
}
```

### 6.5 Path expiry & invalidation

| Event | Action |
|---|---|
| `PeerHere` arrives | Insert into `peer_directory`, TTL = `min(ticket.expiry_ms, now + 60_000)` |
| Forwarding to `next_hop` fails (transport error) | Evict entry immediately; next packet triggers a fresh `FindPeer` |
| Pending query timeout (no `PeerHere` within `MAX_FIND_DEADLINE_MS`) | Drop the queued envelopes; insert negative-cache entry for `5s` |
| Local client disconnects | Bridge immediately emits `PeerGone(client_pub, bridge_pub)` to every federation peer (§5.3). Receivers evict matching cache entries within one RTT. Backstop: the next idempotent-set Directory announce omits the client (§10.3.2). |

---

## 7. Security & trust analysis

### 7.1 What a malicious federated bridge can do

| Attack | Defense |
|---|---|
| Announce "I have peer X" without X's consent | Tickets are signed by X, not by the bridge. Verifier (`verify_ticket`) checks X's signature over `(bridge_pub, expiry, nonce)`. A lying bridge produces a sig that fails verification. |
| Re-announce a stolen ticket at a different bridge | The signed message embeds `bridge_pub`. A ticket signed for bridge A never verifies as a ticket-for-bridge-B. (Already true today.) |
| Send `PeerHere` with a stale ticket | Expiry check in `verify_ticket(…, now_ms)` rejects expired tickets. |
| Drop traffic for X (blackhole) | Detectable via path failure; client retries elicit new `FindPeer`, route eventually converges to a working bridge. Worst case: DoS, not eavesdropping. (E2E session keys are between client and X, not between client and bridges.) |
| Flood the federation with `FindPeer` storms | Per-`(originating_bridge, query_id)` dedup; per-fed-peer rate limit (~20 queries/sec). |

### 7.2 Privacy considerations

The protocol leaks "someone is looking for pubkey X" to every bridge along the BFS path. Mitigations, in increasing order of cost:

1. **Baseline (accepted):** every bridge in the federation that participates in the search learns the target pubkey. This is comparable to DNS recursion: every nameserver in the chain learns what you queried.

2. **Opt-in onion'd queries:** the originator wraps `FindPeer` for each hop with a layered AEAD. Each forwarding bridge can only decrypt enough to know "forward to next federation peers" but not the target. Substantial complexity; defer.

3. **Bloom-filter probing:** announce `BloomFilter(local_clients)` instead of full pubkey lists; the lookup tests membership without revealing the target. Subtle trade-offs around false positives. Defer.

For v1: accept (1). Document it. Users with strong privacy needs continue using explicit `via_bridge`.

### 7.3 Replay & flooding

- `query_id` is a 64-bit random; collision-resistant for any realistic federation size.
- Bridges keep a seen-set of `query_id`s for `QUERY_DEDUP_TTL_MS = 10s`. Same query_id arriving twice → silently dropped.
- Originator deadline (`MAX_FIND_DEADLINE_MS = 2s`) bounds how long a query lives in flight.

---

## 8. Multi-hop announce (v3) vs. on-demand `FindPeer` — when each fires

Both mechanisms ship. They cooperate:

| Scenario | Wins |
|---|---|
| Long-running federation with stable peers | v3 announces with `hops > 0` populate caches proactively; no `FindPeer` needed |
| Brand-new peer joins; client immediately tries to reach them | `FindPeer` resolves before next announce cycle (~7s) |
| Federation partition heals | First post-heal cross-partition packet triggers `FindPeer`; cache repopulates |
| Peer roams between bridges | Old bridge stops announcing them (idempotent-set); receivers evict; next reach triggers `FindPeer` |

Rule of thumb: **announce is the warm cache; `FindPeer` is the cold path.**

---

## 9. Backward compatibility

| Peer version | Behavior |
|---|---|
| v1 (today) | Doesn't know `FindPeer`/`PeerHere`; receives unknown PacketType → silent drop. v1 bridges still serve their direct clients normally; just don't participate in multi-hop discovery. |
| v2 receives v3 directory entry | Currently: rejects whole packet as unknown version. **Fix in v3 implementation:** v3 senders include a v2-shaped chunk for backward-compat until v2 is fully retired. |

The `via_bridge` field in `drift.toml` remains supported. With this proposal it becomes optional, not deprecated. Power users who want deterministic routing can still pin a specific bridge.

---

## 10. Implementation phases

Suggested incremental rollout — each phase is independently usable:

**Phase A — `FindPeer` / `PeerHere` / `PeerGone` between directly-federated bridges (no multi-hop). DONE.**
- ✓ New PacketTypes 22, 23, 24 (`drift-core::header`).
- ✓ Wire codecs (`drift/src/transport/find_peer.rs`, 10 unit tests).
- ✓ Bridge state: `pending_finds`, `recent_queries`, `neg_cache` (`transport::Inner`).
- ✓ `handle_federated`'s `UNKNOWN_BRIDGE_PUB` branch originates `FindPeer` + coalesces waiters.
- ✓ Reply handler caches + flushes waiters; verifies terminal ticket.
- ✓ `PeerGone` emit on local-client disconnect + eviction handling.
- ✓ Integration tests (`drift/tests/federation_discovery.rs`):
  - `find_peer_resolves_cross_bridge_and_caches`
  - `peer_gone_evicts_cached_route`

**Phase B — Multi-hop propagation. DONE.**
- ✓ `MAX_FIND_TTL = 4` honored end-to-end.
- ✓ `recent_queries` seen-set blocks duplicate query_ids within `QUERY_DEDUP_TTL_MS = 10s`.
- ✓ `forwarded_queries` table on `Inner` tracks queries we forwarded for upstream peers.
- ✓ `handle_find_peer` recurses on local miss when `ttl > 1`, excludes the sender, fans out to remaining federation peers.
- ✓ `handle_peer_here` appends local bridge + stub-ticket to path before re-emitting upstream (intermediate hops cryptographically unverified for now — Phase C will add hop-attestation tickets).
- ✓ Transit bridges cache the route too (free win — their own future traffic benefits).
- ✓ Integration test (`find_peer_multi_hop_chain` in `drift/tests/federation_discovery.rs`): A — B — C chain with no A↔C edge; C reaches A's client through B's transparent forward.

**Phase C — `FederationDirectory v3` with `hops` field. DONE.**
- ✓ Wire codec v3 in `drift/src/transport/federated.rs` (129-byte entries; 4 new unit tests).
- ✓ Side-tables `peer_directory_hops` + `peer_directory_tickets` on `Inner`.
- ✓ `parse_directory_v3` accepts both v2 (treats hops=0) and v3 — clean upgrade path.
- ✓ `announce_directory` builds combined v3 payload (direct entries hops=0 + cached transitive entries hops+1), with split-horizon to skip entries learned FROM the recipient.
- ✓ `handle_federation_directory` parses v3, anti-loops by ignoring claims about our own local clients, mirrors prune across side-tables.
- ✓ `MAX_ANNOUNCE_HOPS = 2` cap honored.
- ✓ Integration test: `proactive_announce_propagates_2_hops` (3-bridge chain, no FindPeer fired, cache populates via announce alone).

**Phase D — drift.toml UX. DONE.**
- ✓ `via_bridge` already typed as `Option<String>` in `drift-config::schema` — no schema change required.
- ✓ `drift-mosh/README.md`: added paragraph explaining that target hosts with only `pubkey` (no endpoints, no via_bridge) trigger federation discovery via the default bridge.
- ✓ `drift-vpn/README.md`: peer config table notes that `via_bridge` is optional with federation discovery enabled.
- ✓ Migration: existing configs with explicit `via_bridge` continue to route directly (skip the discovery roundtrip).

**Phase E v1 (minimal) — privacy opt-out. DONE.**
- ✓ `TransportConfig::find_peer_disabled: bool` flag (kept as deprecated alias).
- ✓ When set: UNKNOWN_BRIDGE_PUB envelopes drop silently instead of triggering `FindPeer`; incoming `FindPeer` queries are dropped without reply.
- ✓ Integration test: `find_peer_disabled_blocks_discovery`.

**Phase E v2 — FindPeerMode enum + hashed targets + NoForward. DONE.**
- ✓ `FindPeerMode` enum: `Open` (default) / `NoForward` / `OriginateHashed` / `Disabled`.
- ✓ `find_peer_disabled` resolves to `Disabled` for back-compat (precedence on the deprecated bool).
- ✓ New `PacketType::FindPeerHashed = 25`. 97-byte wire format: `salt[16] || SHA-256(target || salt)[32] || query_id[8] || ttl[1] || originator_bridge[32] || originator_query_at_ms[8]`.
- ✓ `OriginateHashed` mode: bridge emits the hashed variant for outbound queries. Transit bridges that forward only see the hash; they can't identify the target unless they happen to host a matching client (in which case the local-scan reveals the match).
- ✓ `NoForward` mode: bridge answers local hits but refuses to be discovery transit. Useful for leaf bridges that don't want to relay other bridges' lookups.
- ✓ `Disabled` mode: full opt-out (same as the deprecated `find_peer_disabled = true`).
- ✓ Bridge-side scan: `hash_target_pub(client_pub, salt)` computed for each `presence_ticket` entry; O(n) per query in local-client count.
- ✓ Privacy property documented as **asymmetric, not perfect**: forwarders learn only hashes during the query phase. Once a bridge finds a match and replies with `PeerHere`, forwarders along the reply path see the real target. Bulk surveillance by intermediate bridges is defeated; targeted surveillance with a candidate list still works.
- ✓ 3 new unit tests + 2 new integration tests (`originate_hashed_resolves_and_caches`, `no_forward_mode_answers_local_but_does_not_transit`).

**Still deferred — full Phase E:**
- **Bloom-filter probing** in `FederationDirectory` announces: every bridge broadcasts `BloomFilter(local_clients)`; originators check membership locally and only fan out to filter hits. Reduces query exposure from "every bridge in the BFS" to "every bridge whose filter says yes" (true matches + false positives). Wire-format heavy and the privacy story is muddier — defer until use case warrants.
- **True onion-routed lookups** in the Sphinx / Tor sense (each forwarder sees only "next hop", never the target): requires originator to know the path in advance, which is structurally incompatible with reactive discovery. Useful only for the "I already know the route, please confirm" case — not addressed here.

**Bonus: Intermediate hop signing. DONE.**
- ✓ `find_peer::build_hop_attestation` / `verify_hop_attestation` — bridge-self-signed via XEdDSA over `"DRIFT-HOP" || bridge_pub || query_id || expiry || nonce`.
- ✓ Distinct from presence tickets via the 9-byte domain tag (cross-domain replay prevented).
- ✓ Replaces Phase B's zero-padded stub tickets in `PeerHere.path[1..]`. `handle_peer_here` now verifies every intermediate hop's attestation in addition to the terminal client ticket.
- ✓ Bonus expiry binding (60s) — stolen attestations expire fast.
- ✓ 4 new unit tests (roundtrip, wrong-signer, wrong-query-id, expired).

**Bonus: Background GC sweep. DONE.**
- ✓ `Inner::run_find_peer_gc_loop` (1s tick) spawned at construction alongside the route sweep.
- ✓ Prunes expired entries from `pending_finds` (2s lifetime), `recent_queries` (10s), `neg_cache` (5s), `forwarded_queries` (slaved to recent_queries — same query_id key).
- ✓ Bounds memory growth across long-lived bridge processes.

---

## 11. Open questions

1. **Should bridges learn from `PeerHere` replies they're forwarding, even when they're not the originator?** Pro: faster cache fill, less re-query later. Con: cache pollution if upstream lied. Lean: yes, learn — verify_ticket catches lies.

2. **Negative-cache duration.** Currently proposed `5s`. Too long and a peer that just joined is unreachable for 5s; too short and floods recur. Worth A/B testing once Phase A ships.

3. **Should `FindPeer` carry the source_client_pub** (so the answering bridge can decide whether to reveal X exists based on access policy)? Lean: no for v1 — federation is already trust-bounded; access policy belongs at the application layer.

4. **Failover on path-broken-mid-session.** If a bridge in the cached path goes down mid-flow without emitting `PeerGone` (e.g., crash, power loss), the client experiences packet loss until forwarding-error eviction kicks in (transport returns error → entry evicted → fresh `FindPeer` on retry). Possible enhancement: TCP-style RST-on-unknown-route — receiving bridges that have no cache entry for a forwarded packet send `PeerGone(unknown=true)` back. Defer to Phase B.

---

## 12. Non-goals

This proposal explicitly does NOT cover:

- **Federation membership discovery.** Bridges learn about each other from `--federate-with` config or future bootstrap, not from this protocol.
- **Cross-federation routing.** Two disjoint federations don't gossip. By design — the trust model is per-federation, transitive trust within, none across.
- **Bandwidth accounting / rate limiting between bridges.** Separate concern; see federation transport limits.
- **Application-layer discovery (petnames, contacts).** Stays in `drift-core::contacts` / `drift-core::directory`. Petname → pubkey resolution happens before this protocol kicks in.

---

## 13. Reference structures (Rust sketch)

```rust
// drift/src/transport/find_peer.rs (proposed)

use drift_core::header::PacketType;

pub const PACKET_FIND_PEER: PacketType = PacketType::new(22);
pub const PACKET_PEER_HERE: PacketType = PacketType::new(23);
pub const PACKET_PEER_GONE: PacketType = PacketType::new(24);

pub const MAX_FIND_TTL: u8 = 4;
pub const MAX_FIND_DEADLINE_MS: u64 = 2_000;
pub const QUERY_DEDUP_TTL_MS: u64 = 10_000;
pub const NEG_CACHE_TTL_MS: u64 = 5_000;

pub struct FindPeer {
    pub target_client_pub:        [u8; 32],
    pub query_id:                 u64,
    pub ttl:                      u8,
    pub originator_bridge:        [u8; 32],
    pub originator_query_at_ms:   u64,
}

pub struct PeerHere {
    pub target_client_pub: [u8; 32],
    pub query_id:          u64,
    pub path:              Vec<PathEntry>,    // 1..=MAX_FIND_TTL entries
}

pub struct PeerGone {
    pub client_pub:    [u8; 32],
    pub emitted_at_ms: u64,
    pub bridge_pub:    [u8; 32],
}

pub struct PathEntry {
    pub bridge_pub: [u8; 32],
    pub ticket:     PresenceTicket,
}

// State the bridge carries

pub struct PendingFind {
    pub query_id:     u64,
    pub waiters:      Vec<FederatedEnvelopeBytes>,
    pub started_at:   u64,
}

pub struct DirectoryEntry {
    pub next_hop_bridge:  [u8; 32],   // who we send to next on the wire
    pub terminal_bridge:  [u8; 32],   // the bridge that actually has the client
    pub ticket:           PresenceTicket,
    pub hops:             u8,
    pub learned_at:       u64,
}
```

---

## 14. References

- `SPEC.md §10` — Federation (envelope, tickets, directory v2). This proposal builds on it.
- `drift/src/transport/federated.rs` — current wire codec.
- `drift-core/src/directory.rs` — application-layer directory ("librarian") for peer-to-peer discovery without bridges. Different layer, different purpose.
- `drift-core/src/rotation.rs` — identity rotation. Relevant because rotated identities will need their new pubkey to appear in directory announcements; coordinate with rotation's announce machinery.
- Reticulum Network Stack — `LXMF`/`announce` packet design is closest analog in spirit.
- Kademlia / `FIND_NODE` — different topology (DHT vs explicit federation graph) but same recursive-query shape.
