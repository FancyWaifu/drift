//! Sharded peer table.
//!
//! The original DRIFT design had a single `Mutex<PeerTable>`
//! guarding every peer entry. On servers handling thousands of
//! concurrent peers this becomes the dominant lock contention
//! point — every `send_data`, every incoming packet, every
//! background sweep takes the same mutex. Sharding splits the
//! peer table into N independently-locked HashMaps keyed by the
//! peer id, so unrelated operations don't serialize on each
//! other.
//!
//! Two access patterns:
//!
//! * **Hot path (`lock_for`)**: when the caller already knows
//!   which peer it wants (handle_data, send_data, handshake
//!   handlers, etc.), it locks just the one shard that owns
//!   that peer id. O(1) lock, no cross-shard coordination.
//! * **Cold path (`lock_all`)**: background sweeps that need
//!   to iterate every peer (beacon emission, eviction reaper,
//!   handshake retry loop) call `lock_all`, which acquires
//!   every shard in deterministic index order. Lock-ordering
//!   is fixed so deadlock is impossible.
//!
//! Choice of N: 16. Small enough that `lock_all` is cheap;
//! large enough that hot-path contention drops by ~16× under
//! uniform peer-id distribution. Peer ids are BLAKE2b
//! truncations, so the distribution is uniform by construction.

use crate::crypto::PeerId;
use crate::session::{Peer, PeerTable};
use std::collections::HashMap;
use std::net::SocketAddr;
// tokio::sync::Mutex chosen over parking_lot::Mutex despite
// the per-acquire overhead. parking_lot was tried in PERF.3
// (commit 337eb2c) for ~12% throughput on single-peer iperf;
// reverted because the elimination of implicit-yield-on-lock
// caused the loopback_full_mesh test (4 peers in one process,
// same tokio runtime, all racing the same recv loop) to drop
// from 80% pass to 0% pass — the recv loops were starving each
// other on shared workers. The async-mutex's per-acquire yield
// was load-bearing for fairness across many in-process peers.
use tokio::sync::{Mutex, MutexGuard};

/// Number of shards. Must be a power of two so we can use a
/// bit mask for the modulo.
pub(crate) const PEER_SHARD_COUNT: usize = 16;
const PEER_SHARD_MASK: u64 = (PEER_SHARD_COUNT as u64) - 1;

pub(crate) struct PeerShards {
    shards: [Mutex<PeerTable>; PEER_SHARD_COUNT],
    /// Secondary index: `peer.addr` → list of `PeerId`s.
    ///
    /// Purpose: lets the SEC.FIX.1 open-relay gate
    /// (`transport/mesh.rs::forward_packet_inner`) answer "is
    /// this incoming `src_addr` from a known peer?" in O(1)
    /// without taking `lock_all()`. The gate previously walked
    /// every peer linearly under `lock_all()`, which holds all
    /// 16 shard mutexes — defeating the entire sharding design
    /// on the hot forward path.
    ///
    /// Multi-value: NAT'd peers can transiently share a
    /// `SocketAddr` (rare; usually `len = 1`). Membership is
    /// what the gate checks; identity disambiguation is not
    /// required.
    ///
    /// Maintenance: the index is updated by `note_inserted` /
    /// `note_removed` / `note_addr_changed`, which mutation
    /// sites call alongside the corresponding shard mutation.
    /// Lock ordering is: shard → addr_index, so any code path
    /// that locks both must take them in that order. The gate
    /// (`is_known_addr`) takes only `addr_index`, so it cannot
    /// deadlock against a shard holder.
    ///
    /// Brief inconsistency windows are tolerable: a missed
    /// `note_inserted` between shard insert and index update
    /// would cause a legit peer's first packet to be dropped
    /// (false negative on the gate — no security impact, the
    /// peer retries). A missed `note_removed` would briefly
    /// allow forwards from a former-peer addr, but the
    /// downstream lookup (`peers.lock_for(dst).get(dst)`) finds
    /// no destination peer, so the forward drops without
    /// reflecting anything to the would-be victim — also no
    /// security impact.
    addr_index: Mutex<HashMap<SocketAddr, Vec<PeerId>>>,
}

impl Default for PeerShards {
    fn default() -> Self {
        // Initialize each shard with its own PeerTable. We can't
        // use `[Mutex::new(PeerTable::new()); N]` because Mutex
        // isn't Copy — go through array::from_fn instead.
        Self {
            shards: std::array::from_fn(|_| Mutex::new(PeerTable::new())),
            addr_index: Mutex::new(HashMap::new()),
        }
    }
}

#[inline]
fn shard_index(id: &PeerId) -> usize {
    // PeerId is [u8; 8], the BLAKE2b-truncated identity hash.
    // Cast the first 8 bytes to a u64 and mask. The hash is
    // already uniform so no further mixing is needed.
    let h = u64::from_be_bytes(*id);
    (h & PEER_SHARD_MASK) as usize
}

impl PeerShards {
    /// Lock just the shard that owns `id` and return a guard.
    /// The returned guard is a normal `MutexGuard<PeerTable>`,
    /// so all the existing `.get/.get_mut/.insert/.remove` call
    /// sites compile unchanged.
    pub(crate) async fn lock_for(&self, id: &PeerId) -> MutexGuard<'_, PeerTable> {
        self.shards[shard_index(id)].lock().await
    }

    /// Lock every shard in deterministic index order. Used by
    /// background sweeps that need to walk the entire peer
    /// table. The returned `AllPeersGuard` exposes the full
    /// `PeerTable` API (get, get_mut, iter, iter_mut, insert,
    /// remove, contains) so call sites that previously took
    /// `peers.lock().await` and then iterated work with only
    /// a method-name swap.
    pub(crate) async fn lock_all(&self) -> AllPeersGuard<'_> {
        let mut guards: Vec<MutexGuard<'_, PeerTable>> = Vec::with_capacity(PEER_SHARD_COUNT);
        for shard in &self.shards {
            guards.push(shard.lock().await);
        }
        AllPeersGuard { guards }
    }

    // ─── Address index — maintenance API ──────────────────────────
    //
    // Every mutation that adds, removes, or changes a peer's
    // `addr` must call the matching `note_*` helper. Lock
    // ordering: shard → addr_index. Callers may hold the shard
    // lock when calling these; they must not call them while
    // holding the addr_index lock.

    /// Record that a peer with `id` was inserted at `addr`.
    /// Must be called by every site that does
    /// `peers.insert(...)` on a shard guard. Idempotent on the
    /// `(id, addr)` pair — calling twice without an intervening
    /// `note_removed` is a bug but is tolerated (the duplicate
    /// entry would self-correct on next remove).
    pub(crate) async fn note_inserted(&self, id: PeerId, addr: SocketAddr) {
        let mut idx = self.addr_index.lock().await;
        let entry = idx.entry(addr).or_default();
        if !entry.contains(&id) {
            entry.push(id);
        }
    }

    /// Record that a peer with `id` at `addr` was removed.
    /// Must be called by every site that does
    /// `peers.remove(...)` on a shard guard. Tolerant of
    /// double-remove (a no-op if the index doesn't have the
    /// entry).
    pub(crate) async fn note_removed(&self, id: &PeerId, addr: SocketAddr) {
        let mut idx = self.addr_index.lock().await;
        if let Some(vec) = idx.get_mut(&addr) {
            vec.retain(|p| p != id);
            if vec.is_empty() {
                idx.remove(&addr);
            }
        }
    }

    /// Record that a peer with `id` migrated from `old_addr` to
    /// `new_addr`. Must be called by every site that mutates
    /// `peer.addr` on a `&mut Peer`. If `old_addr == new_addr`
    /// the call is a no-op.
    pub(crate) async fn note_addr_changed(
        &self,
        id: PeerId,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    ) {
        if old_addr == new_addr {
            return;
        }
        let mut idx = self.addr_index.lock().await;
        if let Some(vec) = idx.get_mut(&old_addr) {
            vec.retain(|p| p != &id);
            if vec.is_empty() {
                idx.remove(&old_addr);
            }
        }
        let entry = idx.entry(new_addr).or_default();
        if !entry.contains(&id) {
            entry.push(id);
        }
    }

    /// SEC.FIX.1 gate query: does an established peer currently
    /// have `addr` as its known socket address?
    ///
    /// Two-step pattern, deliberately safety-netted against
    /// missed maintenance:
    ///
    ///   1. Fast O(1) check of `addr_index`. If no candidates,
    ///      return `false` immediately — no shard locks taken.
    ///      This is the common case for attack traffic from
    ///      random source addrs.
    ///   2. If the index has candidates, lock each candidate's
    ///      shard and verify the live `peer.addr` actually
    ///      equals `addr`. Catches stale-positive entries that
    ///      would arise if a `note_removed` or
    ///      `note_addr_changed` call was missed somewhere.
    ///
    /// Worst case if maintenance is wrong: a stale entry causes
    /// the gate to do one extra shard lock per candidate before
    /// returning `false` — never a silent open-relay regression.
    /// Best case (maintenance correct): O(1) negative for
    /// attack traffic, single-shard verify for legit traffic.
    /// Either way, strictly faster than the pre-index
    /// `lock_all()` walk on every forwarded packet.
    pub(crate) async fn addr_belongs_to_known_peer(&self, addr: &SocketAddr) -> bool {
        let candidates: Vec<PeerId> = {
            let idx = self.addr_index.lock().await;
            match idx.get(addr) {
                Some(v) if !v.is_empty() => v.clone(),
                _ => return false,
            }
        };
        for id in &candidates {
            let shard = self.shards[shard_index(id)].lock().await;
            if let Some(peer) = shard.get(id) {
                if peer.addr == *addr {
                    return true;
                }
            }
        }
        false
    }

    /// Test-only: raw index check, no verify pass. Lets tests
    /// distinguish "index has the addr" from "addr actually
    /// belongs to a peer right now."
    #[cfg(test)]
    pub(crate) async fn is_known_addr_in_index(&self, addr: &SocketAddr) -> bool {
        self.addr_index.lock().await.contains_key(addr)
    }

    /// Test-only snapshot of the addr_index. Used by the sweep
    /// test to assert the index agrees with `lock_all().iter()`
    /// after each mutation step.
    #[cfg(test)]
    pub(crate) async fn addr_index_snapshot(&self) -> HashMap<SocketAddr, Vec<PeerId>> {
        self.addr_index.lock().await.clone()
    }
}

/// All shards locked, exposed as if it were a single
/// `PeerTable`. Holding this is `O(N)` mutexes; only used on
/// the slow background paths.
pub(crate) struct AllPeersGuard<'a> {
    guards: Vec<MutexGuard<'a, PeerTable>>,
}

impl<'a> AllPeersGuard<'a> {
    #[allow(dead_code)]
    pub(crate) fn get(&self, id: &PeerId) -> Option<&Peer> {
        self.guards[shard_index(id)].get(id)
    }

    pub(crate) fn get_mut(&mut self, id: &PeerId) -> Option<&mut Peer> {
        self.guards[shard_index(id)].get_mut(id)
    }

    pub(crate) fn contains(&self, id: &PeerId) -> bool {
        self.guards[shard_index(id)].contains(id)
    }

    pub(crate) fn insert(&mut self, peer: Peer) {
        let idx = shard_index(&peer.id);
        self.guards[idx].insert(peer);
    }

    pub(crate) fn remove(&mut self, id: &PeerId) -> Option<Peer> {
        self.guards[shard_index(id)].remove(id)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Peer> + use<'_, 'a> {
        self.guards.iter().flat_map(|g| g.iter())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Peer> + use<'_, 'a> {
        self.guards.iter_mut().flat_map(|g| g.iter_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn pid(b: u8) -> PeerId {
        [b; 8]
    }

    #[tokio::test]
    async fn note_inserted_makes_addr_known() {
        let shards = PeerShards::default();
        assert!(!shards.is_known_addr_in_index(&addr(9000)).await);
        shards.note_inserted(pid(1), addr(9000)).await;
        assert!(shards.is_known_addr_in_index(&addr(9000)).await);
    }

    #[tokio::test]
    async fn note_removed_makes_addr_unknown() {
        let shards = PeerShards::default();
        shards.note_inserted(pid(1), addr(9000)).await;
        shards.note_removed(&pid(1), addr(9000)).await;
        assert!(!shards.is_known_addr_in_index(&addr(9000)).await);
    }

    #[tokio::test]
    async fn shared_addr_remains_known_until_last_peer_removed() {
        let shards = PeerShards::default();
        shards.note_inserted(pid(1), addr(9000)).await;
        shards.note_inserted(pid(2), addr(9000)).await;
        shards.note_removed(&pid(1), addr(9000)).await;
        assert!(
            shards.is_known_addr_in_index(&addr(9000)).await,
            "addr still has pid(2)"
        );
        shards.note_removed(&pid(2), addr(9000)).await;
        assert!(!shards.is_known_addr_in_index(&addr(9000)).await);
    }

    #[tokio::test]
    async fn note_addr_changed_moves_membership() {
        let shards = PeerShards::default();
        shards.note_inserted(pid(1), addr(9000)).await;
        shards
            .note_addr_changed(pid(1), addr(9000), addr(9001))
            .await;
        assert!(!shards.is_known_addr_in_index(&addr(9000)).await);
        assert!(shards.is_known_addr_in_index(&addr(9001)).await);
    }

    #[tokio::test]
    async fn note_addr_changed_noop_when_addr_unchanged() {
        let shards = PeerShards::default();
        shards.note_inserted(pid(1), addr(9000)).await;
        shards
            .note_addr_changed(pid(1), addr(9000), addr(9000))
            .await;
        assert!(shards.is_known_addr_in_index(&addr(9000)).await);
        let snap = shards.addr_index_snapshot().await;
        assert_eq!(snap.get(&addr(9000)).map(|v| v.len()), Some(1));
    }

    #[tokio::test]
    async fn double_insert_does_not_dup_entry() {
        let shards = PeerShards::default();
        shards.note_inserted(pid(1), addr(9000)).await;
        shards.note_inserted(pid(1), addr(9000)).await;
        let snap = shards.addr_index_snapshot().await;
        assert_eq!(
            snap.get(&addr(9000)).map(|v| v.len()),
            Some(1),
            "duplicate (id, addr) must dedupe"
        );
    }

    #[tokio::test]
    async fn double_remove_is_noop() {
        let shards = PeerShards::default();
        shards.note_inserted(pid(1), addr(9000)).await;
        shards.note_removed(&pid(1), addr(9000)).await;
        // Second remove must not panic or corrupt state.
        shards.note_removed(&pid(1), addr(9000)).await;
        assert!(!shards.is_known_addr_in_index(&addr(9000)).await);
    }

    // ─── Verify-pass tests (the gate's actual API) ───────────────
    //
    // These exercise `addr_belongs_to_known_peer`, which combines
    // the index check with a shard-verify. The index alone can
    // be wrong (stale positive); the verify pass catches that.

    use crate::session::Peer;
    use drift_core::crypto::Direction;

    fn mk_peer(id_byte: u8, port: u16) -> Peer {
        Peer::new(
            pid(id_byte),
            addr(port),
            [id_byte; 32],
            Direction::Initiator,
        )
    }

    #[tokio::test]
    async fn verify_pass_returns_true_when_peer_actually_has_addr() {
        let shards = PeerShards::default();
        {
            let mut shard = shards.lock_for(&pid(1)).await;
            shard.insert(mk_peer(1, 9000));
        }
        shards.note_inserted(pid(1), addr(9000)).await;
        assert!(shards.addr_belongs_to_known_peer(&addr(9000)).await);
    }

    #[tokio::test]
    async fn verify_pass_rejects_stale_positive() {
        // Simulate a missed `note_removed`: the index says
        // pid(1) lives at addr(9000), but the actual peer
        // table has nothing. The verify pass MUST return
        // false — this is the security-load-bearing case.
        let shards = PeerShards::default();
        shards.note_inserted(pid(1), addr(9000)).await;
        assert!(
            shards.is_known_addr_in_index(&addr(9000)).await,
            "precondition: index has the entry"
        );
        // Note: we DON'T insert into the shard. The shard is
        // empty, but the index has a stale entry. Verify must
        // catch this.
        assert!(
            !shards.addr_belongs_to_known_peer(&addr(9000)).await,
            "stale-positive index entry must NOT pass the verify step"
        );
    }

    #[tokio::test]
    async fn verify_pass_rejects_stale_addr_change() {
        // Simulate a missed `note_addr_changed`: the index
        // says pid(1) lives at addr(9000), but pid(1) has
        // actually migrated to addr(9001). A forward from
        // addr(9000) must NOT be authorized.
        let shards = PeerShards::default();
        {
            let mut shard = shards.lock_for(&pid(1)).await;
            shard.insert(mk_peer(1, 9001)); // peer's REAL addr
        }
        shards.note_inserted(pid(1), addr(9000)).await; // stale index
        assert!(
            !shards.addr_belongs_to_known_peer(&addr(9000)).await,
            "stale addr in index must be caught by verify"
        );
        // The real addr should still verify.
        shards.note_inserted(pid(1), addr(9001)).await;
        assert!(
            shards.addr_belongs_to_known_peer(&addr(9001)).await,
            "real addr should pass verify"
        );
    }

    #[tokio::test]
    async fn verify_pass_fast_negative_when_index_empty() {
        let shards = PeerShards::default();
        // No mutations whatsoever. Gate must say false in
        // O(1) without touching any shard.
        assert!(!shards.addr_belongs_to_known_peer(&addr(9000)).await);
    }

    /// Sweep: randomized interleaving of insert/remove/addr-change.
    /// After each step, the addr_index must agree with what a
    /// hypothetical `lock_all().iter()` walk would build from
    /// scratch. We simulate that walk by tracking the expected
    /// state in a parallel `HashMap` and asserting equality.
    #[tokio::test]
    async fn sweep_addr_index_matches_ground_truth() {
        use std::collections::HashMap;
        let shards = PeerShards::default();
        let mut truth: HashMap<SocketAddr, Vec<PeerId>> = HashMap::new();

        // Deterministic pseudo-random sequence (no rand dep).
        // 50 operations across 8 peer ids and 4 addrs.
        let ops = 50;
        let peer_count = 8u8;
        let addr_count = 4u16;
        for step in 0..ops {
            let id = pid((step % peer_count as usize) as u8);
            let addr_a = addr(9000 + ((step * 7) % addr_count as usize) as u16);
            let addr_b = addr(9000 + ((step * 11) % addr_count as usize) as u16);
            let op = step % 4;
            match op {
                0 => {
                    shards.note_inserted(id, addr_a).await;
                    let v = truth.entry(addr_a).or_default();
                    if !v.contains(&id) {
                        v.push(id);
                    }
                }
                1 => {
                    shards.note_removed(&id, addr_a).await;
                    if let Some(v) = truth.get_mut(&addr_a) {
                        v.retain(|p| p != &id);
                        if v.is_empty() {
                            truth.remove(&addr_a);
                        }
                    }
                }
                2 => {
                    shards.note_addr_changed(id, addr_a, addr_b).await;
                    if addr_a != addr_b {
                        if let Some(v) = truth.get_mut(&addr_a) {
                            v.retain(|p| p != &id);
                            if v.is_empty() {
                                truth.remove(&addr_a);
                            }
                        }
                        let v = truth.entry(addr_b).or_default();
                        if !v.contains(&id) {
                            v.push(id);
                        }
                    }
                }
                _ => {
                    // Idempotent re-insert.
                    shards.note_inserted(id, addr_b).await;
                    let v = truth.entry(addr_b).or_default();
                    if !v.contains(&id) {
                        v.push(id);
                    }
                }
            }
            let snap = shards.addr_index_snapshot().await;
            assert_eq!(
                snap.len(),
                truth.len(),
                "step {}: addr_index has {} entries, truth has {}",
                step,
                snap.len(),
                truth.len()
            );
            for (a, v) in &truth {
                let actual = snap.get(a).expect("missing addr in snapshot");
                // Order may differ; compare as sets.
                let mut va = actual.clone();
                let mut vt = v.clone();
                va.sort();
                vt.sort();
                assert_eq!(va, vt, "step {}: addr {} membership mismatch", step, a);
            }
        }
    }
}
