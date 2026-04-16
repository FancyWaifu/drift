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
use tokio::sync::{Mutex, MutexGuard};

/// Number of shards. Must be a power of two so we can use a
/// bit mask for the modulo.
pub(crate) const PEER_SHARD_COUNT: usize = 16;
const PEER_SHARD_MASK: u64 = (PEER_SHARD_COUNT as u64) - 1;

pub(crate) struct PeerShards {
    shards: [Mutex<PeerTable>; PEER_SHARD_COUNT],
}

impl Default for PeerShards {
    fn default() -> Self {
        // Initialize each shard with its own PeerTable. We can't
        // use `[Mutex::new(PeerTable::new()); N]` because Mutex
        // isn't Copy — go through array::from_fn instead.
        Self {
            shards: std::array::from_fn(|_| Mutex::new(PeerTable::new())),
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

    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut Peer> + use<'_, 'a> {
        self.guards.iter_mut().flat_map(|g| g.iter_mut())
    }
}
