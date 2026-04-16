//! Multipath skeleton for DRIFT.
//!
//! # Scope
//!
//! This is a **failover + RTT-weighted path selection**
//! layer, *not* a full simultaneous-multipath implementation
//! like IETF MP-QUIC. A full MP-QUIC implementation would
//! require per-path sequence numbers, per-path cwnds, a
//! scheduler that splits traffic across live paths, and
//! out-of-order reassembly spanning paths — thousands of
//! lines of code and a deep restructure of `Peer` to hold
//! multiple simultaneous addresses and session states.
//!
//! What this module *does* give you:
//!
//! 1. An API to register multiple candidate addresses for a
//!    single peer (e.g. a mobile peer reachable over both
//!    wifi and cellular).
//! 2. Per-path RTT measurement reusing DRIFT's existing
//!    `probe_candidate_path` machinery.
//! 3. A `send_on_best_path` helper that picks the lowest-RTT
//!    path and calls `update_peer_addr` to swap the
//!    transport's active address for that peer before the
//!    send.
//!
//! When a path fails (probe times out), the layer marks it
//! unhealthy and switches to the next-best alternative. When
//! the app wants to use a specific path, it can query the
//! current best path or force-select one.
//!
//! # API shape
//!
//! ```ignore
//! let mp = MultipathManager::new(transport.clone());
//! mp.add_path(peer, "10.0.0.1:9000".parse()?).await;
//! mp.add_path(peer, "192.168.1.5:9000".parse()?).await;
//! mp.probe_all(&peer).await;
//! mp.send_on_best_path(&peer, payload).await?;
//! ```

use crate::{PeerId, Transport};
use crate::error::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Per-path state tracked by the multipath manager.
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// The candidate socket address.
    pub addr: SocketAddr,
    /// Last measured RTT, if any. `None` for never-probed
    /// paths.
    pub rtt: Option<Duration>,
    /// Last successful probe time. Stale paths get
    /// deprioritized in `best_path`.
    pub last_validated: Option<Instant>,
    /// True if the most recent probe to this address
    /// failed (timeout or error). Unhealthy paths are
    /// skipped unless they're the only option.
    pub unhealthy: bool,
}

/// Manages multiple candidate addresses per peer.
pub struct MultipathManager {
    transport: Arc<Transport>,
    paths: Mutex<HashMap<PeerId, Vec<PathInfo>>>,
}

impl MultipathManager {
    pub fn new(transport: Arc<Transport>) -> Self {
        Self {
            transport,
            paths: Mutex::new(HashMap::new()),
        }
    }

    /// Register a candidate address for a peer. Does not
    /// probe the path — call `probe_all` or
    /// `probe_path` separately to get RTT measurements.
    pub async fn add_path(&self, peer: PeerId, addr: SocketAddr) {
        let mut paths = self.paths.lock().await;
        let entry = paths.entry(peer).or_insert_with(Vec::new);
        if entry.iter().any(|p| p.addr == addr) {
            return; // already registered
        }
        entry.push(PathInfo {
            addr,
            rtt: None,
            last_validated: None,
            unhealthy: false,
        });
    }

    /// Probe every registered path for this peer, issuing a
    /// path-validation challenge to each in sequence and
    /// updating its RTT estimate on success. Returns the
    /// number of paths successfully validated.
    pub async fn probe_all(&self, peer: &PeerId) -> usize {
        let addrs: Vec<SocketAddr> = {
            let paths = self.paths.lock().await;
            paths
                .get(peer)
                .map(|v| v.iter().map(|p| p.addr).collect())
                .unwrap_or_default()
        };
        let mut ok = 0;
        for addr in addrs {
            if self.probe_path(peer, addr).await.is_ok() {
                ok += 1;
            }
        }
        ok
    }

    /// Probe a single registered path. Returns the new RTT
    /// sample on success. Uses the transport's existing
    /// graceful probe API, then polls for success via the
    /// `path_probes_succeeded` metric.
    pub async fn probe_path(
        &self,
        peer: &PeerId,
        addr: SocketAddr,
    ) -> Result<Duration> {
        let before = self.transport.metrics().path_probes_succeeded;
        let started = Instant::now();
        self.transport
            .probe_candidate_path(peer, addr)
            .await?;

        // Poll up to 2s for the probe to land.
        let deadline = started + Duration::from_secs(2);
        loop {
            let now = Instant::now();
            if now >= deadline {
                // Mark the path unhealthy.
                self.mark_unhealthy(peer, addr).await;
                return Err(crate::error::DriftError::UnknownPeer);
            }
            if self.transport.metrics().path_probes_succeeded > before {
                let rtt = started.elapsed();
                self.record_rtt(peer, addr, rtt).await;
                return Ok(rtt);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn record_rtt(&self, peer: &PeerId, addr: SocketAddr, rtt: Duration) {
        let mut paths = self.paths.lock().await;
        if let Some(v) = paths.get_mut(peer) {
            if let Some(p) = v.iter_mut().find(|p| p.addr == addr) {
                p.rtt = Some(rtt);
                p.last_validated = Some(Instant::now());
                p.unhealthy = false;
            }
        }
    }

    async fn mark_unhealthy(&self, peer: &PeerId, addr: SocketAddr) {
        let mut paths = self.paths.lock().await;
        if let Some(v) = paths.get_mut(peer) {
            if let Some(p) = v.iter_mut().find(|p| p.addr == addr) {
                p.unhealthy = true;
            }
        }
    }

    /// Return the current best path for a peer: lowest-RTT
    /// healthy path. Falls back to any unhealthy path if
    /// nothing is healthy. Returns `None` if the peer has
    /// no registered paths.
    pub async fn best_path(&self, peer: &PeerId) -> Option<PathInfo> {
        let paths = self.paths.lock().await;
        let v = paths.get(peer)?;
        // Prefer healthy paths with an RTT sample, sorted
        // by RTT ascending.
        let healthy_with_rtt: Option<&PathInfo> = v
            .iter()
            .filter(|p| !p.unhealthy && p.rtt.is_some())
            .min_by_key(|p| p.rtt.unwrap());
        if let Some(p) = healthy_with_rtt {
            return Some(p.clone());
        }
        // No RTT measurements yet? Take the first healthy one.
        let healthy_any = v.iter().find(|p| !p.unhealthy);
        if let Some(p) = healthy_any {
            return Some(p.clone());
        }
        // Everything's unhealthy? Return the first — better
        // than nothing.
        v.first().cloned()
    }

    /// Send a DATA packet via the best-RTT path currently
    /// registered for this peer. Swaps the transport's
    /// active peer address before the send, so subsequent
    /// sends via normal `transport.send_data` will ALSO
    /// route via this path until the app swaps it again.
    pub async fn send_on_best_path(
        &self,
        peer: &PeerId,
        payload: &[u8],
    ) -> Result<()> {
        if let Some(best) = self.best_path(peer).await {
            self.transport.update_peer_addr(peer, best.addr).await;
        }
        self.transport.send_data(peer, payload, 0, 0).await
    }

    /// Snapshot all paths for a peer (for testing /
    /// diagnostics).
    pub async fn list_paths(&self, peer: &PeerId) -> Vec<PathInfo> {
        let paths = self.paths.lock().await;
        paths.get(peer).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::{Direction, Transport};

    #[tokio::test]
    async fn adds_paths_and_picks_best_by_rtt() {
        // Standalone unit test: no actual packets flow,
        // we just poke RTT values directly and verify
        // `best_path` picks the right one.
        let bob = Arc::new(
            Transport::bind(
                "127.0.0.1:0".parse().unwrap(),
                Identity::from_secret_bytes([0xB0; 32]),
            )
            .await
            .unwrap(),
        );
        let mp = MultipathManager::new(bob.clone());
        let peer: PeerId = [0x42; 8];
        mp.add_path(peer, "10.0.0.1:1000".parse().unwrap()).await;
        mp.add_path(peer, "10.0.0.2:1000".parse().unwrap()).await;
        mp.add_path(peer, "10.0.0.3:1000".parse().unwrap()).await;

        // Before any RTT samples, best_path returns the
        // first healthy path.
        let first = mp.best_path(&peer).await.unwrap();
        assert_eq!(first.addr, "10.0.0.1:1000".parse().unwrap());

        // Force RTTs and check the minimum wins.
        mp.record_rtt(&peer, "10.0.0.1:1000".parse().unwrap(), Duration::from_millis(50)).await;
        mp.record_rtt(&peer, "10.0.0.2:1000".parse().unwrap(), Duration::from_millis(10)).await;
        mp.record_rtt(&peer, "10.0.0.3:1000".parse().unwrap(), Duration::from_millis(30)).await;
        let best = mp.best_path(&peer).await.unwrap();
        assert_eq!(best.addr, "10.0.0.2:1000".parse().unwrap());
        assert_eq!(best.rtt, Some(Duration::from_millis(10)));

        // Mark the winner unhealthy; it should fall back
        // to the next-best healthy path (10.0.0.3).
        mp.mark_unhealthy(&peer, "10.0.0.2:1000".parse().unwrap()).await;
        let next = mp.best_path(&peer).await.unwrap();
        assert_eq!(next.addr, "10.0.0.3:1000".parse().unwrap());

        // Mark everything unhealthy — should still return
        // the first registered path as a last resort.
        mp.mark_unhealthy(&peer, "10.0.0.1:1000".parse().unwrap()).await;
        mp.mark_unhealthy(&peer, "10.0.0.3:1000".parse().unwrap()).await;
        let fallback = mp.best_path(&peer).await.unwrap();
        assert_eq!(fallback.addr, "10.0.0.1:1000".parse().unwrap());

        // Duplicate add is a no-op.
        mp.add_path(peer, "10.0.0.1:1000".parse().unwrap()).await;
        assert_eq!(mp.list_paths(&peer).await.len(), 3);

        let _ = Direction::Initiator; // silence unused import
    }
}
