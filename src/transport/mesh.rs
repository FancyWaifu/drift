//! Mesh overlay: routing table, periodic BEACON emission and
//! ingestion, and hop-TTL packet forwarding.
//!
//! DRIFT's point-to-point session protocol (handshake, AEAD,
//! rekey) is intentionally agnostic to topology. This module
//! sits on top of it and implements an optional learn-and-forward
//! mesh: peers periodically advertise the destinations they know
//! about, neighbors install those advertisements as routes, and
//! packets addressed to a non-local destination get forwarded one
//! hop at a time until the hop-TTL hits zero.
//!
//! End-to-end crypto is preserved across forwarding because the
//! `hop_ttl` byte is zeroed out in the canonical AAD — see
//! `header::canonical_aad`.

use super::Inner;
use crate::crypto::PeerId;
use crate::error::{DriftError, Result};
use crate::header::{canonical_aad, Header, PacketType, HEADER_LEN};
use crate::session::HandshakeState;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tracing::{debug, warn};

/// Default hop budget for a packet we originate that needs mesh
/// forwarding. Generous enough for any realistic small mesh; the
/// receiver-side cap (`MAX_INCOMING_HOP_TTL`) is what protects
/// against amplification.
pub(crate) const DEFAULT_MESH_TTL: u8 = 8;

/// Hard cap on the hop_ttl value we are willing to honor on any
/// incoming packet that we would otherwise forward. DRIFT itself
/// never emits a hop_ttl above `DEFAULT_MESH_TTL`, so anything past
/// this cap is an attacker trying to force us to amplify a single
/// packet into many network hops.
pub(crate) const MAX_INCOMING_HOP_TTL: u8 = 16;

/// Maximum number of (peer_id, metric) entries packed into a
/// single BEACON payload. Bounds both the wire size and how many
/// routes one neighbor can inject in a single advertisement.
pub(crate) const MAX_BEACON_ENTRIES: usize = 64;

/// Hard cap on how many total entries the routing table may hold.
/// Bounds memory against an authenticated neighbor spamming BEACONs
/// with many unique destination peer ids. Updates past the cap are
/// silently dropped unless they replace an existing entry.
pub const MAX_ROUTES: usize = 4096;

/// Hold-down window: once a route is installed or updated,
/// reject re-advertisements for this long unless they are
/// *significantly* better (see `HYSTERESIS_NUMERATOR /
/// HYSTERESIS_DENOMINATOR`). Prevents rapid flapping when a
/// neighbor's RTT estimate oscillates around the hold-down
/// boundary.
pub(crate) const ROUTE_HOLDDOWN: std::time::Duration =
    std::time::Duration::from_secs(2);

/// Hysteresis threshold: a competing advertised cost must be
/// at most this fraction of the current cost to supplant it
/// during hold-down. 80% ⇒ the new path has to beat the
/// current path by at least 20% before we'll flip.
pub(crate) const HYSTERESIS_NUMERATOR: u64 = 80;
pub(crate) const HYSTERESIS_DENOMINATOR: u64 = 100;

/// Staleness cutoff: any route not refreshed by a beacon in
/// this long is presumed dead and purged on the next sweep.
/// Must be > 2 × beacon interval so a single dropped BEACON
/// doesn't wipe otherwise-live routes.
pub(crate) const ROUTE_STALENESS: std::time::Duration =
    std::time::Duration::from_secs(15);

/// Cost sentinel used to represent an unknown / not-yet-
/// measured RTT. Any advertised cost at or above this value
/// is treated as "unreachable" and rejected.
pub(crate) const COST_INFINITY_US: u32 = 10_000_000; // 10 seconds

#[derive(Clone, Copy, Debug)]
pub struct RouteEntry {
    pub next_hop: SocketAddr,
    /// Hop-count metric, retained for backward compatibility
    /// with code that introspects the routing table but no
    /// longer used as the primary selection criterion.
    pub metric: u16,
    /// Cumulative cost from this node to the destination,
    /// measured in microseconds of smoothed RTT. Lower is
    /// better. Dominates `metric` for path selection.
    pub cost_us: u32,
    /// When this entry was last installed or updated. Used
    /// by the hold-down / hysteresis / staleness machinery
    /// to keep the routing table from oscillating under
    /// dynamic metrics.
    pub updated_at: std::time::Instant,
    /// Which PacketIO interface this route was learned
    /// through. Used by `forward_packet` to send via the
    /// correct adapter when bridging across mediums.
    pub interface_id: usize,
}

/// Mesh routing table: destination peer id → (next-hop address, metric).
/// Updated statically via `add_route` and dynamically via BEACON packets.
pub struct RoutingTable {
    routes: HashMap<PeerId, RouteEntry>,
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }
}

impl RoutingTable {
    pub fn insert_static(&mut self, dst: PeerId, next_hop: SocketAddr) {
        // Static inserts always win (explicit app action), even past
        // the cap — but we still don't let them blow up unbounded:
        // a caller trying to add MAX_ROUTES + 1 will hit an implicit
        // limit higher up (peer table size, etc.).
        self.routes.insert(
            dst,
            RouteEntry {
                next_hop,
                metric: 1,
                cost_us: 0, // static routes are free at the routing layer
                updated_at: std::time::Instant::now(),
                interface_id: 0,
            },
        );
    }

    /// RTT-weighted route update. Installs or replaces the
    /// entry for `dst` iff:
    ///
    /// 1. There's currently no entry, OR
    /// 2. The advertised cost is strictly lower AND
    ///    * we're past the hold-down window, OR
    ///    * the new cost beats the current by at least
    ///      the hysteresis threshold (≥20% improvement).
    ///
    /// Returns true when the table was updated. Infinity-
    /// tagged advertisements (`cost_us >= COST_INFINITY_US`)
    /// are always rejected — prevents count-to-infinity
    /// from spreading through the mesh.
    pub fn update_if_better(
        &mut self,
        dst: PeerId,
        next_hop: SocketAddr,
        metric: u16,
        cost_us: u32,
        iface: usize,
    ) -> bool {
        if cost_us >= COST_INFINITY_US {
            return false;
        }
        let now = std::time::Instant::now();
        match self.routes.get(&dst) {
            Some(existing) => {
                if cost_us >= existing.cost_us {
                    return false;
                }
                let age = now.saturating_duration_since(existing.updated_at);
                let beats_hold_down = age >= ROUTE_HOLDDOWN;
                // Hysteresis: during hold-down only a
                // SIGNIFICANTLY better cost can preempt.
                let beats_hysteresis = {
                    let threshold = (existing.cost_us as u64 * HYSTERESIS_NUMERATOR)
                        / HYSTERESIS_DENOMINATOR;
                    (cost_us as u64) <= threshold
                };
                if !beats_hold_down && !beats_hysteresis {
                    return false;
                }
                self.routes.insert(
                    dst,
                    RouteEntry {
                        next_hop,
                        metric,
                        cost_us,
                        updated_at: now,
                        interface_id: iface,
                    },
                );
                true
            }
            None => {
                if self.routes.len() >= MAX_ROUTES {
                    return false;
                }
                self.routes.insert(
                    dst,
                    RouteEntry {
                        next_hop,
                        metric,
                        cost_us,
                        updated_at: now,
                        interface_id: iface,
                    },
                );
                true
            }
        }
    }

    pub fn lookup(&self, dst: &PeerId) -> Option<SocketAddr> {
        self.routes.get(dst).map(|e| e.next_hop)
    }

    /// Return the full route record for `dst`, including
    /// cost and age — used by tests and app-level
    /// introspection.
    pub fn lookup_entry(&self, dst: &PeerId) -> Option<RouteEntry> {
        self.routes.get(dst).copied()
    }

    /// Entries for BEACON emission: `(peer_id, metric,
    /// cost_us)` triples. The cost is what we advertise to
    /// our neighbors so they can compose it with their
    /// neighbor-RTT-to-us.
    pub fn entries(&self) -> Vec<(PeerId, u16, u32)> {
        self.routes
            .iter()
            .map(|(k, v)| (*k, v.metric, v.cost_us))
            .collect()
    }

    /// Purge routes that have gone stale — not refreshed
    /// by a beacon within `ROUTE_STALENESS`. Called on a
    /// periodic sweep.
    pub(crate) fn sweep_stale(&mut self) -> usize {
        let now = std::time::Instant::now();
        let before = self.routes.len();
        self.routes.retain(|_, entry| {
            now.saturating_duration_since(entry.updated_at) < ROUTE_STALENESS
        });
        before - self.routes.len()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl Inner {
    /// Periodic BEACON emitter: every few seconds, send each established
    /// direct neighbor a list of peers we can reach, so they can populate
    /// their routing tables dynamically.
    pub(crate) async fn run_beacon_loop(self: std::sync::Arc<Self>) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(
            self.config.beacon_interval_ms,
        ));
        // Skip the first immediate tick so we don't beacon before any
        // handshakes have completed.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(e) = self.emit_beacons().await {
                warn!(error = %e, "beacon emission failed");
            }
        }
    }

    pub(crate) async fn emit_beacons(&self) -> Result<()> {
        // Build the advertisement: all destinations we know
        // about from the routing table, PLUS all direct peers
        // we have Established sessions with (at cost 0, since
        // they're one hop away via us). This is critical for
        // multi-interface bridging: a bridge that handshakes
        // with a TCP peer needs to immediately advertise that
        // peer to its UDP neighbors so they can route through
        // the bridge without waiting for the TCP peer's own
        // beacons to propagate.
        let mut entries: Vec<(PeerId, u16, u32)> = {
            let routes = self.routes.lock().await;
            routes.entries()
        };
        // Add self.
        entries.push((self.local_peer_id, 0, 0));
        // Add direct peers not already in the routing table.
        {
            let peers = self.peers.lock_all().await;
            let existing: std::collections::HashSet<_> =
                entries.iter().map(|(id, _, _)| *id).collect();
            for peer in peers.iter() {
                if matches!(peer.handshake, HandshakeState::Established { .. })
                    && !existing.contains(&peer.id)
                {
                    entries.push((peer.id, 1, peer.neighbor_rtt_us() as u32));
                }
            }
        }
        if entries.len() > MAX_BEACON_ENTRIES {
            entries.truncate(MAX_BEACON_ENTRIES);
        }

        // Serialize v2: u16 count || [peer_id(8) || metric(2) || cost_us(4)]*
        // Entry size = 14 bytes. Backward incompatible with the
        // older 10-byte entry format; peers must run matching
        // versions of DRIFT.
        let mut payload = Vec::with_capacity(2 + entries.len() * 14);
        payload.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for (id, metric, cost_us) in &entries {
            payload.extend_from_slice(id);
            payload.extend_from_slice(&metric.to_be_bytes());
            payload.extend_from_slice(&cost_us.to_be_bytes());
        }

        // Send to every established peer we have a direct session with.
        // Skip peers whose seq counter has hit the safety ceiling —
        // we can't emit without a re-handshake, but this isn't an
        // error path, just "no beacons today".
        // Only emit beacons to direct neighbors. Peers reachable
        // via mesh already learn routes from their own direct
        // neighbor (the relay we're sending through). Sending
        // beacons to mesh-routed peers would hit the relay with
        // `dst != relay && hop_ttl == 1`, getting dropped as
        // "unknown peer" at `process_incoming`'s forward gate.
        let targets: Vec<(PeerId, SocketAddr, u32)> = {
            let mut peers = self.peers.lock_all().await;
            peers
                .iter_mut()
                .filter_map(|p| {
                    if matches!(p.handshake, HandshakeState::Established { .. })
                        && !p.via_mesh
                    {
                        p.next_seq_checked().map(|seq| (p.id, p.addr, seq))
                    } else {
                        None
                    }
                })
                .collect()
        };

        for (dst_id, addr, seq) in targets {
            let bytes = {
                let mut peers = self.peers.lock_for(&dst_id).await;
                let Some(peer) = peers.get_mut(&dst_id) else {
                    continue;
                };
                let mut header = Header::new(PacketType::Beacon, seq, self.local_peer_id, dst_id);
                header.payload_len = payload.len() as u16;
                header.send_time_ms = peer.send_time_ms();
                let mut hbuf = [0u8; HEADER_LEN];
                header.encode(&mut hbuf);
                let aad = canonical_aad(&hbuf);
                let (tx, _) = peer.handshake.session().ok_or(DriftError::UnknownPeer)?;
                let sealed = tx.seal(seq, PacketType::Beacon as u8, &aad, &payload)?;
                let mut wire = Vec::with_capacity(HEADER_LEN + sealed.len());
                wire.extend_from_slice(&hbuf);
                wire.extend_from_slice(&sealed);
                wire
            };
            self.ifaces.send_for(self.iface_for(&dst_id).await, &bytes, addr).await?;
            self.metrics.beacons_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics.bytes_sent.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            debug!(dst = ?dst_id, n = payload.len(), "sent BEACON");
        }
        Ok(())
    }

    pub(crate) async fn handle_beacon(
        &self,
        header: &Header,
        full_packet: &[u8],
        body: &[u8],
        src: SocketAddr,
        iface_idx: usize,
    ) -> Result<()> {
        if header.dst_id != self.local_peer_id {
            return Err(DriftError::UnknownPeer);
        }
        let peer_id = header.src_id;
        let plaintext = {
            let mut peers = self.peers.lock_for(&peer_id).await;
            let peer = peers.get_mut(&peer_id).ok_or(DriftError::UnknownPeer)?;
            let (_, rx) = peer
                .handshake
                .session()
                .ok_or(DriftError::UnknownPeer)?;
            let mut hbuf = [0u8; HEADER_LEN];
            hbuf.copy_from_slice(&full_packet[..HEADER_LEN]);
            let aad = canonical_aad(&hbuf);
            rx.open(header.seq, PacketType::Beacon as u8, &aad, body)?
        };

        if plaintext.len() < 2 {
            return Ok(());
        }
        let count = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        // v2 wire format: 14 bytes per entry.
        let expected_len = 2 + count * 14;
        if plaintext.len() < expected_len {
            return Ok(());
        }
        // Cap accepted entries per beacon. Matches the emission-side
        // cap and bounds how many routes a single neighbor can inject
        // in one packet; the rest of the payload is silently ignored.
        let count = count.min(MAX_BEACON_ENTRIES);

        // To compose cost properly we need to know our own
        // RTT to THIS neighbor (the one whose beacon we're
        // processing). Read it once up front.
        let neighbor_rtt_us: u32 = {
            let peers = self.peers.lock_for(&peer_id).await;
            peers
                .get(&peer_id)
                .map(|p| p.neighbor_rtt_us())
                .unwrap_or(u32::MAX)
        };
        // If we have no RTT estimate for this neighbor yet,
        // fall back to a small nominal cost (1000 µs) so
        // BEACON processing still makes progress on freshly
        // handshook links. The estimate gets filled in on
        // the next Ping round.
        let effective_neighbor_rtt = if neighbor_rtt_us == u32::MAX {
            1_000
        } else {
            neighbor_rtt_us
        };

        let mut updated = 0;
        let mut routes = self.routes.lock().await;
        for i in 0..count {
            let off = 2 + i * 14;
            let mut id = [0u8; 8];
            id.copy_from_slice(&plaintext[off..off + 8]);
            let metric = u16::from_be_bytes([plaintext[off + 8], plaintext[off + 9]]);
            let advertised_cost = u32::from_be_bytes([
                plaintext[off + 10],
                plaintext[off + 11],
                plaintext[off + 12],
                plaintext[off + 13],
            ]);
            // Skip entries for ourselves.
            if id == self.local_peer_id {
                continue;
            }
            // Our cost to reach `id` via `peer_id` is the RTT
            // to `peer_id` plus whatever `peer_id` told us it
            // costs to reach `id`. Saturating add prevents
            // wraparound turning into an artificially-low
            // cost.
            let new_cost = effective_neighbor_rtt.saturating_add(advertised_cost);
            let new_metric = metric.saturating_add(1);
            if routes.update_if_better(id, src, new_metric, new_cost, iface_idx) {
                updated += 1;
            }
        }
        if updated > 0 {
            debug!(from = ?peer_id, updated, "learned routes from beacon");
        }
        Ok(())
    }

    /// Background sweep: every few seconds, purge routes
    /// that haven't been refreshed by a beacon within
    /// `ROUTE_STALENESS`. Prevents dead routes from
    /// lingering after a neighbor goes offline.
    pub(crate) async fn run_route_sweep_loop(self: std::sync::Arc<Self>) {
        // Sweep roughly once per stale cutoff / 3 — that's
        // enough to catch every expiry within one stale
        // window without spinning.
        let period = ROUTE_STALENESS / 3;
        let mut ticker = tokio::time::interval(period);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let purged = self.routes.lock().await.sweep_stale();
            if purged > 0 {
                debug!(purged, "purged stale routes");
            }
        }
    }

    /// Decrement hop_ttl in the wire header and forward the packet to the
    /// next hop looked up from the routing table. Does not touch the
    /// ciphertext — end-to-end crypto is preserved because hop_ttl is
    /// zeroed in the canonical AAD.
    pub(crate) async fn forward_packet(&self, data: &[u8], header: &Header) -> Result<()> {
        // Two-tier lookup: first check the routing table (mesh
        // routes learned from beacons), then fall back to the
        // peer table (direct sessions). The peer-table fallback
        // is what makes cross-medium bridging work without
        // waiting for full beacon convergence: the bridge has
        // direct sessions with every peer it handshook, so it
        // can immediately forward to any of them regardless of
        // whether beacons have propagated the route yet.
        //
        // This is the key insight: the bridge's adapters hand
        // off bytes, the bridge checks "who is this addressed
        // to?", finds the destination in its peer table, picks
        // the right interface, and sends. The destination peer
        // receives the bytes on their adapter and processes
        // them as if they arrived directly.
        let (next_hop, fwd_iface) = {
            // Try routing table first (has mesh cost info).
            let routes = self.routes.lock().await;
            if let Some(entry) = routes.lookup_entry(&header.dst_id) {
                (entry.next_hop, entry.interface_id)
            } else {
                drop(routes);
                // Fall back to peer table: if we have a direct
                // session with the destination, forward to
                // their addr via their interface.
                let peers = self.peers.lock_for(&header.dst_id).await;
                match peers.get(&header.dst_id) {
                    Some(peer) if peer.handshake.is_ready_for_data() => {
                        (peer.addr, peer.interface_id)
                    }
                    _ => {
                        debug!(dst = ?header.dst_id, "no route or peer for destination");
                        return Ok(());
                    }
                }
            }
        };

        let mut forwarded = data.to_vec();
        // hop_ttl lives at byte 28 of the header.
        forwarded[28] = header.hop_ttl.saturating_sub(1);
        self.ifaces.send_for(fwd_iface, &forwarded, next_hop).await?;
        self.metrics.forwarded.fetch_add(1, Ordering::Relaxed);
        debug!(
            dst = ?header.dst_id,
            next_hop = ?next_hop,
            iface = fwd_iface,
            new_ttl = forwarded[28],
            "forwarded"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn hop(n: u8) -> SocketAddr {
        format!("127.0.0.1:{}", 10000 + n as u16).parse().unwrap()
    }

    #[test]
    fn update_picks_lower_cost_over_hop_count() {
        let mut rt = RoutingTable::default();
        let dst = [1u8; 8];
        // First advertisement: 2 hops but fast.
        assert!(rt.update_if_better(dst, hop(1), 2, 1_000, 0));
        // Competing advertisement: 1 hop but slow.
        // Used to win under hop-count routing. Must LOSE
        // under RTT-weighted routing.
        //
        // NOTE: this is from a brand-new neighbor (new
        // next_hop), so hold-down would normally preempt
        // unless the new cost beats the hysteresis threshold.
        // 5_000 is > 1_000 so the new-cost check rejects it
        // regardless.
        assert!(!rt.update_if_better(dst, hop(2), 1, 5_000, 0));
        let e = rt.lookup_entry(&dst).unwrap();
        assert_eq!(e.next_hop, hop(1));
        assert_eq!(e.cost_us, 1_000);
    }

    #[test]
    fn infinity_cost_always_rejected() {
        let mut rt = RoutingTable::default();
        let dst = [2u8; 8];
        assert!(!rt.update_if_better(dst, hop(1), 1, COST_INFINITY_US, 0));
        assert!(!rt.update_if_better(dst, hop(1), 1, COST_INFINITY_US + 1, 0));
        assert!(rt.lookup(&dst).is_none());
    }

    #[test]
    fn hold_down_rejects_marginal_improvements() {
        let mut rt = RoutingTable::default();
        let dst = [3u8; 8];
        assert!(rt.update_if_better(dst, hop(1), 1, 10_000, 0));
        // A new path that's only 5% better must be refused
        // during the hold-down window (needs ≥20% to
        // preempt). This protects against oscillation.
        assert!(!rt.update_if_better(dst, hop(2), 1, 9_500, 0));
        let e = rt.lookup_entry(&dst).unwrap();
        assert_eq!(e.next_hop, hop(1));
    }

    #[test]
    fn hysteresis_accepts_big_improvements_during_holddown() {
        let mut rt = RoutingTable::default();
        let dst = [4u8; 8];
        assert!(rt.update_if_better(dst, hop(1), 1, 10_000, 0));
        // 70% of 10_000 = 7_000, which IS ≤ hysteresis
        // threshold (80% * 10_000 = 8_000). Should win
        // even during hold-down.
        assert!(rt.update_if_better(dst, hop(2), 1, 7_000, 0));
        let e = rt.lookup_entry(&dst).unwrap();
        assert_eq!(e.next_hop, hop(2));
    }

    #[test]
    fn staleness_sweep_removes_dead_routes() {
        // We can't easily wait 15 s in a unit test, so
        // manually forge an updated_at in the past and
        // assert the sweep catches it.
        let mut rt = RoutingTable::default();
        let dst = [5u8; 8];
        assert!(rt.update_if_better(dst, hop(1), 1, 1_000, 0));
        // Manually reach in and backdate the entry.
        if let Some(e) = rt.routes.get_mut(&dst) {
            e.updated_at = std::time::Instant::now()
                .checked_sub(ROUTE_STALENESS + std::time::Duration::from_secs(1))
                .unwrap();
        }
        let purged = rt.sweep_stale();
        assert_eq!(purged, 1);
        assert!(rt.lookup(&dst).is_none());
    }

    #[test]
    fn cap_still_holds_under_rtt_routing() {
        let mut rt = RoutingTable::default();
        // Each insert uses a unique dst and unique cost so
        // they're all fresh inserts rather than updates
        // (which would hit the hold-down path).
        for i in 0..(MAX_ROUTES + 1000) {
            let mut dst = [0u8; 8];
            dst[..4].copy_from_slice(&(i as u32).to_be_bytes());
            rt.update_if_better(dst, hop(1), 1, 1000 + i as u32, 0);
        }
        assert_eq!(rt.len(), MAX_ROUTES);
    }
}
