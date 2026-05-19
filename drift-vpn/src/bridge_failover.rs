//! Runtime bridge failover for federated peers.
//!
//! Each peer with two-or-more `via_bridge` entries (combined
//! list from `via_bridge` + `via_bridges`) gets a supervisor
//! task that watches the active bridge's health and swaps to
//! the next available bridge in the list when the active one
//! fails. Mirrors the existing direct-endpoint failover in
//! `routing.rs` / `daemon::supervise_all`, but for federated
//! peers — where the swap primitive is "call
//! `Transport::add_federated_peer` again with a different
//! bridge_handle" (which is idempotent and updates the peer's
//! `federated_via` / `federated_target_bridge_pub` fields in
//! place).
//!
//! Two behaviors:
//!
//! 1. **Failover down**: when the active bridge has been
//!    non-Established or stale for `STALE_THRESHOLD`, walk the
//!    list from the active position forward looking for a
//!    healthy bridge. If found, swap to it. Hold for
//!    `HOLD_SECS` before another swap is allowed (flap
//!    suppression — same primitive the direct-endpoint
//!    supervisor uses).
//!
//! 2. **Re-elevation**: when the active bridge isn't the
//!    highest-priority one (index > 0), periodically check if
//!    any higher-priority bridge has come back. If yes, swap
//!    up. This keeps the system on the operator's preferred
//!    wire whenever possible — no "stuck on the slow fallback
//!    forever" failure mode.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use drift::Transport;
use drift_core::PeerId;
use tracing::{debug, info, warn};

use crate::config::Failover;

/// How often the supervisor wakes up to check bridge health.
const TICK: Duration = Duration::from_secs(10);

/// How long an active bridge can be non-Established or
/// last-seen-stale before we count it as "failed" and try to
/// fail over.
const STALE_THRESHOLD: Duration = Duration::from_secs(30);

/// How often the re-elevation probe walks the higher-priority
/// bridges looking for one that's recovered. 2 min keeps
/// per-bridge re-probe cost low (one peer_is_established check
/// each) while bounding how long we stay on the fallback after
/// the preferred wire heals.
const RE_ELEVATE_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// One supervisor's state. Cheaply cloneable into the spawned
/// task — bridge_handles is a small `HashMap` and bridge_specs
/// is a small `Vec`.
pub struct BridgeSupervisor {
    /// The federated peer this supervisor manages. We re-call
    /// `add_federated_peer(this_pubkey, new_bridge_handle, …)`
    /// to swap; the transport updates the existing entry in
    /// place.
    pub federated_peer_pub: [u8; 32],
    /// Diagnostic only — the federated peer's `PeerId`. Logged
    /// on swap so operators can correlate with `drift-vpn status`.
    pub federated_peer_pid: PeerId,
    /// Bridge specs in priority order. Same order as the
    /// per-peer `via_bridge_list()` returns — entry 0 is the
    /// most-preferred.
    pub bridge_specs: Vec<String>,
    /// All registered bridge handles. Keyed by the original
    /// spec string so we can look up the matching
    /// `(PeerId, [u8; 32])` (bridge peer id + bridge pubkey)
    /// when swapping.
    pub bridge_handles: HashMap<String, (PeerId, [u8; 32])>,
    /// Index into `bridge_specs` for the currently-active
    /// bridge. Used for both the failover walk (look forward
    /// from here) and re-elevation (look backward from here).
    pub active_idx: usize,
    /// Operator-configured failover knobs (check_interval,
    /// stale_secs, hold_secs, enabled). We honor `hold_secs`
    /// for flap suppression; everything else is independent
    /// of the direct-endpoint supervisor's settings since the
    /// bridge swap is a different mechanism.
    pub failover: Failover,
}

/// Spawn the supervisor task. Returns the task handle so the
/// caller can hold it for the daemon's lifetime (drift-vpn's
/// pattern is to forget the handle — `tokio::spawn` keeps the
/// task alive until the runtime shuts down).
pub fn spawn(transport: Arc<Transport>, state: BridgeSupervisor) {
    if !state.failover.enabled {
        debug!(
            peer = %hex::encode(state.federated_peer_pid),
            "bridge failover disabled by config"
        );
        return;
    }
    if state.bridge_specs.len() < 2 {
        // Single-bridge peers can't fail over — no point
        // running a supervisor.
        return;
    }
    tokio::spawn(async move {
        run_supervisor(transport, state).await;
    });
}

async fn run_supervisor(transport: Arc<Transport>, mut state: BridgeSupervisor) {
    let peer_pid_hex = hex::encode(state.federated_peer_pid);
    info!(
        peer = %peer_pid_hex,
        active_spec = %state.bridge_specs[state.active_idx],
        total_bridges = state.bridge_specs.len(),
        "bridge failover supervisor started"
    );

    // Per-bridge "first observed non-healthy" timestamps. Once
    // an active bridge has been failing continuously for
    // STALE_THRESHOLD, we declare it failed and try to swap.
    // The map clears entries as bridges recover.
    let mut failing_since: HashMap<PeerId, Instant> = HashMap::new();
    // Earliest time at which we'll consider another swap.
    let mut hold_until = Instant::now();
    // Earliest time at which we'll re-probe higher-priority
    // bridges. Lazy init: only matters once active_idx > 0.
    let mut next_re_elevate = Instant::now() + RE_ELEVATE_INTERVAL;

    loop {
        tokio::time::sleep(TICK).await;
        let now = Instant::now();
        let active_spec = state.bridge_specs[state.active_idx].clone();
        let (active_pid, _active_target_pub) = match state.bridge_handles.get(&active_spec) {
            Some(v) => *v,
            None => {
                // Should never happen — bridge_handles is
                // populated from the same source as bridge_specs
                // before the supervisor spawns.
                warn!(
                    peer = %peer_pid_hex,
                    spec = %active_spec,
                    "supervisor sees active bridge with no handle; aborting"
                );
                return;
            }
        };

        // ─── Active-bridge health check ────────────────────────
        let active_healthy = is_bridge_healthy(&transport, &active_pid).await;
        if active_healthy {
            failing_since.remove(&active_pid);
        } else {
            failing_since.entry(active_pid).or_insert(now);
        }

        // ─── Failover down (active failing) ────────────────────
        if !active_healthy && now >= hold_until {
            let failed_for = failing_since
                .get(&active_pid)
                .map(|t| now.duration_since(*t))
                .unwrap_or_default();
            if failed_for >= STALE_THRESHOLD {
                // Walk forward looking for a healthy bridge.
                let next = next_healthy_after(&transport, &state, state.active_idx + 1).await;
                if let Some(next_idx) = next {
                    if let Err(e) = swap_to(&transport, &mut state, next_idx, "failover").await {
                        warn!(
                            peer = %peer_pid_hex,
                            error = %e,
                            "failover swap failed; will retry next tick"
                        );
                    } else {
                        hold_until = now + Duration::from_secs(state.failover.hold_secs);
                        next_re_elevate = now + RE_ELEVATE_INTERVAL;
                    }
                } else {
                    debug!(
                        peer = %peer_pid_hex,
                        "no healthy bridge to fail over to; staying on active"
                    );
                }
            }
        }

        // ─── Re-elevation up (active is fallback, prefer higher) ─
        if state.active_idx > 0 && now >= next_re_elevate && now >= hold_until {
            // Walk indices [0..active_idx) — anything in this
            // range is higher-priority than the current active.
            let preferred = first_healthy_in_range(&transport, &state, 0, state.active_idx).await;
            if let Some(preferred_idx) = preferred {
                if let Err(e) =
                    swap_to(&transport, &mut state, preferred_idx, "re-elevation").await
                {
                    warn!(
                        peer = %peer_pid_hex,
                        error = %e,
                        "re-elevation swap failed; will retry next interval"
                    );
                } else {
                    hold_until = now + Duration::from_secs(state.failover.hold_secs);
                }
            }
            next_re_elevate = now + RE_ELEVATE_INTERVAL;
        }
    }
}

/// "Healthy" = the bridge's drift session is Established AND
/// we've heard from it recently. Stale-but-Established (no
/// packets in N seconds) counts as unhealthy — corporate
/// keepalive timeouts kill the underlying TCP/TLS session
/// before drift's own state machine notices.
async fn is_bridge_healthy(transport: &Transport, bridge_pid: &PeerId) -> bool {
    let m = match transport.peer_metrics(bridge_pid).await {
        Some(m) => m,
        None => return false,
    };
    if !m.is_established {
        return false;
    }
    // Last-seen freshness. The supervisor's TICK is 10 s, so
    // we accept up to 3× that before calling it stale. The
    // configured keepalive (typically 20 s) refreshes
    // last_seen, so a healthy peer should be well under this.
    let stale_after = Duration::from_secs(45);
    Instant::now().duration_since(m.last_seen) < stale_after
}

/// Find the lowest index >= `from_idx` whose bridge is healthy.
/// Used for failover-down (look forward from active position).
async fn next_healthy_after(
    transport: &Transport,
    state: &BridgeSupervisor,
    from_idx: usize,
) -> Option<usize> {
    for i in from_idx..state.bridge_specs.len() {
        let spec = &state.bridge_specs[i];
        if let Some((pid, _)) = state.bridge_handles.get(spec) {
            if is_bridge_healthy(transport, pid).await {
                return Some(i);
            }
        }
    }
    None
}

/// Find the lowest index in [start..end) whose bridge is
/// healthy. Used for re-elevation (look at higher-priority
/// bridges than the current active).
async fn first_healthy_in_range(
    transport: &Transport,
    state: &BridgeSupervisor,
    start: usize,
    end: usize,
) -> Option<usize> {
    for i in start..end.min(state.bridge_specs.len()) {
        let spec = &state.bridge_specs[i];
        if let Some((pid, _)) = state.bridge_handles.get(spec) {
            if is_bridge_healthy(transport, pid).await {
                return Some(i);
            }
        }
    }
    None
}

/// Perform the swap: call `add_federated_peer` again with the
/// new bridge handle. The transport updates the existing peer
/// entry's `federated_via` / `federated_target_bridge_pub`
/// fields in place, and subsequent `send_data` calls route
/// through the new bridge automatically.
async fn swap_to(
    transport: &Transport,
    state: &mut BridgeSupervisor,
    new_idx: usize,
    reason: &str,
) -> anyhow::Result<()> {
    let old_idx = state.active_idx;
    let new_spec = state.bridge_specs[new_idx].clone();
    let (new_pid, new_target_pub) = state
        .bridge_handles
        .get(&new_spec)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("bridge handle missing for {}", new_spec))?;
    transport
        .add_federated_peer(state.federated_peer_pub, new_pid, new_target_pub)
        .await?;
    state.active_idx = new_idx;
    info!(
        peer = %hex::encode(state.federated_peer_pid),
        reason = %reason,
        from_spec = %state.bridge_specs[old_idx],
        to_spec = %new_spec,
        from_idx = old_idx,
        to_idx = new_idx,
        "bridge failover swap"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges_basics() {
        // Compile-time sanity that the constants are sensible.
        assert!(TICK < STALE_THRESHOLD);
        assert!(STALE_THRESHOLD < RE_ELEVATE_INTERVAL);
    }

    #[test]
    fn constants_relative_order() {
        ranges_basics();
    }
}
