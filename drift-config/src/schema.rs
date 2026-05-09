//! Wire-level schema for `drift.toml` — the single source-of-truth
//! file managed by `drift-config`.
//!
//! Two namespaces in one file:
//!
//! - `[network]` + `[hosts.X]` — generic DRIFT inventory: identity
//!   pubkeys, multi-transport endpoints, ssh access info. Read by
//!   every DRIFT tool.
//! - `[vpn]` + `[vpn.X]` — drift-vpn-specific overlay: tun
//!   addresses, CIDR, hub/spoke roles. Read only by `drift-vpn config`.
//!
//! Other tools (drift-mosh, drift-http, …) layer the same way:
//! they get their own top-level namespace (`[mosh]`, `[http]`,
//! etc.) and cross-reference the generic `[hosts.X]` entries by
//! host name.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level schema. Everything is optional so partial files
/// (just the network + a few hosts; no VPN overlay yet) are
/// valid through the lifecycle of a deployment.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DriftToml {
    #[serde(default)]
    pub network: Network,

    /// Generic peer inventory. Key is the host's local name
    /// (free-form, used for human reference and `--ssh` lookups).
    #[serde(default)]
    pub hosts: BTreeMap<String, Host>,

    /// drift-vpn overlay. Optional — empty until you run
    /// `drift-vpn config init`.
    #[serde(default)]
    pub vpn: Option<VpnOverlay>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Network {
    /// Human-readable name. Purely for the operator's benefit.
    #[serde(default = "default_network_name")]
    pub name: String,
}

fn default_network_name() -> String {
    "drift-network".to_string()
}

/// One host's generic DRIFT info: identity + reachability.
///
/// Deliberately *small*. drift.toml is meant to be shareable
/// (commit it to a private repo, paste it in a friend's chat to
/// bootstrap them) — so it carries only what other peers need to
/// reach this host. Operator-side deployment info (ssh targets,
/// systemd paths, etc.) belongs in a separate operator-local
/// file, never in the inventory.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Host {
    /// 64-hex X25519 pubkey. Required for any peer that another
    /// host wants to reach.
    pub pubkey: String,

    /// DRIFT URLs at which this host accepts inbound connections.
    /// Empty = the host doesn't listen (pure roaming client).
    /// Order matters: peers try these in priority order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
}

/// drift-vpn overlay: settings that apply to the VPN as a whole
/// and per-host VPN augmentations (tun address, role).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VpnOverlay {
    /// Tun network range, e.g. "10.99.0.0/24". Each host's
    /// `tun_addr` must fall in this range.
    pub cidr: String,

    /// Default tun MTU. drift-vpn defaults to 1340 (leaves room
    /// under DRIFT's payload limit).
    #[serde(default = "default_mtu")]
    pub mtu: u32,

    /// Per-host VPN augmentation. Key matches a `[hosts.X]` key.
    #[serde(flatten, default)]
    pub hosts: BTreeMap<String, VpnHost>,
}

fn default_mtu() -> u32 {
    1340
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VpnHost {
    /// IP inside the tun network, e.g. "10.99.0.1".
    pub tun_addr: String,

    /// Topology role:
    /// - `hub`   — listens, services many peers, has direct routes to all
    /// - `spoke` — listens locally; reaches other spokes via the hub
    /// - `client`— roaming, no listener; connects outbound only
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "spoke".to_string()
}

impl DriftToml {
    /// Find the [hosts.X] entry that matches a name. Returns
    /// (name, host) for ergonomics.
    pub fn host(&self, name: &str) -> Option<(&str, &Host)> {
        self.hosts.get_key_value(name).map(|(k, v)| (k.as_str(), v))
    }

    /// Iterate every host that has at least one endpoint —
    /// candidates for hubs / reachable peers.
    pub fn reachable_hosts(&self) -> impl Iterator<Item = (&String, &Host)> {
        self.hosts.iter().filter(|(_, h)| !h.endpoints.is_empty())
    }

    /// True when the file contains nothing except defaults
    /// (used by `init` to refuse overwriting a real config).
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.vpn.is_none()
    }
}
