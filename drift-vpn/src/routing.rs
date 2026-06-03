//! IP-packet → peer-pubkey routing.
//!
//! Each peer in the config declares `allowed_ips = [...]`; an
//! outbound IP packet from the tun device is routed to whichever
//! peer's allowed-IPs contain the packet's destination address.
//! This is the same model WireGuard uses.
//!
//! Implementation: a flat `Vec<(IpNet, PeerId)>` sorted by
//! prefix length descending — longest match wins, which is
//! what you want for overlapping prefixes (e.g., one peer
//! claims `10.0.0.0/8` and another `10.0.5.0/24`; the /24
//! peer should win for traffic to 10.0.5.x). Linear scan over
//! the flat table is much more cache-friendly than nested
//! peer→allowed_ips iteration; per-packet cost stays under a
//! microsecond well into the four-digit-peer-count range.
//!
//! For 1000+ peers with overlapping prefixes, swap to a
//! Patricia trie. Not worth it yet.
//!
//! Reverse-path validation: when a packet arrives FROM a peer,
//! its source IP must fall in that peer's allowed_ips —
//! otherwise the peer is spoofing. This is the second function
//! in this module; both directions need it.

use anyhow::{anyhow, Result};
use drift_core::PeerId;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone)]
pub(crate) struct PeerRoute {
    pub peer_id: PeerId,
    pub allowed_ips: Vec<IpNet>,
}

pub(crate) struct RouteTable {
    pub routes: Vec<PeerRoute>,
    /// peer_id → route index, for quick reverse lookups.
    by_peer_id: HashMap<PeerId, usize>,
    /// Flat lookup table: every `(IpNet, PeerId)` pair across
    /// all peers, sorted by prefix length descending. The
    /// forward path scans this once instead of nesting two
    /// loops over peers and their allowed_ips.
    flat: Vec<(IpNet, PeerId)>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            by_peer_id: HashMap::new(),
            flat: Vec::new(),
        }
    }

    pub fn add(&mut self, route: PeerRoute) {
        let idx = self.routes.len();
        self.by_peer_id.insert(route.peer_id, idx);
        for net in &route.allowed_ips {
            self.flat.push((*net, route.peer_id));
        }
        self.routes.push(route);
        // Stable sort by prefix length descending — longer
        // prefixes (more specific) come first, so a linear
        // scan naturally implements longest-prefix match.
        self.flat
            .sort_by_key(|(b, _)| std::cmp::Reverse(b.prefix_len()));
    }

    /// Forward routing: which peer's allowed_ips contain this
    /// destination IP? `None` if the packet is for nobody we
    /// know — drop it. Longest-prefix match wins.
    pub fn route_for_dst(&self, dst: IpAddr) -> Option<&PeerRoute> {
        let pid = self
            .flat
            .iter()
            .find(|(net, _)| net.contains(&dst))
            .map(|(_, pid)| *pid)?;
        let idx = *self.by_peer_id.get(&pid)?;
        Some(&self.routes[idx])
    }

    /// Reverse-path validation: is `src` allowed to come from
    /// `peer`? If yes, the packet's claimed source matches what
    /// the peer is supposed to own. If no, drop — the peer is
    /// either misconfigured or spoofing.
    ///
    /// Stays peer-scoped (not flat-table) because the question
    /// is "does THIS peer own src," not "who owns src." A flat
    /// scan would need to also check that the matching peer is
    /// the one we received from, which is the same number of
    /// comparisons but with worse locality.
    #[allow(dead_code)]
    pub fn src_is_valid(&self, peer: &PeerId, src: IpAddr) -> bool {
        matches!(self.src_status(peer, src), SrcStatus::Allowed)
    }

    /// Detailed reverse-path validation: distinguishes between
    /// "peer not in route table at all" and "peer known but
    /// claimed src isn't in their allowed_ips."
    ///
    /// The two cases are very different operationally:
    ///   - **UnknownPeer**: usually mesh-forwarded traffic from
    ///     a peer-of-peer we don't directly know, or a startup
    ///     race. Mostly noise. Log at DEBUG.
    ///   - **ConfigMismatch**: peer is one of ours, but they're
    ///     using a source IP outside what we listed for them.
    ///     Either a config drift (their tun IP differs from our
    ///     allowed_ips entry) or a real spoofing attempt. Log
    ///     at WARN.
    pub fn src_status(&self, peer: &PeerId, src: IpAddr) -> SrcStatus {
        match self.by_peer_id.get(peer) {
            None => SrcStatus::UnknownPeer,
            Some(&idx) => {
                if self.routes[idx]
                    .allowed_ips
                    .iter()
                    .any(|n| n.contains(&src))
                {
                    SrcStatus::Allowed
                } else {
                    SrcStatus::ConfigMismatch
                }
            }
        }
    }
}

/// Outcome of `RouteTable::src_status`. See `src_status` doc
/// for the operational meaning of each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SrcStatus {
    Allowed,
    UnknownPeer,
    ConfigMismatch,
}

/// Classify a tunneled L3 packet for DRIFT's deadline-aware
/// delivery and semantic coalescing. Returns
/// `(deadline_ms, coalesce_group)` for `Transport::send_data`.
///
/// DRIFT's deadline says "drop this packet rather than deliver
/// it after `now + deadline_ms`." `coalesce_group` is a 32-bit
/// id; packets with the same group are eligible for semantic
/// coalescing in the send queue (e.g. only-keep-newest).
///
/// Heuristic by L4:
///   - **TCP**: `(0, 0)` — no deadline, no coalescing. TCP
///     does its own reliability; we want every byte delivered.
///   - **UDP DNS / TFTP / NTP** (port < 1024 mostly): treat as
///     latency-sensitive control. 100ms deadline.
///   - **UDP RTP-shaped** (high port, payload >= 200 bytes):
///     a media frame. 50ms deadline + coalesce-group keyed on
///     `(src_port, dst_port)` so successive frames in the same
///     flow replace each other. Cheap, effective for video
///     over a saturated link.
///   - **Other UDP**: 200ms deadline, no coalescing. Most app
///     traffic; gives DRIFT permission to drop a stale packet
///     under congestion but doesn't reorder relative to itself.
///   - **ICMP / IGMP / GRE / etc**: `(0, 0)` — small, infrequent,
///     not worth a deadline.
///
/// All numbers are loose. The point is to give DRIFT *any*
/// signal it can act on instead of the all-zeros that v0.5
/// shipped with.
pub(crate) fn classify_for_qos(pkt: &[u8]) -> (u16, u32) {
    if pkt.len() < 20 {
        return (0, 0);
    }
    let (proto, header_len) = match pkt[0] >> 4 {
        4 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return (0, 0);
            }
            (pkt[9], ihl)
        }
        6 => {
            // IPv6 fixed header is 40B; skip past extension
            // headers in a future revision. For now treat
            // anything-with-extensions as opaque.
            if pkt.len() < 40 {
                return (0, 0);
            }
            (pkt[6], 40)
        }
        _ => return (0, 0),
    };

    const TCP: u8 = 6;
    const UDP: u8 = 17;
    match proto {
        TCP => (0, 0),
        UDP => {
            // UDP header is 8 bytes: src_port(2) dst_port(2)
            // length(2) checksum(2). Need at least header_len + 8.
            if pkt.len() < header_len + 8 {
                return (0, 0);
            }
            let sport = u16::from_be_bytes([pkt[header_len], pkt[header_len + 1]]);
            let dport = u16::from_be_bytes([pkt[header_len + 2], pkt[header_len + 3]]);
            let payload_len = pkt.len() - header_len - 8;
            // Latency-sensitive control? DNS, NTP, mDNS, …
            if dport < 1024 || sport < 1024 {
                return (100, 0); // 100ms
            }
            // Media-frame-shaped? High ports and a chunky body.
            // We don't insist on RTP — large UDP datagrams on
            // high ports are usually media-ish.
            if payload_len >= 200 {
                let key = ((sport as u32) << 16) | (dport as u32);
                return (50, key); // 50ms + coalesce
            }
            // Generic UDP: cap staleness, no coalescing.
            (200, 0)
        }
        _ => (0, 0),
    }
}

/// Pull dst + src IPv4/IPv6 addresses out of a raw L3 packet
/// (the format the tun device hands us).
///
/// IPv4 layout (RFC 791):
///   bytes  0    : version<<4 | ihl
///   bytes  9    : protocol
///   bytes 12..16: src
///   bytes 16..20: dst
///
/// IPv6 layout (RFC 8200):
///   bytes  0    : version<<4 | tc[7..4]
///   bytes  8..24: src
///   bytes 24..40: dst
pub(crate) fn parse_endpoints(pkt: &[u8]) -> Result<(IpAddr, IpAddr)> {
    if pkt.is_empty() {
        return Err(anyhow!("empty packet"));
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return Err(anyhow!("IPv4 packet too short ({} < 20)", pkt.len()));
            }
            let src = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            Ok((IpAddr::V4(src), IpAddr::V4(dst)))
        }
        6 => {
            if pkt.len() < 40 {
                return Err(anyhow!("IPv6 packet too short ({} < 40)", pkt.len()));
            }
            let mut src = [0u8; 16];
            src.copy_from_slice(&pkt[8..24]);
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&pkt[24..40]);
            Ok((
                IpAddr::V6(std::net::Ipv6Addr::from(src)),
                IpAddr::V6(std::net::Ipv6Addr::from(dst)),
            ))
        }
        v => Err(anyhow!("unsupported IP version {}", v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_src_and_dst_from_minimal_ipv4_header() {
        let mut pkt = vec![0x45]; // version 4, IHL 5
        pkt.resize(20, 0);
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let (src, dst) = parse_endpoints(&pkt).unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn parses_src_and_dst_from_minimal_ipv6_header() {
        let mut pkt = vec![0x60];
        pkt.resize(40, 0);
        pkt[8..24].copy_from_slice(&[0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let (src, dst) = parse_endpoints(&pkt).unwrap();
        assert!(matches!(src, IpAddr::V6(_)));
        assert!(matches!(dst, IpAddr::V6(_)));
    }

    #[test]
    fn route_for_dst_finds_peer() {
        let mut t = RouteTable::new();
        t.add(PeerRoute {
            peer_id: [1u8; 8],
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        });
        t.add(PeerRoute {
            peer_id: [2u8; 8],
            allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
        });
        let r = t
            .route_for_dst(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
            .unwrap();
        assert_eq!(r.peer_id, [1u8; 8]);
        let r = t
            .route_for_dst(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 9)))
            .unwrap();
        assert_eq!(r.peer_id, [2u8; 8]);
        assert!(t
            .route_for_dst(IpAddr::V4(Ipv4Addr::new(10, 0, 9, 1)))
            .is_none());
    }

    #[test]
    fn longest_prefix_match_wins() {
        // Peer A owns 10.0.0.0/8 (broad); peer B owns the more
        // specific 10.0.5.0/24 inside it. A packet to 10.0.5.7
        // must route to B, not A — that's what longest-prefix
        // match means and what users expect.
        let mut t = RouteTable::new();
        let pid_a = [1u8; 8];
        let pid_b = [2u8; 8];
        t.add(PeerRoute {
            peer_id: pid_a,
            allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
        });
        t.add(PeerRoute {
            peer_id: pid_b,
            allowed_ips: vec!["10.0.5.0/24".parse().unwrap()],
        });
        // 10.0.5.7 is in both, B is more specific.
        let r = t
            .route_for_dst(IpAddr::V4(Ipv4Addr::new(10, 0, 5, 7)))
            .unwrap();
        assert_eq!(r.peer_id, pid_b, "more specific prefix must win");
        // 10.0.7.1 is only in A's /8.
        let r = t
            .route_for_dst(IpAddr::V4(Ipv4Addr::new(10, 0, 7, 1)))
            .unwrap();
        assert_eq!(r.peer_id, pid_a);
        // Insert order shouldn't matter — repeat with reversed insert.
        let mut t2 = RouteTable::new();
        t2.add(PeerRoute {
            peer_id: pid_b,
            allowed_ips: vec!["10.0.5.0/24".parse().unwrap()],
        });
        t2.add(PeerRoute {
            peer_id: pid_a,
            allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
        });
        let r = t2
            .route_for_dst(IpAddr::V4(Ipv4Addr::new(10, 0, 5, 7)))
            .unwrap();
        assert_eq!(r.peer_id, pid_b);
    }

    #[test]
    fn src_validation_rejects_spoof() {
        let mut t = RouteTable::new();
        let pid = [1u8; 8];
        t.add(PeerRoute {
            peer_id: pid,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        });
        assert!(t.src_is_valid(&pid, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(!t.src_is_valid(&pid, IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))));
    }
}
