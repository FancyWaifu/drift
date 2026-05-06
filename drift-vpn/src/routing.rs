//! IP-packet → peer-pubkey routing.
//!
//! Each peer in the config declares `allowed_ips = [...]`; an
//! outbound IP packet from the tun device is routed to whichever
//! peer's allowed-IPs contain the packet's destination address.
//! This is the same model WireGuard uses.
//!
//! v0.1 implementation: linear scan over peers. For ≤100 peers
//! it's well under a microsecond. If/when we ever ship a
//! deployment with 1000+ peers, swap to a longest-prefix-match
//! trie.
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
pub struct PeerRoute {
    pub peer_id: PeerId,
    pub allowed_ips: Vec<IpNet>,
}

pub struct RouteTable {
    pub routes: Vec<PeerRoute>,
    /// peer_id → route index, for quick reverse lookups.
    by_peer_id: HashMap<PeerId, usize>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            by_peer_id: HashMap::new(),
        }
    }

    pub fn add(&mut self, route: PeerRoute) {
        let idx = self.routes.len();
        self.by_peer_id.insert(route.peer_id, idx);
        self.routes.push(route);
    }

    /// Forward routing: which peer's allowed_ips contain this
    /// destination IP? `None` if the packet is for nobody we
    /// know — drop it.
    pub fn route_for_dst(&self, dst: IpAddr) -> Option<&PeerRoute> {
        self.routes
            .iter()
            .find(|r| r.allowed_ips.iter().any(|n| n.contains(&dst)))
    }

    /// Reverse-path validation: is `src` allowed to come from
    /// `peer`? If yes, the packet's claimed source matches what
    /// the peer is supposed to own. If no, drop — the peer is
    /// either misconfigured or spoofing.
    pub fn src_is_valid(&self, peer: &PeerId, src: IpAddr) -> bool {
        match self.by_peer_id.get(peer) {
            Some(&idx) => self.routes[idx]
                .allowed_ips
                .iter()
                .any(|n| n.contains(&src)),
            None => false,
        }
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
pub fn parse_endpoints(pkt: &[u8]) -> Result<(IpAddr, IpAddr)> {
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
    fn parse_ipv4() {
        let mut pkt = vec![0x45]; // version 4, IHL 5
        pkt.resize(20, 0);
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let (src, dst) = parse_endpoints(&pkt).unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn parse_ipv6() {
        let mut pkt = vec![0x60];
        pkt.resize(40, 0);
        pkt[8..24].copy_from_slice(&[
            0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        pkt[24..40].copy_from_slice(&[
            0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);
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
        let r = t.route_for_dst(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))).unwrap();
        assert_eq!(r.peer_id, [1u8; 8]);
        let r = t.route_for_dst(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 9))).unwrap();
        assert_eq!(r.peer_id, [2u8; 8]);
        assert!(t.route_for_dst(IpAddr::V4(Ipv4Addr::new(10, 0, 9, 1))).is_none());
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
