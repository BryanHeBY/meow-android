#![forbid(unsafe_code)]

//! A first-pass policy for one explicit IPv4 ZeroTier network.
//! This module has no VPN, SDK, DNS or socket dependencies.

pub mod apps;
pub mod membership;
mod packet;
pub use packet::PacketError;

use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    network: u32,
    mask: u32,
    length: u8,
}

impl Prefix {
    pub fn new(address: Ipv4Addr, length: u8) -> Option<Self> {
        if length > 32 {
            return None;
        }
        let mask = if length == 0 {
            0
        } else {
            u32::MAX << (32 - length)
        };
        Some(Self {
            network: u32::from(address) & mask,
            mask,
            length,
        })
    }

    pub fn contains(self, address: Ipv4Addr) -> bool {
        u32::from(address) & self.mask == self.network
    }

    pub fn overlaps(self, other: Self) -> bool {
        let mask = self.mask & other.mask;
        self.network & mask == other.network & mask
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    EmptyOverlay,
    DefaultRoute,
    ReservedOrConflictingRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Clash,
    ZeroTier,
    DropOverlayUnavailable,
}

pub struct OverlayPolicy {
    approved: Vec<Prefix>,
}

impl OverlayPolicy {
    /// Only explicitly authorized overlay prefixes are accepted. The caller supplies
    /// the active local LAN, VPN-interface and fake-IP IPv4 ranges as conflicts.
    pub fn new(approved: Vec<Prefix>, conflicts: &[Prefix]) -> Result<Self, PolicyError> {
        if approved.is_empty() {
            return Err(PolicyError::EmptyOverlay);
        }
        if approved.iter().any(|p| p.length == 0) {
            return Err(PolicyError::DefaultRoute);
        }
        let reserved = [
            Prefix::new(Ipv4Addr::new(0, 0, 0, 0), 8).unwrap(),
            Prefix::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap(),
            Prefix::new(Ipv4Addr::new(169, 254, 0, 0), 16).unwrap(),
            Prefix::new(Ipv4Addr::new(224, 0, 0, 0), 3).unwrap(),
        ];
        if approved.iter().any(|p| {
            reserved
                .iter()
                .chain(conflicts)
                .any(|other| p.overlaps(*other))
        }) {
            return Err(PolicyError::ReservedOrConflictingRoute);
        }
        Ok(Self { approved })
    }

    /// Keep routing intent across reconnects: an unavailable overlay is not
    /// permission to send its private traffic through another upstream.
    pub fn classify(&self, address: IpAddr, ready: bool) -> Destination {
        match address {
            IpAddr::V4(ip) if self.approved.iter().any(|p| p.contains(ip)) => {
                if ready {
                    Destination::ZeroTier
                } else {
                    Destination::DropOverlayUnavailable
                }
            }
            _ => Destination::Clash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(ip: &str, bits: u8) -> Prefix {
        Prefix::new(ip.parse().unwrap(), bits).unwrap()
    }

    #[test]
    fn matches_exact_ipv4_boundaries_and_preserves_existing_ipv6_path() {
        let policy = OverlayPolicy::new(vec![prefix("10.77.20.42", 24)], &[]).unwrap();
        for ip in ["10.77.20.0", "10.77.20.1", "10.77.20.255"] {
            assert_eq!(
                policy.classify(ip.parse().unwrap(), true),
                Destination::ZeroTier
            );
        }
        for ip in ["10.77.19.255", "10.77.21.0", "1.1.1.1", "::1"] {
            assert_eq!(
                policy.classify(ip.parse().unwrap(), true),
                Destination::Clash
            );
        }
    }

    #[test]
    fn supports_explicit_host_routes_without_claiming_neighbours() {
        let policy = OverlayPolicy::new(vec![prefix("10.77.0.6", 32)], &[]).unwrap();
        assert_eq!(
            policy.classify("10.77.0.6".parse().unwrap(), true),
            Destination::ZeroTier
        );
        assert_eq!(
            policy.classify("10.77.0.7".parse().unwrap(), true),
            Destination::Clash
        );
        assert!(Prefix::new(Ipv4Addr::LOCALHOST, 33).is_none());
    }

    #[test]
    fn selected_overlay_never_falls_back_when_the_node_is_offline() {
        let policy = OverlayPolicy::new(vec![prefix("10.77.0.0", 16)], &[]).unwrap();
        assert_eq!(
            policy.classify("10.77.0.6".parse().unwrap(), false),
            Destination::DropOverlayUnavailable
        );
        assert_eq!(
            policy.classify("1.1.1.1".parse().unwrap(), false),
            Destination::Clash
        );
    }

    #[test]
    fn rejects_default_route_and_conflicts_in_both_overlap_directions() {
        assert_eq!(
            OverlayPolicy::new(vec![prefix("0.0.0.0", 0)], &[]).err(),
            Some(PolicyError::DefaultRoute)
        );
        for (candidate, collision) in [
            (prefix("198.18.5.0", 24), prefix("198.18.0.0", 16)),
            (prefix("172.19.0.0", 16), prefix("172.19.0.0", 30)),
            (prefix("192.168.1.0", 24), prefix("192.168.1.0", 24)),
        ] {
            assert_eq!(
                OverlayPolicy::new(vec![candidate], &[collision]).err(),
                Some(PolicyError::ReservedOrConflictingRoute)
            );
        }
    }

    #[test]
    fn rejects_multicast_and_loopback_routes() {
        for p in [prefix("224.0.0.0", 4), prefix("127.0.0.1", 32)] {
            assert_eq!(
                OverlayPolicy::new(vec![p], &[]).err(),
                Some(PolicyError::ReservedOrConflictingRoute)
            );
        }
    }
}
