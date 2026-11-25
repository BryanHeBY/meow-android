//! Resolve next hops inside the overlay; authorization is checked separately.
use crate::Prefix;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedRoute {
    pub target: Prefix,
    pub via: Option<Ipv4Addr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextHop {
    OnLink,
    Gateway(Ipv4Addr),
}

/// Ignore default routes and reject ambiguous or off-link next hops. Do not
/// fall back to a less specific route after finding an invalid match.
pub fn next_hop(
    local: Ipv4Addr,
    attached: Prefix,
    advertised: &[ManagedRoute],
    destination: Ipv4Addr,
) -> Option<NextHop> {
    if destination == local {
        return None;
    }
    let mut best = attached
        .contains(destination)
        .then_some((attached.length, Some(NextHop::OnLink)));
    for route in advertised {
        let length = route.target.length;
        if length == 0 || !route.target.contains(destination) {
            continue;
        }
        // An explicit link route still works outside the node's address mask.
        let hop = match route.via {
            None => Some(NextHop::OnLink),
            Some(ip)
                if ip != local
                    && attached.contains(ip)
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && (attached.length >= 31
                        || (u32::from(ip) != attached.network
                            && u32::from(ip) != (attached.network | !attached.mask))) =>
            {
                Some(NextHop::Gateway(ip))
            }
            _ => None,
        };
        match best {
            Some((n, _)) if n > length => {}
            Some((n, previous)) if n == length => {
                if previous != hop {
                    best = Some((length, None));
                }
            }
            _ => best = Some((length, hop)),
        }
    }
    best.and_then(|(_, hop)| hop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn prefix(s: &str, n: u8) -> Prefix {
        Prefix::new(ip(s), n).unwrap()
    }

    #[test]
    fn resolves_longest_prefix_without_accepting_default_or_unreachable_gateway() {
        let local = ip("10.12.0.7");
        let attached = prefix("10.12.0.7", 24);
        let broad = ManagedRoute {
            target: prefix("192.168.0.0", 16),
            via: Some(ip("10.12.0.1")),
        };
        let specific = ManagedRoute {
            target: prefix("192.168.11.0", 24),
            via: Some(ip("10.12.0.2")),
        };
        let invalid = ManagedRoute {
            target: prefix("192.168.11.100", 32),
            via: Some(ip("10.13.0.1")),
        };
        let default = ManagedRoute {
            target: prefix("0.0.0.0", 0),
            via: Some(ip("10.12.0.1")),
        };
        let routes = [specific, broad, invalid, default];
        for (addr, expect) in [
            ("10.12.0.3", Some(NextHop::OnLink)),
            ("10.12.0.7", None),
            ("192.168.0.30", Some(NextHop::Gateway(ip("10.12.0.1")))),
            ("192.168.11.30", Some(NextHop::Gateway(ip("10.12.0.2")))),
            ("192.168.11.100", None),
            ("8.8.8.8", None),
        ] {
            assert_eq!(next_hop(local, attached, &routes, ip(addr)), expect);
        }
    }

    #[test]
    fn allows_explicit_on_link_routes_and_rejects_equal_length_conflicts() {
        let local = ip("10.12.0.7");
        let attached = prefix("10.12.0.0", 24);
        let direct = ManagedRoute {
            target: prefix("172.18.0.0", 24),
            via: None,
        };
        let a = ManagedRoute {
            target: prefix("192.168.1.0", 24),
            via: Some(ip("10.12.0.2")),
        };
        let b = ManagedRoute {
            via: Some(ip("10.12.0.3")),
            ..a
        };
        let routes = [a, b, a, direct];
        assert_eq!(
            next_hop(local, attached, &routes, ip("172.18.0.8")),
            Some(NextHop::OnLink)
        );
        assert_eq!(next_hop(local, attached, &routes, ip("192.168.1.8")), None);
        let broadcast = ManagedRoute {
            via: Some(ip("10.12.0.255")),
            ..a
        };
        assert_eq!(
            next_hop(local, attached, &[broadcast], ip("192.168.1.8")),
            None
        );
    }
}
