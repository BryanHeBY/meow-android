use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};

/// Only this address is advertised by Android's configureVpnIp, even when
/// IPv6 forwarding is enabled. It is a local stub, never an upstream socket.
const VPN_DNS: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 2);

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub(crate) struct DnsHijackPolicy(bool);

impl Default for DnsHijackPolicy {
    fn default() -> Self {
        Self::new(true)
    }
}

impl DnsHijackPolicy {
    pub(crate) const fn new(enabled: bool) -> Self {
        Self(enabled)
    }

    pub(crate) fn is_vpn_endpoint(dst: SocketAddr) -> bool {
        dst.port() == 53 && dst.ip() == VPN_DNS
    }

    pub(crate) fn captures(self, dst: SocketAddr) -> bool {
        dst.port() == 53 && (self.0 || Self::is_vpn_endpoint(dst))
    }

    pub(crate) fn captures_raw_ipv4(self, dst: SocketAddr, has_owner_gate: bool) -> bool {
        // External datagrams with an owner gate need the shared stack's
        // Clash/Direct/Drop dispatch. The VPN stub is never a physical peer.
        self.captures(dst) && (!has_owner_gate || Self::is_vpn_endpoint(dst))
    }
}

// Full reads the same typed setting in its strict overlay envelope. Lite
// ignores fields it does not use, but never accepts a non-boolean DNS setting.
#[cfg(any(test, all(target_os = "android", not(feature = "zerotier"))))]
pub(crate) fn parse_lite_session(json: &[u8]) -> Result<DnsHijackPolicy, &'static str> {
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Settings {
        dns_hijacking: DnsHijackPolicy,
    }
    if json.len() > 256 * 1024 {
        return Err("TUN session settings exceed the size limit");
    }
    if json.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err("invalid TUN session settings");
    }
    serde_json::from_slice::<Settings>(json)
        .map(|settings| settings.dns_hijacking)
        .map_err(|_| "invalid TUN session settings")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_ipv4_uses_owner_dispatch_for_external_plain_dns_only() {
        let stub = SocketAddr::from((VPN_DNS, 53));
        let external = SocketAddr::from(([192, 0, 2, 1], 53));
        let doh = SocketAddr::from(([192, 0, 2, 1], 443));
        let dot = SocketAddr::from(([192, 0, 2, 1], 853));
        for enabled in [false, true] {
            let policy = DnsHijackPolicy::new(enabled);
            for gated in [false, true] {
                assert!(policy.captures_raw_ipv4(stub, gated));
                assert_eq!(policy.captures_raw_ipv4(external, gated), enabled && !gated);
                assert_eq!(
                    policy.captures(external),
                    enabled,
                    "a gated datagram still reaches the ordinary Clash/Direct/Drop dispatcher"
                );
                assert!(!policy.captures_raw_ipv4(doh, gated));
                assert!(!policy.captures_raw_ipv4(dot, gated));
                assert!(!policy.captures(doh));
                assert!(!policy.captures(dot));
            }
        }
    }

    #[test]
    fn native_session_dns_switch_has_identical_strict_boolean_defaults() {
        for (input, expected) in [
            (br#"{}"#.as_slice(), true),
            (br#"{ "dns_hijacking": true }"#, true),
            (br#"{ "dns_hijacking": false }"#, false),
        ] {
            assert_eq!(
                parse_lite_session(input),
                Ok(DnsHijackPolicy::new(expected))
            );
            #[cfg(feature = "zerotier")]
            assert_eq!(
                crate::zerotier_config::parse_session(input).map(|(_, _, dns)| dns),
                Ok(DnsHijackPolicy::new(expected)),
            );
        }
        for input in [
            br#"{ "dns_hijacking": null }"#.as_slice(),
            br#"{ "dns_hijacking": "false" }"#,
            br#"{ "dns_hijacking": 0 }"#,
            br#"{ "dns_hijacking": false, "dns_hijacking": true }"#,
            br#"[false]"#,
        ] {
            assert!(parse_lite_session(input).is_err());
            #[cfg(feature = "zerotier")]
            assert!(crate::zerotier_config::parse_session(input).is_err());
        }
    }
}
