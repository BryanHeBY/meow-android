//! App-authored DNS policy snapshots. A missing snapshot preserves the
//! original profile policy; selected rows never become the authored source.

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, Default)]
pub(crate) struct NameserverPolicyOverride {
    rows: Option<Vec<(String, String)>>,
    dns_ipv6: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Snapshot {
    nameserver_policy: Option<Vec<Row>>,
    ipv6: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    pattern: String,
    transport: Transport,
    endpoint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum Transport {
    Udp,
    Tcp,
}

impl NameserverPolicyOverride {
    pub(crate) fn decode(wire: &str) -> Result<Self> {
        ensure!(wire.len() <= 16_384, "DNS policy exceeds size limit");
        // Keep the formats disjoint. Struct deserializers can accept a
        // positional sequence; only a JSON object may carry DNS IPv6.
        // Deserialize directly so duplicate object fields are not collapsed.
        let (rows, dns_ipv6) = if wire.trim_start().starts_with('{') {
            let snapshot: Snapshot = serde_json::from_str(wire).context("invalid DNS snapshot")?;
            (snapshot.nameserver_policy, Some(snapshot.ipv6))
        } else {
            (
                serde_json::from_str::<Option<Vec<Row>>>(wire).context("invalid DNS policy")?,
                None,
            )
        };
        let Some(rows) = rows else {
            return Ok(Self {
                rows: None,
                dns_ipv6,
            });
        };
        ensure!(rows.len() <= 32, "DNS policy exceeds row limit");
        let mut patterns = HashSet::new();
        let mut validated = Vec::with_capacity(rows.len());
        for row in rows {
            let domain = row.pattern.strip_prefix("+.").unwrap_or(&row.pattern);
            ensure!(
                valid_domain(domain) && patterns.insert(row.pattern.clone()),
                "invalid DNS policy pattern"
            );
            ensure!(
                !row.endpoint.contains('%'),
                "scoped DNS policy endpoints are unsupported"
            );
            let address = row
                .endpoint
                .parse::<SocketAddr>()
                .context("DNS policy requires a numeric address and port")?;
            ensure!(
                address.port() != 0
                    && row
                        .endpoint
                        .rsplit_once(':')
                        .is_some_and(|(_, port)| port == address.port().to_string()),
                "invalid DNS policy port"
            );
            let ip = address.ip();
            ensure!(
                !ip.is_unspecified()
                    && !ip.is_multicast()
                    && match ip {
                        IpAddr::V4(v4) => !v4.is_broadcast(),
                        IpAddr::V6(v6) =>
                            !v6.is_unicast_link_local() && v6.to_ipv4_mapped().is_none(),
                    },
                "invalid DNS policy address"
            );
            let scheme = match row.transport {
                Transport::Udp => "udp",
                Transport::Tcp => "tcp",
            };
            validated.push((row.pattern, format!("{scheme}://{address}")));
        }
        Ok(Self {
            rows: Some(validated),
            dns_ipv6,
        })
    }

    pub(crate) fn apply(&self, dns: &mut Mapping) {
        if let Some(ipv6) = self.dns_ipv6 {
            dns.insert("ipv6".into(), Value::Bool(ipv6));
        }
        if let Some(rows) = &self.rows {
            // Mapping's insertion order is retained through serde_yaml and
            // the core's RawNameserverPolicy. An empty map clears explicitly.
            let mut policy = Mapping::new();
            for (pattern, target) in rows {
                policy.insert(pattern.clone().into(), target.clone().into());
            }
            dns.insert("nameserver-policy".into(), Value::Mapping(policy));
        }
    }
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_override::{engine_dns_block, DnsUpstreams};

    #[test]
    fn dns_ipv6_override_separates_builtin_defaults_and_authored_dns() {
        let profile = Some(serde_yaml::from_str::<Value>("ipv6: true").unwrap());
        let key = Value::String("ipv6".into());
        let inherit = NameserverPolicyOverride::decode("null").unwrap();
        let builtin = engine_dns_block(profile.clone(), &DnsUpstreams::Builtin, &inherit).unwrap();
        assert!(!builtin.contains_key(&key));
        let preserved = engine_dns_block(profile.clone(), &DnsUpstreams::Cn, &inherit).unwrap();
        assert_eq!(preserved.get(&key), Some(&Value::Bool(true)));

        let no_aaaa =
            NameserverPolicyOverride::decode(r#"{"nameserverPolicy":[],"ipv6":false}"#).unwrap();
        let allow_aaaa =
            NameserverPolicyOverride::decode(r#"{"nameserverPolicy":null,"ipv6":true}"#).unwrap();
        for mode in [DnsUpstreams::Builtin, DnsUpstreams::Cn] {
            let suppressed = engine_dns_block(profile.clone(), &mode, &no_aaaa).unwrap();
            let allowed = engine_dns_block(profile.clone(), &mode, &allow_aaaa).unwrap();
            assert_eq!(suppressed.get(&key), Some(&Value::Bool(false)));
            assert_eq!(allowed.get(&key), Some(&Value::Bool(true)));
            assert!(suppressed["nameserver-policy"]
                .as_mapping()
                .unwrap()
                .is_empty());
        }
        for wire in [
            r#"{"ipv6":"true"}"#,
            r#"{"ipv6":null}"#,
            r#"{"ipv6":true,"extra":0}"#,
        ] {
            assert!(NameserverPolicyOverride::decode(wire).is_err());
        }
        assert_eq!(profile.unwrap().get("ipv6"), Some(&Value::Bool(true)));
    }

    #[test]
    fn dns_snapshot_never_reinterprets_legacy_arrays_and_rejects_duplicate_fields() {
        for malformed in [
            "[null,false]",
            "[[],true]",
            "  [null, true]",
            r#"{"ipv6":true,"dynamic":false}"#,
            r#"{"ipv6":false,"ipv6":true}"#,
            r#"{"nameserverPolicy":[],"ipv6":true,"nameserverPolicy":null}"#,
        ] {
            assert!(
                NameserverPolicyOverride::decode(malformed).is_err(),
                "{malformed}"
            );
        }
        let mut dns = Mapping::new();
        for legacy in [
            "null",
            "[]",
            r#"[{"pattern":"example.test","transport":"UDP","endpoint":"127.0.0.1:53"}]"#,
        ] {
            NameserverPolicyOverride::decode(legacy)
                .unwrap()
                .apply(&mut dns);
            assert!(!dns.contains_key("ipv6"));
        }
        let snapshot = NameserverPolicyOverride::decode(r#"  {"ipv6":false}"#).unwrap();
        snapshot.apply(&mut dns);
        assert_eq!(dns.get("ipv6"), Some(&Value::Bool(false)));
    }

    #[test]
    fn only_safe_typed_rules_enter_the_snapshot() {
        for (pattern, transport, endpoint) in [
            ("rule-set:corp", "UDP", "127.0.0.1:53"),
            ("*.test", "UDP", "127.0.0.1:53"),
            ("test", "HTTPS", "127.0.0.1:53"),
            ("test", "TCP", "host.test:53"),
            ("test", "TCP", "127.0.0.1:00053"),
            ("test", "UDP", "127.0.0.1:53#proxy"),
            ("test", "UDP", "127.0.0.1:53/path"),
            ("test", "TCP", "[fe80::1%2]:53"),
            ("test", "TCP", "[::ffff:127.0.0.1]:53"),
            ("test", "TCP", "0.0.0.0:53"),
            ("test", "TCP", "224.0.0.1:53"),
        ] {
            let wire = serde_json::json!([{ "pattern": pattern, "transport": transport, "endpoint": endpoint }]);
            assert!(
                NameserverPolicyOverride::decode(&wire.to_string()).is_err(),
                "{wire}"
            );
        }
        assert!(NameserverPolicyOverride::decode(
            r#"[{"pattern":"x.test","transport":"UDP","endpoint":"127.0.0.1:53","proxy":"x"}]"#
        )
        .is_err());
    }

    #[test]
    fn inherited_advanced_policy_is_never_promoted_from_builtin() {
        let authored: Value = serde_yaml::from_str("nameserver-policy:\n  'rule-set:corp': 'https://resolver.invalid/dns-query#node'\n  '+.example.test': 'udp://127.0.0.1:53'").unwrap();
        let original = authored["nameserver-policy"].clone();
        for mode in [
            DnsUpstreams::Builtin,
            DnsUpstreams::Inherit,
            DnsUpstreams::Profile,
            DnsUpstreams::Cn,
        ] {
            let expected = if matches!(mode, DnsUpstreams::Builtin) {
                None
            } else {
                Some(&original)
            };
            let inherited = engine_dns_block(
                Some(authored.clone()),
                &mode,
                &NameserverPolicyOverride::default(),
            )
            .unwrap();
            assert_eq!(inherited.get("nameserver-policy"), expected);
            let cleared = engine_dns_block(
                Some(authored.clone()),
                &mode,
                &NameserverPolicyOverride::decode("[]").unwrap(),
            )
            .unwrap();
            assert!(cleared["nameserver-policy"]
                .as_mapping()
                .unwrap()
                .is_empty());
            let explicit = NameserverPolicyOverride::decode(
                r#"[{"pattern":"only.test","transport":"TCP","endpoint":"[::1]:5353"}]"#,
            )
            .unwrap();
            let replaced = engine_dns_block(Some(authored.clone()), &mode, &explicit).unwrap();
            assert_eq!(replaced["nameserver-policy"].as_mapping().unwrap().len(), 1);
            assert_eq!(
                replaced["nameserver-policy"]["only.test"],
                "tcp://[::1]:5353"
            );
        }
        assert_eq!(authored["nameserver-policy"], original);
    }
}
