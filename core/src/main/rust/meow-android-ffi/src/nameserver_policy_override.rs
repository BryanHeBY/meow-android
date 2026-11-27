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
    fallback: Option<Fallback>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Snapshot {
    nameserver_policy: Option<Vec<Row>>,
    #[serde(default, deserialize_with = "present_bool")]
    ipv6: Option<bool>,
    #[serde(default, deserialize_with = "present_fallback")]
    fallback: Option<RawFallback>,
}

fn present_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    bool::deserialize(d).map(Some)
}

fn present_fallback<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RawFallback>, D::Error> {
    map_only::<RawFallback, _>(d).map(Some)
}

fn map_only<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(d: D) -> Result<T, D::Error> {
    struct OnlyMap<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for OnlyMap<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a DNS settings object")
        }

        fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    d.deserialize_map(OnlyMap(std::marker::PhantomData))
}

#[derive(Clone, Debug)]
enum Fallback {
    Disabled,
    Replace {
        upstreams: Vec<String>,
        domains: Vec<String>,
        cidrs: Vec<String>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
enum RawFallback {
    Disabled {},
    Replace {
        endpoints: Vec<Endpoint>,
        domains: Vec<String>,
        cidrs: Vec<String>,
    },
}

struct Endpoint {
    transport: Transport,
    endpoint: String,
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            transport: Transport,
            endpoint: String,
        }
        let fields = map_only::<Fields, _>(d)?;
        Ok(Self {
            transport: fields.transport,
            endpoint: fields.endpoint,
        })
    }
}

impl RawFallback {
    fn validate(self) -> Result<Fallback> {
        let Self::Replace {
            endpoints,
            domains,
            cidrs,
        } = self
        else {
            return Ok(Fallback::Disabled);
        };
        ensure!(
            (1..=8).contains(&endpoints.len()),
            "invalid DNS fallback upstream count"
        );
        ensure!(
            domains.len() <= 8 && cidrs.len() <= 16,
            "too many DNS fallback filters"
        );
        let mut seen = HashSet::new();
        let mut upstreams = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let upstream = numeric_upstream(endpoint.transport, &endpoint.endpoint)?;
            ensure!(
                seen.insert(upstream.clone()),
                "duplicate DNS fallback upstream"
            );
            upstreams.push(upstream);
        }
        let mut seen = HashSet::new();
        for domain in &domains {
            ensure!(
                valid_domain(domain.strip_prefix("+.").unwrap_or(domain)) && seen.insert(domain),
                "invalid or duplicate DNS fallback domain"
            );
        }
        let mut cidr_identities = HashSet::new();
        for cidr in &cidrs {
            let identity = cidr_identity(cidr).context("invalid DNS fallback CIDR")?;
            ensure!(
                cidr_identities.insert(identity),
                "duplicate DNS fallback CIDR"
            );
        }
        Ok(Fallback::Replace {
            upstreams,
            domains,
            cidrs,
        })
    }
}

fn cidr_identity(text: &str) -> Option<(IpAddr, u32)> {
    let (address, width) = text.split_once('/')?;
    let width_num = width.parse::<u32>().ok()?;
    if width != width_num.to_string() {
        return None;
    }
    let ip = address.parse::<IpAddr>().ok()?;
    let valid = match ip {
        IpAddr::V4(ip) if width_num <= 32 => {
            width_num == 32 || (u32::from(ip) & (u32::MAX >> width_num)) == 0
        }
        IpAddr::V6(ip) if width_num <= 128 && ip.to_ipv4_mapped().is_none() => {
            width_num == 128 || (u128::from(ip) & (u128::MAX >> width_num)) == 0
        }
        _ => false,
    };
    valid.then_some((ip, width_num))
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
        let (rows, dns_ipv6, fallback) = if wire.trim_start().starts_with('{') {
            let snapshot: Snapshot = serde_json::from_str(wire).context("invalid DNS snapshot")?;
            let fallback = snapshot.fallback.map(RawFallback::validate).transpose()?;
            ensure!(
                snapshot.ipv6.is_some() || fallback.is_some(),
                "empty DNS snapshot object"
            );
            (snapshot.nameserver_policy, snapshot.ipv6, fallback)
        } else {
            (
                serde_json::from_str::<Option<Vec<Row>>>(wire).context("invalid DNS policy")?,
                None,
                None,
            )
        };
        let Some(rows) = rows else {
            return Ok(Self {
                rows: None,
                dns_ipv6,
                fallback,
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
            validated.push((row.pattern, numeric_upstream(row.transport, &row.endpoint)?));
        }
        Ok(Self {
            rows: Some(validated),
            dns_ipv6,
            fallback,
        })
    }

    pub(crate) fn apply_fallback(&self, dns: &mut Mapping) {
        let Some(fallback) = &self.fallback else {
            return;
        };
        dns.remove("fallback");
        dns.remove("fallback-filter");
        if let Fallback::Replace {
            upstreams,
            domains,
            cidrs,
        } = fallback
        {
            let sequence = |items: &[String]| {
                Value::Sequence(items.iter().cloned().map(Value::String).collect())
            };
            dns.insert("fallback".into(), sequence(upstreams));
            let filter = Mapping::from_iter([
                ("geoip".into(), Value::Bool(false)),
                ("domain".into(), sequence(domains)),
                ("ipcidr".into(), sequence(cidrs)),
            ]);
            dns.insert("fallback-filter".into(), Value::Mapping(filter));
        }
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

fn numeric_upstream(transport: Transport, endpoint: &str) -> Result<String> {
    ensure!(
        !endpoint.contains('%'),
        "scoped DNS policy endpoints are unsupported"
    );
    let address = endpoint
        .parse::<SocketAddr>()
        .context("DNS policy requires a numeric address and port")?;
    ensure!(
        address.port() != 0
            && endpoint
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
                IpAddr::V6(v6) => !v6.is_unicast_link_local() && v6.to_ipv4_mapped().is_none(),
            },
        "invalid DNS policy address"
    );
    let scheme = match transport {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
    };
    Ok(format!("{scheme}://{address}"))
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
    fn dns_fallback_replaces_or_disables_the_whole_pair_and_preserves_inherited_yaml() {
        let authored: Value = serde_yaml::from_str(
            "nameserver: ['rcode://refused']\nfallback: ['https://authored.test/dns-query']\nfallback-filter: {geoip: true, geoip-code: JP, domain: ['*.example.test']}\n",
        ).unwrap();
        let profile = Some(authored.clone());
        let inherit = NameserverPolicyOverride::decode("null").unwrap();
        let disabled =
            NameserverPolicyOverride::decode(r#"{"fallback":{"mode":"disabled"}}"#).unwrap();
        let replaced = NameserverPolicyOverride::decode(r#"{"fallback":{"mode":"replace","endpoints":[{"transport":"UDP","endpoint":"127.0.0.1:5353"}],"domains":["+.example.test"],"cidrs":["203.0.113.0/24","2001:db8::/32"]}}"#).unwrap();
        for mode in [DnsUpstreams::Profile, DnsUpstreams::Builtin] {
            let inherited = engine_dns_block(profile.clone(), &mode, &inherit).unwrap();
            let disabled = engine_dns_block(profile.clone(), &mode, &disabled).unwrap();
            let replaced = engine_dns_block(profile.clone(), &mode, &replaced).unwrap();
            assert!(!disabled.contains_key("fallback"));
            assert!(!disabled.contains_key("fallback-filter"));
            assert_eq!(
                replaced["fallback"][0].as_str(),
                Some("udp://127.0.0.1:5353")
            );
            assert_eq!(replaced["fallback-filter"]["geoip"].as_bool(), Some(false));
            assert!(replaced["fallback-filter"].get("geoip-code").is_none());
            if mode == DnsUpstreams::Profile {
                assert_eq!(inherited.get("fallback"), authored.get("fallback"));
                assert_eq!(
                    inherited.get("fallback-filter"),
                    authored.get("fallback-filter")
                );
            } else {
                assert!(!inherited.contains_key("fallback"));
                assert!(!inherited.contains_key("fallback-filter"));
            }
        }
        assert_eq!(
            cidr_identity("2001:db8::/32"),
            cidr_identity("2001:0db8:0:0:0:0:0:0/32")
        );
        assert_ne!(
            cidr_identity("2001:db8::/32"),
            cidr_identity("2001:db9::/32")
        );
        for bad in [
            r#"{"ipv6":true,"fallback":null}"#,
            r#"{"fallback":{"mode":"disabled","geoip":true}}"#,
            r#"{"fallback":{"mode":"disabled","mode":"replace"}}"#,
            r#"{"fallback":{"mode":"replace","endpoints":[["UDP","127.0.0.1:53"]],"domains":[],"cidrs":[]}}"#,
            r#"{"fallback":{"mode":"replace","endpoints":[],"domains":[],"cidrs":[]}}"#,
            r#"{"fallback":{"mode":"replace","endpoints":[{"transport":"UDP","endpoint":"127.0.0.1:53#Node"}],"domains":[],"cidrs":[]}}"#,
            r#"{"fallback":{"mode":"replace","endpoints":[{"transport":"UDP","endpoint":"127.0.0.1:53"}],"domains":[],"cidrs":["203.0.113.1/24"]}}"#,
            r#"{"fallback":{"mode":"replace","endpoints":[{"transport":"UDP","endpoint":"127.0.0.1:53"}],"domains":[],"cidrs":["2001:db8::/32","2001:0db8:0:0:0:0:0:0/32"]}}"#,
            r#"{"fallback":{"mode":"replace","endpoints":[{"transport":"UDP","transport":"TCP","endpoint":"127.0.0.1:53"}],"domains":[],"cidrs":[]}}"#,
        ] {
            assert!(NameserverPolicyOverride::decode(bad).is_err(), "{bad}");
        }
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
