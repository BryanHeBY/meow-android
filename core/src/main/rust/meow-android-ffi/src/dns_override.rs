use anyhow::{bail, Result};
use meow_common::{AdapterType, Proxy};
use meow_config::raw::RawDns;
use meow_dns::{NameServerEntry, NameServerUrl};
use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsIssue {
    InvalidSettings,
    ProfileChanged,
    Pending,
    ProfileUnavailable,
    ProxyUnavailable,
    SplitUnavailable,
    ResolverRejected,
    SaveFailed,
}

impl std::fmt::Display for DnsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::InvalidSettings => "INVALID_SETTINGS",
            Self::ProfileChanged => "PROFILE_CHANGED",
            Self::Pending => "PENDING",
            Self::ProfileUnavailable => "PROFILE_UNAVAILABLE",
            Self::ProxyUnavailable => "PROXY_UNAVAILABLE",
            Self::SplitUnavailable => "SPLIT_UNAVAILABLE",
            Self::ResolverRejected => "RESOLVER_REJECTED",
            Self::SaveFailed => "SAVE_FAILED",
        };
        f.write_str(name)
    }
}

impl std::error::Error for DnsIssue {}

pub(crate) const CN_NAMESERVERS: &[&str] = &["tcp://119.29.29.29", "tcp://223.5.5.5"];
const NEUTRAL_NAMESERVERS: &[&str] = &["tcp://1.1.1.1", "tcp://8.8.8.8"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsUpstreams {
    Inherit,
    Profile,
    Builtin,
    Cn,
    Split { proxy: String },
    Custom(Vec<Upstream>),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Upstream {
    transport: Transport,
    endpoint: String,
    egress: Egress,
    #[serde(default)]
    proxy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Udp,
    Tcp,
    Tls,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Egress {
    Direct,
    Proxy,
}

impl DnsUpstreams {
    #[cfg(test)]
    pub(crate) fn decode(wire: &str) -> Result<Self> {
        Self::decode_scoped(wire).map(|(mode, _)| mode)
    }

    pub(crate) fn decode_scoped(wire: &str) -> Result<(Self, Option<i64>)> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Preference {
            version: u8,
            mode: String,
            #[serde(default)]
            split_proxy: String,
            #[serde(default)]
            upstreams: Vec<Upstream>,
            profile_id: Option<i64>,
        }
        if wire.len() > 16_384 {
            bail!("DNS preference is too large");
        }
        let pref: Preference =
            serde_json::from_str(wire).map_err(|_| anyhow::anyhow!("Invalid DNS preference"))?;
        if pref.version != 1 {
            bail!("Unsupported DNS preference version");
        }
        let mode = match pref.mode.as_str() {
            "inherit" => Self::Inherit,
            "profile" => Self::Profile,
            "builtin" => Self::Builtin,
            "cn" => Self::Cn,
            "split" => {
                validate_proxy_name(&pref.split_proxy)?;
                Self::Split {
                    proxy: pref.split_proxy,
                }
            }
            "custom" => {
                if !(1..=6).contains(&pref.upstreams.len()) {
                    bail!("Enter between one and six DNS upstreams");
                }
                for (index, upstream) in pref.upstreams.iter().enumerate() {
                    upstream
                        .entry()
                        .map_err(|e| anyhow::anyhow!("DNS upstream {}: {e}", index + 1))?;
                }
                Self::Custom(pref.upstreams)
            }
            _ => bail!("Unknown DNS mode"),
        };
        Ok((mode, pref.profile_id))
    }

    pub(crate) fn require_scope(&self, owner: Option<i64>, selected: i64) -> Result<()> {
        if self.requires_profile() {
            let owner = owner.filter(|&id| id > 0).ok_or(DnsIssue::Pending)?;
            if owner != selected {
                bail!(DnsIssue::ProfileUnavailable);
            }
        }
        Ok(())
    }

    pub(crate) fn requires_profile(&self) -> bool {
        self.proxy_targets().next().is_some()
    }

    pub(crate) fn check_android_support(&self) -> Result<()> {
        // Android's UDP bridge resolves fake-IP destinations before the core
        // classifies the flow. The pinned core cannot return the resulting NAT
        // key to this bridge after classifying, so Split stays unavailable.
        if matches!(self, Self::Split { .. }) {
            bail!(DnsIssue::SplitUnavailable);
        }
        Ok(())
    }

    pub(crate) fn check_resolver(&self, resolver: &meow_dns::Resolver) -> Result<()> {
        if self.requires_profile() {
            let clients = resolver
                .main_nameservers()
                .iter()
                .map(|client| client.is_proxied());
            let matches = match self {
                Self::Split { .. } => clients.eq([true]),
                Self::Custom(upstreams) => {
                    clients.eq(upstreams.iter().map(|u| u.egress == Egress::Proxy))
                }
                _ => unreachable!(),
            };
            if !matches {
                bail!(DnsIssue::ResolverRejected);
            }
        }
        Ok(())
    }

    pub(crate) fn mode(&self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::Profile => "profile",
            Self::Builtin => "builtin",
            Self::Cn => "cn",
            Self::Split { .. } => "split",
            Self::Custom(_) => "custom",
        }
    }

    fn proxy_targets(&self) -> impl Iterator<Item = (&str, bool)> {
        let split = match self {
            Self::Split { proxy } => Some((proxy.as_str(), false)),
            _ => None,
        };
        let custom = match self {
            Self::Custom(upstreams) => upstreams.as_slice(),
            _ => &[],
        };
        split.into_iter().chain(custom.iter().filter_map(|server| {
            (server.egress == Egress::Proxy)
                .then_some((server.proxy.as_str(), server.transport == Transport::Udp))
        }))
    }

    pub(crate) fn check_targets<'a>(
        &self,
        get: impl Fn(&str) -> Option<&'a dyn Proxy>,
    ) -> Result<()> {
        for (name, needs_udp) in self.proxy_targets() {
            let Some(proxy) = get(name) else {
                bail!(DnsIssue::ProxyUnavailable);
            };
            // Groups can select DIRECT, DNS, or an implicit COMPATIBLE
            // member. A self-dialing node gives this override a stable egress.
            if !is_proxy_node(proxy) || proxy.has_configured_dialer() {
                bail!(DnsIssue::ProxyUnavailable);
            }
            if needs_udp && !proxy.support_udp() {
                bail!(DnsIssue::ProxyUnavailable);
            }
        }
        Ok(())
    }

    /// Only inspect cached YAML and construct the named inline adapters.
    /// The VPN load and live commit check the actual published proxy registry.
    pub(crate) fn check_cached_profile(
        &self,
        yaml: &str,
        policy: &crate::nameserver_policy_override::NameserverPolicyOverride,
    ) -> Result<()> {
        if !self.requires_profile() {
            return Ok(());
        }
        let mode = self.clone();
        let policy = policy.clone();
        let prepared = meow_common::yaml::run_on_parse_stack(yaml, move |yaml| {
            crate::engine::strip_and_inject_with_policy(yaml, mode, &policy)
        })
        .map_err(|_| DnsIssue::ResolverRejected)?
        .map_err(|_| DnsIssue::ResolverRejected)?;
        let raw = meow_config::parse_raw_yaml(&prepared).map_err(|_| DnsIssue::ResolverRejected)?;
        let mut proxies = std::collections::HashMap::new();
        for (name, _) in self.proxy_targets() {
            if proxies.contains_key(name) {
                continue;
            }
            if matches!(
                name,
                "DIRECT"
                    | "REJECT"
                    | "REJECT-DROP"
                    | "COMPATIBLE"
                    | "PASS"
                    | "PASS-RULE"
                    | "GLOBAL"
            ) || raw
                .proxy_groups
                .iter()
                .flatten()
                .any(|group| group.name == name)
            {
                bail!(DnsIssue::ProxyUnavailable);
            }
            let node = raw
                .proxies
                .iter()
                .flatten()
                .rev()
                .find(|node| node.get("name").and_then(|value| value.as_str()) == Some(name))
                .ok_or(DnsIssue::ProxyUnavailable)?;
            // The standalone parser is for unchained nodes. Avoid creating
            // external plugin subprocesses while checking a cached profile.
            let chained = node
                .get("dialer-proxy")
                .is_some_and(|value| !value.is_null() && value.as_str() != Some(""));
            if chained || meow_config::proxy_parser::node_selects_external_plugin(node) {
                bail!(DnsIssue::ProxyUnavailable);
            }
            let proxy =
                meow_config::proxy_parser::parse_proxy(node, meow_config::effective_ipv6(raw.ipv6))
                    .map_err(|_| DnsIssue::ProxyUnavailable)?;
            proxies.insert(name, proxy);
        }
        self.check_targets(|name| proxies.get(name).map(std::sync::Arc::as_ref))
    }
}

fn is_proxy_node(proxy: &dyn Proxy) -> bool {
    matches!(
        proxy.adapter_type(),
        AdapterType::Shadowsocks
            | AdapterType::Socks5
            | AdapterType::Http
            | AdapterType::Vmess
            | AdapterType::Vless
            | AdapterType::Trojan
            | AdapterType::Hysteria2
            | AdapterType::TrustTunnel
            | AdapterType::Anytls
            | AdapterType::Snell
            | AdapterType::WireGuard
    )
}

fn validate_proxy_name(proxy: &str) -> Result<()> {
    if proxy.is_empty()
        || proxy.len() > 256
        || proxy.trim() != proxy
        || proxy.chars().any(char::is_control)
    {
        bail!("Enter the exact proxy node name");
    }
    Ok(())
}

fn proxy_parameter(proxy: &str) -> String {
    use std::fmt::Write;
    let mut encoded = String::new();
    for byte in proxy.bytes() {
        write!(encoded, "%{byte:02X}").expect("writing to a String");
    }
    encoded
}

impl Upstream {
    fn entry(&self) -> Result<String> {
        let endpoint = self.endpoint.as_str();
        if endpoint.is_empty()
            || endpoint.len() > 512
            || !endpoint.is_ascii()
            || endpoint
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            || endpoint.contains(['@', '?', '#', '\\'])
        {
            bail!("Enter a hostname or IP, optionally with a port or DoH path");
        }
        let (authority, path) = endpoint.split_once('/').unwrap_or((endpoint, ""));
        if self.transport != Transport::Https && authority != endpoint {
            bail!("Only DoH accepts a path");
        }
        if path
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !b"-._~!$&'()*+,;=:/%".contains(&b))
            || path.match_indices('%').any(|(i, _)| {
                path.as_bytes()
                    .get(i + 1..i + 3)
                    .is_none_or(|digits| !digits.iter().all(u8::is_ascii_hexdigit))
            })
        {
            bail!("Invalid DoH path");
        }
        let scheme = match self.transport {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Tls => "tls",
            Transport::Https => "https",
        };
        let mut entry = format!("{scheme}://{endpoint}");
        let url = NameServerUrl::parse(&entry)
            .map_err(|_| anyhow::anyhow!("Invalid DNS host or port"))?;
        if url
            .needs_bootstrap()
            .is_some_and(|host| !valid_hostname(host))
        {
            bail!("Invalid DNS hostname");
        }
        if self.egress == Egress::Proxy {
            validate_proxy_name(&self.proxy)?;
            if matches!(self.transport, Transport::Udp | Transport::Tcp) {
                entry.push('#');
                // The core does not percent-decode plain proxy tags.
                entry.push_str(&self.proxy);
            } else {
                entry.push_str("?proxy=");
                entry.push_str(&proxy_parameter(&self.proxy));
            }
        }
        if self.transport == Transport::Https {
            entry.push_str(if self.egress == Egress::Proxy {
                "&h3=false"
            } else {
                "?h3=false"
            });
        }
        let parsed = NameServerEntry::parse(&entry)
            .map_err(|_| anyhow::anyhow!("Invalid DNS egress or endpoint"))?;
        if self.egress == Egress::Proxy && parsed.proxy.as_deref() != Some(self.proxy.as_str()) {
            bail!("The proxy name is incompatible with this DNS transport");
        }
        Ok(entry)
    }
}

fn valid_hostname(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && !(host.contains('.') && host.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        && (host.parse::<IpAddr>().is_ok()
            || host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
}

pub(crate) fn fake_ip_filter_mode_supported(mode: Option<&Value>) -> bool {
    mode.is_none_or(|mode| {
        mode.is_null()
            || matches!(
                mode.as_str(),
                Some("blacklist" | "black-list" | "whitelist" | "white-list")
            )
    })
}

// Mirror the pin's DomainTrie token normalization before inheriting a
// policy into Built-in DNS. Strict profile validation otherwise raises on
// a dead label, an error Built-in did not inherit before this feature.
fn inherited_fake_ip_pattern_valid(value: &Value) -> bool {
    value.as_str().is_some_and(|key| {
        let key = key.trim();
        let domain = key
            .strip_prefix("+.")
            .or_else(|| key.strip_prefix("*."))
            .or_else(|| key.strip_prefix('.'))
            .unwrap_or(key)
            .trim_end_matches('.');
        !domain.is_empty() && domain.split('.').all(|label| !label.is_empty())
    })
}

pub(crate) fn engine_dns_block(
    profile: Option<Value>,
    mode: &DnsUpstreams,
    policy: &crate::nameserver_policy_override::NameserverPolicyOverride,
) -> Result<Mapping> {
    let mut dns = match (mode, profile) {
        // Built-in changes upstreams, not local DNS record/synthesis policy.
        // Do not carry any authored upstream or sockets into this branch.
        (DnsUpstreams::Builtin, profile) => {
            let mut dns = Mapping::new();
            if let Some(enabled) = profile
                .as_ref()
                .and_then(|value| value.get("use-hosts"))
                .and_then(Value::as_bool)
            {
                dns.insert("use-hosts".into(), enabled.into());
            }
            // Preserve supported local policy as a pair. Never drop an
            // unsupported mode alone: doing so would reinterpret its list.
            let filter_mode = profile
                .as_ref()
                .and_then(|value| value.get("fake-ip-filter-mode"));
            let filter = profile
                .as_ref()
                .and_then(|value| value.get("fake-ip-filter"));
            let valid_list = filter.is_none_or(|value| {
                value.is_null()
                    || value
                        .as_sequence()
                        .is_some_and(|list| list.iter().all(inherited_fake_ip_pattern_valid))
            });
            if fake_ip_filter_mode_supported(filter_mode) && valid_list {
                if let Some(filter) = filter {
                    dns.insert("fake-ip-filter".into(), filter.clone());
                }
                if let Some(mode) = filter_mode {
                    dns.insert("fake-ip-filter-mode".into(), mode.clone());
                }
            }
            dns
        }
        (_, None | Some(Value::Null)) => Mapping::new(),
        (_, Some(Value::Mapping(dns))) => {
            // Expand before checking for absent keys. The live rebuild then
            // sees the same inherited lists as startup.
            let mut block = Value::Mapping(dns);
            block
                .apply_merge()
                .map_err(|_| anyhow::anyhow!("Invalid DNS YAML merge"))?;
            match block {
                Value::Mapping(dns) => dns,
                _ => unreachable!(),
            }
        }
        _ => bail!("The profile DNS section must be a mapping"),
    };
    for (key, value) in [
        ("enable", true.into()),
        ("listen", "".into()),
        ("enhanced-mode", "fake-ip".into()),
        ("fake-ip-range", "28.0.0.0/8".into()),
    ] {
        dns.insert(key.into(), value);
    }
    policy.apply_fallback(&mut dns);
    match mode {
        DnsUpstreams::Builtin => {
            set(&mut dns, "nameserver", CN_NAMESERVERS.iter().copied());
            set(
                &mut dns,
                "default-nameserver",
                CN_NAMESERVERS.iter().copied(),
            );
        }
        DnsUpstreams::Cn => set(&mut dns, "nameserver", CN_NAMESERVERS.iter().copied()),
        DnsUpstreams::Split { proxy } => {
            if has_list(&dns, "fallback")
                || dns
                    .get("direct-nameserver-follow-policy")
                    .and_then(Value::as_bool)
                    == Some(true)
            {
                bail!("Split DNS conflicts with the profile DNS fallback or DIRECT policy");
            }
            // Rule-following DNS is absent in the pin. Only the core's
            // dedicated DIRECT slot and a named DoH adapter are used here.
            set(
                &mut dns,
                "nameserver",
                [format!(
                    "https://1.1.1.1/dns-query#cloudflare-dns.com?proxy={}&h3=false",
                    proxy_parameter(proxy)
                )],
            );
            set(
                &mut dns,
                "direct-nameserver",
                CN_NAMESERVERS.iter().copied(),
            );
            set(
                &mut dns,
                "default-nameserver",
                NEUTRAL_NAMESERVERS.iter().copied(),
            );
            set(
                &mut dns,
                "proxy-server-nameserver",
                NEUTRAL_NAMESERVERS.iter().copied(),
            );
        }
        DnsUpstreams::Custom(upstreams) => set(
            &mut dns,
            "nameserver",
            upstreams
                .iter()
                .map(Upstream::entry)
                .collect::<Result<Vec<_>>>()?,
        ),
        DnsUpstreams::Inherit | DnsUpstreams::Profile => {}
    }
    let missing_main = !has_list(&dns, "nameserver");
    for key in ["nameserver", "default-nameserver"] {
        if !has_list(&dns, key) {
            set(&mut dns, key, NEUTRAL_NAMESERVERS.iter().copied());
        }
    }
    if (missing_main || mode.proxy_targets().next().is_some())
        && !has_list(&dns, "proxy-server-nameserver")
    {
        set(
            &mut dns,
            "proxy-server-nameserver",
            NEUTRAL_NAMESERVERS.iter().copied(),
        );
    }
    policy.apply(&mut dns);
    // An override that uses a node must never change that node's own lookup
    // into a lookup routed through itself. Reject tagged node pools/policies
    // before any bootstrap lookup. Subscription mode keeps its own policy.
    let raw: RawDns = serde_yaml::from_value(Value::Mapping(dns.clone()))
        .map_err(|_| anyhow::anyhow!("Invalid DNS settings in the profile"))?;
    if missing_main || mode.proxy_targets().next().is_some() {
        let node_entries = raw
            .proxy_server_nameserver
            .iter()
            .flatten()
            .map(String::as_str)
            .chain(
                raw.proxy_server_nameserver_policy
                    .iter()
                    .flat_map(|policy| policy.values())
                    .flat_map(|entry| entry.as_urls()),
            );
        for entry in node_entries {
            if NameServerEntry::parse(entry).map_or(true, |entry| entry.proxy.is_some()) {
                bail!("Node DNS must use independent upstreams for this mode");
            }
        }
    }
    Ok(dns)
}

fn set(dns: &mut Mapping, key: &str, entries: impl IntoIterator<Item = impl Into<Value>>) {
    dns.insert(
        key.into(),
        Value::Sequence(entries.into_iter().map(Into::into).collect()),
    );
}

pub(crate) fn has_list(dns: &Mapping, key: &str) -> bool {
    match dns.get(key) {
        None | Some(Value::Null) => false,
        Some(Value::Sequence(list)) => !list.is_empty(),
        Some(_) => true,
    }
}

/// Keep transport/authority, using neither the URL path nor any settings
/// embedded in parameters, fragments or userinfo.
pub(crate) fn safe_endpoint(raw: &str) -> String {
    use meow_dns::upstream::HostOrIp;
    let Ok(entry) = NameServerEntry::parse(raw) else {
        return "[redacted upstream]".into();
    };
    let (scheme, addr, port) = match entry.url {
        NameServerUrl::Udp { addr, port } => ("udp", addr, port),
        NameServerUrl::Tcp { addr, port } => ("tcp", addr, port),
        NameServerUrl::Tls { addr, port, .. } => ("tls", addr, port),
        NameServerUrl::Https { addr, port, .. } => ("https", addr, port),
        NameServerUrl::Quic { addr, port, .. } => ("quic", addr, port),
        NameServerUrl::RCode { .. } => return "DNS response code".into(),
        _ => return "[redacted upstream]".into(),
    };
    let host = match addr {
        HostOrIp::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
        HostOrIp::Ip(ip) => ip.to_string(),
        HostOrIp::Host(host) if valid_hostname(&host) => host,
        HostOrIp::Host(_) => return "[redacted upstream]".into(),
    };
    let egress = if entry.proxy.is_some() {
        " (named proxy)"
    } else {
        ""
    };
    format!("{scheme}://{host}:{port}{egress}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(transport: &str, endpoint: &str, proxy: Option<&str>) -> Result<DnsUpstreams> {
        let pref = serde_json::json!({
            "version": 1,
            "mode": "custom",
            "upstreams": [{
                "transport": transport,
                "endpoint": endpoint,
                "egress": if proxy.is_some() { "proxy" } else { "direct" },
                "proxy": proxy.unwrap_or_default(),
            }]
        });
        DnsUpstreams::decode(&pref.to_string())
    }

    #[test]
    fn cached_dns_checks_only_compatible_inline_nodes() {
        let profile = "\
proxies: [{name: Node, type: http, server: 192.0.2.8, port: 8080}]
proxy-groups: [{name: Group, type: select, proxies: [Node]}]
proxy-providers: {Remote: {type: http, url: 'https://must-not-fetch.invalid/private'}}
rules: [MATCH,DIRECT]
";
        let tcp = custom("tcp", "192.0.2.53", Some("Node")).unwrap();
        tcp.check_cached_profile(profile, &Default::default())
            .unwrap();
        for mode in [
            custom("tcp", "192.0.2.53", Some("Group")).unwrap(),
            custom("tcp", "192.0.2.53", Some("Unknown")).unwrap(),
            custom("udp", "192.0.2.53", Some("Node")).unwrap(),
        ] {
            let issue = mode
                .check_cached_profile(profile, &Default::default())
                .unwrap_err();
            assert_eq!(
                issue.downcast::<DnsIssue>().unwrap(),
                DnsIssue::ProxyUnavailable
            );
        }
        assert!(tcp
            .check_cached_profile(
                &profile.replace("port: 8080", "port: 8080, dialer-proxy: Group"),
                &Default::default(),
            )
            .is_err());
    }

    #[test]
    fn named_custom_preflight_applies_policy_snapshot_without_bypassing_shape_or_node_checks() {
        use crate::nameserver_policy_override::NameserverPolicyOverride;
        let profile = "dns: {nameserver-policy: broken-map}\nproxies: [{name: Node, type: http, server: 192.0.2.8, port: 8080}]\nrules: [MATCH,DIRECT]\n";
        let mode = custom("tcp", "192.0.2.53", Some("Node")).unwrap();
        let empty = NameserverPolicyOverride::decode("[]").unwrap();
        let row = NameserverPolicyOverride::decode(
            r#"[{"pattern":"only.test","transport":"TCP","endpoint":"127.0.0.1:5353"}]"#,
        )
        .unwrap();
        assert_eq!(
            mode.check_cached_profile(profile, &NameserverPolicyOverride::default())
                .unwrap_err()
                .downcast::<DnsIssue>()
                .unwrap(),
            DnsIssue::ResolverRejected
        );
        mode.check_cached_profile(profile, &empty).unwrap();
        mode.check_cached_profile(profile, &row).unwrap();
        let no_node = profile.replace("name: Node", "name: Other");
        assert_eq!(
            mode.check_cached_profile(&no_node, &empty)
                .unwrap_err()
                .downcast::<DnsIssue>()
                .unwrap(),
            DnsIssue::ProxyUnavailable
        );
        let scalar = profile.replace("{nameserver-policy: broken-map}", "scalar");
        assert_eq!(
            mode.check_cached_profile(&scalar, &row)
                .unwrap_err()
                .downcast::<DnsIssue>()
                .unwrap(),
            DnsIssue::ResolverRejected
        );
    }

    #[test]
    fn named_dns_requires_saved_identity_even_when_yaml_is_identical() {
        let mode = custom("tcp", "192.0.2.53", Some("Node")).unwrap();
        mode.require_scope(Some(11), 11).unwrap();
        let error = mode.require_scope(Some(11), 12).unwrap_err();
        assert_eq!(
            error.downcast::<DnsIssue>().unwrap(),
            DnsIssue::ProfileUnavailable
        );
        let error = mode.require_scope(None, 11).unwrap_err();
        assert_eq!(error.downcast::<DnsIssue>().unwrap(), DnsIssue::Pending);
        custom("tcp", "192.0.2.53", None)
            .unwrap()
            .require_scope(None, 0)
            .unwrap();
    }

    #[test]
    fn android_dns_rejects_split_until_the_udp_path_can_keep_the_core_route() {
        let mode = DnsUpstreams::Split {
            proxy: "Node".into(),
        };
        let error = mode.check_android_support().unwrap_err();
        assert_eq!(
            error.downcast::<DnsIssue>().unwrap(),
            DnsIssue::SplitUnavailable
        );
    }

    #[test]
    fn custom_dns_validates_endpoints_and_round_trips_named_egress() {
        for invalid in [
            "https://dns.example",
            "user:secret@dns.example",
            "dns.example:0",
            "dns.example:65536",
            "dns.example:bad",
            "dns.example:443?proxy=secret",
            "dns.example#secret",
            "dns.example/%xx",
            "dns.example/path with space",
            "bad..example",
            "999.1.1.1",
        ] {
            let err = custom("https", invalid, None).unwrap_err().to_string();
            assert!(err.starts_with("DNS upstream 1:"));
            assert!(!err.contains("secret"));
        }
        assert!(custom("quic", "dns.example", None).is_err());
        assert!(custom("tcp", "dns.example/path", None).is_err());
        assert!(custom("tcp", "dns.example", Some("")).is_err());
        for (transport, address, name) in [
            ("tcp", "192.0.2.2:5353", "Node A"),
            ("udp", "[2001:db8::53]:5353", "Node B"),
            ("tls", "dns.example", "Node C"),
            ("https", "dns.example/private/path", "🌐 P#?&%"),
        ] {
            let DnsUpstreams::Custom(upstreams) = custom(transport, address, Some(name)).unwrap()
            else {
                unreachable!()
            };
            let entry = upstreams[0].entry().unwrap();
            let parsed = NameServerEntry::parse(&entry).unwrap();
            assert_eq!(parsed.proxy.as_deref(), Some(name));
            assert!(entry.starts_with(transport));
        }
    }

    #[test]
    fn status_redacts_upstream_paths_parameters_credentials_and_proxy_names() {
        assert_eq!(
            safe_endpoint("https://dns.example/private?token=secret?proxy=hidden#sni.example"),
            "https://dns.example:443 (named proxy)"
        );
        assert_eq!(
            safe_endpoint("https://username:password@dns.example/path"),
            "[redacted upstream]"
        );
        assert_eq!(
            safe_endpoint("tcp://[2001:db8::53]:5353"),
            "tcp://[2001:db8::53]:5353"
        );
    }
}
