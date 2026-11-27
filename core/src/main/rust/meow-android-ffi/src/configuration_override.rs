//! Startup overrides change only the runtime copy. The engine still owns DNS
//! injection and the legacy behavior of an unset IPv6 key.

use anyhow::{Context, Result};
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE};
use jni::JNIEnv;
use meow_common::ProcessLookupMode;

fn runtime_yaml(yaml: &str, enabled: bool) -> Result<String> {
    meow_common::yaml::run_on_parse_stack(yaml, move |yaml| {
        let mut doc: serde_yaml::Value =
            serde_yaml::from_str(yaml).context("parsing profile YAML")?;
        let map = doc.as_mapping_mut().context("expected a profile mapping")?;
        // An explicit top-level key also wins over any YAML merge.
        map.insert("ipv6".into(), enabled.into());
        serde_yaml::to_string(&doc).context("serializing runtime profile")
    })
    .context("starting the YAML parser")?
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FakeIpFilterMode {
    Blacklist,
    Whitelist,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FakeIpFilterOverride {
    patterns: Option<Vec<String>>,
    mode: Option<FakeIpFilterMode>,
}

pub(crate) fn source_dns_requires_builtin(yaml: &str) -> Result<bool> {
    meow_common::yaml::run_on_parse_stack(yaml, |yaml| {
        let mut doc: serde_yaml::Value =
            serde_yaml::from_str(yaml).context("parsing profile YAML")?;
        doc.apply_merge().context("applying profile YAML merges")?;
        let map = doc.as_mapping().context("expected a profile mapping")?;
        Ok(map
            .get("dns")
            .is_some_and(|dns| !dns.is_null() && !dns.is_mapping()))
    })
    .context("starting the YAML parser")?
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeSourceDnsRequiresBuiltin(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
) -> jboolean {
    let result = (|| -> Result<bool> {
        let yaml: String = env.get_string(&yaml)?.into();
        source_dns_requires_builtin(&yaml)
    })();
    match result {
        Ok(required) => jboolean::from(required),
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "Could not inspect the profile DNS shape",
            );
            JNI_FALSE
        }
    }
}

fn overlay_dns_mapping(
    map: &mut serde_yaml::Mapping,
    builtin_dns: bool,
) -> Result<&mut serde_yaml::Mapping> {
    use serde_yaml::Value;
    let block = map.entry("dns".into()).or_insert(Value::Null);
    // Built-in has always discarded a non-mapping authored DNS block.
    // Other modes still require their actual profile DNS to be a map.
    if block.is_null() || (builtin_dns && !block.is_mapping()) {
        *block = Value::Mapping(serde_yaml::Mapping::new());
    }
    block.as_mapping_mut().context("expected a DNS mapping")
}

pub(crate) fn fake_ip_filter_yaml(
    yaml: &str,
    options: FakeIpFilterOverride,
    builtin_dns: bool,
) -> Result<String> {
    meow_common::yaml::run_on_parse_stack(yaml, move |yaml| {
        use serde_yaml::Value;
        let mut doc: Value = serde_yaml::from_str(yaml).context("parsing profile YAML")?;
        doc.apply_merge().context("applying profile YAML merges")?;
        let map = doc.as_mapping_mut().context("expected a profile mapping")?;
        if options.patterns.is_none() && options.mode.is_none() {
            return serde_yaml::to_string(&doc).context("serializing runtime profile");
        }
        let dns = overlay_dns_mapping(map, builtin_dns)?;
        anyhow::ensure!(
            crate::dns_override::fake_ip_filter_mode_supported(dns.get("fake-ip-filter-mode"))
                || (options.mode.is_some() && options.patterns.is_some()),
            "replace both Fake-IP mode and patterns when the profile uses an unsupported mode"
        );
        if let Some(patterns) = options.patterns {
            anyhow::ensure!(patterns.len() <= 256, "too many filter patterns");
            let mut seen = std::collections::HashSet::new();
            for pattern in &patterns {
                let domain = pattern.strip_prefix("+.").unwrap_or(pattern);
                anyhow::ensure!(
                    seen.insert(pattern)
                        && !domain.is_empty()
                        && domain.len() <= 253
                        && domain.split('.').all(|label| {
                            !label.is_empty()
                                && label.len() <= 63
                                && !label.starts_with('-')
                                && !label.ends_with('-')
                                && label.bytes().all(|c| {
                                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'
                                })
                        }),
                    "invalid Fake-IP filter pattern"
                );
            }
            dns.insert("fake-ip-filter".into(), serde_yaml::to_value(&patterns)?);
        }
        if let Some(mode) = options.mode {
            let wire = match mode {
                FakeIpFilterMode::Blacklist => "blacklist",
                FakeIpFilterMode::Whitelist => "whitelist",
            };
            dns.insert("fake-ip-filter-mode".into(), wire.into());
        }
        serde_yaml::to_string(&doc).context("serializing runtime profile")
    })
    .context("starting the YAML parser")?
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeOverrideFakeIpFilter(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
    options: JString,
    builtin_dns: jboolean,
) -> jstring {
    let result = (|| -> Result<String> {
        let yaml: String = env.get_string(&yaml)?.into();
        let options: String = env.get_string(&options)?.into();
        fake_ip_filter_yaml(
            &yaml,
            serde_json::from_str(&options)?,
            builtin_dns != JNI_FALSE,
        )
    })();
    match result {
        Ok(runtime) => env
            .new_string(runtime)
            .map_or(std::ptr::null_mut(), |s| s.into_raw()),
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "Could not prepare the saved Fake-IP filter. If the profile uses an unsupported mode, replace both the mode and patterns.",
            );
            std::ptr::null_mut()
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DnsHostsOverride {
    hosts: Option<std::collections::BTreeMap<String, std::net::IpAddr>>,
    use_hosts: Option<bool>,
}

pub(crate) fn dns_hosts_yaml(
    yaml: &str,
    options: DnsHostsOverride,
    builtin_dns: bool,
) -> Result<String> {
    meow_common::yaml::run_on_parse_stack(yaml, move |yaml| {
        use serde_yaml::Value;
        let mut doc: Value = serde_yaml::from_str(yaml).context("parsing profile YAML")?;
        doc.apply_merge().context("applying profile YAML merges")?;
        let map = doc.as_mapping_mut().context("expected a profile mapping")?;
        if let Some(hosts) = options.hosts {
            anyhow::ensure!(hosts.len() <= 256, "too many host records");
            for name in hosts.keys() {
                anyhow::ensure!(
                    !name.is_empty()
                        && name.len() <= 253
                        && name.split('.').all(|label| {
                            !label.is_empty()
                                && label.len() <= 63
                                && !label.starts_with('-')
                                && !label.ends_with('-')
                                && label.bytes().all(|c| {
                                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'
                                })
                        }),
                    "invalid host record name"
                );
            }
            map.insert("hosts".into(), serde_yaml::to_value(hosts)?);
        }
        if let Some(enabled) = options.use_hosts {
            overlay_dns_mapping(map, builtin_dns)?.insert("use-hosts".into(), enabled.into());
        }
        serde_yaml::to_string(&doc).context("serializing runtime profile")
    })
    .context("starting the YAML parser")?
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeOverrideDnsHosts(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
    options: JString,
    builtin_dns: jboolean,
) -> jstring {
    let result = (|| -> Result<String> {
        let yaml: String = env.get_string(&yaml)?.into();
        let options: String = env.get_string(&options)?.into();
        dns_hosts_yaml(
            &yaml,
            serde_json::from_str(&options)?,
            builtin_dns != JNI_FALSE,
        )
    })();
    match result {
        Ok(runtime) => env
            .new_string(runtime)
            .map_or(std::ptr::null_mut(), |s| s.into_raw()),
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "Could not prepare the profile with the saved DNS hosts overrides",
            );
            std::ptr::null_mut()
        }
    }
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoreBehaviorOverride {
    unified_delay: Option<bool>,
    tcp_concurrent: Option<bool>,
    find_process_mode: Option<ProcessLookupMode>,
    log_level: Option<crate::log_level::LogLevelOverride>,
}

fn core_behavior_yaml(yaml: &str, options: CoreBehaviorOverride) -> Result<String> {
    anyhow::ensure!(options.find_process_mode != Some(ProcessLookupMode::Strict));
    meow_common::yaml::run_on_parse_stack(yaml, move |yaml| {
        let mut doc: serde_yaml::Value =
            serde_yaml::from_str(yaml).context("parsing profile YAML")?;
        let map = doc.as_mapping_mut().context("expected a profile mapping")?;
        if let Some(value) = options.unified_delay {
            map.insert("unified-delay".into(), value.into());
        }
        if let Some(value) = options.tcp_concurrent {
            map.insert("tcp-concurrent".into(), value.into());
        }
        if let Some(value) = options.find_process_mode {
            map.insert("find-process-mode".into(), value.as_str().into());
        }
        if let Some(value) = options.log_level {
            map.insert("log-level".into(), value.as_str().into());
        }
        serde_yaml::to_string(&doc).context("serializing runtime profile")
    })
    .context("starting the YAML parser")?
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeOverrideCoreBehavior(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
    options: JString,
) -> jstring {
    let result = (|| -> Result<String> {
        let yaml: String = env.get_string(&yaml)?.into();
        let options: String = env.get_string(&options)?.into();
        core_behavior_yaml(&yaml, serde_json::from_str(&options)?)
    })();
    match result {
        Ok(runtime) => env
            .new_string(runtime)
            .map_or(std::ptr::null_mut(), |s| s.into_raw()),
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "Could not prepare the profile with the saved core behavior overrides",
            );
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativePreviewProfileOverrides(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
) -> jstring {
    let Ok(yaml) = env.get_string(&yaml) else {
        return std::ptr::null_mut();
    };
    let Ok(raw) = profile_raw(&String::from(yaml)) else {
        return std::ptr::null_mut();
    };
    let preview = serde_json::json!({
        "ipv6": raw.ipv6,
        "unifiedDelay": raw.unified_delay.unwrap_or(false),
        "tcpConcurrent": meow_config::effective_tcp_concurrent(raw.tcp_concurrent),
        "logLevel": crate::log_level::effective(raw.log_level.as_deref()).as_str(),
        "findProcessMode": crate::engine::android_process_lookup(raw.find_process_mode.unwrap_or_default()),
    });
    env.new_string(preview.to_string())
        .map_or(std::ptr::null_mut(), |s| s.into_raw())
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeOverrideIpv6(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
    enabled: jboolean,
) -> jstring {
    let Ok(yaml) = env.get_string(&yaml) else {
        return std::ptr::null_mut();
    };
    let yaml: String = yaml.into();
    match runtime_yaml(&yaml, enabled != JNI_FALSE) {
        Ok(runtime) => env
            .new_string(runtime)
            .map_or(std::ptr::null_mut(), |s| s.into_raw()),
        Err(err) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", format!("{err:#}"));
            std::ptr::null_mut()
        }
    }
}

/// Read the profile choice using the same strip and parse as engine startup.
/// This performs no DNS setup or provider fetches.
fn profile_raw(yaml: &str) -> Result<meow_config::raw::RawConfig> {
    let stripped = meow_common::yaml::run_on_parse_stack(yaml, |yaml| {
        crate::engine::strip_and_inject(yaml, crate::engine::DnsUpstreams::Builtin)
    })??;
    meow_config::parse_raw_yaml(&stripped)
}

fn profile_ipv6(yaml: &str) -> Result<Option<bool>> {
    Ok(profile_raw(yaml)?.ipv6)
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeProfileIpv6(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
) -> jint {
    let Ok(yaml) = env.get_string(&yaml) else {
        return -2;
    };
    let yaml: String = yaml.into();
    match profile_ipv6(&yaml) {
        Ok(Some(false)) => 0,
        Ok(Some(true)) => 1,
        Ok(None) => -1,
        Err(_) => -2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_ip_filter_yaml(yaml: &str, options: FakeIpFilterOverride) -> Result<String> {
        super::fake_ip_filter_yaml(yaml, options, false)
    }

    fn dns_hosts_yaml(yaml: &str, options: DnsHostsOverride) -> Result<String> {
        super::dns_hosts_yaml(yaml, options, false)
    }

    use crate::engine::{self, DnsUpstreams};

    #[test]
    fn log_level_override_changes_only_the_runtime_value() -> Result<()> {
        let yaml = "log-level: warning\nmode: rule\n";
        let override_options = serde_json::from_str(r#"{"logLevel":"silent"}"#)?;
        let runtime = core_behavior_yaml(yaml, override_options)?;
        let raw = profile_raw(&runtime)?;
        assert_eq!(raw.log_level.as_deref(), Some("silent"));
        assert_eq!(profile_raw(yaml)?.log_level.as_deref(), Some("warning"));
        assert!(serde_json::from_str::<CoreBehaviorOverride>(r#"{"logLevel":"trace"}"#).is_err());
        assert!(serde_json::from_str::<CoreBehaviorOverride>(r#"{"logLevel":false}"#).is_err());
        assert_eq!(crate::log_level::effective(None).as_str(), "info");
        assert_eq!(
            crate::log_level::effective(Some("warn")).as_str(),
            "warning"
        );
        Ok(())
    }

    #[test]
    fn core_behavior_overlay_preserves_source_and_distinguishes_false_from_inherit() {
        let source = "defaults: &defaults {unified-delay: true, tcp-concurrent: true}\n<<: *defaults\nfind-process-mode: always\nrules: ['MATCH,DIRECT']\n";
        let options = serde_json::from_str(
            r#"{"unifiedDelay":false,"tcpConcurrent":false,"findProcessMode":"off"}"#,
        )
        .unwrap();
        let runtime = core_behavior_yaml(source, options).unwrap();
        let raw = profile_raw(&runtime).unwrap();
        assert_eq!(raw.unified_delay, Some(false));
        assert_eq!(raw.tcp_concurrent, Some(false));
        assert_eq!(raw.find_process_mode, Some(ProcessLookupMode::Off));
        let unchanged = profile_raw(source).unwrap();
        assert_eq!(unchanged.unified_delay, Some(true));
        assert_eq!(unchanged.tcp_concurrent, Some(true));
        assert_eq!(unchanged.find_process_mode, Some(ProcessLookupMode::Always));
        let strict = serde_json::from_str(r#"{"findProcessMode":"strict"}"#).unwrap();
        assert!(core_behavior_yaml(source, strict).is_err());
        assert!(serde_json::from_str::<CoreBehaviorOverride>(r#"{"other":true}"#).is_err());
        assert!(core_behavior_yaml("[]", CoreBehaviorOverride::default()).is_err());
    }

    #[test]
    fn runtime_override_preserves_the_source_and_pins_dns_and_tun_together() {
        let yaml = "defaults: &defaults { ipv6: false }\n<<: *defaults\ndns: { nameserver: ['rcode://refused'] }\nrules: ['MATCH,DIRECT']\n";
        assert_eq!(profile_ipv6(yaml).unwrap(), Some(false));
        for enabled in [true, false] {
            let runtime = runtime_yaml(yaml, enabled).unwrap();
            assert_eq!(profile_ipv6(&runtime).unwrap(), Some(enabled));
            for dns in [DnsUpstreams::Builtin, DnsUpstreams::Profile] {
                let stripped = engine::strip_and_inject(&runtime, dns).unwrap();
                let raw = meow_config::parse_raw_yaml(&stripped).unwrap();
                assert_eq!(engine::tun_ipv6(raw.ipv6), enabled);
                assert_eq!(meow_config::effective_ipv6(raw.ipv6), enabled);
                let block = raw.dns.unwrap();
                assert_eq!(block.enhanced_mode.as_deref(), Some("fake-ip"));
                assert_eq!(block.fake_ip_range.as_deref(), Some("28.0.0.0/8"));
            }
        }
        assert_eq!(profile_ipv6(yaml).unwrap(), Some(false));
    }

    #[tokio::test]
    async fn forced_ipv6_controls_aaaa_synthesis_in_the_loaded_resolver() {
        let yaml = "dns:\n  nameserver: ['rcode://refused']\n  fake-ip-range6: fdfe:dcba:9877::/64\nrules: ['MATCH,DIRECT']\n";
        for enabled in [true, false] {
            let runtime = runtime_yaml(yaml, enabled).unwrap();
            let stripped = engine::strip_and_inject(&runtime, DnsUpstreams::Profile).unwrap();
            let config = meow_config::load_config_from_str(&stripped).await.unwrap();
            let query = crate::test_support::dns_query("meow-test.invalid", 28);
            let response = meow_dns::DnsServer::handle_query(&query, &config.dns.resolver)
                .await
                .unwrap();
            assert_eq!(
                u16::from_be_bytes([response[6], response[7]]),
                u16::from(enabled)
            );
        }
    }

    #[tokio::test]
    async fn override_hosts_affects_actual_dns_answers_in_each_mode() {
        let authored = r#"
ipv6: true
hosts: {v4.hosts.test: 192.0.2.1, v6.hosts.test: '2001:db8::1'}
dns: {nameserver: ['rcode://refused']}
rules: ['MATCH,DIRECT']
"#;
        let expected_v4 = std::net::Ipv4Addr::new(192, 0, 2, 53).octets();
        let expected_v6 = "2001:db8::53"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        for mode in [DnsUpstreams::Builtin, DnsUpstreams::Profile] {
            for (json, expect_override, expect_authored) in [
                (
                    r#"{"hosts":{"v4.hosts.test":"192.0.2.53","v6.hosts.test":"2001:db8::53"},"useHosts":true}"#,
                    true,
                    false,
                ),
                (
                    r#"{"hosts":{"v4.hosts.test":"192.0.2.53","v6.hosts.test":"2001:db8::53"},"useHosts":false}"#,
                    false,
                    false,
                ),
                (r#"{"hosts":{}}"#, false, false),
                (r#"{}"#, false, true),
            ] {
                let runtime =
                    dns_hosts_yaml(authored, serde_json::from_str(json).unwrap()).unwrap();
                let stripped = engine::strip_and_inject(&runtime, mode.clone()).unwrap();
                // Keep the real DNS packet handler, but make every upstream synthetic.
                let mut dns_only: serde_yaml::Value = serde_yaml::from_str(&stripped).unwrap();
                let dns = dns_only["dns"].as_mapping_mut().unwrap();
                for key in [
                    "nameserver",
                    "default-nameserver",
                    "proxy-server-nameserver",
                ] {
                    dns.insert(
                        key.into(),
                        serde_yaml::to_value(["rcode://refused"]).unwrap(),
                    );
                }
                let config =
                    meow_config::load_config_from_str(&serde_yaml::to_string(&dns_only).unwrap())
                        .await
                        .unwrap();
                let resolver = &config.dns.resolver;
                for (name, kind, expected, original) in [
                    (
                        "v4.hosts.test",
                        1,
                        &expected_v4[..],
                        &std::net::Ipv4Addr::new(192, 0, 2, 1).octets()[..],
                    ),
                    (
                        "v6.hosts.test",
                        28,
                        &expected_v6[..],
                        &"2001:db8::1"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets()[..],
                    ),
                ] {
                    let query = crate::test_support::dns_query(name, kind);
                    let reply = meow_dns::DnsServer::handle_query(&query, resolver)
                        .await
                        .unwrap();
                    assert_eq!(reply.ends_with(expected), expect_override, "{json} {name}");
                    assert_eq!(reply.ends_with(original), expect_authored, "{json} {name}");
                }
            }
        }
    }

    #[tokio::test]
    async fn fake_ip_filter_controls_dns_answers_and_reverse_map() {
        let authored = r#"
dns:
  nameserver: ['rcode://refused']
  fake-ip-filter: ['+.skip.test']
  fake-ip-filter-mode: blacklist
rules: ['MATCH,DIRECT']
"#;
        for mode in [DnsUpstreams::Builtin, DnsUpstreams::Profile] {
            for (json, root_fake, sub_fake, other_fake) in [
                (r#"{}"#, false, false, true),
                (r#"{"mode":"WHITELIST"}"#, true, true, false),
                (
                    r#"{"patterns":["skip.test"],"mode":"BLACKLIST"}"#,
                    false,
                    true,
                    true,
                ),
                (r#"{"patterns":[],"mode":"BLACKLIST"}"#, true, true, true),
                (r#"{"patterns":[],"mode":"WHITELIST"}"#, true, true, true),
            ] {
                let runtime =
                    fake_ip_filter_yaml(authored, serde_json::from_str(json).unwrap()).unwrap();
                let stripped = engine::strip_and_inject(&runtime, mode.clone()).unwrap();
                let mut local: serde_yaml::Value = serde_yaml::from_str(&stripped).unwrap();
                for key in [
                    "nameserver",
                    "default-nameserver",
                    "proxy-server-nameserver",
                ] {
                    local["dns"].as_mapping_mut().unwrap().insert(
                        key.into(),
                        serde_yaml::to_value(["rcode://refused"]).unwrap(),
                    );
                }
                let config =
                    meow_config::load_config_from_str(&serde_yaml::to_string(&local).unwrap())
                        .await
                        .unwrap();
                let resolver = &config.dns.resolver;
                for (host, is_fake) in [
                    ("skip.test", root_fake),
                    ("sub.skip.test", sub_fake),
                    ("other.test", other_fake),
                ] {
                    let query = crate::test_support::dns_query(host, 1);
                    let reply = meow_dns::DnsServer::handle_query(&query, resolver)
                        .await
                        .unwrap();
                    let answers = u16::from_be_bytes([reply[6], reply[7]]);
                    assert_eq!(answers, u16::from(is_fake), "{json} {host}");
                    if is_fake {
                        let bytes: [u8; 4] = reply[reply.len() - 4..].try_into().unwrap();
                        assert_eq!(bytes[0], 28);
                        let ip = std::net::Ipv4Addr::from(bytes);
                        assert_eq!(resolver.reverse_lookup(ip.into()).as_deref(), Some(host));
                    }
                }
            }
        }
        assert!(serde_json::from_str::<FakeIpFilterOverride>(r#"{"mode":"RULE"}"#).is_err());
        let wrong = serde_json::from_str(r#"{"patterns":["RULE-SET,lan"]}"#).unwrap();
        assert!(fake_ip_filter_yaml(authored, wrong).is_err());
    }

    #[tokio::test]
    async fn unsupported_authored_fake_ip_mode_never_inherits_as_builtin_blacklist() {
        // REFUSED is synthetic: any A answer is a fake address, never egress.
        async fn resolves_fake_authored(yaml: &str, mode: DnsUpstreams, name: &str) -> bool {
            let stripped = engine::strip_and_inject(yaml, mode).unwrap();
            let mut local: serde_yaml::Value = serde_yaml::from_str(&stripped).unwrap();
            for key in [
                "nameserver",
                "default-nameserver",
                "proxy-server-nameserver",
            ] {
                local["dns"].as_mapping_mut().unwrap().insert(
                    key.into(),
                    serde_yaml::to_value(["rcode://refused"]).unwrap(),
                );
            }
            let config = meow_config::load_config_from_str(&serde_yaml::to_string(&local).unwrap())
                .await
                .unwrap();
            let query = crate::test_support::dns_query(name, 1);
            let reply = meow_dns::DnsServer::handle_query(&query, &config.dns.resolver)
                .await
                .unwrap();
            u16::from_be_bytes([reply[6], reply[7]]) == 1
        }

        for (mode_line, unsupported) in [
            ("  fake-ip-filter-mode: rule\n", true),
            ("  fake-ip-filter-mode: future-mode\n", true),
            ("  fake-ip-filter-mode: null\n", false),
            ("", false),
        ] {
            let authored = format!(
                "dns:\n  nameserver: ['rcode://refused']\n  fake-ip-filter: ['+.original.test']\n{mode_line}rules: ['MATCH,DIRECT']\n"
            );
            let inherit =
                fake_ip_filter_yaml(&authored, serde_json::from_str("{}").unwrap()).unwrap();
            let partial_mode = fake_ip_filter_yaml(
                &authored,
                serde_json::from_str(r#"{"mode":"WHITELIST"}"#).unwrap(),
            );
            let partial_list = fake_ip_filter_yaml(
                &authored,
                serde_json::from_str(r#"{"patterns":["another.test"]}"#).unwrap(),
            );
            assert_eq!(partial_mode.is_err(), unsupported);
            assert_eq!(partial_list.is_err(), unsupported);
            let replacement = fake_ip_filter_yaml(
                &authored,
                serde_json::from_str(r#"{"mode":"WHITELIST","patterns":["another.test"]}"#)
                    .unwrap(),
            )
            .unwrap();
            for mode in [DnsUpstreams::Builtin, DnsUpstreams::Profile] {
                // Profile continues interpreting authored YAML as before, including
                // the pinned core's existing fallback for unknown modes.
                let builtin = matches!(mode, DnsUpstreams::Builtin);
                let stripped = engine::strip_and_inject(&inherit, mode.clone()).unwrap();
                let raw = meow_config::parse_raw_yaml(&stripped).unwrap().dns.unwrap();
                assert_eq!(raw.fake_ip_filter.is_none(), unsupported && builtin);
                assert_eq!(
                    resolves_fake_authored(&inherit, mode.clone(), "original.test").await,
                    unsupported && builtin,
                    "{mode_line} builtin={builtin}"
                );
                assert!(!resolves_fake_authored(&replacement, mode.clone(), "original.test").await);
                assert!(resolves_fake_authored(&replacement, mode.clone(), "another.test").await);
                if !unsupported {
                    assert!(
                        resolves_fake_authored(
                            partial_mode.as_ref().unwrap(),
                            mode.clone(),
                            "original.test"
                        )
                        .await
                    );
                    assert!(
                        !resolves_fake_authored(
                            partial_list.as_ref().unwrap(),
                            mode,
                            "another.test"
                        )
                        .await
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn builtin_dns_overlays_tolerate_scalar_and_invalid_inherited_policy_only_in_builtin() {
        fn load_without_egress(
            stripped: String,
        ) -> impl std::future::Future<Output = Result<meow_config::Config>> {
            async move {
                let mut local: serde_yaml::Value = serde_yaml::from_str(&stripped)?;
                for key in [
                    "nameserver",
                    "default-nameserver",
                    "proxy-server-nameserver",
                ] {
                    local["dns"].as_mapping_mut().unwrap().insert(
                        key.into(),
                        serde_yaml::to_value(["rcode://refused"]).unwrap(),
                    );
                }
                meow_config::load_config_from_str(&serde_yaml::to_string(&local)?).await
            }
        }

        let scalar = "strict: true\ndns: legacy-scalar\nrules: ['MATCH,DIRECT']\n";
        let hosts_options = r#"{"hosts":{"local.test":"192.0.2.65"},"useHosts":true}"#;
        let fake_options = r#"{"patterns":["+.skip.test"],"mode":"BLACKLIST"}"#;
        assert!(
            super::dns_hosts_yaml(scalar, serde_json::from_str(hosts_options).unwrap(), false)
                .is_err()
        );
        assert!(super::fake_ip_filter_yaml(
            scalar,
            serde_json::from_str(fake_options).unwrap(),
            false
        )
        .is_err());
        assert!(engine::strip_and_inject(scalar, DnsUpstreams::Profile).is_err());
        let baseline = engine::load_profile(scalar, &DnsUpstreams::Builtin, load_without_egress)
            .await
            .unwrap();
        assert!(baseline
            .config
            .dns
            .resolver
            .lookup_hosts_all("local.test")
            .is_none());
        let with_hosts =
            super::dns_hosts_yaml(scalar, serde_json::from_str(hosts_options).unwrap(), true)
                .unwrap();
        let runtime = super::fake_ip_filter_yaml(
            &with_hosts,
            serde_json::from_str(fake_options).unwrap(),
            true,
        )
        .unwrap();
        let loaded = engine::load_profile(&runtime, &DnsUpstreams::Builtin, load_without_egress)
            .await
            .unwrap();
        for (name, expected) in [
            ("local.test", Some(192)),
            ("sub.skip.test", None),
            ("other.test", Some(28)),
        ] {
            let query = crate::test_support::dns_query(name, 1);
            let reply = meow_dns::DnsServer::handle_query(&query, &loaded.config.dns.resolver)
                .await
                .unwrap();
            let answer =
                (u16::from_be_bytes([reply[6], reply[7]]) == 1).then(|| reply[reply.len() - 4]);
            assert_eq!(answer, expected, "{name}");
        }
        assert!(scalar.contains("dns: legacy-scalar"));

        let malformed = "strict: true\ndns: {fake-ip-filter: ['a..test', '+.good.test'], fake-ip-filter-mode: blacklist}\nrules: ['MATCH,DIRECT']\n";
        assert!(
            engine::load_profile(malformed, &DnsUpstreams::Profile, load_without_egress)
                .await
                .is_err()
        );
        let builtin = engine::load_profile(malformed, &DnsUpstreams::Builtin, load_without_egress)
            .await
            .unwrap();
        let query = crate::test_support::dns_query("sub.good.test", 1);
        let reply = meow_dns::DnsServer::handle_query(&query, &builtin.config.dns.resolver)
            .await
            .unwrap();
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1);
        assert_eq!(reply[reply.len() - 4], 28);

        // Previously-authored core-supported wildcard spellings survive
        // even though the app editor offers a smaller explicit subset.
        let valid = "strict: true\ndns: {fake-ip-filter: ['*.wild.test', '.other.test'], fake-ip-filter-mode: blacklist}\nrules: ['MATCH,DIRECT']\n";
        let builtin = engine::load_profile(valid, &DnsUpstreams::Builtin, load_without_egress)
            .await
            .unwrap();
        for (host, count) in [
            ("a.wild.test", 0),
            ("a.b.wild.test", 1),
            ("a.b.other.test", 0),
        ] {
            let query = crate::test_support::dns_query(host, 1);
            let reply = meow_dns::DnsServer::handle_query(&query, &builtin.config.dns.resolver)
                .await
                .unwrap();
            assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), count, "{host}");
        }
    }

    #[test]
    fn inherited_unset_keeps_legacy_aaaa_and_tun_defaults() {
        let yaml = "rules: ['MATCH,DIRECT']\n";
        let raw = profile_ipv6(yaml).unwrap();
        assert_eq!(raw, None);
        assert!(engine::tun_ipv6(raw));
        assert!(!meow_config::effective_ipv6(raw));
    }
}
