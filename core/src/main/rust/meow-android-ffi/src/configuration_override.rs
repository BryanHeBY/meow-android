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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DnsHostsOverride {
    hosts: Option<std::collections::BTreeMap<String, std::net::IpAddr>>,
    use_hosts: Option<bool>,
}

fn dns_hosts_yaml(yaml: &str, options: DnsHostsOverride) -> Result<String> {
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
            let block = map.entry("dns".into()).or_insert(Value::Null);
            if block.is_null() {
                *block = Value::Mapping(serde_yaml::Mapping::new());
            }
            block
                .as_mapping_mut()
                .context("expected a DNS mapping")?
                .insert("use-hosts".into(), enabled.into());
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
) -> jstring {
    let result = (|| -> Result<String> {
        let yaml: String = env.get_string(&yaml)?.into();
        let options: String = env.get_string(&options)?.into();
        dns_hosts_yaml(&yaml, serde_json::from_str(&options)?)
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
    use crate::engine::{self, DnsUpstreams};

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

    #[test]
    fn inherited_unset_keeps_legacy_aaaa_and_tun_defaults() {
        let yaml = "rules: ['MATCH,DIRECT']\n";
        let raw = profile_ipv6(yaml).unwrap();
        assert_eq!(raw, None);
        assert!(engine::tun_ipv6(raw));
        assert!(!meow_config::effective_ipv6(raw));
    }
}
