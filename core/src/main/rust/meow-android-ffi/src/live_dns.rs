//! DNS changes are prepared in the core's config mutation lane and published
//! only after the staged preference is committed. The shared resolver slot
//! moves TUN, routing and DIRECT lookups together without restarting the VPN.

use crate::dns_override::{engine_dns_block, safe_endpoint, DnsIssue, DnsUpstreams};
use crate::engine;
use anyhow::{anyhow, bail, Result};
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jlong, jstring};
use jni::JNIEnv;
use meow_api::routes::DnsServerHandle;
use meow_config::raw::{RawConfig, RawDns};
use meow_config::rule_provider::RuleProvider;
use meow_config::DnsConfig;
use meow_dns::Resolver;
use meow_tunnel::Tunnel;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Weak};

struct Applied {
    mode: DnsUpstreams,
    resolver: Weak<Resolver>,
}

pub(crate) struct LiveDns {
    profile_id: i64,
    profile_dns: Option<serde_yaml::Value>,
    config_path: Option<String>,
    applied: Mutex<Applied>,
    raw_config: Arc<RwLock<RawConfig>>,
    rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
    dns_server: Arc<RwLock<Option<DnsServerHandle>>>,
}

impl LiveDns {
    #[allow(
        clippy::too_many_arguments,
        reason = "each input comes from the starting engine generation"
    )]
    pub(crate) fn new(
        profile_id: i64,
        profile_dns: Option<serde_yaml::Value>,
        config_path: Option<String>,
        mode: DnsUpstreams,
        resolver: &Arc<Resolver>,
        raw_config: Arc<RwLock<RawConfig>>,
        rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
        dns_server: Arc<RwLock<Option<DnsServerHandle>>>,
    ) -> Self {
        Self {
            profile_id,
            profile_dns,
            config_path,
            applied: Mutex::new(Applied {
                mode,
                resolver: Arc::downgrade(resolver),
            }),
            raw_config,
            rule_providers,
            dns_server,
        }
    }

    fn candidate(&self, tunnel: &Tunnel, mode: &DnsUpstreams) -> Result<Option<RawConfig>> {
        let applied = self.applied.lock();
        if applied.mode == *mode && applied.resolver.ptr_eq(&Arc::downgrade(&tunnel.resolver())) {
            return Ok(None);
        }
        drop(applied);
        let block = engine_dns_block(self.profile_dns.clone(), mode)
            .map_err(|_| DnsIssue::ResolverRejected)?;
        let mut dns: RawDns = serde_yaml::from_value(serde_yaml::Value::Mapping(block))
            .map_err(|_| DnsIssue::ResolverRejected)?;
        let mut candidate = self.raw_config.read().clone();
        // Keep the store opened at startup so the same fake IP remains
        // attached to the same name after a mode change.
        if let Some(previous) = &candidate.dns {
            dns.store_fake_ip = previous.store_fake_ip;
            if dns.fake_ip_range6.is_none() {
                dns.fake_ip_range6.clone_from(&previous.fake_ip_range6);
            }
        }
        candidate.dns = Some(dns);
        Ok(Some(candidate))
    }

    async fn rebuild(&self, tunnel: &Tunnel, candidate: &RawConfig) -> Result<Option<DnsConfig>> {
        let route = tunnel.route_snapshot();
        let rule_providers = self.rule_providers.read().clone();
        meow_api::routes::reconcile_dns_config(
            &self.raw_config,
            candidate,
            self.config_path.as_deref(),
            &route.proxies,
            Some(&rule_providers),
            None,
            Some(tunnel.resolver()),
            Some(&route.dialer_registry),
        )
        .await
        .map_err(|_| anyhow!(DnsIssue::ResolverRejected))
    }

    fn publish(
        &self,
        tunnel: &Tunnel,
        dns: Option<&DnsConfig>,
        candidate: RawConfig,
        mode: DnsUpstreams,
    ) {
        if let Some(dns) = dns {
            dns.resolver
                .restore_reverse_cache(tunnel.resolver().reverse_cache_snapshot());
            meow_api::routes::install_resolver_everywhere(tunnel, &self.dns_server, dns);
        }
        self.raw_config.write().dns = candidate.dns;
        *self.applied.lock() = Applied {
            mode,
            resolver: Arc::downgrade(&tunnel.resolver()),
        };
    }
}

fn commit(
    mode: DnsUpstreams,
    running_profile_id: Option<i64>,
    persist: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let Some(running_profile_id) = running_profile_id else {
        return persist();
    };
    crate::get_runtime().block_on(async {
        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
        let running = crate::ENGINE
            .lock()
            .as_ref()
            .map(|state| (state.tunnel.clone(), Arc::clone(&state.live_dns)));
        let (tunnel, live) = running.ok_or(DnsIssue::ProfileChanged)?;
        if live.profile_id != running_profile_id {
            bail!(DnsIssue::ProfileChanged);
        }
        let route = tunnel.route_snapshot();
        mode.check_targets(|name| route.proxies.get(name).map(Arc::as_ref))?;
        let prepared = match live.candidate(&tunnel, &mode)? {
            Some(candidate) => Some((live.rebuild(&tunnel, &candidate).await?, candidate)),
            None => None,
        };
        if let Some((Some(dns), _)) = &prepared {
            mode.check_resolver(&dns.resolver)?;
        } else {
            mode.check_resolver(&tunnel.resolver())?;
        }
        let engine = crate::ENGINE.lock();
        if !engine
            .as_ref()
            .is_some_and(|state| Arc::ptr_eq(&state.live_dns, &live))
        {
            bail!(DnsIssue::ProfileChanged);
        }
        // Renaming is the only fallible operation after preparation. Until
        // it succeeds, every consumer keeps the existing resolver.
        persist()?;
        if let Some((dns, candidate)) = prepared {
            live.publish(&tunnel, dns.as_ref(), candidate, mode);
        }
        Ok(())
    })
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    mode: Option<&'static str>,
    missing_main: bool,
    primary: Vec<String>,
    fallback: Vec<String>,
    direct: Vec<String>,
    node: Vec<String>,
    bootstrap: Vec<String>,
    policy_entries: usize,
    running_profile_id: Option<i64>,
}

fn status() -> Status {
    let _lane = meow_api::routes::CONFIG_MUTATION.blocking_lock();
    let engine = crate::ENGINE.lock();
    let Some(state) = engine.as_ref() else {
        return Status::default();
    };
    let live = &state.live_dns;
    let applied = live.applied.lock();
    let own = applied
        .resolver
        .ptr_eq(&Arc::downgrade(&state.tunnel.resolver()));
    let raw = live.raw_config.read();
    let dns = raw.dns.as_ref();
    let endpoints = |list: Option<&Vec<String>>| {
        list.into_iter()
            .flatten()
            .take(12)
            .map(|entry| safe_endpoint(entry))
            .collect()
    };
    Status {
        mode: Some(if own { applied.mode.mode() } else { "external" }),
        missing_main: own
            && engine::uses_missing_dns_pool(live.profile_dns.as_ref(), &applied.mode),
        primary: endpoints(dns.and_then(|d| d.nameserver.as_ref())),
        fallback: endpoints(dns.and_then(|d| d.fallback.as_ref())),
        direct: endpoints(dns.and_then(|d| d.direct_nameserver.as_ref())),
        node: endpoints(dns.and_then(|d| d.proxy_server_nameserver.as_ref())),
        bootstrap: endpoints(dns.and_then(|d| d.default_nameserver.as_ref())),
        policy_entries: dns
            .and_then(|d| d.nameserver_policy.as_ref())
            .map_or(0, |policy| policy.len()),
        running_profile_id: Some(live.profile_id).filter(|&id| id > 0),
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeDnsStatus(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let json = serde_json::to_string(&status()).expect("DNS status is serializable");
    env.new_string(json)
        .map_or(std::ptr::null_mut(), |s| s.into_raw())
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeCommitDns(
    mut env: JNIEnv,
    _class: JClass,
    settings: JString,
    staged: JString,
    target: JString,
    selected_profile_id: jlong,
    apply_live: jboolean,
) -> jstring {
    let mut read = |value: &JString| {
        env.get_string(value)
            .map(String::from)
            .map_err(|_| DnsIssue::InvalidSettings)
    };
    let result = (|| {
        let (mode, owner) = DnsUpstreams::decode_scoped(&read(&settings)?)
            .map_err(|_| DnsIssue::InvalidSettings)?;
        mode.check_android_support()?;
        mode.require_scope(owner, selected_profile_id)?;
        let staged = read(&staged)?;
        let target = read(&target)?;
        commit(
            mode,
            (apply_live != 0).then_some(selected_profile_id),
            || std::fs::rename(staged, target).map_err(|_| anyhow!(DnsIssue::SaveFailed)),
        )
    })();
    dns_result(&env, result)
}

fn dns_result(env: &JNIEnv, result: Result<()>) -> jstring {
    result
        .err()
        .map(|e| {
            e.downcast::<DnsIssue>()
                .unwrap_or(DnsIssue::ResolverRejected)
        })
        .and_then(|issue| env.new_string(issue.to_string()).ok())
        .map_or(std::ptr::null_mut(), |s| s.into_raw())
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeCheckCachedDns(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
    settings: JString,
) -> jstring {
    let result = (|| {
        let yaml: String = env
            .get_string(&yaml)
            .map_err(|_| DnsIssue::InvalidSettings)?
            .into();
        let settings: String = env
            .get_string(&settings)
            .map_err(|_| DnsIssue::InvalidSettings)?
            .into();
        let (mode, _) =
            DnsUpstreams::decode_scoped(&settings).map_err(|_| DnsIssue::InvalidSettings)?;
        mode.check_android_support()?;
        mode.check_cached_profile(&yaml)
    })();
    dns_result(&env, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dns_query, from_the_profile_nameserver, SERIAL};
    use std::net::IpAddr;
    use std::time::Duration;

    fn apply(mode: DnsUpstreams) -> Result<()> {
        let running_id = status().running_profile_id;
        commit(mode, running_id, || Ok(()))
    }

    fn resolver() -> Arc<meow_dns::Resolver> {
        Arc::clone(
            &crate::DNS_RESOLVER
                .read()
                .as_ref()
                .expect("a resolver")
                .read()
                .resolver,
        )
    }

    fn nameservers() -> Option<Vec<String>> {
        let engine = crate::ENGINE.lock();
        let raw = engine.as_ref().unwrap().live_dns.raw_config.read();
        raw.dns.as_ref().and_then(|d| d.nameserver.clone())
    }

    fn txt_response_code(resolver: &meow_dns::Resolver) -> u8 {
        let query = dns_query("meow-test.invalid", 16);
        let reply = crate::get_runtime()
            .block_on(meow_dns::DnsServer::handle_query(&query, resolver))
            .unwrap();
        reply[3] & 0x0f
    }

    /// Starts an engine on `profile`, run from a fresh home dir that the
    /// returned guard removes along with the engine.
    fn start(profile: &str, upstreams: DnsUpstreams, name: &str) -> impl Drop {
        start_engine(Some(profile), upstreams, name)
    }

    fn start_engine(profile: Option<&str>, upstreams: DnsUpstreams, name: &str) -> impl Drop {
        struct Running(std::path::PathBuf);
        impl Drop for Running {
            fn drop(&mut self) {
                crate::stop_engine();
                *crate::HOME_DIR.lock() = None;
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        // `<dir>/meow`, as the app's `no_backup/meow`: the engine takes the
        // parent for `XDG_CONFIG_HOME`, and keeps its logbook under the home.
        let dir = std::env::temp_dir().join(format!("meow-{name}-{}", std::process::id()));
        let home = dir.join("meow");
        std::fs::create_dir_all(&home).unwrap();
        if let Some(profile) = profile {
            std::fs::write(home.join("config.yaml"), profile).unwrap();
        }
        *crate::HOME_DIR.lock() = Some(home.to_str().unwrap().to_string());
        let running = Running(dir);
        assert_eq!(
            crate::start_engine(None, None, upstreams, 41),
            0,
            "{}",
            crate::get_error()
        );
        running
    }

    /// Off and on again on a running engine: the queries move to the other
    /// upstreams, everything the tunnel and tun2socks resolve through moves
    /// with them, and the addresses answered before the switch still name
    /// their hosts: a real one, and a fake one also for a profile that
    /// persists its fake IPs, whose `store-fake-ip` the built-in block drops.
    #[test]
    fn the_switch_moves_a_running_engine_and_keeps_the_addresses_it_answered() {
        let _serial = SERIAL.lock();
        let rt = crate::get_runtime();
        let engine = start(
            "dns:\n  store-fake-ip: true\n  nameserver: ['rcode://refused']\n\
             rules: [MATCH,DIRECT]\n",
            DnsUpstreams::Profile,
            "live-dns",
        );

        let before = resolver();
        assert_eq!(txt_response_code(&before), 5);
        let fake = rt
            .block_on(before.lookup_ipv4("a.example"))
            .expect("a fake IP");
        assert!(before.is_fake_ip(fake));
        let real = IpAddr::from([203, 0, 113, 7]);
        before.preload_cache("real.example", &[real], Duration::from_secs(60));

        apply(DnsUpstreams::Builtin).unwrap();
        let builtin = resolver();
        assert!(
            !Arc::ptr_eq(&builtin, &before),
            "the resolver was not rebuilt"
        );
        assert!(Arc::ptr_eq(&builtin, &engine::tunnel().unwrap().resolver()));
        assert_eq!(builtin.reverse_lookup(fake).as_deref(), Some("a.example"));
        assert_eq!(
            builtin.reverse_lookup(real).as_deref(),
            Some("real.example")
        );
        let builtin_pool = crate::dns_override::CN_NAMESERVERS
            .iter()
            .map(|ns| ns.to_string());
        assert_eq!(nameservers(), Some(builtin_pool.collect()));

        apply(DnsUpstreams::Profile).unwrap();
        let profile = resolver();
        assert!(!Arc::ptr_eq(&profile, &builtin));
        assert_eq!(txt_response_code(&profile), 5);
        assert_eq!(profile.reverse_lookup(fake).as_deref(), Some("a.example"));
        assert_eq!(
            profile.reverse_lookup(real).as_deref(),
            Some("real.example")
        );
        assert_eq!(
            rt.block_on(profile.lookup_ipv4("a.example")),
            Some(fake),
            "the host got another fake IP"
        );
        assert_eq!(nameservers(), Some(vec!["rcode://refused".into()]));

        // Already there: nothing is rebuilt.
        apply(DnsUpstreams::Profile).unwrap();
        assert!(Arc::ptr_eq(&resolver(), &profile));

        drop(engine);
        assert!(crate::DNS_RESOLVER.read().is_none());
        // With no engine there is nothing to switch.
        apply(DnsUpstreams::Builtin).unwrap();
    }

    /// A profile DNS block that does not build leaves the engine where it
    /// was, and still counts as not switched: turning the switch back on is
    /// a no-op, not a second rebuild.
    #[test]
    fn a_profile_dns_that_fails_keeps_the_running_one() {
        let _serial = SERIAL.lock();
        let _engine = start(
            "dns:\n  nameserver-policy:\n    'rule-set:missing': udp://127.0.0.1:1\n\
             rules: [MATCH,DIRECT]\n",
            DnsUpstreams::Builtin,
            "live-dns-broken",
        );
        let before = resolver();

        let err = commit(DnsUpstreams::Profile, Some(41), || {
            panic!("rejected resolver reached persistence")
        })
        .unwrap_err();
        assert_eq!(
            err.downcast::<DnsIssue>().unwrap(),
            DnsIssue::ResolverRejected
        );
        assert!(Arc::ptr_eq(&resolver(), &before));
        assert!(Arc::ptr_eq(&engine::tunnel().unwrap().resolver(), &before));

        apply(DnsUpstreams::Builtin).unwrap();
        assert!(Arc::ptr_eq(&resolver(), &before));
    }

    #[test]
    fn dns_without_a_profile_starts_with_an_independent_pool() {
        let _serial = SERIAL.lock();
        let _engine = start_engine(None, DnsUpstreams::Inherit, "no-dns-profile");
        let applied = status();
        assert!(applied.missing_main);
        assert_eq!(applied.mode, Some("inherit"));
        assert_eq!(applied.primary, ["tcp://1.1.1.1:53", "tcp://8.8.8.8:53"]);
        assert_eq!(applied.primary, applied.node);
        assert_eq!(applied.primary, applied.bootstrap);
        assert!(resolver()
            .main_nameservers()
            .iter()
            .all(|client| !client.is_proxied()));
    }

    #[test]
    fn dns_disk_commit_failure_preserves_the_resolver_and_the_preference() {
        let _serial = SERIAL.lock();
        let _engine = start(
            "rules: [MATCH,DIRECT]\n",
            DnsUpstreams::Inherit,
            "live-dns-disk",
        );
        let before = resolver();
        let home = crate::HOME_DIR.lock().clone().unwrap();
        let target = std::path::Path::new(&home).join("builtin_dns");
        let stage = target.with_extension("tmp");
        std::fs::write(&target, "profile").unwrap();
        let publish = || std::fs::rename(&stage, &target).map_err(anyhow::Error::from);
        assert!(commit(DnsUpstreams::Cn, Some(41), publish).is_err());
        assert!(Arc::ptr_eq(&before, &resolver()));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "profile");
        let applied = status();
        assert_eq!(applied.mode, Some("inherit"));
        assert!(applied.missing_main);
        assert_eq!(applied.node, ["tcp://1.1.1.1:53", "tcp://8.8.8.8:53"]);
        std::fs::write(&stage, r#"{"version":1,"mode":"cn"}"#).unwrap();
        commit(DnsUpstreams::Cn, Some(41), publish).unwrap();
        assert!(!Arc::ptr_eq(&before, &resolver()));
        assert_eq!(status().mode, Some("cn"));
        assert!(std::fs::read_to_string(&target).unwrap().contains("cn"));
    }

    #[test]
    fn dns_commit_rejects_a_different_running_profile_before_persisting() {
        let _serial = SERIAL.lock();
        let _engine = start(
            "rules: [MATCH,DIRECT]\n",
            DnsUpstreams::Inherit,
            "stale-dns-profile",
        );
        let before = resolver();
        let error = commit(DnsUpstreams::Cn, Some(42), || {
            panic!("stale write reached disk")
        })
        .unwrap_err();
        assert_eq!(
            error.downcast::<DnsIssue>().unwrap(),
            DnsIssue::ProfileChanged
        );
        assert_eq!(status().running_profile_id, Some(41));
        assert!(Arc::ptr_eq(&before, &resolver()));
    }

    #[test]
    fn custom_dns_live_switch_sends_tcp_dns_through_the_named_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _serial = SERIAL.lock();
        let rt = crate::get_runtime();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = rt.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") && headers.len() < 2048 {
                headers.push(stream.read_u8().await.unwrap());
            }
            assert!(headers.starts_with(b"CONNECT 192.0.2.53:5353 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut query = vec![0; usize::from(stream.read_u16().await.unwrap())];
            stream.read_exact(&mut query).await.unwrap();
            let reply = crate::test_support::txt_reply(&query).unwrap();
            stream.write_u16(reply.len() as u16).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        let _engine = start(&format!("proxies: [{{name: Node, type: http, server: 127.0.0.1, port: {port}}}]\nrules: [MATCH,DIRECT]\n"),
            DnsUpstreams::Inherit, "custom-dns-proxy");
        let custom = DnsUpstreams::decode(
            r#"{
            "version":1,"mode":"custom","upstreams":[
                {"transport":"tcp","endpoint":"192.0.2.53:5353","egress":"proxy","proxy":"Node"}
            ]
        }"#,
        )
        .unwrap();
        apply(custom).unwrap();
        let sent = rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let query = dns_query("custom-dns.invalid", 16);
                let reply = meow_dns::DnsServer::handle_query(&query, &resolver())
                    .await
                    .unwrap();
                peer.await.unwrap();
                from_the_profile_nameserver(&reply)
            })
            .await
            .unwrap()
        });
        assert!(sent);
        assert_eq!(status().primary, ["tcp://192.0.2.53:5353 (named proxy)"]);
    }

    #[test]
    fn split_dns_binds_a_named_doh_adapter_and_a_separate_direct_resolver() {
        let _serial = SERIAL.lock();
        let profile = "\
proxies: [{name: 'Node & Co', type: socks5, server: 192.0.2.8, port: 1080}]
proxy-groups: [{name: Group, type: select, proxies: [DIRECT, 'Node & Co']}]
dns:
  nameserver: ['udp://192.0.2.53']
  fake-ip-filter: ['*.lan']
  nameserver-policy: {'+.example': 'rcode://success'}
rules: [MATCH,DIRECT]
";
        let mode = |proxy: &str| DnsUpstreams::Split {
            proxy: proxy.into(),
        };
        let _engine = start(profile, mode("Node & Co"), "split-dns");
        let applied = status();
        assert_eq!(applied.mode, Some("split"));
        assert_eq!(applied.primary, ["https://1.1.1.1:443 (named proxy)"]);
        assert_eq!(
            applied.direct,
            ["tcp://119.29.29.29:53", "tcp://223.5.5.5:53"]
        );
        assert_eq!(applied.node, applied.bootstrap);
        assert_eq!(applied.policy_entries, 1);
        let current = resolver();
        assert!(current.main_nameservers()[0].is_proxied());
        let direct = current.direct_resolver().expect("a DIRECT resolver");
        assert!(direct
            .main_nameservers()
            .iter()
            .all(|client| !client.is_proxied()));
        assert!(apply(mode("Group")).is_err());
        assert!(apply(mode("missing")).is_err());
        assert!(Arc::ptr_eq(&current, &resolver()));
        let home = crate::HOME_DIR.lock().clone().unwrap();
        assert_eq!(
            std::fs::read_to_string(std::path::Path::new(&home).join("config.yaml")).unwrap(),
            profile
        );
        assert!(!std::path::Path::new(&home)
            .join("config.android-stripped.yaml")
            .exists());
    }
}
