//! Engine helpers — `tunnel()` accessor plus the config strip + DNS
//! plumbing, adapted from meow-ios `engine::pinned_dns_block` /
//! `strip_listener_fields`. The strip enforces architecturally that:
//!
//!   * No loopback listener bind: `port`, `socks-port`, `mixed-port`,
//!     `tproxy-port`, and `listeners:` are stripped. tun2socks dispatches
//!     every TCP flow in-process via `meow_tunnel::tcp::handle_tcp`.
//!   * No SNI / ALPN sniffing: redundant once DNS is fake-IP, because
//!     `pre_handle_metadata` reverses the fake-IP back to the qname the
//!     resolver originally returned.
//!   * DNS stays in-process fake-IP: whatever the profile's `dns:` block
//!     says, the resolver runs in fake-IP mode (`28.0.0.0/8`) with no listen
//!     socket. The profile still picks the upstreams (`nameserver`,
//!     `fallback`, `nameserver-policy`, `fake-ip-filter`, …); a profile
//!     without a main pool uses independent IP-literal upstreams.
//!   * Connection notes on unless the profile says otherwise: the
//!     connection detail page reads each flow's notes (the DNS lookups a
//!     rule needed, the rule that matched, the dial) from
//!     `GET /connections/{id}`.

use anyhow::{Context, Result};
use meow_config::{load_config, Config};
use meow_tunnel::Tunnel;
use std::path::{Path, PathBuf};

/// Returns a clone of the running engine's `Tunnel` handle, or `None` if the
/// engine isn't running. Mirrors meow-ios `engine::tunnel()`.
pub fn tunnel() -> Option<Tunnel> {
    crate::ENGINE.lock().as_ref().map(|s| s.tunnel.clone())
}

/// Match meow-app's per-load setting, including resetting a previous profile.
pub(crate) fn apply_unified_delay(raw: &meow_config::raw::RawConfig) {
    meow_proxy::health::set_unified_delay(raw.unified_delay.unwrap_or(false));
}

pub(crate) use crate::dns_override::DnsUpstreams;
use crate::dns_override::{engine_dns_block, has_list};

/// Strip the shorthand listener ports + explicit `listeners:` array +
/// `sniffer:` block from a raw config YAML, replace its `dns:` block with
/// [`engine_dns_block`] and default `connection-notes` to on. Operates on a
/// generic `serde_yaml::Value` so unmodelled top-level keys (`tun:`,
/// `experimental:`, `profile:`, etc.) round-trip unchanged.
pub(crate) fn strip_and_inject(yaml: &str, upstreams: DnsUpstreams) -> Result<String> {
    strip(yaml, &upstreams).map(|(stripped, _)| stripped)
}

/// Import admission checks the document's shape. A DNS mode may replace
/// fields in the profile's DNS section when the profile is activated.
pub(crate) fn validate_profile_structure(yaml: &str) -> Result<()> {
    let stripped = meow_common::yaml::run_on_parse_stack(yaml, |yaml| {
        strip_and_inject(yaml, DnsUpstreams::Builtin)
    })
    .map_err(|_| anyhow::anyhow!("Could not read the profile"))??;
    meow_config::parse_raw_yaml(&stripped)
        .map(|_| ())
        .map_err(|_| anyhow::anyhow!("Invalid profile structure"))
}

/// [`strip_and_inject`], also handing back the profile's own `dns:` block.
fn strip(yaml: &str, upstreams: &DnsUpstreams) -> Result<(String, Option<serde_yaml::Value>)> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|_| anyhow::anyhow!("Invalid profile YAML"))?;
    doc.apply_merge()
        .map_err(|_| anyhow::anyhow!("Invalid profile YAML merge"))?;
    let profile_dns;
    if let serde_yaml::Value::Mapping(m) = &mut doc {
        profile_dns = m.remove("dns");
        for key in [
            "port",
            "socks-port",
            "mixed-port",
            "tproxy-port",
            "listeners",
            "sniffer",
            "subscriptions",
            // The app pins the API server to 127.0.0.1:9090 via
            // nativeStartEngine, so the user's value is never used — and
            // mihomo-style shorthand like `external-controller: :9090`
            // fails meow-config's strict address parse since v0.20.
            // `secret:` stays: it is what an on-device dashboard
            // authenticates with (see `api_secret`).
            "external-controller",
            "external-controller-tls",
        ] {
            m.remove(serde_yaml::Value::String(key.to_string()));
        }
        m.insert(
            serde_yaml::Value::String("dns".into()),
            serde_yaml::Value::Mapping(engine_dns_block(profile_dns.clone(), upstreams)?),
        );
        // In the YAML rather than only on the tunnel: the API's config
        // rebuilds re-read the flag from the raw config they apply.
        let notes = serde_yaml::Value::String("connection-notes".into());
        if !m.contains_key(&notes) {
            m.insert(notes, serde_yaml::Value::Bool(true));
        }
    } else {
        anyhow::bail!("The profile must be a YAML mapping");
    }
    let stripped = serde_yaml::to_string(&doc)
        .map_err(|_| anyhow::anyhow!("Could not prepare the profile"))?;
    Ok((stripped, profile_dns))
}

/// The secret the API server runs with: the profile's `secret:` when it sets
/// one, so an on-device dashboard keeps the credential its user chose, else
/// `minted`, the random one `MeowInstance` generated for this start. Without
/// a secret any app on the device could read `/connections` and drive the
/// engine through 127.0.0.1.
pub fn api_secret(profile: Option<String>, minted: Option<String>) -> Option<String> {
    profile
        .filter(|s| !s.is_empty())
        .or(minted.filter(|s| !s.is_empty()))
}

/// Whether the VPN carries IPv6, from the profile's top-level `ipv6:`. Like
/// mihomo, whose `parseIPV6` drops the TUN's IPv6 address only for an
/// explicit `ipv6: false` (its `ipv6` defaults to on), an unset key keeps
/// IPv6 on. The engine's `ipv6` only filters AAAA answers: an app that
/// brings its own IPv6 address (HTTPDNS, a cached literal) would still
/// reach DIRECT over IPv6 through a TUN that routes `::/0`.
pub fn tun_ipv6(raw_ipv6: Option<bool>) -> bool {
    raw_ipv6.unwrap_or(true)
}

/// The profile's `logbook.enable`, on unless it says otherwise — also when
/// the YAML does not parse, so the failed load is recorded.
pub fn logbook_enabled(yaml: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Profile {
        logbook: Option<meow_config::raw::RawLogbook>,
    }
    let logbook = serde_yaml::from_str::<Profile>(yaml)
        .ok()
        .and_then(|profile| profile.logbook);
    meow_config::raw::RawLogbook::enabled(logbook.as_ref())
}

/// The profile's `traffic-ledger:` — on, with hosts, unless it says
/// otherwise; also when the YAML does not parse.
pub fn traffic_ledger(yaml: &str) -> (bool, meow_common::traffic_ledger::Options) {
    #[derive(serde::Deserialize)]
    struct Profile {
        #[serde(rename = "traffic-ledger")]
        traffic_ledger: Option<meow_config::raw::RawTrafficLedger>,
    }
    let ledger = serde_yaml::from_str::<Profile>(yaml)
        .ok()
        .and_then(|profile| profile.traffic_ledger);
    (
        meow_config::raw::RawTrafficLedger::enabled(ledger.as_ref()),
        meow_config::raw::RawTrafficLedger::options(ledger.as_ref()),
    )
}

/// A loaded config and the profile's DNS section for future live overrides.
#[derive(Debug)]
pub(crate) struct Loaded<T> {
    pub config: T,
    pub profile_dns: Option<serde_yaml::Value>,
}

pub(crate) fn uses_missing_dns_pool(
    profile_dns: Option<&serde_yaml::Value>,
    mode: &DnsUpstreams,
) -> bool {
    matches!(mode, DnsUpstreams::Inherit | DnsUpstreams::Profile)
        && !profile_dns
            .and_then(serde_yaml::Value::as_mapping)
            .is_some_and(|dns| has_list(dns, "nameserver"))
}

pub(crate) async fn load_profile<T, F, Fut>(
    yaml: &str,
    mode: &DnsUpstreams,
    load: F,
) -> Result<Loaded<T>>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mode = mode.clone();
    let (stripped, profile_dns) =
        meow_common::yaml::run_on_parse_stack(yaml, move |yaml| strip(yaml, &mode))
            .map_err(|_| anyhow::anyhow!("Could not read the profile"))??;
    // The core may include complete URLs, policy keys and node names in its
    // errors. Only expose a fixed summary across the Android/logging boundary.
    let config = load(stripped).await.map_err(|e| load_failure(&e))?;
    Ok(Loaded {
        config,
        profile_dns,
    })
}

fn load_failure(err: &anyhow::Error) -> anyhow::Error {
    let summary = format!("{err:#}").to_ascii_lowercase();
    let message = if summary.contains("unknown proxy") && summary.contains("nameserver") {
        "A DNS proxy name is missing from the active profile."
    } else if summary.contains("bootstrap") || summary.contains("cannot resolve") {
        "Could not bootstrap the DNS resolver. Check the profile DNS and bootstrap upstreams."
    } else if summary.contains("dns") || summary.contains("nameserver") {
        "The core rejected the DNS settings. Check the upstreams, proxy names and DNS policies."
    } else {
        "Could not load the profile. Check its configuration."
    };
    anyhow::anyhow!(message)
}

/// RAII handle that removes a file on drop. Used so the sibling
/// `config.yaml.android-stripped.yaml` we hand to `load_config` never
/// survives past the load call — including on `?` early-returns, panics,
/// and profile-swap failures.
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Read `config_path`, apply its runtime DNS settings, and hand a sibling
/// `config.yaml.android-stripped.yaml` to `load_config`. The sibling
/// placement is deliberate: `load_config` uses `path.parent()` as the
/// rule-/proxy-provider `cache_dir`, so colocating with the original keeps
/// rule-provider cache files in the home dir. Using `load_config_from_str`
/// would silently disable that caching.
pub(crate) async fn load_stripped_config(
    config_path: &str,
    upstreams: &DnsUpstreams,
) -> Result<Loaded<Config>> {
    let original = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading config from {config_path}"))?;
    let stripped_path = sibling_stripped_path(config_path);
    // Boxed so the loader's large future lives on the heap: unoptimised
    // builds copy a future through the stack at every async layer above it,
    // and the engine starts on a Java thread with a 1 MB stack.
    let load = |stripped: String| {
        let stripped_path = stripped_path.clone();
        Box::pin(async move {
            std::fs::write(&stripped_path, stripped).with_context(|| {
                format!("writing stripped config to {}", stripped_path.display())
            })?;
            let _guard = TempFileGuard(stripped_path.clone());
            load_config(stripped_path.to_str().expect("utf-8 path")).await
        })
    };
    load_profile(&original, upstreams, load).await
}

/// The file [`load_stripped_config`] hands to `load_config`. A rebuild
/// passes it on too: it picks the provider cache dir, and with it the
/// fake-IP store file.
pub fn sibling_stripped_path(config_path: &str) -> PathBuf {
    Path::new(config_path).with_extension("android-stripped.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_override::CN_NAMESERVERS;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn dns_import_and_effective_activation_have_distinct_verdicts() {
        let _serial = crate::test_support::SERIAL.lock();
        let profile = "rules: [MATCH,DIRECT]\ndns:\n  default-nameserver: {invalid: 'unused'}\n";
        validate_profile_structure(profile).unwrap();
        crate::validate_effective_config(profile, &DnsUpstreams::Builtin).unwrap();
        assert!(crate::validate_effective_config(profile, &DnsUpstreams::Inherit).is_err());
        assert!(validate_profile_structure("proxies: 123").is_err());
        assert!(!meow_config::is_offline_validate());
    }

    #[tokio::test]
    async fn unified_delay_profile_controls_cold_and_warm_probes_and_resets() {
        use async_trait::async_trait;
        use meow_common::{
            AdapterType, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
        };
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::mpsc;
        use tokio::time::{sleep, Duration};

        struct Conn(DuplexStream);
        impl AsyncRead for Conn {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }
        impl AsyncWrite for Conn {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.0).poll_write(cx, buf)
            }
            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_shutdown(cx)
            }
        }
        impl ProxyConn for Conn {}

        struct Fixture {
            health: ProxyHealth,
            dials: AtomicUsize,
            requests: mpsc::UnboundedSender<String>,
        }
        #[async_trait]
        impl ProxyAdapter for Fixture {
            fn name(&self) -> &str {
                "synthetic"
            }
            fn adapter_type(&self) -> AdapterType {
                AdapterType::Direct
            }
            fn addr(&self) -> &str {
                ""
            }
            fn support_udp(&self) -> bool {
                false
            }
            fn health(&self) -> &ProxyHealth {
                &self.health
            }
            async fn dial_udp(
                &self,
                _: &Metadata,
            ) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
                Err(meow_common::MeowError::UdpNotSupported)
            }
            async fn dial_tcp(
                &self,
                metadata: &Metadata,
            ) -> meow_common::Result<Box<dyn ProxyConn>> {
                assert_eq!(metadata.host.as_str(), "probe.invalid");
                assert_eq!(metadata.dst_port, 80);
                let count = self.dials.fetch_add(1, Ordering::Relaxed) + 1;
                let requests = self.requests.clone();
                let (client, mut stream) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    for index in 0..count {
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            let mut byte = [0];
                            stream.read_exact(&mut byte).await.unwrap();
                            request.push(byte[0]);
                        }
                        requests.send(String::from_utf8(request).unwrap()).unwrap();
                        if index == 0 {
                            sleep(Duration::from_millis(250)).await;
                        }
                        stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                    }
                });
                Ok(Box::new(Conn(client)))
            }
        }

        // One in-memory node and URL; the first response is delayed to
        // model setup cost, not to claim a physical network comparison.
        let (requests, mut received) = mpsc::unbounded_channel();
        let node = Fixture {
            health: ProxyHealth::new(),
            dials: AtomicUsize::new(0),
            requests,
        };
        let url = "http://probe.invalid/generate_204";
        let apply = |profile: &str| {
            let stripped = strip_and_inject(profile, DnsUpstreams::Builtin).unwrap();
            let raw: meow_config::raw::RawConfig = serde_yaml::from_str(&stripped).unwrap();
            apply_unified_delay(&raw);
        };
        apply("unified-delay: false\n");
        assert!(!meow_proxy::health::unified_delay());
        assert_eq!(node.dials.load(Ordering::Relaxed), 0);
        let cold = meow_proxy::health::url_test(&node, url, None, Duration::from_secs(3))
            .await
            .unwrap();
        apply("unified-delay: true\n");
        assert!(meow_proxy::health::unified_delay());
        let warm = meow_proxy::health::url_test(&node, url, None, Duration::from_secs(3))
            .await
            .unwrap();
        apply("unified-delay: false\n");
        assert!(!meow_proxy::health::unified_delay());
        apply("unified-delay: true\n");
        apply("{}\n");
        assert!(!meow_proxy::health::unified_delay());
        assert_eq!(node.dials.load(Ordering::Relaxed), 2);
        let requests: Vec<_> = (0..3).map(|_| received.try_recv().unwrap()).collect();
        assert!(requests[0].starts_with("GET /generate_204 HTTP/1.1\r\n"));
        assert!(requests[1..]
            .iter()
            .all(|r| r.starts_with("HEAD /generate_204 HTTP/1.1\r\n")));
        assert!(
            cold >= 200 && cold > warm.saturating_add(150),
            "cold={cold}ms warm={warm}ms"
        );
    }

    fn dns_of(stripped: &str) -> serde_yaml::Mapping {
        let doc: serde_yaml::Value = serde_yaml::from_str(stripped).unwrap();
        doc["dns"].as_mapping().cloned().expect("dns block")
    }

    fn list(items: &[&str]) -> serde_yaml::Value {
        serde_yaml::Value::Sequence(items.iter().map(|&s| s.into()).collect())
    }

    const PROFILE: &str = "\
mixed-port: 7890
external-controller: :9090
mode: rule
dns:
  enable: false
  listen: 0.0.0.0:53
  enhanced-mode: redir-host
  fake-ip-range: 198.18.0.1/16
  default-nameserver: [223.5.5.5]
  nameserver: [tls://dns.alidns.com]
  fallback: [tls://8.8.8.8]
  fake-ip-filter: ['*.local']
rules:
  - MATCH,DIRECT
";

    #[test]
    fn profile_keeps_its_upstreams_on_pinned_plumbing() {
        let stripped = strip_and_inject(PROFILE, DnsUpstreams::Profile).unwrap();
        let dns = dns_of(&stripped);
        assert_eq!(dns["enable"], serde_yaml::Value::from(true));
        assert_eq!(dns["listen"], serde_yaml::Value::from(""));
        assert_eq!(dns["enhanced-mode"], serde_yaml::Value::from("fake-ip"));
        assert_eq!(dns["fake-ip-range"], serde_yaml::Value::from("28.0.0.0/8"));
        assert_eq!(dns["nameserver"], list(&["tls://dns.alidns.com"]));
        assert_eq!(dns["default-nameserver"], list(&["223.5.5.5"]));
        assert_eq!(dns["fallback"], list(&["tls://8.8.8.8"]));
        assert_eq!(dns["fake-ip-filter"], list(&["*.local"]));

        let doc: serde_yaml::Value = serde_yaml::from_str(&stripped).unwrap();
        assert!(doc.get("mixed-port").is_none());
        assert!(doc.get("external-controller").is_none());
        assert_eq!(doc["mode"], serde_yaml::Value::from("rule"));
    }

    #[test]
    fn missing_upstreams_use_an_independent_pool_in_both_subscription_modes() {
        for yaml in [
            "dns: {nameserver: [], fake-ip-filter: ['*.lan']}\n",
            "dns:\n",
            "mode: rule\n",
        ] {
            for mode in [DnsUpstreams::Inherit, DnsUpstreams::Profile] {
                let dns = dns_of(&strip_and_inject(yaml, mode).unwrap());
                for key in [
                    "nameserver",
                    "default-nameserver",
                    "proxy-server-nameserver",
                ] {
                    assert_eq!(
                        dns[key],
                        list(&["tcp://1.1.1.1", "tcp://8.8.8.8"]),
                        "{yaml}"
                    );
                }
                assert_eq!(dns["enhanced-mode"], "fake-ip");
                if yaml.contains("*.lan") {
                    assert_eq!(dns["fake-ip-filter"], list(&["*.lan"]));
                }
            }
        }
    }

    #[test]
    fn builtin_drops_the_profile_dns_block() {
        let dns = dns_of(&strip_and_inject(PROFILE, DnsUpstreams::Builtin).unwrap());
        let keys: Vec<_> = dns.keys().filter_map(serde_yaml::Value::as_str).collect();
        assert_eq!(
            keys,
            [
                "enable",
                "listen",
                "enhanced-mode",
                "fake-ip-range",
                "nameserver",
                "default-nameserver"
            ]
        );
        assert_eq!(dns["nameserver"], list(CN_NAMESERVERS));
        assert_eq!(dns["default-nameserver"], list(CN_NAMESERVERS));
    }

    #[test]
    fn connection_notes_default_on_but_the_profile_wins() {
        let notes = |yaml: &str, upstreams: DnsUpstreams| {
            let doc: serde_yaml::Value =
                serde_yaml::from_str(&strip_and_inject(yaml, upstreams).unwrap()).unwrap();
            doc.get("connection-notes")
                .and_then(serde_yaml::Value::as_bool)
        };
        for upstreams in [DnsUpstreams::Profile, DnsUpstreams::Builtin] {
            assert_eq!(notes(PROFILE, upstreams.clone()), Some(true));
            assert_eq!(notes("connection-notes: false\n", upstreams), Some(false));
        }
    }

    #[test]
    fn the_profile_secret_survives_the_strip() {
        let doc: serde_yaml::Value = serde_yaml::from_str(
            &strip_and_inject(
                "secret: hunter2\nexternal-controller: :9090\n",
                DnsUpstreams::Profile,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(doc["secret"].as_str(), Some("hunter2"));
        assert!(doc.get("external-controller").is_none());
    }

    #[test]
    fn the_profile_secret_wins_else_the_minted_one() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(api_secret(s("mine"), s("minted")), s("mine"));
        assert_eq!(api_secret(None, s("minted")), s("minted"));
        assert_eq!(api_secret(s(""), s("minted")), s("minted"));
        assert_eq!(api_secret(None, s("")), None);
        assert_eq!(api_secret(None, None), None);
    }

    #[test]
    fn the_traffic_ledger_is_on_with_hosts_unless_the_profile_says_otherwise() {
        assert_eq!(
            traffic_ledger("rules: [MATCH,DIRECT]\n"),
            (true, Default::default())
        );
        let (enable, options) = traffic_ledger("traffic-ledger:\n  hosts: false\n");
        assert!(enable && !options.hosts);
        assert!(!traffic_ledger("traffic-ledger: {enable: false}\n").0);
        assert!(traffic_ledger("proxies: [\n").0, "an unparsable profile");
    }

    #[test]
    fn the_logbook_is_on_unless_the_profile_turns_it_off() {
        assert!(logbook_enabled("rules: [MATCH,DIRECT]\n"));
        assert!(logbook_enabled("logbook: {}\n"));
        assert!(logbook_enabled("logbook:\n  enable: true\n"));
        assert!(!logbook_enabled("mode: rule\nlogbook:\n  enable: false\n"));
        assert!(logbook_enabled("proxies: [\n"), "an unparsable profile");
    }

    #[tokio::test]
    async fn the_engine_records_notes_for_a_stripped_profile() {
        let stripped = strip_and_inject("rules: [MATCH,DIRECT]\n", DnsUpstreams::Builtin).unwrap();
        let config = meow_config::load_config_from_str(&stripped).await.unwrap();
        assert!(config.general.connection_notes);
    }

    #[tokio::test]
    async fn the_vpn_carries_ipv6_unless_the_profile_turns_it_off() {
        for (profile, want) in [("ipv6: false\n", false), ("ipv6: true\n", true), ("", true)] {
            let yaml = format!("{profile}rules: [MATCH,DIRECT]\n");
            let stripped = strip_and_inject(&yaml, DnsUpstreams::Builtin).unwrap();
            let config = meow_config::load_config_from_str(&stripped).await.unwrap();
            assert_eq!(tun_ipv6(config.raw.ipv6), want, "{profile:?}");
        }
    }

    #[tokio::test]
    async fn invalid_dns_is_rejected_and_a_core_failure_is_redacted_without_retry() {
        for yaml in ["dns: off", "dns: {nameserver: broken}", "dns: [missing"] {
            let load = load_profile(yaml, &DnsUpstreams::Inherit, |_| async {
                panic!("the invalid profile reached the core");
                #[allow(unreachable_code)]
                Ok(())
            });
            assert!(load.await.is_err());
        }
        let calls = AtomicUsize::new(0);
        let failed: Result<Loaded<()>> = load_profile(PROFILE, &DnsUpstreams::Profile, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { anyhow::bail!("cannot resolve https://secret.example/private-token") }
        })
        .await;
        assert_eq!(
            failed.unwrap_err().to_string(),
            "Could not bootstrap the DNS resolver. Check the profile DNS and bootstrap upstreams."
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
