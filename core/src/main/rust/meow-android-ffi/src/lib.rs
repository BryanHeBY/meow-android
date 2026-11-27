//! Rust half of the meow-android native stack — JNI surface for the Kotlin
//! VPN service.
//!
//! Embeds the meow-rs proxy engine (pinned to a release tag) and the
//! tun2socks layer in one cdylib. Outbound socket protection is wired
//! through upstream's `meow_common::SocketProtector` hook — see
//! `protect.rs` — so no proxy-side patches are needed. Every netstack TCP flow is dispatched
//! in-process via `meow_tunnel::tcp::handle_tcp` — no SOCKS5 loopback
//! hop. DNS is delegated to meow's resolver, pinned to fake-IP mode
//! (28.0.0.0/8) by `engine::strip_and_inject` but on the profile's own
//! upstreams or an explicit override. `live_dns` changes the resolver
//! without restarting the tunnel.
//! the tun2socks UDP/53 intercept hands every in-TUN DNS datagram straight to
//! `meow_dns::DnsServer::handle_query`.

mod app_controller;
mod configuration_override;
mod diagnostics;
#[cfg(all(feature = "zerotier", any(test, target_os = "android")))]
mod direct_exit;
mod dns_override;
mod engine;
mod ip_info;
mod live_dns;
mod log_level;
mod logbook;
mod logging;
mod nameserver_policy_override;
mod outbound;
mod owner;
mod probe;
mod protect;
#[cfg(test)]
mod test_support;
mod traffic;
mod tun2socks;
mod tun_egress;
#[cfg(all(target_os = "android", feature = "zerotier"))]
mod zerotier;
#[cfg(all(feature = "zerotier", any(test, target_os = "android")))]
mod zerotier_config;
#[cfg(all(
    feature = "zerotier",
    any(target_os = "android", all(test, target_os = "linux"))
))]
mod zerotier_wake;
#[cfg(all(target_os = "android", feature = "zerotier"))]
mod zerotier_worker;

use dashmap::DashMap;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use meow_api::log_stream::LogMessage;
use meow_api::ApiServer;
use meow_common::TunnelMode;
use meow_config::proxy_provider::ProxyProvider;
use meow_tunnel::Tunnel;
use parking_lot::{Mutex, RwLock};
use std::sync::{Arc, Once, OnceLock};
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// Global allocator
//
// mimalloc instead of the platform malloc (scudo on Android API 30+).
// Empirically returns freed pages to the OS more aggressively under the
// allocation patterns meow + tun2socks generate (many short-lived
// per-flow allocations + the geoip mmdb scan), keeping VPN-service RSS
// closer to working set.
// ---------------------------------------------------------------------------

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

pub(crate) fn get_runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        // Worker count left at the tokio default (one per CPU). Blocking
        // pool capped at 2 so background work (file I/O, redb writes, geoip
        // mmdb scans) can't explode RSS via tokio's default 512-thread cap.
        // Per-thread stack stays at the tokio default (2 MB): capping it at
        // 512 KB overflowed on the latency-probe call chain (url_test →
        // adapter dial → DNS resolver → tracing → android_logger → logcat)
        // and SIGSEGV'd the :vpn process. Stacks are demand-paged, so the
        // real RSS cost is only the pages actually touched.
        tokio::runtime::Builder::new_multi_thread()
            .max_blocking_threads(2)
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}

pub(crate) struct EngineState {
    pub(crate) tunnel: Tunnel,
    /// Whether the VPN routes IPv6 into the TUN (see `engine::tun_ipv6`).
    tun_ipv6: bool,
    /// The profile and published state for live DNS settings.
    pub(crate) live_dns: Arc<live_dns::LiveDns>,
    /// The API's providers: a network switch resets the sessions of their
    /// proxies too, as no group may reach them (`outbound`).
    pub(crate) proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
    controllers: Option<ControllerTasks>,
}

struct ControllerConfig {
    dashboard_addr: String,
    dashboard_secret: String,
    capability: String,
}

struct ControllerTasks {
    dashboard: tokio::task::JoinHandle<()>,
    app: tokio::task::JoinHandle<()>,
    app_controller: Arc<app_controller::AppController>,
}

pub(crate) static ENGINE: Mutex<Option<EngineState>> = Mutex::new(None);
pub(crate) static HOME_DIR: Mutex<Option<String>> = Mutex::new(None);
// Overwritten on every engine start (and cleared on stop) so tun2socks' DNS
// intercept always queries the current session's resolver, not the first one.
pub(crate) static DNS_RESOLVER: RwLock<Option<meow_dns::ResolverSlot>> = RwLock::new(None);

// ---------------------------------------------------------------------------
// Thread-local error message
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

fn set_error(msg: String) {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg);
}

fn get_error() -> String {
    LAST_ERROR.with(|e| e.borrow().clone())
}

// ---------------------------------------------------------------------------
// Minimal config
// ---------------------------------------------------------------------------

const MINIMAL_CONFIG: &str = "\
mode: rule\n\
log-level: info\n\
allow-lan: false\n\
proxies: []\n\
proxy-groups: []\n\
rules:\n\
  - MATCH,DIRECT\n\
";

// ---------------------------------------------------------------------------
// Process-wide tracing subscriber + log broadcast channel
//
// Mirrors meow-ios `engine::log_broadcast_tx` / `install_tracing_subscriber`.
// `set_global_default` can only be installed once per process; subsequent
// engine restarts reuse the same broadcast::Sender that was registered the
// first time.
// ---------------------------------------------------------------------------

fn log_broadcast_tx() -> &'static broadcast::Sender<LogMessage> {
    static TX: OnceLock<broadcast::Sender<LogMessage>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, _rx) = broadcast::channel(128);
        tx
    })
}

fn install_tracing_subscriber() {
    log_level::install(log_broadcast_tx());
    spawn_log_buffer_drainer();
}

// ---------------------------------------------------------------------------
// In-memory log ring buffer for the Kotlin `getLogs` MethodChannel poll
//
// The logs screen polls every couple of seconds and appends whatever it gets,
// so reads have drain semantics: a background task accumulates formatted lines
// from the same broadcast channel the API `/logs` endpoint uses, and
// `nativeGetLogs` returns + clears the pending lines. The buffer is capped so
// it stays bounded while the screen is closed (oldest lines dropped first).
// ---------------------------------------------------------------------------

const LOG_BUFFER_CAP: usize = 2000;

fn log_buffer() -> &'static Mutex<std::collections::VecDeque<String>> {
    static BUF: OnceLock<Mutex<std::collections::VecDeque<String>>> = OnceLock::new();
    BUF.get_or_init(|| Mutex::new(std::collections::VecDeque::new()))
}

fn spawn_log_buffer_drainer() {
    static SPAWNED: Once = Once::new();
    SPAWNED.call_once(|| {
        let mut rx = log_broadcast_tx().subscribe();
        get_runtime().spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(msg) => {
                        let line = format!("{} {}", msg.level.as_str().to_uppercase(), msg.payload);
                        let mut buf = log_buffer().lock();
                        buf.push_back(line);
                        while buf.len() > LOG_BUFFER_CAP {
                            buf.pop_front();
                        }
                    }
                    // Reader fell behind the 128-slot channel; skip the gap.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    });
}

fn drain_log_buffer() -> Vec<String> {
    log_buffer().lock().drain(..).collect()
}

// ---------------------------------------------------------------------------
// Engine lifecycle
// ---------------------------------------------------------------------------

#[cfg(test)]
fn start_engine(
    controllers: Option<ControllerConfig>,
    mode: Option<TunnelMode>,
    dns: engine::DnsUpstreams,
    profile_id: i64,
    source_dns_requires_builtin: bool,
) -> i32 {
    start_engine_with_policy(
        controllers,
        mode,
        dns,
        profile_id,
        source_dns_requires_builtin,
        Default::default(),
    )
}

fn start_engine_with_policy(
    controllers: Option<ControllerConfig>,
    mode: Option<TunnelMode>,
    dns: engine::DnsUpstreams,
    profile_id: i64,
    source_dns_requires_builtin: bool,
    nameserver_policy: nameserver_policy_override::NameserverPolicyOverride,
) -> i32 {
    logging::bridge_log("start_engine: acquiring ENGINE lock");
    let mut engine = ENGINE.lock();
    if engine.is_some() {
        set_error("proxy is already running".to_string());
        return -1;
    }

    let rt = get_runtime();
    match rt.block_on(start_engine_async(
        controllers,
        mode,
        dns,
        profile_id,
        source_dns_requires_builtin,
        nameserver_policy,
    )) {
        Ok((state, app_port)) => {
            logging::bridge_log("start_engine: engine started successfully");
            *engine = Some(state);
            i32::from(app_port)
        }
        Err(e) => {
            logging::bridge_log(&format!("start_engine: ERROR: {}", e));
            meow_common::logbook::engine_stopped(meow_common::logbook::Stop::Failed(&format!(
                "{e:#}"
            )));
            set_error(e.to_string());
            -1
        }
    }
}

async fn start_engine_async(
    controllers: Option<ControllerConfig>,
    mode: Option<TunnelMode>,
    dns: engine::DnsUpstreams,
    profile_id: i64,
    source_dns_requires_builtin: bool,
    nameserver_policy: nameserver_policy_override::NameserverPolicyOverride,
) -> Result<(EngineState, u16), anyhow::Error> {
    if source_dns_requires_builtin && !matches!(dns, engine::DnsUpstreams::Builtin) {
        return Err(dns_override::DnsIssue::ResolverRejected.into());
    }
    install_tracing_subscriber();
    let tcp_policy = engine::StartupTcpPolicy::capture();
    let mut startup_logs = log_level::StartupLogLevel::new();

    // Resolve config path + set XDG_CONFIG_HOME (meow-config looks for
    // $XDG_CONFIG_HOME/meow/Country.mmdb). Our dir is .../no_backup/meow,
    // so XDG_CONFIG_HOME is the parent.
    let config_path = if let Some(dir) = HOME_DIR.lock().as_ref() {
        if let Some(parent) = std::path::Path::new(dir).parent() {
            std::env::set_var("XDG_CONFIG_HOME", parent);
            logging::bridge_log(&format!(
                "start_engine_async: set XDG_CONFIG_HOME={}",
                parent.display()
            ));
        }
        Some(format!("{}/config.yaml", dir))
    } else {
        None
    };

    // Geodata DBs are bundled in the APK and seeded into the engine home
    // dir by MeowInstance.copyGeoxAssets() before nativeStartEngine
    // fires. The on-disk files at `$XDG_CONFIG_HOME/meow/Country.mmdb` and
    // `…/GeoLite2-ASN.mmdb` are guaranteed to exist by the time we reach
    // load_config, so no pre-VPN network fetch is needed here. See
    // `core/build.gradle.kts` (downloadGeoxAssets) for the bundling path.

    // Apply DNS in a runtime copy. The minimal profile is used only when
    // there is no configuration file.
    let load_error = |error: anyhow::Error| {
        if dns.requires_profile() && !error.is::<dns_override::DnsIssue>() {
            dns_override::DnsIssue::ResolverRejected.into()
        } else {
            error
        }
    };
    let (loaded, loaded_from) = match config_path.as_deref() {
        Some(path) if std::path::Path::new(path).exists() => {
            logging::bridge_log(&format!(
                "start_engine_async: loading config from {path}, DNS mode: {}",
                dns.mode()
            ));
            // The logbook opens under the engine home (`XDG_CONFIG_HOME`,
            // set above) before the load, so the load's own events — a
            // provider that fails to fetch — are recorded.
            let profile = std::fs::read_to_string(path).unwrap_or_default();
            meow_common::logbook::apply(engine::logbook_enabled(&profile));
            let (ledger, ledger_options) = engine::traffic_ledger(&profile);
            meow_common::traffic_ledger::apply(ledger, ledger_options);
            let stripped_path = engine::sibling_stripped_path(path);
            (
                engine::load_stripped_config(path, &dns, &nameserver_policy, &mut startup_logs)
                    .await
                    .map_err(load_error)?,
                stripped_path.to_str().map(str::to_string),
            )
        }
        _ => {
            logging::bridge_log("start_engine_async: using minimal config");
            meow_common::logbook::apply(true);
            meow_common::traffic_ledger::apply(true, Default::default());
            let logs = &mut startup_logs;
            let loaded = engine::load_profile_with_policy(
                MINIMAL_CONFIG,
                &dns,
                &nameserver_policy,
                |stripped| {
                    Box::pin(async move {
                        let raw = meow_config::parse_raw_yaml(&stripped)?;
                        logs.apply(raw.log_level.as_deref());
                        engine::build_startup_config(raw, None).await
                    })
                },
            )
            .await
            .map_err(load_error)?;
            (loaded, None)
        }
    };
    // What the logbook's start entry names.
    let config_source = match (&loaded_from, config_path) {
        (Some(_), Some(path)) => path,
        _ => "built-in config".to_owned(),
    };
    let engine::Loaded {
        mut config,
        profile_dns,
    } = loaded;
    dns.check_targets(|name| config.proxies.get(name).map(Arc::as_ref))?;
    dns.check_resolver(&config.dns.resolver)?;
    logging::bridge_log(&format!(
        "start_engine_async: config loaded, proxies={}, rules={}",
        config.proxies.len(),
        config.rules.len()
    ));

    // JNI always supplies both controllers. Resolver-only host tests may
    // omit them so they can exercise the engine without network listeners.
    let controllers = if let Some(controllers) = controllers {
        let app = app_controller::AppController::new(controllers.capability)?;
        let dashboard_addr: std::net::SocketAddr = controllers.dashboard_addr.parse()?;
        anyhow::ensure!(
            dashboard_addr.ip().is_loopback(),
            "controller must bind to loopback"
        );
        config.api.external_controller = Some(dashboard_addr);
        let dashboard_secret =
            engine::api_secret(config.api.secret.take(), Some(controllers.dashboard_secret))
                .ok_or_else(|| anyhow::anyhow!("dashboard controller requires authentication"))?;
        // Bind both ports before spawning either server or publishing engine state.
        let dashboard_listener = tokio::net::TcpListener::bind(dashboard_addr)
            .await
            .map_err(|e| anyhow::anyhow!("bind dashboard controller: {e}"))?;
        let app_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| anyhow::anyhow!("bind app controller: {e}"))?;
        let app_addr = app_listener.local_addr()?;
        Some((
            dashboard_addr,
            dashboard_secret,
            dashboard_listener,
            app_addr,
            app_listener,
            app,
        ))
    } else {
        None
    };
    let tun_ipv6 = engine::tun_ipv6(config.raw.ipv6);
    // The app's route-mode picker outlives a session, so its pick replaces
    // the profile's `mode:`. `raw` is what `GET /configs` echoes back.
    if let Some(mode) = mode {
        logging::bridge_log(&format!("start_engine_async: route mode override {mode}"));
        config.general.mode = mode;
        config.raw.mode = Some(mode.to_string());
    }

    // Install the global host-resolver hook so `meow_common::connect_tcp_host`
    // (used by every proxy adapter that dials by hostname — Trojan, VLESS,
    // SS, SOCKS5, HTTP, …) routes the lookup through meow-rs's own
    // `Resolver` instead of libc's `getaddrinfo`. Critical on Android: the
    // VPN's DNS server is `172.19.0.2` (our TUN), so `getaddrinfo` would
    // loop the query back through the engine's fake-IP pool and the
    // protected outbound socket would then try to dial a non-routable
    // `28.0.0.0/8` address. `proxy_resolver` is the config's
    // `proxy-server-nameserver` pool, used for proxy-server hostnames when set.
    // Unconditional, as meow-app does on the VPN platforms.
    meow_common::set_host_resolver(Arc::new(
        meow_dns::ResolverHostHook::new_with_proxy_resolver(
            Arc::clone(&config.dns.resolver),
            config.dns.proxy_resolver.clone(),
        ),
    ));

    *DNS_RESOLVER.write() = Some(Arc::clone(&config.dns.resolver_slot));

    // Same startup order as meow-app's `run`: share the config's resolver
    // slot, install the provider dialer registry before the first
    // `update_routing` (provider nodes resolve `dialer-proxy` against it),
    // then publish the routing table in one step.
    let raw_config = Arc::new(RwLock::new(config.raw.clone()));
    let tunnel = Tunnel::new_with_slot(Arc::clone(&config.dns.resolver_slot));
    tunnel.set_dns_outbound_cell(config.provider_dns_cell.clone());
    tunnel.set_dialer_registry(config.provider_dialer_registry.clone());
    tunnel.set_mode(config.general.mode);
    tunnel.set_connection_notes(config.general.connection_notes);
    tunnel.set_process_lookup_mode(engine::android_process_lookup(
        config.general.find_process_mode,
    ));
    // The health mode is process-wide in meow-proxy. Apply it on every
    // engine start, including the default, before any health checks start.
    engine::apply_unified_delay(&config.raw);
    // The profile's `tcp-idle-timeout` (off unless set): ends relays silent
    // in both directions, which TUN netstack flows need since keepalive
    // never reaches them.
    tunnel.set_tcp_idle_timeout(config.general.tcp_idle_timeout);
    tunnel.update_routing(
        config.proxies,
        config.rules,
        config.sub_rules,
        config.dialer_registry,
    );
    // The UDP NAT sweeper: evicts sessions idle in both directions (the
    // tun2socks reply readers touch the same clock on every reply).
    tunnel.spawn_background_tasks();
    // Periodic probes for url-test / fallback groups. The tasks hold a weak
    // tunnel handle, so they end with the engine.
    tunnel.reconcile_health_checks(&meow_config::extract_health_check_specs(
        config.raw.proxy_groups.as_deref().unwrap_or(&[]),
    ));

    let proxy_providers: Arc<DashMap<_, _>> =
        Arc::new(config.proxy_providers.into_iter().collect());
    let rule_providers = Arc::new(RwLock::new(config.rule_providers));
    // No DNS listener: tun2socks answers in-TUN queries in-process.
    let dns_server = Arc::new(RwLock::new(None));
    let live_dns = Arc::new(live_dns::LiveDns::new(
        profile_id,
        profile_dns,
        source_dns_requires_builtin,
        nameserver_policy,
        loaded_from,
        dns,
        &config.dns.resolver,
        Arc::clone(&raw_config),
        Arc::clone(&rule_providers),
        Arc::clone(&dns_server),
    ));

    // `interval:` refresh loops for rule and proxy providers.
    let rule_provider_refresh =
        Arc::new(meow_config::rule_provider_refresh::RefreshSupervisor::default());
    rule_provider_refresh.reconcile(&rule_providers);
    // Record the providers the load left out now that it is running.
    config.dropped_providers.record();
    let proxy_provider_refresh =
        Arc::new(meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor::default());
    proxy_provider_refresh.reconcile(&proxy_providers, config.raw.proxy_providers.as_ref());

    // Providers the load left owing a remote fetch (served from their cache,
    // cut off by the deadline, failed, or with a `proxy:` that could not
    // resolve before `update_routing`) fetch now, retrying with backoff.
    meow_config::proxy_provider::spawn_deferred_initial_fetches(&proxy_providers);

    let listeners_for_api = config.listeners.named.clone();
    let log_tx = log_broadcast_tx().clone();

    let api_server = |addr, secret| {
        ApiServer::new(
            tunnel.clone(),
            Some(addr),
            Some(secret),
            meow_config::ApiCorsConfig::default(),
            // No config path: the app restarts the engine to apply a config,
            // and `PUT /configs` must not persist into the stripped copy.
            None,
            Arc::clone(&raw_config),
            log_tx.clone(),
            Arc::clone(&proxy_providers),
            Arc::clone(&rule_providers),
            Arc::clone(&rule_provider_refresh),
            Arc::clone(&proxy_provider_refresh),
            listeners_for_api.clone(),
            // Keep the built-in dashboard; no profile external web root.
            None,
            Arc::clone(&dns_server),
            config.provider_dialer_registry.clone(),
            // No embedded NTP supervisor in the Android service.
            None,
        )
    };
    let (controllers, app_port) = match controllers {
        Some((
            dashboard_addr,
            secret,
            dashboard_listener,
            app_addr,
            app_listener,
            app_controller,
        )) => {
            let dashboard = api_server(dashboard_addr, secret);
            let app = api_server(app_addr, app_controller.secret()).router();
            let dashboard = tokio::spawn(async move {
                if let Err(e) = dashboard.run_on(dashboard_listener).await {
                    tracing::error!("Dashboard controller error: {}", e);
                }
            });
            let app = tokio::spawn({
                let app_controller = Arc::clone(&app_controller);
                async move {
                    if let Err(e) = app_controller.serve(app_listener, app).await {
                        tracing::error!("App controller error: {}", e);
                    }
                }
            });
            (
                Some(ControllerTasks {
                    dashboard,
                    app,
                    app_controller,
                }),
                app_addr.port(),
            )
        }
        None => (None, 0),
    };

    // No SOCKS5 / HTTP loopback listener — tun2socks dispatches every flow
    // through `meow_tunnel::tcp::handle_tcp` in-process (same path as
    // meow-ios). The `listeners.*` block in user configs is intentionally
    // ignored on Android.

    logging::bridge_log("start_engine_async: all tasks spawned");
    tcp_policy.commit();
    startup_logs.commit();
    meow_common::logbook::engine_started(&config_source);
    Ok((
        EngineState {
            tunnel,
            tun_ipv6,
            live_dns,
            proxy_providers,
            controllers,
        },
        app_port,
    ))
}

// ---------------------------------------------------------------------------
// JNI entry points
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeInit(
    _env: JNIEnv,
    _class: JClass,
) {
    logging::init_android_logger();
    logging::bridge_log("nativeInit: android logger initialized");
    // Process-wide engine policy, set before any config load (engine start
    // in `:vpn`, validation in the UI process):
    //  * tun2socks names each flow's owner (owner.rs), so PROCESS-NAME / UID
    //    rules stay live; their liveness is fixed when rules are built.
    //  * A provider feed must not hold the VPN start: the tunnel only comes
    //    up once the config has loaded (and with "Block connections without
    //    VPN" no fetch can succeed before then). Uncached providers get this
    //    long; stragglers land in the background, failures retry there.
    meow_common::process_lookup::enable_inbound_process_info();
    meow_config::set_provider_fetch_deadline(Some(PROVIDER_FETCH_DEADLINE));
}

/// How long a config load waits for provider downloads with no cache.
const PROVIDER_FETCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeSetHomeDir(
    mut env: JNIEnv,
    _class: JClass,
    dir: JString,
) {
    let dir_str: String = env.get_string(&dir).map(|s| s.into()).unwrap_or_default();
    logging::bridge_log(&format!("nativeSetHomeDir: {}", dir_str));
    if dir_str.is_empty() {
        *HOME_DIR.lock() = None;
    } else {
        // meow-config resolves geodata at `$XDG_CONFIG_HOME/meow/Country.mmdb`.
        // Our home dir is `.../no_backup/meow`, so XDG_CONFIG_HOME is its
        // parent. Set it here (not only in start_engine) so config validation
        // — used by the YAML editor and config import before any VPN start —
        // can load the bundled GeoIP DB instead of failing on the default
        // relative `./meow/Country.mmdb` path.
        if let Some(parent) = std::path::Path::new(&dir_str).parent() {
            std::env::set_var("XDG_CONFIG_HOME", parent);
        }
        *HOME_DIR.lock() = Some(dir_str);
    }
}

/// Drains and returns the buffered engine log lines as a single newline-joined
/// string (empty if none pending). Kotlin splits it back into a list for the
/// logs screen. Safe to call whether or not the engine is running.
#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeGetLogs(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let joined = drain_log_buffer().join("\n");
    env.new_string(joined)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeStartEngine(
    mut env: JNIEnv,
    _class: JClass,
    addr: JString,
    dashboard_secret: JString,
    mode: JString,
    dns: JString,
    profile_id: jlong,
    capability: JString,
    source_dns_requires_builtin: jni::sys::jboolean,
    nameserver_policy: JString,
) -> jint {
    let mut read =
        |value: &JString| -> String { env.get_string(value).map(String::from).unwrap_or_default() };
    let dns = read(&dns);
    let settings = engine::DnsUpstreams::decode_scoped(&dns)
        .map_err(|_| anyhow::Error::from(dns_override::DnsIssue::InvalidSettings))
        .and_then(|(settings, owner)| {
            settings.check_android_support()?;
            settings.require_scope(owner, profile_id)?;
            let policy = nameserver_policy_override::NameserverPolicyOverride::decode(&read(
                &nameserver_policy,
            ))
            .map_err(|_| anyhow::Error::from(dns_override::DnsIssue::InvalidSettings))?;
            Ok((settings, policy))
        });
    match settings {
        Ok((settings, policy)) => start_engine_with_policy(
            Some(ControllerConfig {
                dashboard_addr: read(&addr),
                dashboard_secret: read(&dashboard_secret),
                capability: read(&capability),
            }),
            parse_mode_override(&read(&mode)),
            settings,
            profile_id,
            source_dns_requires_builtin != jni::sys::JNI_FALSE,
            policy,
        ),
        Err(error) => {
            set_error(error.to_string());
            -1
        }
    }
}

/// Empty means "keep the config's `mode:`". An unknown value is logged and
/// ignored rather than failing the start: a stale pick must not brick the VPN.
fn parse_mode_override(raw: &str) -> Option<TunnelMode> {
    if raw.is_empty() {
        return None;
    }
    match raw.parse() {
        Ok(mode) => Some(mode),
        Err(e) => {
            logging::bridge_log(&format!("nativeStartEngine: ignoring route mode: {e}"));
            None
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeStopEngine(
    _env: JNIEnv,
    _class: JClass,
) {
    stop_engine();
}

fn stop_engine() {
    // A probe holds a route snapshot, so it would keep dialing through the
    // stopped engine's proxies until its own budget ran out.
    probe::cancel_all();
    tun2socks::stop();
    protect::clear();
    owner::clear();
    let mut engine = ENGINE.lock();
    // Under the lock: a start or a DNS switch (`live_dns`) still running
    // would otherwise install its resolver after this.
    *DNS_RESOLVER.write() = None;
    if let Some(state) = engine.take() {
        if let Some(controllers) = &state.controllers {
            controllers.app_controller.stop();
        }
        // What the connections carried since the last minute's flush, while
        // the tunnel still holds them.
        meow_common::traffic_ledger::flush();
        // Ends the tun2socks UDP reply readers now rather than at their next
        // idle check.
        state.tunnel.close_all_udp_sessions();
        // Join both accept loops while holding ENGINE so the next start sees
        // neither old listener. The private gate also revokes accepted sockets.
        if let Some(controllers) = state.controllers {
            controllers.app.abort();
            controllers.dashboard.abort();
            get_runtime().block_on(async {
                let _ = tokio::join!(controllers.app, controllers.dashboard);
            });
        }
        meow_common::logbook::engine_stopped(meow_common::logbook::Stop::Requested("app"));
    }
    log_level::reset();
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_ZeroTierNative_nativeInspectMoon(
    env: JNIEnv,
    _class: JClass,
    input: jni::objects::JByteArray,
) -> jni::sys::jstring {
    if env
        .get_array_length(&input)
        .map_or(true, |n| !(1..=16_384).contains(&n))
    {
        return std::ptr::null_mut();
    }
    env.convert_byte_array(input)
        .ok()
        .and_then(|bytes| zerotier::moon_id(&bytes))
        .and_then(|world| env.new_string(format!("{world:016x}")).ok())
        .map_or(std::ptr::null_mut(), JString::into_raw)
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeStartTun2Socks(
    mut env: JNIEnv,
    _class: JClass,
    vpn_service: JObject,
    fd: jint,
    dns_port: jint,
    overlay_root: JString,
    overlay_settings: JString,
    block_app_udp443: jboolean,
) -> jint {
    logging::bridge_log(&format!(
        "nativeStartTun2Socks: fd={}, dns={}",
        fd, dns_port
    ));

    if fd < 0 {
        set_error("invalid file descriptor".to_string());
        return -1;
    }

    // Install the global SocketProtector — every outbound TCP/UDP fd
    // meow-rs opens (proxy adapters + the DNS resolver's default
    // SocketFactory) will fire VpnService.protect() before connect/bind.
    protect::install(&env, &vpn_service);
    // Lets tun2socks tag each connection with the app that opened it.
    owner::install(&mut env, &vpn_service);

    #[cfg(target_os = "android")]
    let start = (|| -> Result<(), String> {
        #[cfg(feature = "zerotier")]
        let (root, config, meow_enabled) = {
            let root: String = env
                .get_string(&overlay_root)
                .map_err(|e| e.to_string())?
                .into();
            let json: String = env
                .get_string(&overlay_settings)
                .map_err(|e| e.to_string())?
                .into();
            let (config, meow_enabled) = zerotier_config::parse_session(json.as_bytes())?;
            (root, config, meow_enabled)
        };
        #[cfg(not(feature = "zerotier"))]
        let _ = (overlay_root, overlay_settings);
        // Capture this exact service instance, not a process-global pointer
        // that a newer session can replace while the old task exits.
        let report_exit = env.get_java_vm().ok().and_then(|jvm| {
            env.new_global_ref(&vpn_service).ok().map(|service| {
                Box::new(move |code: i32| {
                    if let Ok(mut env) = jvm.attach_current_thread() {
                        if env
                            .call_method(
                                service.as_obj(),
                                "recordUnexpectedTunExit",
                                "(I)V",
                                &[jni::objects::JValue::Int(code)],
                            )
                            .is_err()
                        {
                            let _ = env.exception_clear();
                        }
                    }
                }) as Box<dyn FnOnce(i32) + Send>
            })
        });
        tun2socks::start_android(
            fd,
            block_app_udp443 != JNI_FALSE,
            #[cfg(feature = "zerotier")]
            config.map(|config| (root.into(), config)),
            report_exit,
            #[cfg(feature = "zerotier")]
            meow_enabled,
        )
    })();
    #[cfg(not(target_os = "android"))]
    let start = {
        let _ = (overlay_root, overlay_settings);
        tun2socks::start_with_udp443_policy(fd, block_app_udp443 != JNI_FALSE)
    };
    match start {
        Ok(()) => {
            logging::bridge_log("nativeStartTun2Socks: started successfully");
            0
        }
        Err(e) => {
            logging::bridge_log(&format!("nativeStartTun2Socks: ERROR: {}", e));
            set_error(e);
            -1
        }
    }
}

/// Stops only raw packet forwarding. The engine, protected sockets,
/// controller API, fake-IP and selector state do not belong to the TUN fd.
#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeStopTun2Socks(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if tun2socks::stop() {
        // UDP NAT entries belong to the old TUN readers. Close those sessions
        // so the new forwarding generation doesn't reuse pending replies.
        if let Some(engine) = ENGINE.lock().as_ref() {
            engine.tunnel.close_all_udp_sessions();
        }
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_ZeroTierNative_nativeApplyZeroTier(
    mut env: JNIEnv,
    _class: JClass,
    overlay_root: JString,
    overlay_settings: JString,
) -> jint {
    use tun2socks::OverlayApplyError::{NotApplied, OutcomeUnknown};
    let result = (|| {
        let root: String = env
            .get_string(&overlay_root)
            .map_err(|e| NotApplied(e.to_string()))?
            .into();
        let json: String = env
            .get_string(&overlay_settings)
            .map_err(|e| NotApplied(e.to_string()))?
            .into();
        let config = zerotier_config::parse(json.as_bytes()).map_err(|e| NotApplied(e.into()))?;
        tun2socks::apply_overlay(config.map(|config| (root.into(), config)))
    })();
    match result {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(OutcomeUnknown) => {
            set_error("ZeroTier apply outcome unknown; reconnect before retrying".into());
            -2
        }
        Err(NotApplied(mut err)) => {
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
                err = "invalid ZeroTier JNI input".into();
            }
            set_error(err);
            -1
        }
    }
}

#[cfg(all(target_os = "android", feature = "zerotier"))]
#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_ZeroTierNative_nativeSetMeowForwarding(
    _env: JNIEnv,
    _class: JClass,
    enabled: jboolean,
) -> jint {
    match tun2socks::set_meow_forwarding(enabled != JNI_FALSE) {
        Ok(()) => 0,
        Err(err) => {
            set_error(err.into());
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeIsRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if ENGINE.lock().is_some() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeGetUploadTraffic(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let engine = ENGINE.lock();
    match engine.as_ref() {
        Some(state) => state.tunnel.statistics().snapshot().0,
        None => 0,
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeGetDownloadTraffic(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let engine = ENGINE.lock();
    match engine.as_ref() {
        Some(state) => state.tunnel.statistics().snapshot().1,
        None => 0,
    }
}

#[cfg(test)]
fn validate_effective_config(yaml: &str, mode: &engine::DnsUpstreams) -> anyhow::Result<()> {
    validate_effective_config_with_policy(yaml, mode, &Default::default())
}

fn validate_effective_config_with_policy(
    yaml: &str,
    mode: &engine::DnsUpstreams,
    policy: &nameserver_policy_override::NameserverPolicyOverride,
) -> anyhow::Result<()> {
    mode.check_android_support()?;
    // The core's offline flag is process-wide. Validation runs in the
    // app process; holding ENGINE also prevents a same-process caller
    // from starting a serving resolver under this flag.
    let engine = ENGINE.lock();
    anyhow::ensure!(
        engine.is_none(),
        "Cannot validate while the engine is running in this process"
    );
    struct Offline;
    impl Drop for Offline {
        fn drop(&mut self) {
            meow_config::set_offline_validate(false);
        }
    }
    meow_config::set_offline_validate(true);
    let _offline = Offline;
    let load = engine::load_profile_with_policy(yaml, mode, policy, |stripped| {
        Box::pin(async move { meow_config::load_config_from_str(&stripped).await })
    });
    let loaded = get_runtime().block_on(load)?;
    mode.check_targets(|name| loaded.config.proxies.get(name).map(Arc::as_ref))?;
    mode.check_resolver(&loaded.config.dns.resolver)
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeValidateConfig(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
    dns: JString,
    nameserver_policy: JString,
) -> jint {
    let yaml: String = env.get_string(&yaml).map(|s| s.into()).unwrap_or_default();
    let dns: String = env.get_string(&dns).map(|s| s.into()).unwrap_or_default();
    let wire: String = env
        .get_string(&nameserver_policy)
        .map(|s| s.into())
        .unwrap_or_default();
    let validate = || {
        let (mode, _) = engine::DnsUpstreams::decode_scoped(&dns)
            .map_err(|_| dns_override::DnsIssue::InvalidSettings)?;
        let policy = nameserver_policy_override::NameserverPolicyOverride::decode(&wire)
            .map_err(|_| dns_override::DnsIssue::InvalidSettings)?;
        validate_effective_config_with_policy(&yaml, &mode, &policy)
    };
    match validate() {
        Ok(()) => 0,
        Err(e) => {
            set_error(format!("validate config: {}", e));
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeValidateProfileStructure(
    mut env: JNIEnv,
    _class: JClass,
    yaml: JString,
) -> jint {
    let yaml: String = env.get_string(&yaml).map(|s| s.into()).unwrap_or_default();
    match engine::validate_profile_structure(&yaml) {
        Ok(_) => 0,
        Err(e) => {
            set_error(format!("validate config: {}", e));
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeGetLastError(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let msg = get_error();
    env.new_string(&msg)
        .unwrap_or_else(|_| env.new_string("").unwrap())
        .into_raw()
}

/// Whether `VpnService` routes IPv6 into the TUN for the running engine's
/// profile (see `engine::tun_ipv6`); false when the engine is stopped.
#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeTunIpv6(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if ENGINE.lock().as_ref().is_some_and(|s| s.tun_ipv6) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// What Settings shows as the engine version; `build.rs` reads the release
/// (or the release plus the commit, for a pin to one) from Cargo.lock.
const ENGINE_VERSION: &str = concat!("meow-rs v", env!("MEOW_RS_VERSION"));

#[no_mangle]
pub extern "system" fn Java_io_github_madeye_meow_core_MeowCore_nativeVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    env.new_string(ENGINE_VERSION)
        .unwrap_or_else(|_| env.new_string("").unwrap())
        .into_raw()
}

#[cfg(test)]
mod tests {
    use super::ENGINE_VERSION;

    #[test]
    fn advanced_policy_only_changes_on_successful_engine_start() {
        use super::*;
        use meow_common::{dial::tcp_concurrent, ProcessLookupMode};
        use meow_proxy::health::unified_delay;

        let _serial = test_support::SERIAL.lock();
        let root = std::env::temp_dir().join(format!("meow-advanced-start-{}", std::process::id()));
        let home = root.join("meow");
        std::fs::create_dir_all(&home).unwrap();
        *HOME_DIR.lock() = Some(home.to_str().unwrap().into());
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                stop_engine();
                *HOME_DIR.lock() = None;
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root);
        let config = home.join("config.yaml");
        let start =
            |controller| start_engine(controller, None, engine::DnsUpstreams::Builtin, 41, false);
        let write_settings = |settings: &str| {
            std::fs::write(&config, format!("logbook: {{enable: false}}\n{settings}")).unwrap();
        };
        write_settings("unified-delay: true\ntcp-concurrent: false\nfind-process-mode: off\n");
        assert_eq!(start(None), 0, "{}", get_error());
        let current = engine::tunnel().unwrap();
        assert_eq!(current.process_lookup_mode(), ProcessLookupMode::Off);
        assert!(unified_delay());
        assert!(!tcp_concurrent());
        get_runtime().block_on(engine::tests::check_tcp_candidate_scheduling(false));

        write_settings("unified-delay: false\ntcp-concurrent: true\nfind-process-mode: always\n");
        assert_eq!(start(None), -1, "a second start must be rejected");
        assert_eq!(current.process_lookup_mode(), ProcessLookupMode::Off);
        assert!(unified_delay());
        assert!(!tcp_concurrent());
        stop_engine();

        let invalid = ControllerConfig {
            dashboard_addr: "0.0.0.0:0".into(),
            dashboard_secret: "synthetic".into(),
            capability: "ab".repeat(32),
        };
        assert_eq!(start(Some(invalid)), -1);
        assert_eq!(get_error(), "controller must bind to loopback");
        assert!(engine::tunnel().is_none());
        assert!(DNS_RESOLVER.read().is_none());
        assert!(unified_delay());
        assert!(!tcp_concurrent());

        assert_eq!(start(None), 0, "{}", get_error());
        assert_eq!(
            engine::tunnel().unwrap().process_lookup_mode(),
            ProcessLookupMode::Always
        );
        assert!(!unified_delay());
        assert!(tcp_concurrent());
        get_runtime().block_on(engine::tests::check_tcp_candidate_scheduling(true));
        stop_engine();

        write_settings("find-process-mode: strict\n");
        assert_eq!(start(None), 0, "{}", get_error());
        assert_eq!(
            engine::tunnel().unwrap().process_lookup_mode(),
            ProcessLookupMode::Always
        );
        assert!(!unified_delay());
        assert!(tcp_concurrent());
    }

    #[test]
    fn the_engine_version_identifies_the_pinned_fork() {
        let version = ENGINE_VERSION.strip_prefix("meow-rs v").unwrap();
        let kernel =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../../vendor/meow-rs");
        assert!(kernel.join("crates/meow-tunnel/Cargo.toml").is_file());
        let published_version = include_str!("../Cargo.lock")
            .split("[[package]]")
            .find(|package| package.contains("\nname = \"meow-tunnel\"\n"))
            .and_then(|package| {
                package
                    .lines()
                    .find_map(|line| line.strip_prefix("version = "))
            })
            .map(|field| field.trim_matches('"'))
            .unwrap();
        if kernel.join(".git").exists() {
            let result = std::process::Command::new("git")
                .arg("-C")
                .arg(&kernel)
                .args(["rev-parse", "--verify", "HEAD"])
                .output()
                .unwrap();
            assert!(result.status.success(), "{result:?}");
            let pinned = std::str::from_utf8(&result.stdout).unwrap().trim();
            let (printed_version, printed_revision) = version.split_once('+').unwrap();
            assert_eq!(printed_version, published_version);
            assert!(printed_revision.len() >= 7 && pinned.starts_with(printed_revision));
        } else {
            assert_eq!(version, published_version);
        }
    }
}
