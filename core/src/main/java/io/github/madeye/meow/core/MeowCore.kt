package io.github.madeye.meow.core

object MeowCore {
    init {
        System.loadLibrary("meow_android_ffi")
        nativeInit()
    }

    /** Ensure the shared library has been initialized before flavor-specific JNI calls. */
    internal fun ensureLoaded() = Unit

    external fun nativeInit()
    external fun nativeSetHomeDir(dir: String)
    /**
     * [dashboardSecret] guards the dashboard API unless the profile sets its own `secret:`.
     * [capability] guards the app's private listener. Returns its bound port, or -1 on failure.
     * [mode] overrides the config's `mode:` (`rule`/`global`/`direct`); empty keeps it.
     * [dns] carries the saved DNS preference.
     * [profileId] is the immutable ID of the profile this engine will run.
     * [sourceDnsRequiresBuiltin] preserves the authored DNS shape through runtime overlays.
     */
    external fun nativeStartEngine(
        addr: String,
        dashboardSecret: String,
        mode: String,
        dns: String,
        profileId: Long,
        capability: String,
        sourceDnsRequiresBuiltin: Boolean = false,
        nameserverPolicy: String = "null",
        fallbackTransition: Long = 0L,
        fallbackRecovery: Boolean = false,
    ): Int

    /** Commits a staged preference and, when requested, installs its live resolver. Returns a DNS issue code on failure. */
    external fun nativeCommitDns(dns: String, staged: String, target: String, selectedId: Long, applyLive: Boolean): String?

    fun nativeCheckCachedDns(yaml: String, settings: String, nameserverPolicy: String = "null"): String? =
        nativeCheckCachedDnsForProfile(yaml, settings, nameserverPolicy, 0L)
    external fun nativeCheckCachedDnsForProfile(
        yaml: String, settings: String, nameserverPolicy: String, frozenProfileId: Long,
        fallbackTransition: Long = 0L, fallbackRecovery: Boolean = false,
    ): String?
    external fun nativeCheckFallbackGeoIp(): Boolean
    internal external fun nativeBeginFallbackGeoIpTransition(): Long
    internal external fun nativeStageFallbackGeoIpTransition(
        token: Long, previousProfileId: Long, previousNeedsReader: Boolean,
        candidateProfileId: Long, settings: String, nameserverPolicy: String,
    ): Long
    internal external fun nativeDiscardFallbackGeoIpTransition(token: Long)

    /** Applied DNS status with redacted endpoint details. */
    external fun nativeDnsStatus(): String?

    /**
     * Whether the VPN routes IPv6 for the running engine's profile: off only
     * for an explicit `ipv6: false`, as in mihomo. False when it is stopped.
     */
    external fun nativeTunIpv6(): Boolean
    /** Overrides the top-level IPv6 key in a runtime copy of the profile. */
    external fun nativeOverrideIpv6(yaml: String, enabled: Boolean): String

    /** Checks the merged authored DNS shape without probing a resolver. */
    external fun nativeSourceDnsRequiresBuiltin(yaml: String): Boolean
    external fun nativeOverrideFakeIpFilter(yaml: String, options: String, builtinDns: Boolean): String
    external fun nativeOverrideDnsHosts(yaml: String, options: String, builtinDns: Boolean): String
    /** Applies the typed core behavior choices to the runtime copy. */
    external fun nativeOverrideCoreBehavior(yaml: String, options: String): String

    /** Startup values from the profile, without using the network. */
    external fun nativePreviewProfileOverrides(yaml: String): String?

    /** Profile IPv6 for the preview: 0 off, 1 on, -1 unset, -2 unreadable. */
    external fun nativeProfileIpv6(yaml: String): Int

    external fun nativeStopEngine()
    external fun nativeStartTun2Socks(
        vpnService: Any,
        fd: Int,
        dnsPort: Int,
        overlayRoot: String,
        overlaySettings: String,
        blockAppUdp443: Boolean,
    ): Int
    /** Stop the forwarding stack only; keep the live engine and controller. Off Main. */
    external fun nativeStopTun2Socks(): Boolean
    external fun nativeIsRunning(): Boolean
    external fun nativeGetUploadTraffic(): Long
    external fun nativeGetDownloadTraffic(): Long
    external fun nativeValidateConfig(yaml: String, dns: String, nameserverPolicy: String = "null"): Int
    external fun nativeValidateProfileStructure(yaml: String): Int
    external fun nativeGetLastError(): String
    external fun nativeVersion(): String
    external fun nativeGetLogs(): String
    external fun nativeTestDirectTcp(host: String, port: Int): String
    external fun nativeTestDnsResolver(dnsAddr: String): String

    /**
     * Runs one proxy-detail probe through [proxy] (empty: wherever the
     * engine's routing sends it) and returns its JSON answer, blocking until
     * it ends; null only when the JVM could not take the answer.
     * [nativeCancelProxyProbe] with the same [id] ends it early.
     */
    external fun nativeProbeProxy(id: Long, proxy: String, kind: String, arg: String): String?
    external fun nativeCancelProxyProbe(id: Long)

    /**
     * Where [ip] is registered, from the GeoX databases in [dir] (the engine
     * home): `{"country": "CN", "asn": 136958, "org": "…"}`, leaving out what
     * they do not know. Offline; needs no running engine. Null only when the
     * JVM could not take the answer.
     */
    external fun nativeLookupIp(dir: String, ip: String): String?

    /**
     * A page of the engine's logbook in [dir] (the engine home), newest
     * first: `{"entries": [...], "rev": 7, "more": true}`, or
     * `{"error": "…"}`. [before] pages back from an entry id, [since] polls
     * for what was written after a page's `rev`, 0 leaving either unset;
     * [limit] 0 is the engine's default page; [level] is the lowest level
     * returned, [kind] a kind or its area (`config` matches `config.reload`),
     * empty for all. Read-only and offline: needs no running engine. Null
     * only when the JVM could not take the answer.
     */
    external fun nativeReadLogbook(
        dir: String,
        before: Long,
        since: Long,
        limit: Int,
        level: String,
        kind: String,
    ): String?

    /**
     * The engine's traffic ledger in [dir] (the engine home) for the local
     * days [from] to [to] (`LocalDate.toEpochDay()`, both included), grouped
     * [by] `host`, `app`, `policy` or `interface`, largest first, keeping
     * the rows whose [host], [app], [policy] and [iface] match, empty for
     * any:
     * `{"from": "2026-11-01", "to": "2026-11-30", "upload": n, "download": n,
     * "requests": n, "rows": [{"name": "…", "upload": n, …}]}`, or
     * `{"error": "…"}`. Read-only and offline: needs no running engine. Null
     * only when the JVM could not take the answer.
     */
    external fun nativeReadTraffic(
        dir: String,
        from: Int,
        to: Int,
        by: String,
        host: String,
        app: String,
        policy: String,
        iface: String,
    ): String?

    /** Deletes everything in the traffic ledger in [dir] (the engine home); false when it could not. */
    external fun nativeClearTraffic(dir: String): Boolean

    /**
     * The network the engine's traffic goes out on, as the traffic ledger
     * labels it (`Wi-Fi`, `Cellular`, `Ethernet`, `Other`). Kept until the
     * next call, across engine restarts in this process.
     */
    external fun nativeSetTrafficInterface(label: String)

    /**
     * The device's time zone for the traffic ledger's days: the UTC offset
     * now, in seconds, and its next change — at the Unix second [nextAt]
     * (0 for none) to [nextOffset].
     */
    external fun nativeSetTimeZone(offset: Int, nextAt: Long, nextOffset: Int)

    /**
     * Records a `network.change` entry in the engine's logbook: [message]
     * is one English sentence, [fields] a JSON object of its details, and
     * [warning] picks the level over info. Dropped while no engine has
     * started in this process or its profile turned the logbook off.
     */
    external fun nativeRecordNetworkChange(warning: Boolean, message: String, fields: String)

    /**
     * The network the engine's sockets go out on changed to [network]
     * (`Wi-Fi 324`): closes the engine's connections and UDP sessions, drops
     * its pooled DNS upstream connections and resets its proxies' pooled
     * sessions, in the background, and records it as a `network.change`.
     * Returns at once; nothing happens while no engine runs.
     */
    external fun nativeResetOutbound(network: String)
}
