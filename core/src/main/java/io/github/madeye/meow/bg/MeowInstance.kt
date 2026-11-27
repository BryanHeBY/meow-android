package io.github.madeye.meow.bg

import android.content.Context
import android.net.Network
import io.github.madeye.meow.Core
import io.github.madeye.meow.aidl.ControllerEndpoint
import io.github.madeye.meow.aidl.SessionStats
import io.github.madeye.meow.aidl.TrafficStats
import io.github.madeye.meow.core.MeowCore
import io.github.madeye.meow.database.ClashProfile
import io.github.madeye.meow.preference.ConfigurationOverride
import io.github.madeye.meow.preference.ConfigurationOverrideStore
import io.github.madeye.meow.preference.CoreBehaviorRuntime
import io.github.madeye.meow.preference.DnsHostsRuntime
import io.github.madeye.meow.preference.DnsIssue
import io.github.madeye.meow.preference.DnsSettings
import io.github.madeye.meow.preference.DnsSettingsStore
import io.github.madeye.meow.preference.Ipv6Override
import io.github.madeye.meow.preference.RouteModeStore
import io.github.madeye.meow.traffic.TrafficNetwork
import java.io.File
import java.security.SecureRandom
import java.time.Instant
import java.time.ZoneId
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber

internal class DnsActivationException(val issue: DnsIssue) : RuntimeException(issue.message)

class MeowInstance(profile: ClashProfile) {
    val profile = profile.copy()
    val activeConfig = requireNotNull(ActiveConfig.of(this.profile))
    val profileName: String get() = profile.name
    @Volatile internal var appliedDns: DnsSettings? = null
    @Volatile internal var appliedOverride: ConfigurationOverride? = null

    companion object {
        private val random by lazy { SecureRandom() }

        private fun mintCredential(): String =
            ByteArray(32).also(random::nextBytes).joinToString("") { String.format(Locale.US, "%02x", it) }

        /// The engine home dir (`.../no_backup/meow`). meow-rs resolves
        /// geodata at `$XDG_CONFIG_HOME/meow/Country.mmdb`, i.e. relative to
        /// this dir's parent.
        fun homeDir(context: Context): File =
            File(Core.deviceStorage.noBackupFilesDir, "meow").apply { mkdirs() }

        /// Seed bundled GeoX databases and register the home dir with meow-rs
        /// (which also sets `XDG_CONFIG_HOME`). Idempotent and cheap on repeat
        /// calls. Needed before [MeowCore.nativeValidateConfig] so config
        /// validation (YAML editor, config import) can load the GeoIP DB even
        /// when the VPN has never been started this process.
        fun prepareEngineHome(context: Context): File {
            val dir = homeDir(context)
            copyGeoxAssets(context, dir)
            MeowCore.nativeSetHomeDir(dir.absolutePath)
            return dir
        }

        // Copy bundled GeoX databases from APK assets into the engine home
        // dir. Skips files that already exist (cached from a prior start).
        // Asset names follow the upstream release naming; targets follow
        // meow-rs's discovery names (`Country.mmdb` with capital C, see
        // meow_config::default_geoip_path).
        private fun copyGeoxAssets(context: Context, configDir: File) {
            val files = listOf(
                "country.mmdb" to "Country.mmdb",
                "GeoLite2-ASN.mmdb" to "GeoLite2-ASN.mmdb",
            )
            for ((assetName, targetName) in files) {
                val target = File(configDir, targetName)
                if (target.exists() && target.length() > 0) continue
                try {
                    context.assets.open("geox/$assetName").use { input ->
                        target.outputStream().use { output -> input.copyTo(output) }
                    }
                    Timber.d("MeowInstance: seeded $targetName from assets (${target.length()} bytes)")
                } catch (e: Exception) {
                    Timber.w(e, "MeowInstance: failed to seed $targetName from assets")
                }
            }
        }
    }

    private var blockAppUdp443 = false

    private var prevTx: Long = 0
    private var prevRx: Long = 0
    private var lastUpdate: Long = 0

    // Set once the engine is up, for the Statistics screen; see sessionStats.
    @Volatile private var meter: NetworkTrafficMeter? = null
    private var networks: DefaultNetwork? = null
    @Volatile internal var physicalNetwork: Network? = null
        private set
    internal var controllerEndpoint: ControllerEndpoint? = null
        private set

    // JNI startup blocks while loading remote proxy/rule providers. Keep it
    // off the service's main thread so lifecycle callbacks remain responsive.
    // Await completion before establishing the TUN; cancellation still waits
    // for native startup to unwind before BaseService tears the engine down.
    suspend fun start(configDir: File, context: Context) = withContext(Dispatchers.IO) {
        // Seed the engine home dir with bundled GeoX databases so meow-rs
        // never has to reach the network on first start — the upstream
        // pre-VPN fetch in meow-config goes via raw github.com which is
        // unreliable on censored / metered links. APK assets are populated
        // at build time by the `:core:downloadGeoxAssets` Gradle task.
        copyGeoxAssets(context, configDir)
        // Note: nativeSetHomeDir is also called below; prepareEngineHome and
        // this start() path share copyGeoxAssets via the companion object.

        val configFile = File(configDir, "config.yaml")
        // Runtime-only stripping and DNS injection run in the core for both
        // the cached candidate check and the engine load.
        val yaml = activeConfig.yaml
        // A DNS rollback restores the previous engine snapshot. A normal start
        // reads the next-start overrides once, before applying any of them.
        val override = appliedOverride ?: ConfigurationOverrideStore.default.effective(profile.id.takeIf { it > 0 })
        blockAppUdp443 = override.blocksAppUdp443
        val runtimeYaml = when (override.ipv6) {
            Ipv6Override.INHERIT -> yaml
            Ipv6Override.FORCE_ON -> MeowCore.nativeOverrideIpv6(yaml, true)
            Ipv6Override.FORCE_OFF -> MeowCore.nativeOverrideIpv6(yaml, false)
        }
        // The shared user route-mode pick overrides the profile's `mode:`; empty
        // follows the profile.
        val routeMode = RouteModeStore.default.load()?.wire.orEmpty()
        val capability = mintCredential()
        // Before the start, so the traffic ledger counts days in the
        // device's zone from its first flush.
        pushTimeZone()
        DnsSettingsStore.default.withSavedValue { saved ->
            val dns = appliedDns ?: saved
            val selected = activeConfig.takeIf { it.profileId > 0 }
            val issue = DnsSettingsStore.default.activationIssue(dns, selected, MeowCore::nativeCheckCachedDns)
            if (issue != null) throw DnsActivationException(issue)
            val withCore = CoreBehaviorRuntime.apply(runtimeYaml, override.coreBehavior)
            configFile.writeText(DnsHostsRuntime.apply(withCore, override.dnsHosts))
            MeowCore.nativeSetHomeDir(configDir.absolutePath)
            val port = MeowCore.nativeStartEngine(
                "127.0.0.1:9090", mintCredential(), routeMode, dns.encode(), activeConfig.profileId, capability,
            )
            if (port <= 0) {
                val error = MeowCore.nativeGetLastError()
                DnsIssue.entries.firstOrNull { it.name == error }?.let { throw DnsActivationException(it) }
                throw RuntimeException("Failed to start engine: $error")
            }
            appliedDns = dns
            appliedOverride = override
            controllerEndpoint = ControllerEndpoint(port, capability)
        }
        val meter = NetworkTrafficMeter(startedAt = System.currentTimeMillis())
        var outbound: Network? = null
        networks = DefaultNetwork(context) { network, capabilities ->
            physicalNetwork = network.takeIf {
                capabilities?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true
            }
            // Every network change also re-reads the zone: one that moves
            // the device to another is, more often than not, a trip.
            pushTimeZone()
            if (network != null) {
                MeowCore.nativeSetTrafficInterface(capabilities?.ledgerLabel() ?: TrafficNetwork.OTHER)
            }
            meter.onNetwork(
                capabilities?.trafficKind(),
                MeowCore.nativeGetUploadTraffic(),
                MeowCore.nativeGetDownloadTraffic(),
            )
            if (network == null) return@DefaultNetwork
            // What the engine opened on the network before (connections,
            // pooled and QUIC sessions, DNS upstreams) is cut off with it or
            // left on a network no longer in use: it is torn down for the
            // apps and the engine to redial, as FlClash does.
            if (outbound != null && network != outbound) {
                MeowCore.nativeResetOutbound(network.describe(capabilities))
            }
            outbound = network
        }.also { it.start() }
        this@MeowInstance.meter = meter
        Timber.d("MeowInstance: engine started")
    }

    /** Tells the engine's traffic ledger which day it is where the device is. */
    private fun pushTimeZone() {
        val now = Instant.now()
        val rules = ZoneId.systemDefault().rules
        val next = rules.nextTransition(now)
        MeowCore.nativeSetTimeZone(
            rules.getOffset(now).totalSeconds,
            next?.toEpochSecond() ?: 0L,
            next?.offsetAfter?.totalSeconds ?: 0,
        )
    }

    /** Whether the started engine's profile lets the VPN carry IPv6. */
    fun tunIpv6(): Boolean = MeowCore.nativeTunIpv6()

    fun startTun2Socks(vpnService: android.net.VpnService, fd: Int, overlayConfig: String) {
        val result = MeowCore.nativeStartTun2Socks(
            vpnService, fd, 1053, OverlayPlatform.rootPath(), overlayConfig, blockAppUdp443,
        )
        if (result != 0) {
            throw RuntimeException("Failed to start tun2socks: ${MeowCore.nativeGetLastError()}")
        }
        Timber.d("MeowInstance: tun2socks started")
    }

    fun stop() {
        networks?.stop()
        networks = null
        physicalNetwork = null
        meter = null
        controllerEndpoint = null
        MeowCore.nativeStopEngine()
        Timber.d("MeowInstance: engine stopped")
    }

    /** The session so far, or null until the engine is up. Any thread. */
    fun sessionStats(): SessionStats? =
        meter?.read(MeowCore.nativeGetUploadTraffic(), MeowCore.nativeGetDownloadTraffic())

    fun requestTrafficUpdate(): TrafficStats {
        val tx = MeowCore.nativeGetUploadTraffic()
        val rx = MeowCore.nativeGetDownloadTraffic()
        val now = System.currentTimeMillis()
        val elapsed = if (lastUpdate > 0) now - lastUpdate else 1000L
        val stats = TrafficStats(
            txRate = if (elapsed > 0) (tx - prevTx) * 1000 / elapsed else 0,
            rxRate = if (elapsed > 0) (rx - prevRx) * 1000 / elapsed else 0,
            txTotal = tx,
            rxTotal = rx,
        )
        prevTx = tx
        prevRx = rx
        lastUpdate = now
        return stats
    }
}
