package io.github.madeye.meow.bg

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Network
import android.net.DnsResolver
import android.os.Build
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import androidx.core.content.ContextCompat
import io.github.madeye.meow.Core
import io.github.madeye.meow.core.BuildConfig
import io.github.madeye.meow.core.MeowCore
import io.github.madeye.meow.diagnostics.FaultDiagnostics
import io.github.madeye.meow.diagnostics.FaultKind
import io.github.madeye.meow.diagnostics.FaultProcess
import io.github.madeye.meow.preference.DataStore
import io.github.madeye.meow.preference.PerAppConfigStore
import io.github.madeye.meow.repo.PerAppMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import timber.log.Timber
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import android.net.VpnService as BaseVpnService

class VpnService : BaseVpnService(), BaseService.Interface {
    companion object {
        private const val VPN_MTU = 1500

        /** `android.os.Process.INVALID_UID`, a constant that only exists from API 29. */
        private const val INVALID_UID = -1

        /**
         * Starts the VPN. The caller must already hold VPN consent
         * ([android.net.VpnService.prepare] returned null); without it the
         * service just stops itself again.
         *
         * startForegroundService rather than startService, so callers that
         * are not on screen (a Quick Settings tile, the service restarting
         * itself) work too: an app holding VPN consent is exempt from the
         * background foreground-service start restriction, and the service
         * answers the call with startForeground() on every path. A background
         * caller with no such exemption gets an IllegalStateException
         * (ForegroundServiceStartNotAllowedException on Android 12+).
         *
         * False when the system could not launch the `:vpn` process for the
         * service: AMS reports any such failure as "Unable to start service
         * …: process is bad", thrown in the caller as a SecurityException.
         */
        fun start(context: Context): Boolean = try {
            ContextCompat.startForegroundService(context, Intent(context, VpnService::class.java))
            true
        } catch (e: SecurityException) {
            // Uncaught it took down the caller, the UI process (#119). The VPN
            // just stays Stopped; the caller tells the user. IllegalState keeps
            // propagating: the QS tile's activity fallback depends on it.
            Timber.w(e, "VpnService: start refused")
            false
        }
    }

    inner class NullConnectionException : NullPointerException(), BaseService.ExpectedException {
        override fun getLocalizedMessage() = "Reboot required"
    }

    override val data = BaseService.Data(this)
    override val tag: String get() = "MeowVpnService"
    override fun createNotification(): ServiceNotification =
        ServiceNotification(this)

    private var conn: ParcelFileDescriptor? = null
    private val tunChanges = Mutex()
    private var tunPlan: TunPlan? = null
    private var meowForwarding = true
    private var overlayApplyUnknown = false

    private var metered = false
    private var networkChanges: NetworkChangeRecorder? = null
    /** Keeps the declared underlying network current, below API 29 only. */
    private var underlying: DefaultNetwork? = null
    private val directNetwork: Network? get() = data.meowInstance?.physicalNetwork

    override fun onBind(intent: Intent) = when (intent.action) {
        SERVICE_INTERFACE -> super<BaseVpnService>.onBind(intent)
        else -> super<BaseService.Interface>.onBind(intent)
    }

    /** Native worker stopped without a shutdown request. Do not forward exception text. */
    @androidx.annotation.Keep
    fun recordUnexpectedTunExit(code: Int) {
        FaultDiagnostics.record(FaultProcess.VPN, FaultKind.TUN_EXIT, code)
    }

    override fun onRevoke() = stopRunner()

    override suspend fun killProcesses(scope: CoroutineScope) = tunChanges.withLock {
        underlying?.stop()
        underlying = null
        networkChanges?.stop()
        networkChanges = null
        super.killProcesses(scope)
        closeTun(conn)
        conn = null
        tunPlan = null
        overlayApplyUnknown = false
        meowForwarding = true
        data.setForwarding(0)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int =
        super<BaseService.Interface>.onStartCommand(intent, flags, startId)

    override suspend fun preInit() {
        if (prepare(this) != null) throw NullConnectionException()
    }

    override suspend fun startProcesses() {
        val configDir = File(Core.deviceStorage.noBackupFilesDir, "meow")
        configDir.mkdirs()
        data.meowInstance!!.start(configDir, this)
        startVpn()
    }

    override val isVpnService get() = true

    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }

    /**
     * The uid of the app that owns one tunnelled flow, or
     * [INVALID_UID] when the system cannot tell (Android 9 and older
     * have no such query). Called over JNI from the FFI's owner.rs, on a
     * worker thread, for each new TCP connection and UDP session;
     * [localAddr] / [remoteAddr] are the app socket's raw IPv4 or IPv6
     * address bytes.
     */
    fun connectionOwnerUid(
        protocol: Int,
        localAddr: ByteArray,
        localPort: Int,
        remoteAddr: ByteArray,
        remotePort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return INVALID_UID
        return try {
            connectivity.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(InetAddress.getByAddress(localAddr), localPort),
                InetSocketAddress(InetAddress.getByAddress(remoteAddr), remotePort),
            )
        } catch (_: Exception) {
            // Must not reach the native caller: SecurityException once this
            // service is no longer the active VPN, IllegalArgumentException for
            // a protocol the platform rejects.
            INVALID_UID
        }
    }

    /**
     * The first package installed under [uid], or null for uids no package
     * owns (root, system daemons). Called over JNI from the FFI's owner.rs,
     * which caches the answer per uid.
     */
    fun packageForUid(uid: Int): String? = packageManager.getPackagesForUid(uid)?.firstOrNull()

    @androidx.annotation.Keep
    fun packagesForOverlayUid(uid: Int): Array<String> =
        packageManager.getPackagesForUid(uid) ?: emptyArray()

    /** Protect only the explicit direct fallback, never routes under lockdown. */
    @androidx.annotation.Keep
    fun protectDirectSocket(fd: Int): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && !isLockdownEnabled && protect(fd)

    /** System DNS on the physical network, including the platform's Private DNS. */
    @androidx.annotation.Keep
    fun resolveDirectDns(query: ByteArray): ByteArray? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || isLockdownEnabled) return null
        if (query.size !in 12..4096) return null
        val network = directNetwork ?: return null
        val capabilities = connectivity.getNetworkCapabilities(network) ?: return null
        if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return null
        val signal = CancellationSignal()
        val result = CompletableFuture<ByteArray?>()
        return try {
            DnsResolver.getInstance().rawQuery(
                network, query, DnsResolver.FLAG_EMPTY, { it.run() }, signal,
                object : DnsResolver.Callback<ByteArray> {
                    override fun onAnswer(answer: ByteArray, rcode: Int) {
                        result.complete(answer.takeIf { it.size in 12..4096 })
                    }
                    override fun onError(error: DnsResolver.DnsException) {
                        result.complete(null)
                    }
                },
            )
            val answer = result.get(3, TimeUnit.SECONDS)
            answer.takeIf { !isLockdownEnabled && directNetwork == network }
        } catch (_: Exception) {
            null
        } finally {
            signal.cancel()
        }
    }

    /**
     * Snapshot directly attached IPv4 networks before establishing our own VPN.
     * Default routes and the gateway's remote routes are not local subnets.
     */
    private fun overlayConfig(reconfiguring: Boolean): JSONObject {
        if (!BuildConfig.ZEROTIER) return JSONObject()
        val settings = OverlayPlatform.configText() ?: return JSONObject()
        val config = JSONObject(settings).apply { remove("saved_networks") }
        if (!config.optBoolean("enabled")) return config
        val network = directNetwork ?: connectivity.activeNetwork
        val capabilities = network?.let(connectivity::getNetworkCapabilities)
        // Do not rebuild the local-LAN exclusions from the VPN itself if the
        // physical network has yet to be reported on a live session.
        check(!reconfiguring || capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true) {
            "Physical network has not been identified"
        }
        val localRoutes = if (capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true) {
            connectivity.getLinkProperties(network)?.routes.orEmpty()
                .filter { !it.hasGateway() && it.destination.address is Inet4Address && it.destination.prefixLength > 0 }
                .map { it.destination.toString() }
                .distinct()
        } else emptyList()
        return config.put("local_cidrs", JSONArray(localRoutes))
    }

    private fun buildPlan(reconfiguring: Boolean = false): TunPlan {
        val overlayConfig = overlayConfig(reconfiguring)
        // Per-app VPN routing — the file store is authoritative: this process
        // caches SharedPreferences for its whole lifetime, so edits saved
        // after the first establish would never reach the next one. A file
        // holding a mode this build does not know is treated like a missing
        // one: the prefs keys are written alongside every save and stand in.
        val perApp = PerAppConfigStore.default.load()
            ?.takeIf { PerAppMode.from(it.mode) != null }
        val perAppPackages: Set<String> = perApp?.packages ?: try {
            JSONArray(DataStore.perAppPackages).let { arr ->
                (0 until arr.length()).map { arr.getString(it) }.toSet()
            }
        } catch (_: Exception) { emptySet() }
        val perAppMode = perApp?.mode ?: DataStore.perAppMode

        // Note: we deliberately do NOT add the meow package to
        // `addDisallowedApplication` here. The engine and tun2socks run in
        // the `:vpn` process and rely on `VpnService.protect(fd)` (called
        // from the patched meow-proxy connect hook and the meow-dns
        // SocketFactory) to bypass the TUN on a per-socket basis. Excluding
        // the whole app's uid would also exempt traffic users may want to
        // intercept (e.g. a built-in browser preview) and would shadow the
        // protect path the rest of the stack is designed around.
        val clash = VpnAppCapture.fromClash(PerAppMode.from(perAppMode), perAppPackages)
        val capture = if (overlayConfig.optBoolean("enabled")) {
            val mode = overlayConfig.getString("app_mode")
            require(mode in setOf("all", "allow", "exclude")) { "Invalid ZeroTier app policy" }
            val overlayPackages = overlayConfig.optJSONArray("packages")?.let { list ->
                (0 until list.length()).map { list.getString(it) }.toSet()
            }.orEmpty()
            val overlay = VpnAppCapture(mode, overlayPackages)
            check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ||
                    (clash.mode == "all" && (overlay.mode == "all" ||
                        (overlay.mode == "exclude" && overlay.packages.isEmpty())))) {
                "Separate VPN app rules need Android 10 or later"
            }
            overlayConfig.put("clash_app_mode", clash.mode)
                .put("clash_packages", JSONArray(clash.packages))
            clash.union(overlay)
        } else clash

        val instance = checkNotNull(data.meowInstance)
        return TunPlan(
            envelope = TunEnvelope(capture, instance.tunIpv6(), metered),
            overlayEnabled = overlayConfig.optBoolean("enabled"),
            overlayJson = overlayConfig.toString(),
            dnsHijacking = instance.dnsHijacking,
        )
    }

    private fun establish(plan: TunPlan): ParcelFileDescriptor {
        val builder = Builder()
            .setSession("Meow VPN")
            .setMtu(VPN_MTU)
        configureVpnIp(plan.envelope.ipv6, builder::addAddress, builder::addRoute, builder::addDnsServer)
        val capture = plan.envelope.capture
        when (capture.mode) {
            "exclude" -> for (pkg in capture.packages) {
                try { builder.addDisallowedApplication(pkg) }
                catch (_: android.content.pm.PackageManager.NameNotFoundException) { }
            }
            "allow" -> {
                var installed = 0
                for (pkg in capture.packages) {
                    try {
                        builder.addAllowedApplication(pkg)
                        installed++
                    } catch (_: android.content.pm.PackageManager.NameNotFoundException) { }
                }
                // Android interprets an empty Builder allowlist as all apps.
                check(installed > 0) { "None of the selected VPN apps are installed" }
            }
        }

        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(plan.envelope.metered)
        return builder.establish() ?: throw NullConnectionException()
    }

    private fun closeTun(fd: ParcelFileDescriptor?) {
        if (fd == null) return
        try {
            fd.close()
        } catch (e: java.io.IOException) {
            Timber.w(e, "VPN interface close failed")
        }
    }

    private suspend fun attachTun(fd: ParcelFileDescriptor, plan: TunPlan) {
        val instance = checkNotNull(data.meowInstance)
        val nativeConfig = plan.nativeConfig(meowForwarding)
        withContext(Dispatchers.IO) {
            instance.startTun2Socks(this@VpnService, fd.fd, nativeConfig)
        }
    }

    private fun publishForwarding() {
        val plan = tunPlan
        val meow = if (plan != null && meowForwarding && data.meowInstance?.profile?.id != 0L)
            ForwardingControl.MEOW else 0
        val overlay = if (!overlayApplyUnknown && plan?.overlayEnabled == true) ForwardingControl.ZEROTIER else 0
        data.setForwarding(meow or overlay)
    }

    private suspend fun startVpn() = tunChanges.withLock {
        meowForwarding = true
        overlayApplyUnknown = false
        val plan = buildPlan()
        val fd = establish(plan)
        conn = fd
        attachTun(fd, plan)
        tunPlan = plan
        publishForwarding()
        // Records in the logbook which network the VPN sits on, and what the
        // apps on it are told, as the networks change.
        networkChanges?.stop()
        val networkChanges = NetworkChangeRecorder(this).also { it.start() }
        this.networkChanges = networkChanges
        // The underlying network. From API 29 a VPN that declares none sits on
        // the default network and follows it, its capabilities included; one
        // it declares is what Android answers the apps on it with
        // (getActiveNetworkInfo), even once that network is gone. A VPN that
        // declared the Wi-Fi it then left had the apps believe they were
        // offline until it restarted. Below API 29 nothing is followed, so
        // the declaration follows the default network instead, as
        // Clash Meta for Android does.
        underlying?.stop()
        underlying = if (Build.VERSION.SDK_INT < 29) {
            DefaultNetwork(this) { network, _ ->
                setUnderlyingNetworks(network?.let { arrayOf(it) })
                networkChanges.declare(network)
                Timber.d("VpnService: setUnderlyingNetworks=$network")
            }.also { it.start() }
        } else {
            null
        }
    }

    override suspend fun applyZeroTier(): Int = tunChanges.withLock {
        if (!BuildConfig.ZEROTIER) return@withLock ForwardingControl.OFFLINE
        if (data.state != BaseService.State.Connected) {
            return@withLock if (data.state == BaseService.State.Stopped)
                ForwardingControl.OFFLINE else ForwardingControl.FAILED
        }
        try {
            val proposed = buildPlan(reconfiguring = true)
            if (!proposed.overlayEnabled && (!meowForwarding || data.meowInstance?.profile?.id == 0L)) {
                // There is no remaining tunnel to keep available.
                stopRunner()
                return@withLock ForwardingControl.STOPPED
            }
            val old = tunPlan
            if (!overlayApplyUnknown && proposed == old) return@withLock ForwardingControl.APPLIED
            val replaceInterface = old == null || old.envelope.requiresNewInterface(proposed.envelope)
            if (!replaceInterface && !overlayApplyUnknown) {
                when (withContext(Dispatchers.IO) {
                    OverlayPlatform.apply(proposed.nativeConfig(meowForwarding))
                }) {
                    0 -> {
                        tunPlan = proposed
                        publishForwarding()
                        return@withLock ForwardingControl.APPLIED
                    }
                    1 -> Unit // same interface, native forwarding only needs rebuilding
                    -2 -> {
                        // Native began a transition but has not acknowledged it.
                        // Meow remains independently live; don't guess the ZT state.
                        overlayApplyUnknown = true
                        publishForwarding()
                        return@withLock ForwardingControl.INDETERMINATE
                    }
                    else -> return@withLock ForwardingControl.FAILED
                }
            }
            replaceForwarding(old, proposed, replaceInterface)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "applying ZeroTier settings failed")
            ForwardingControl.FAILED
        }
    }

    /** Rebind a data-plane only; never recreate MeowInstance or its controller.
     * If establishment fails, the old VPN still works. Once Android has installed
     * a replacement, keep it open even on attach error (fail closed) until a
     * recovery plan can bind forwarding again or the user stops the master VPN.
     */
    private suspend fun replaceForwarding(old: TunPlan?, proposed: TunPlan, replaceInterface: Boolean): Int {
        val previousFd = conn
        val nextFd = if (replaceInterface || previousFd == null) establish(proposed) else previousFd
        conn = nextFd
        // The native stack owns a duplicate of its fd. A timed-out shutdown
        // cannot write through an Android fd integer reused by the replacement.
        val stopped = withContext(Dispatchers.IO) { MeowCore.nativeStopTun2Socks() }
        if (previousFd !== nextFd) closeTun(previousFd)
        if (!stopped) {
            tunPlan = null
            publishForwarding()
            return ForwardingControl.FAILED
        }
        tunPlan = null
        try {
            attachTun(nextFd, proposed)
            tunPlan = proposed
            overlayApplyUnknown = false
            publishForwarding()
            return ForwardingControl.REBUILT
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "new VPN forwarding failed; restoring previous plan")
        }
        if (old != null && !overlayApplyUnknown) {
            try {
                val recovery = if (replaceInterface) establish(old) else nextFd
                conn = recovery
                if (recovery !== nextFd) closeTun(nextFd)
                attachTun(recovery, old)
                tunPlan = old
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w(e, "previous forwarding could not be restored")
            }
        }
        publishForwarding()
        return ForwardingControl.FAILED
    }

    override suspend fun setMeowForwarding(enabled: Boolean): Int = tunChanges.withLock {
        if (!BuildConfig.ZEROTIER) return@withLock ForwardingControl.OFFLINE
        val plan = tunPlan
        if (data.state != BaseService.State.Connected || overlayApplyUnknown || plan?.overlayEnabled != true ||
            data.meowInstance?.profile?.id == 0L
        ) return@withLock ForwardingControl.OFFLINE
        if (meowForwarding == enabled) return@withLock ForwardingControl.APPLIED
        if (withContext(Dispatchers.IO) { OverlayPlatform.setMeowForwarding(enabled) } != 0) {
            return@withLock ForwardingControl.FAILED
        }
        meowForwarding = enabled
        publishForwarding()
        ForwardingControl.APPLIED
    }

    override fun onDestroy() {
        super.onDestroy()
        data.binder.close()
    }
}
