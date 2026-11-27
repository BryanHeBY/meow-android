package io.github.madeye.meow.bg

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.IBinder
import android.os.RemoteCallbackList
import android.os.RemoteException
import androidx.core.content.ContextCompat
import io.github.madeye.meow.Core
import io.github.madeye.meow.core.BuildConfig
import io.github.madeye.meow.aidl.IMeowService
import io.github.madeye.meow.aidl.IMeowServiceCallback
import io.github.madeye.meow.aidl.SessionStats
import io.github.madeye.meow.aidl.TrafficStats
import io.github.madeye.meow.aidl.VpnServiceSnapshot
import io.github.madeye.meow.core.MeowCore
import io.github.madeye.meow.preference.DnsApplicability
import io.github.madeye.meow.preference.DnsIssue
import io.github.madeye.meow.preference.DnsStatus
import io.github.madeye.meow.preference.ConfigurationOverride
import io.github.madeye.meow.preference.ConfigurationOverrideStore
import io.github.madeye.meow.preference.DnsSettings
import io.github.madeye.meow.preference.DnsSettingsStore
import io.github.madeye.meow.database.ClashProfile
import io.github.madeye.meow.database.PrivateDatabase
import io.github.madeye.meow.utils.Action
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import timber.log.Timber

object BaseService {
    enum class State(val canStop: Boolean = false) {
        Idle,
        Connecting(true),
        Connected(true),
        Stopping,
        Stopped,
    }

    private val _localState = MutableStateFlow(State.Stopped)

    /**
     * The state of the service in *this* process, observable without binding.
     * Only `:vpn` hosts the service, so only code running there can use it:
     * the Quick Settings tile is declared in `:vpn` for exactly this. Any
     * other process must go through the binder
     * ([io.github.madeye.meow.aidl.MeowConnection]).
     */
    val localState: StateFlow<State> = _localState.asStateFlow()

    interface ExpectedException

    internal class Reload(
        val profile: ClashProfile,
        val previous: MeowInstance,
        val candidateDns: DnsSettings,
        val candidateOverride: ConfigurationOverride,
        val previousDns: DnsSettings?,
        val previousOverride: ConfigurationOverride?,
        val fallbackTransition: Long,
    ) {
        fun discard() {
            if (fallbackTransition > 0) MeowCore.nativeDiscardFallbackGeoIpTransition(fallbackTransition)
        }
    }

    internal class DnsRejection(val selection: ActiveConfig?, val issue: DnsIssue)

    class Data internal constructor(private val service: Interface) {
        @Volatile var lifecycle = VpnServiceSnapshot(State.Stopped.ordinal)
            private set
        val state: State get() = State.entries[lifecycle.state]
        @Volatile var meowInstance: MeowInstance? = null
        var notification: ServiceNotification? = null
        var closeReceiverRegistered = false
        @Volatile var forwardingFlags = 0
            private set
        val binder = Binder(this, service)

        fun setForwarding(flags: Int) {
            if (forwardingFlags == flags) return
            forwardingFlags = flags
            binder.forwardingChanged(flags)
        }
        var connectingJob: Job? = null
        var restartAfterStop = false
        internal var reload: Reload? = null
        internal var reloadCheck: Job? = null
        @Volatile internal var dnsRejection: DnsRejection? = null
        @Volatile internal var dnsSaveRejection: DnsRejection? = null

        /**
         * A reload arrived mid-start; [Interface.reloadIfChanged] runs again
         * once connected. A stale flag from a start that failed is harmless:
         * the check compares against what the next start actually read.
         */
        var reloadPending = false

        val closeReceiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SHUTDOWN -> {}
                    Action.RELOAD -> service.reloadIfChanged()
                    else -> service.stopRunner()
                }
            }
        }

        fun changeState(s: State, msg: String? = null) {
            if (state == s && msg == null) return
            val profile = meowInstance?.profile
            val next = VpnServiceSnapshot(
                state = s.ordinal,
                revision = lifecycle.revision + 1,
                runId = when (s) {
                    State.Connecting -> java.util.UUID.randomUUID().toString()
                    State.Stopped, State.Idle -> null
                    else -> lifecycle.runId
                },
                profileId = profile?.id?.takeIf { it > 0 },
                profileName = profile?.name.orEmpty(),
                controller = if (s == State.Connected) {
                    checkNotNull(meowInstance?.controllerEndpoint) { "App controller was not started" }
                } else null,
            )
            lifecycle = next
            _localState.value = s
            binder.stateChanged(next, msg)
            notification?.onStateChanged(s)
        }
    }

    class Binder(
        @Volatile private var data: Data?,
        private val service: Interface,
    ) : IMeowService.Stub(), CoroutineScope, AutoCloseable {
        // RemoteCallbackList drops dead binders automatically; the parallel
        // bandwidthListeners map must mirror that. If a binder that died with
        // the app process stayed in the map, the 1 Hz traffic looper would
        // keep ticking for it and a later (re)registering listener would be
        // silently skipped by the isEmpty() guard — freezing traffic stats
        // until the service itself is destroyed.
        private val callbacks = object : RemoteCallbackList<IMeowServiceCallback>() {
            override fun onCallbackDied(callback: IMeowServiceCallback) {
                launch {
                    if (bandwidthListeners.remove(callback.asBinder()) != null &&
                        bandwidthListeners.isEmpty()
                    ) {
                        looper?.cancel()
                        looper = null
                    }
                }
            }
        }
        private val bandwidthListeners = mutableMapOf<IBinder, Long>()
        override val coroutineContext = Dispatchers.Main.immediate + Job()
        private var looper: Job? = null

        override fun getLifecycle(): VpnServiceSnapshot = data?.lifecycle ?: VpnServiceSnapshot(State.Idle.ordinal)

        override fun registerCallback(cb: IMeowServiceCallback) { callbacks.register(cb) }

        private fun broadcast(work: (IMeowServiceCallback) -> Unit) {
            val count = callbacks.beginBroadcast()
            try {
                repeat(count) {
                    try { work(callbacks.getBroadcastItem(it)) }
                    catch (_: RemoteException) {}
                    catch (e: Exception) { Timber.w(e) }
                }
            } finally { callbacks.finishBroadcast() }
        }

        private suspend fun loop() {
            while (true) {
                delay(bandwidthListeners.values.minOrNull() ?: return)
                val instance = data?.meowInstance ?: continue
                if (data?.state != State.Connected || bandwidthListeners.isEmpty()) continue
                val stats = instance.requestTrafficUpdate()
                broadcast { item ->
                    if (bandwidthListeners.contains(item.asBinder())) {
                        item.trafficUpdated(0, stats)
                    }
                }
            }
        }

        override fun startListeningForBandwidth(cb: IMeowServiceCallback, timeout: Long) {
            launch {
                // Always (re)register the listener — the previous guard only
                // added it when the map was empty, so after an app-process
                // restart the new binder was silently ignored while the stale
                // dead entry kept the looper running for nobody.
                bandwidthListeners[cb.asBinder()] = timeout
                if (looper?.isActive != true) {
                    looper = launch { loop() }
                }
            }
        }

        override fun stopListeningForBandwidth(cb: IMeowServiceCallback) {
            launch {
                if (bandwidthListeners.remove(cb.asBinder()) != null && bandwidthListeners.isEmpty()) {
                    looper?.cancel()
                    looper = null
                }
            }
        }

        override fun unregisterCallback(cb: IMeowServiceCallback) {
            stopListeningForBandwidth(cb)
            callbacks.unregister(cb)
        }

        // Runs on the calling binder thread, not Main: a probe blocks for as
        // long as it measures.
        override fun probeProxy(id: Long, proxy: String, kind: String, arg: String): String =
            MeowCore.nativeProbeProxy(id, proxy, kind, arg)
                ?: """{"error":"the probe returned no answer","code":"failed"}"""

        override fun cancelProxyProbe(id: Long) = MeowCore.nativeCancelProxyProbe(id)

        override fun setDnsSettings(settings: String, selectedId: Long): String? {
            val serviceData = data ?: return DnsIssue.SERVICE_UNAVAILABLE.name
            val state = serviceData.state
            val running = serviceData.meowInstance
            if (state == State.Connecting || state == State.Stopping) return DnsIssue.PROFILE_CHANGED.name
            val expected = selectedId.takeIf { it > 0 }
            val request = ActiveConfig.of(Core.currentProfile)
            val issue = DnsSettingsStore.default.commit(
                settings, expected, { ActiveConfig.of(Core.currentProfile) },
                { yaml, wire, policy ->
                    val frozenId = request?.profileId?.takeIf {
                        state == State.Connected && running?.activeConfig == request
                    } ?: 0L
                    MeowCore.nativeCheckCachedDnsForProfile(yaml, wire, policy, frozenId)
                },
                policyFor = { profile ->
                    if (state == State.Connected && running?.activeConfig == profile) {
                        running?.appliedOverride?.dnsWireOverride
                    } else {
                        ConfigurationOverrideStore.default.effective(profile.profileId).dnsWireOverride.also {
                            if (it.usesFallbackGeoIp) MeowInstance.prepareEngineHome(Core.app)
                        }
                    }
                },
                freshExplicitCountry = state != State.Connected || running?.activeConfig != request,
                frozenGeneration = serviceData.lifecycle.runId.takeIf {
                    state == State.Connected && running?.activeConfig == request
                },
            ) { selected, scoped, staged, target ->
                PrivateDatabase.withProfileTransaction {
                    if (ActiveConfig.of(Core.currentProfile) != selected || serviceData.state != state ||
                        serviceData.meowInstance !== running || data !== serviceData
                    ) {
                        DnsIssue.PROFILE_CHANGED
                    } else {
                        // A rejected reload can leave an older profile running. Save for
                        // the selection without rebuilding that older session's resolver.
                        val applyLive = state == State.Connected &&
                            (running?.activeConfig == selected || (selected == null && running?.activeConfig?.profileId == 0L))
                        val error = MeowCore.nativeCommitDns(
                            scoped.encode(), staged.absolutePath, target.absolutePath, selectedId, applyLive,
                        )?.let(DnsIssue::fromWire)
                        if (error == null && applyLive) running?.appliedDns = scoped
                        error
                    }
                }
            }
            serviceData.dnsSaveRejection = issue?.takeIf { request?.profileId == expected }
                ?.let { DnsRejection(request, it) }
            if (issue == null) launch {
                val rejected = serviceData.dnsRejection?.takeIf { it.selection == request }
                if (rejected != null) serviceData.dnsRejection = null
                if (rejected != null && serviceData.state == State.Connected) service.reloadIfChanged()
            }
            return issue?.name
        }

        override fun getDnsStatus(): String {
            val selected = ActiveConfig.of(Core.currentProfile)
            val store = DnsSettingsStore.default
            val saved = store.load()
            val native = MeowCore.nativeDnsStatus()?.let { Json.decodeFromString(DnsStatus.serializer(), it) }
                ?: DnsStatus()
            val rejection = data?.dnsRejection?.takeIf { it.selection == selected }?.issue
            val running = data?.meowInstance
            val frozenGeneration = data?.lifecycle?.runId.takeIf {
                data?.state == State.Connected && running?.activeConfig == selected
            }
            val issue = rejection ?: store.statusActivationIssue(saved.settings, selected, frozenGeneration, policyFor = { profile ->
                if (data?.state == State.Connected && running?.activeConfig == profile) {
                    running?.appliedOverride?.dnsWireOverride
                } else {
                    ConfigurationOverrideStore.default.effective(profile.profileId).dnsWireOverride.also {
                        if (it.usesFallbackGeoIp) MeowInstance.prepareEngineHome(Core.app)
                    }
                }
            }, validate = { yaml, wire, policy ->
                val frozenId = selected?.profileId?.takeIf {
                    data?.state == State.Connected && running?.activeConfig == selected
                } ?: 0L
                MeowCore.nativeCheckCachedDnsForProfile(yaml, wire, policy, frozenId)
            })
            val lastSave = data?.dnsSaveRejection?.takeIf { it.selection == selected }?.issue
            val scope = saved.settings.applicability(selected?.profileId)
            val applicability = when {
                issue == DnsIssue.SPLIT_UNAVAILABLE -> DnsApplicability.UNAVAILABLE
                scope != DnsApplicability.AVAILABLE -> scope
                issue != null -> DnsApplicability.UNAVAILABLE
                native.runningProfileId != selected?.profileId || data?.meowInstance?.activeConfig != selected ->
                    DnsApplicability.PENDING
                else -> DnsApplicability.AVAILABLE
            }
            return Json.encodeToString(DnsStatus.serializer(), native.copy(
                selectedProfileId = selected?.profileId,
                applicability = applicability,
                issue = issue ?: lastSave ?: DnsIssue.INVALID_SETTINGS.takeIf { saved.invalid },
            ))
        }

        // On the binder thread: two counter reads, nothing that blocks.
        override fun getSessionStats(): SessionStats? = data?.meowInstance?.sessionStats()

        override fun getForwardingFlags(): Int = data?.forwardingFlags ?: 0

        override fun applyZeroTier(): Int = dispatchChange { service.applyZeroTier() }

        override fun setMeowForwarding(enabled: Boolean): Int =
            dispatchChange { service.setMeowForwarding(enabled) }

        private fun dispatchChange(change: suspend () -> Int): Int =
            if (data == null) ForwardingControl.OFFLINE else runBlocking(Dispatchers.Main.immediate) {
                change()
            }

        fun forwardingChanged(flags: Int) = launch {
            broadcast { it.forwardingChanged(flags) }
        }

        fun dnsActivationRejected(issue: DnsIssue) = launch {
            broadcast { it.dnsActivationRejected(issue.name) }
        }

        fun stateChanged(snapshot: VpnServiceSnapshot, msg: String?) = launch {
            broadcast { it.stateChanged(snapshot, msg) }
        }

        override fun close() {
            callbacks.kill()
            cancel()
            data = null
        }
    }

    interface Interface {
        val data: Data
        val tag: String
        fun createNotification(): ServiceNotification

        fun onBind(intent: Intent): IBinder? =
            if (intent.action == Action.SERVICE) data.binder else null

        fun forceLoad() {
            val s = data.state
            when {
                s == State.Stopped -> startRunner()
                s.canStop -> stopRunner(true)
                else -> Timber.w("Illegal state $s when invoking use")
            }
        }

        /**
         * Handles [Action.RELOAD], which the UI sends after committing a
         * change to the selected profile (`vpn.ConfigReloader`). Unlike
         * [forceLoad] it never starts a stopped service, and it restarts only
         * if the selected profile now differs from the one this run started
         * with, so duplicate or cancelled-out requests cost nothing.
         *
         * The restart is [stopRunner]'s: the TUN goes down and comes back,
         * [onStartCommand] uses the checked selection snapshot,
         * [MeowInstance.start] replays the route mode from `RouteModeStore`,
         * and the engine restores selector picks from its own cache file
         * (`selector-cache.json` in the engine home dir, keyed by group name).
         */
        fun reloadIfChanged() {
            val data = data
            val running = data.meowInstance
            var selected: ClashProfile? = null
            when (ReloadPolicy.onRequest(data.state, running?.activeConfig) {
                selected = Core.currentProfile
                ActiveConfig.of(selected)
            }) {
                ReloadPolicy.Decision.Defer -> {
                    data.reloadPending = true
                    return
                }
                ReloadPolicy.Decision.Ignore -> {
                    data.reloadCheck?.cancel()
                    return
                }
                ReloadPolicy.Decision.Restart -> Unit
            }
            data.reloadCheck?.cancel()
            val profile = selected ?: return
            if (running == null) return
            val candidate = ActiveConfig.of(profile)
            val token = MeowCore.nativeBeginFallbackGeoIpTransition()
            data.reloadCheck = data.binder.launch {
                var handedOff = false
                try {
                    val store = DnsSettingsStore.default
                    while (data.state == State.Connected && data.meowInstance === running) {
                        val settings = store.load().settings
                        val previousDns = running.appliedDns
                        val previousOverride = running.appliedOverride
                        var staged = 0L
                        val next = withContext(Dispatchers.IO) {
                            val override = ConfigurationOverrideStore.default.effective(profile.id)
                            val policy = override.dnsWireOverride
                            val previousNeedsReader = previousOverride?.dnsWireOverride?.usesFallbackGeoIp == true
                            if (policy.usesFallbackGeoIp || previousNeedsReader) {
                                staged = MeowCore.nativeStageFallbackGeoIpTransition(
                                    token, running.activeConfig.profileId, previousNeedsReader,
                                    profile.id, settings.encode(), policy.wire(),
                                )
                            }
                            val issue = when {
                                staged == -1L -> DnsIssue.GEOIP_UNAVAILABLE
                                staged < 0 -> DnsIssue.PROFILE_CHANGED
                                else -> store.freshActivationIssue(settings, candidate, { policy }) { yaml, wire, policyWire ->
                                    MeowCore.nativeCheckCachedDnsForProfile(
                                        yaml, wire, policyWire, if (staged > 0) profile.id else 0L, staged,
                                    )
                                }
                            }
                            override to issue
                        }
                        if (data.state != State.Connected || data.meowInstance !== running) return@launch
                        if (ActiveConfig.of(Core.currentProfile) != candidate) return@launch
                        if (store.load().settings != settings || running.appliedDns != previousDns ||
                            running.appliedOverride != previousOverride) continue
                        val (override, issue) = next
                        if (issue != null) {
                            data.dnsRejection = DnsRejection(candidate, issue)
                            data.binder.dnsActivationRejected(issue)
                        } else {
                            data.dnsRejection = null
                            data.reload = Reload(profile, running, settings, override, previousDns, previousOverride, staged)
                            handedOff = staged > 0
                            Timber.i("Reloading: the selected profile changed")
                            stopRunner(true)
                        }
                        return@launch
                    }
                } catch (failure: java.io.IOException) {
                    Timber.w(failure, "Could not read the next DNS profile")
                    data.dnsRejection = DnsRejection(candidate, DnsIssue.INVALID_SETTINGS)
                    data.binder.dnsActivationRejected(DnsIssue.INVALID_SETTINGS)
                } finally {
                    if (!handedOff) MeowCore.nativeDiscardFallbackGeoIpTransition(token)
                }
            }
        }

        val isVpnService get() = false

        suspend fun startProcesses()

        /** Starts this service again, e.g. on reload; see [VpnService.start]. */
        fun startRunner() {
            this as Context
            try {
                ContextCompat.startForegroundService(this, Intent(this, javaClass))
            } catch (e: IllegalStateException) {
                // A refused restart leaves the VPN stopped; crashing :vpn over
                // it would not bring it back either. Nothing will start behind
                // the notification stopRunner kept for the restart, so drop it.
                Timber.w(e, "restart refused")
                data.reload?.discard()
                data.reload = null
                data.notification?.destroy()
                data.notification = null
            } catch (e: SecurityException) {
                // A refused launch (see [VpnService.start]); not expected
                // here, as :vpn is already running, but handled the same.
                Timber.w(e, "restart refused")
                data.reload?.discard()
                data.reload = null
                data.notification?.destroy()
                data.notification = null
            }
        }

        suspend fun killProcesses(scope: CoroutineScope) {
            data.meowInstance?.stop()
            data.meowInstance = null
        }

        fun stopRunner(restart: Boolean = false, msg: String? = null) {
            if (!restart) {
                data.reload?.discard()
                data.reload = null
                data.reloadCheck?.cancel()
            }
            if (data.state == State.Stopping) {
                if (!restart) data.restartAfterStop = false
                return
            }
            data.restartAfterStop = restart
            data.changeState(State.Stopping)
            if (restart) data.notification?.showConnecting()
            GlobalScope.launch(Dispatchers.Main.immediate) {
                data.connectingJob?.cancelAndJoin()
                this@Interface as Service
                coroutineScope {
                    killProcesses(this)
                    val data = data
                    if (data.closeReceiverRegistered) {
                        unregisterReceiver(data.closeReceiver)
                        data.closeReceiverRegistered = false
                    }
                }
                // A restart keeps the notification, and so the foreground:
                // dropping it would flash it away and leave the next start to
                // promote the service anew, which Android 12+ may refuse while
                // the app is in the background. Otherwise it is torn down here
                // rather than in the block above, which can suspend: a start
                // arriving meanwhile is answered with this notification (see
                // onStartCommand) and then ignored, so it must still be
                // removed. Nothing suspends from here to Stopped.
                val restartNow = data.restartAfterStop
                data.restartAfterStop = false
                if (!restartNow) {
                    data.notification?.destroy()
                    data.notification = null
                }
                data.changeState(State.Stopped, msg)
                if (restartNow) startRunner() else stopSelf()
            }
        }

        suspend fun applyZeroTier(): Int = ForwardingControl.OFFLINE
        suspend fun setMeowForwarding(enabled: Boolean): Int = ForwardingControl.OFFLINE

        suspend fun preInit() {}

        fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
            val data = data
            // Starts arrive through startForegroundService (see
            // VpnService.start), whose watchdog kills :vpn unless
            // startForeground() follows within seconds — so answer it before
            // anything can bail out, including the redundant-start,
            // null-intent and no-profile returns below and the Room lookup in
            // between. After a restart the notification is still up and this
            // only refreshes it.
            val notification = data.notification
                ?: createNotification().also { data.notification = it }
            notification.startForeground()
            if (data.state != State.Stopped) return Service.START_NOT_STICKY
            // Every real start carries an intent: VpnService.start's, or the
            // system's always-on one. A null intent is the system re-creating
            // :vpn after its process died, which it does despite
            // START_NOT_STICKY while the UI is still bound. Connecting on it
            // would turn a VPN the user just stopped back on whenever the stop
            // is what killed :vpn, so it only takes the notification down.
            if (intent == null) {
                data.reload?.discard()
                data.reload = null
                notification.destroy()
                data.notification = null
                (this as Service).stopSelf(startId)
                return Service.START_NOT_STICKY
            }

            val reload = data.reload.also { data.reload = null }
            val selected = Core.currentProfile
            val superseded = reload != null && ActiveConfig.of(selected) != ActiveConfig.of(reload.profile)
            val profile = if (superseded) requireNotNull(reload).previous.profile else reload?.profile ?: selected
            val starting = profile ?: if (BuildConfig.ZEROTIER && OverlayPlatform.hasActiveNetwork()) {
                // Joining without an imported Clash profile is a legitimate
                // ZeroTier-only use. Non-overlay traffic stays direct.
                ClashProfile(
                    name = "ZeroTier",
                    yamlContent = "mode: rule\nipv6: false\nrules: ['MATCH,DIRECT']\n",
                    autoUpdate = false,
                )
            } else null
            this as Context
            if (starting == null) {
                reload?.discard()
                stopRunner(false, "No profile selected")
                return Service.START_NOT_STICKY
            }
            notification.setProfileName(starting.name)

            data.meowInstance = MeowInstance(starting).also {
                if (reload != null && (reload.fallbackTransition > 0 || superseded)) {
                    it.fallbackTransition = reload.fallbackTransition
                    it.fallbackRecovery = superseded
                    it.appliedDns = if (superseded) reload.previousDns else reload.candidateDns
                    it.appliedOverride = if (superseded) reload.previousOverride else reload.candidateOverride
                }
            }

            if (!data.closeReceiverRegistered) {
                ContextCompat.registerReceiver(this, data.closeReceiver, IntentFilter().apply {
                    addAction(Action.RELOAD)
                    addAction(Intent.ACTION_SHUTDOWN)
                    addAction(Action.CLOSE)
                }, ContextCompat.RECEIVER_NOT_EXPORTED)
                data.closeReceiverRegistered = true
            }

            data.changeState(State.Connecting)
            data.connectingJob = GlobalScope.launch(Dispatchers.Main.immediate) {
                try {
                    preInit()
                    val attempted = ActiveConfig.of(starting)
                    val restored = try {
                        startProcesses()
                        data.dnsRejection = null
                        null
                    } catch (exc: DnsActivationException) {
                        data.dnsRejection = DnsRejection(attempted, exc.issue)
                        val previous = reload?.previous?.takeUnless { superseded } ?: throw exc
                        val previousDns = reload.previousDns ?: throw exc
                        notification.setProfileName(previous.profileName)
                        data.meowInstance = MeowInstance(previous.profile).also {
                            it.appliedDns = previousDns
                            it.appliedOverride = reload.previousOverride
                            it.fallbackTransition = reload.fallbackTransition
                            it.fallbackRecovery = true
                        }
                        startProcesses()
                        exc.issue
                    }
                    data.changeState(State.Connected)
                    if (restored != null) data.binder.dnsActivationRejected(restored)
                    val queued = data.reloadPending
                    data.reloadPending = false
                    if ((queued && restored == null) || (reload != null && ActiveConfig.of(Core.currentProfile) != attempted)) {
                        reloadIfChanged()
                    }
                } catch (_: CancellationException) {
                } catch (exc: DnsActivationException) {
                    data.binder.dnsActivationRejected(exc.issue)
                    stopRunner(false)
                } catch (exc: Throwable) {
                    Timber.w(exc)
                    stopRunner(false, "Service failed: ${exc.localizedMessage}")
                } finally {
                    reload?.discard()
                    data.connectingJob = null
                }
            }
            return Service.START_NOT_STICKY
        }
    }
}
