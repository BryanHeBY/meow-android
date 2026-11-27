package io.github.madeye.meow.ui.screens.home

import io.github.madeye.meow.BuildConfig

import androidx.compose.runtime.Immutable
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.madeye.meow.analytics.Analytics
import io.github.madeye.meow.api.ControllerAccess
import io.github.madeye.meow.api.ControllerStatus
import io.github.madeye.meow.api.controllerStatus
import io.github.madeye.meow.api.MeowApi
import io.github.madeye.meow.api.MeowApiException
import io.github.madeye.meow.api.RouteMode
import io.github.madeye.meow.bg.BaseService
import io.github.madeye.meow.preference.RouteModeStore
import io.github.madeye.meow.repo.ProfileRepository
import io.github.madeye.meow.vpn.VpnStateRepository
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import io.github.madeye.meow.vpn.ControllerSession
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import timber.log.Timber

@Immutable
data class HomeUiState(
    val state: BaseService.State = BaseService.State.Idle,
    val profileName: String = "",
    val hasProfile: Boolean = false,
    /** False until Room's first answer, so launch doesn't flash the no-profile prompt. */
    val profileLoaded: Boolean = false,
    val routeMode: RouteMode = RouteMode.Rule,
    val routeModeStatus: ControllerStatus = ControllerStatus.Offline,
    val meowForwarding: Boolean = true,
    val overlayForwarding: Boolean = false,
    val forwardingChangePending: Boolean = false,
) {
    val isConnected: Boolean get() = state == BaseService.State.Connected

    val showMeowForwarding: Boolean get() = BuildConfig.ZEROTIER && isConnected && hasProfile
    val canToggleMeowForwarding: Boolean
        get() = showMeowForwarding && overlayForwarding && !forwardingChangePending

    /** The switch is inert mid-transition, matching the old Flutter behaviour. */
    val isBusy: Boolean
        get() = state == BaseService.State.Connecting || state == BaseService.State.Stopping
}

/** Loading is separate from a loaded, intentionally unset override. */
@Immutable
internal data class NextRouteMode(val override: RouteMode?)

class HomeViewModel(
    private val vpn: VpnStateRepository,
    private val controller: ControllerAccess,
    private val profiles: ProfileRepository,
    private val apiForSession: (ControllerSession) -> MeowApi,
    private val analytics: Analytics,
    private val routeModes: RouteModeStore,
    private val routeChanges: RouteChanges,
) : ViewModel() {

    private val savedMode = MutableStateFlow<NextRouteMode?>(null)
    internal val nextRouteMode = savedMode.asStateFlow()
    private val _nextRouteModeSaveFailed = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    internal val nextRouteModeSaveFailed = _nextRouteModeSaveFailed.asSharedFlow()

    private val reloadMode = MutableStateFlow(0L)
    private val _routeModeFailed = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val routeModeFailed = _routeModeFailed.asSharedFlow()
    private val modeSwitch = Mutex()
    private val forwardingChangePending = MutableStateFlow(false)
    private val channels = combine(
        vpn.meowForwarding, vpn.overlayForwarding, forwardingChangePending,
    ) { meow, overlay, pending -> Triple(meow, overlay, pending) }

    private val configuredMode = combine(
        savedMode,
        profiles.observeSelected().map { it?.yamlContent }.distinctUntilChanged(),
    ) { saved, yaml -> saved?.override ?: yaml?.let(RouteMode::configured) ?: RouteMode.Rule }

    private val runtimeMode = controller.observe(reloadMode) { session ->
        modeSwitch.withLock { apiForSession(session).configs() }
    }

    val uiState: StateFlow<HomeUiState> = combine(
        controller.lifecycle, profiles.observeSelected(), runtimeMode, configuredMode, channels,
    ) { lifecycle, profile, data, configured, channel ->
        val runtime = data.takeIf { it.session != null && it.session == lifecycle.session }
        HomeUiState(
            state = lifecycle.state,
            profileName = lifecycle.profileName.ifEmpty { profile?.name.orEmpty() },
            hasProfile = profile != null,
            profileLoaded = true,
            routeMode = runtime?.value?.routeMode ?: configured,
            routeModeStatus = runtime?.status ?: lifecycle.controllerStatus,
            meowForwarding = channel.first,
            overlayForwarding = channel.second,
            forwardingChangePending = channel.third,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(replayExpirationMillis = 0), HomeUiState())

    init {
        viewModelScope.launch {
            modeSwitch.withLock {
                savedMode.value = NextRouteMode(withContext(Dispatchers.IO) { routeModes.load() })
            }
        }
    }

    /** The `:vpn` process may have been killed while backgrounded. */
    fun onResume() = vpn.refresh()

    fun refreshRouteMode() { reloadMode.update { it + 1 } }

    fun onConnectRequested() = analytics.vpnConnect()

    fun onDisconnect(context: android.content.Context) {
        analytics.vpnDisconnect()
        vpn.requestStop(context)
    }

    suspend fun setMeowForwarding(enabled: Boolean): Int {
        if (forwardingChangePending.value || !uiState.value.canToggleMeowForwarding) return 2
        forwardingChangePending.value = true
        return try {
            vpn.setMeowForwarding(enabled).also { result ->
                if (result == 0) routeChanges.notifyChanged()
            }
        } finally {
            forwardingChangePending.value = false
        }
    }

    /**
     * Persists [mode] for every later engine start and, while connected,
     * switches the running engine too. Open connections are then closed: the
     * engine only re-routes new flows, so an app that stays connected (a
     * stream, a chat socket) would otherwise keep its old route.
     */
    fun onSelectRouteMode(mode: RouteMode) {
        val lifecycle = controller.lifecycle.value
        if (lifecycle.session == null && lifecycle.state != BaseService.State.Stopped) return
        if (lifecycle.session != null && uiState.value.routeModeStatus != ControllerStatus.Ready) return
        viewModelScope.launch {
            modeSwitch.withLock {
                if (controller.lifecycle.value == lifecycle) switchRouteMode(mode, lifecycle.session)
            }
        }
    }

    /** Advanced writes only the next-start setting; it must not change live routes. */
    internal fun setNextRouteMode(mode: RouteMode?) {
        viewModelScope.launch {
            modeSwitch.withLock {
                val current = savedMode.value ?: return@withLock
                if (current.override == mode) return@withLock
                try {
                    saveRouteMode(mode)
                } catch (e: IOException) {
                    Timber.w(e, "saving next route mode failed")
                    _nextRouteModeSaveFailed.tryEmit(Unit)
                }
            }
        }
    }

    private suspend fun saveRouteMode(mode: RouteMode?, session: ControllerSession? = null) {
        val saved = withContext(Dispatchers.IO) {
            if (session != null && !controller.isCurrent(session)) return@withContext false
            if (mode == null) routeModes.clear() else routeModes.save(mode)
            true
        }
        if (saved) savedMode.value = NextRouteMode(mode)
    }

    private suspend fun switchRouteMode(mode: RouteMode, session: ControllerSession?) {
        if (session != null) {
            try {
                controller.write(session) { apiForSession(session).setMode(mode) }
            } catch (e: MeowApiException) {
                if (!controller.isCurrent(session)) return
                Timber.w(e, "switching route mode failed")
                _routeModeFailed.tryEmit(Unit)
                refreshRouteMode()
                return
            }
        }
        try {
            saveRouteMode(mode, session)
        } catch (e: IOException) {
            Timber.w(e, "saving route mode failed")
        }
        analytics.routeModeSelect(mode.wire)
        if (session != null && controller.isCurrent(session)) {
            refreshRouteMode()
            try {
                controller.write(session) { apiForSession(session).closeAllConnections() }
            } catch (e: MeowApiException) {
                Timber.w(e, "closing connections after a route mode switch failed")
            }
            if (controller.isCurrent(session)) routeChanges.notifyChanged()
        }
    }
}
