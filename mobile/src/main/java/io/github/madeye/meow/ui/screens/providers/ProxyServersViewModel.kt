package io.github.madeye.meow.ui.screens.providers

import androidx.compose.runtime.Immutable
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.madeye.meow.api.ControllerAccess
import io.github.madeye.meow.api.ControllerStatus
import io.github.madeye.meow.api.controllerStatus
import io.github.madeye.meow.vpn.ControllerSession
import io.github.madeye.meow.api.MeowApi
import io.github.madeye.meow.api.MeowApiException
import io.github.madeye.meow.api.Proxy
import io.github.madeye.meow.api.ProxiesResult
import io.github.madeye.meow.api.ProxyProvider
import io.github.madeye.meow.api.ProxyProviderNode
import io.github.madeye.meow.repo.ProfileRepository
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.async
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import timber.log.Timber

private const val INLINE_PROXIES_ID = "inline-proxies"
private val BUILTIN_PROXY_TYPES = setOf("direct", "reject", "rejectdrop", "pass", "passrule", "compatible")

enum class ProxyServerKind {
    Provider,
    Inline,
}

@Immutable
data class ProxyServerNodeUi(
    val name: String,
    val type: String,
    val delayMs: Int?,
    val timedOut: Boolean,
    val testing: Boolean = false,
)

@Immutable
data class ProxyServerProviderUi(
    /** Stable identity used for callbacks and Compose keys. */
    val id: String,
    val name: String,
    val vehicleType: String,
    val testUrl: String,
    val expectedStatus: String,
    val nodes: List<ProxyServerNodeUi>,
    val kind: ProxyServerKind = ProxyServerKind.Provider,
    val checking: Boolean = false,
)

@Immutable
data class ProxyServersUiState(
    val providers: List<ProxyServerProviderUi> = emptyList(),
    /** The active local profile can be edited from the inline proxy card. */
    val editableProfileId: Long? = null,
    /** Case-insensitive search applied to node names and protocol types. */
    val query: String = "",
    val status: ControllerStatus = ControllerStatus.Loading,
    val waitingForProviders: Boolean = false,
)

private data class ServersRead(
    val rows: List<ProxyServerProviderUi>,
    val editableProfileId: Long?,
    val pendingProviders: Boolean,
)

/** Loads both configured provider nodes and inline `proxies:` nodes. */
class ProxyServersViewModel(
    private val controller: ControllerAccess,
    private val apiForSession: (ControllerSession) -> MeowApi,
    private val profiles: ProfileRepository,
) : ViewModel() {
    private val reload = MutableStateFlow(0L)
    private val probeJob = SupervisorJob(viewModelScope.coroutineContext.job)
    private val probes = CoroutineScope(viewModelScope.coroutineContext + probeJob)
    private val query = MutableStateFlow("")
    private val _state = MutableStateFlow(ProxyServersUiState())
    private var displayedSession: ControllerSession? = null
    private var displayedValue: ServersRead? = null
    private val _probeFailed = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val probeFailed = _probeFailed.asSharedFlow()

    private val observation = controller.observe(reload, ServersRead::pendingProviders) { session ->
        val api = apiForSession(session)
        coroutineScope {
            val inline = async { api.proxies() }
            val providers = api.proxyProviders()
            val profile = session.profileId?.let { profiles.getById(it) }
            ServersRead(
                proxyServerProviders(inline.await(), providers),
                profile?.takeIf { it.url.isBlank() }?.id,
                providers.any { it.awaitingFirstUpdate },
            )
        }
    }

    val uiState: StateFlow<ProxyServersUiState> = combine(
        controller.lifecycle, observation, _state, query,
    ) { vpn, snapshot, local, search ->
        val session = snapshot.session
        if (session == null || session != vpn.session) {
            ProxyServersUiState(query = search, status = vpn.controllerStatus)
        } else {
            val value = snapshot.value
            val base = ProxyServersUiState(
                providers = value?.rows.orEmpty(),
                editableProfileId = value?.editableProfileId,
                query = search,
                status = snapshot.status,
                waitingForProviders = snapshot.waitingForProviders,
            )
            if (displayedSession != session || local.status != base.status ||
                local.waitingForProviders != base.waitingForProviders || value != displayedValue
            ) {
                displayedSession = session
                displayedValue = value
                _state.value = base
                base
            } else {
                local.copy(query = search)
            }
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(replayExpirationMillis = 0), ProxyServersUiState())

    fun load() {
        reload.update { it + 1 }
    }

    fun setQuery(query: String) {
        this.query.value = query
    }

    fun stopProbes() {
        probeJob.cancelChildren()
        _state.update { state ->
            state.copy(providers = state.providers.map { provider ->
                provider.copy(checking = false, nodes = provider.nodes.map { it.copy(testing = false) })
            })
        }
    }

    fun healthCheck(providerId: String) {
        val session = displayedSession?.takeIf(controller::isCurrent) ?: return
        val provider = _state.value.providers.firstOrNull { it.id == providerId } ?: return
        if (provider.kind != ProxyServerKind.Provider) return
        if (provider.checking) return
        setProviderChecking(providerId, true)
        probes.launch {
            val api = apiForSession(session)
            try {
                controller.write(session) { api.healthCheckProxyProvider(provider.name) }
                val refreshed = controller.read(session) { api.proxyProviders() }.firstOrNull { it.name == provider.name }
                if (refreshed != null) replaceProvider(refreshed.toUi()) else setProviderChecking(providerId, false)
            } catch (e: MeowApiException) {
                if (!controller.isCurrent(session)) return@launch
                Timber.w(e, "proxy provider health check failed: %s", provider.name)
                setProviderChecking(providerId, false)
                _probeFailed.tryEmit(Unit)
            }
        }
    }

    fun testNode(providerId: String, nodeName: String) {
        val session = displayedSession?.takeIf(controller::isCurrent) ?: return
        val provider = _state.value.providers.firstOrNull { it.id == providerId } ?: return
        val node = provider.nodes.firstOrNull { it.name == nodeName } ?: return
        if (node.testing) return
        updateNode(providerId, nodeName) { it.copy(testing = true) }
        probes.launch {
            val api = apiForSession(session)
            try {
                val delay = controller.write(session) {
                    if (provider.kind == ProxyServerKind.Inline) {
                        api.testProxyDelay(
                            name = nodeName,
                            url = provider.testUrl.ifBlank { MeowApi.DELAY_TEST_URL },
                        )
                    } else {
                        api.testProxyProviderDelay(
                            provider = provider.name,
                            name = nodeName,
                            url = provider.testUrl.ifBlank { MeowApi.DELAY_TEST_URL },
                            expectedStatus = provider.expectedStatus,
                        )
                    }
                }
                updateNode(providerId, nodeName) {
                    it.copy(delayMs = delay.takeIf { measured -> measured > 0 }, timedOut = delay <= 0, testing = false)
                }
            } catch (e: MeowApiException) {
                if (!controller.isCurrent(session)) return@launch
                Timber.w(e, "proxy node test failed: %s/%s", provider.name, nodeName)
                val timedOut = e is MeowApiException.Http && e.code == 504
                if (timedOut) {
                    updateNode(providerId, nodeName) { it.copy(testing = false, delayMs = null, timedOut = true) }
                } else {
                    updateNode(providerId, nodeName) { it.copy(testing = false) }
                    _probeFailed.tryEmit(Unit)
                }
            }
        }
    }

    private fun setProviderChecking(name: String, checking: Boolean) {
        _state.update { state ->
            state.copy(providers = state.providers.map { provider ->
                if (provider.id == name) provider.copy(checking = checking) else provider
            })
        }
    }

    private fun replaceProvider(provider: ProxyServerProviderUi) {
        _state.update { state ->
            state.copy(providers = state.providers.map { if (it.id == provider.id) provider else it })
        }
    }

    private fun updateNode(
        providerId: String,
        nodeName: String,
        transform: (ProxyServerNodeUi) -> ProxyServerNodeUi,
    ) {
        _state.update { state ->
            state.copy(providers = state.providers.map { provider ->
                if (provider.id != providerId) provider else provider.copy(
                    nodes = provider.nodes.map { node ->
                        if (node.name == nodeName) transform(node) else node
                    },
                )
            })
        }
    }
}

/** Converts both API views into the cards shown by the screen. */
internal fun proxyServerProviders(
    inline: ProxiesResult?,
    providers: List<ProxyProvider>,
): List<ProxyServerProviderUi> {
    val providerCards = providers.map(ProxyProvider::toUi)
    val inlineNodes = inline?.proxies.orEmpty()
        .values
        .filterNot { it.type.lowercase() in BUILTIN_PROXY_TYPES }
        .sortedWith(compareBy<Proxy, String>(String.CASE_INSENSITIVE_ORDER) { it.name }.thenBy { it.name })
        .map { proxy ->
            ProxyServerNodeUi(
                name = proxy.name,
                type = proxy.type,
                delayMs = proxy.latestDelay.takeIf { it > 0 },
                timedOut = proxy.history.isNotEmpty() && proxy.latestDelay <= 0,
            )
        }
    if (inlineNodes.isEmpty()) return providerCards
    return providerCards + ProxyServerProviderUi(
        id = INLINE_PROXIES_ID,
        name = INLINE_PROXIES_ID,
        vehicleType = "",
        testUrl = "",
        expectedStatus = "",
        nodes = inlineNodes,
        kind = ProxyServerKind.Inline,
    )
}

/** Keeps provider cards stable while filtering only their node rows. */
internal fun filterProxyServerProviders(
    providers: List<ProxyServerProviderUi>,
    query: String,
): List<ProxyServerProviderUi> {
    val needle = query.trim()
    if (needle.isEmpty()) return providers
    return providers.mapNotNull { provider ->
        val nodes = provider.nodes.filter { node ->
            node.name.contains(needle, ignoreCase = true) ||
                node.type.contains(needle, ignoreCase = true)
        }
        provider.takeIf { nodes.isNotEmpty() }?.copy(nodes = nodes)
    }
}

private fun ProxyProvider.toUi() = ProxyServerProviderUi(
    id = "provider:$name",
    name = name,
    vehicleType = vehicleType,
    testUrl = testUrl,
    expectedStatus = expectedStatus,
    nodes = nodes.map(ProxyProviderNode::toUi),
)

private fun ProxyProviderNode.toUi() = ProxyServerNodeUi(
    name = name,
    type = type,
    delayMs = latestDelay,
    timedOut = timedOut,
)
