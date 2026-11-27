package io.github.madeye.meow.ui.screens.proxies

import androidx.compose.runtime.Immutable
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.madeye.meow.api.ControllerAccess
import io.github.madeye.meow.api.ControllerSnapshot
import io.github.madeye.meow.api.ControllerStatus
import io.github.madeye.meow.api.GroupDelayTester
import io.github.madeye.meow.api.MeowApi
import io.github.madeye.meow.api.MeowApiException
import io.github.madeye.meow.api.ProxiesResult
import io.github.madeye.meow.api.RouteMode
import io.github.madeye.meow.api.controllerStatus
import io.github.madeye.meow.bg.BaseService
import io.github.madeye.meow.diagnostics.FaultDiagnostics
import io.github.madeye.meow.diagnostics.FaultKind
import io.github.madeye.meow.diagnostics.FaultProcess
import io.github.madeye.meow.database.ClashProfile
import io.github.madeye.meow.ui.screens.providers.proxyDialersFromYaml
import io.github.madeye.meow.vpn.ControllerSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

@Immutable
data class ProxyNodeUi(
    val name: String,
    val type: String,
    val delay: NodeDelay,
    val selected: Boolean,
    /** The saved inline dialer setting; not evidence of the live route. */
    val dialer: String? = null,
)

@Immutable
data class ProxyGroupUi(
    val name: String,
    val type: String,
    val now: String,
    val nodes: List<ProxyNodeUi>,
    /** The group's own health-check URL, which its latency test probes with. */
    val testUrl: String? = null,
    /** Share of members tested while a latency test runs; `null` otherwise. */
    val testProgress: Float? = null,
)

@Immutable
data class ProxyGroupsUiState(
    val state: BaseService.State = BaseService.State.Idle,
    val hasProfile: Boolean = false,
    val groups: List<ProxyGroupUi> = emptyList(),
    val expandedGroup: String? = null,
    val status: ControllerStatus = ControllerStatus.Loading,
    val waitingForProviders: Boolean = false,
)

private data class GroupsRead(val rows: List<ProxyGroupUi>, val pendingProviders: Boolean)

class ProxyGroupsViewModel(
    private val controller: ControllerAccess,
    selectedProfile: Flow<ClashProfile?>,
    private val apiForSession: (ControllerSession) -> MeowApi,
    private val onRouteChanged: () -> Unit,
    private val onNodeSelected: (String) -> Unit,
    private val saveSelection: suspend (Long, String, () -> Boolean) -> Unit,
    private val loadProfileYaml: suspend (Long) -> String? = { null },
) : ViewModel() {
    private val reload = MutableStateFlow(0L)
    private val expanded = MutableStateFlow<String?>(null)
    private val groupTests = MutableStateFlow<Map<String, GroupTestProgress>>(emptyMap())
    private val testJobs = HashMap<String, Job>()
    private val selection = Mutex()
    private val _selectionFailed = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val selectionFailed = _selectionFailed.asSharedFlow()
    private val _testFailed = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val testFailed = _testFailed.asSharedFlow()

    private val snapshot = controller.observe(reload, GroupsRead::pendingProviders, ::recordLoadFailure) { session ->
        val api = apiForSession(session)
        val mode = api.configs().routeMode
        val proxies = api.proxies()
        val pending = api.proxyProviders().any { it.awaitingFirstUpdate }
        val dialers = loadDialers(session)
        controller.requireCurrent(session)
        GroupsRead(proxies.rows(mode, dialers), pending)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(replayExpirationMillis = 0), ControllerSnapshot())

    val uiState: StateFlow<ProxyGroupsUiState> = combine(
        controller.lifecycle, selectedProfile, snapshot, groupTests, expanded,
    ) { vpn, profile, data, tests, expandedGroup ->
        val current = data.takeIf { it.session != null && it.session == vpn.session }
        ProxyGroupsUiState(
            state = vpn.state,
            hasProfile = profile != null,
            groups = current?.value?.rows.orEmpty().withTests(tests),
            expandedGroup = expandedGroup,
            status = current?.status ?: vpn.controllerStatus,
            waitingForProviders = current?.waitingForProviders == true,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(replayExpirationMillis = 0), ProxyGroupsUiState())

    init {
        viewModelScope.launch {
            var previous: ControllerSession? = null
            controller.lifecycle.collect { vpn ->
                if (vpn.session == previous) return@collect
                previous = vpn.session
                stopTests()
                expanded.value = null
            }
        }
    }

    fun stopTests() {
        val jobs = testJobs.values.toList()
        testJobs.clear()
        jobs.forEach { it.cancel() }
        groupTests.value = emptyMap()
    }

    fun onToggleExpanded(group: String) {
        expanded.value = if (expanded.value == group) null else group
    }

    fun onRetry() {
        reload.update { it + 1 }
    }

    fun onSelectNode(group: String, node: String) {
        val session = currentGroups() ?: return
        val target = snapshot.value.value?.rows?.firstOrNull { it.name == group } ?: return
        if (target.nodes.none { it.name == node }) return
        viewModelScope.launch {
            selection.withLock {
                if (!controller.isCurrent(session)) return@withLock
                try {
                    controller.write(session) { apiForSession(session).selectProxy(group, node) }
                    onRouteChanged()
                    onNodeSelected(node)
                    // The database selection can move before the service restarts.
                    session.profileId?.let { profileId ->
                        saveSelection(profileId, node) { controller.isCurrent(session) }
                    }
                } catch (e: MeowApiException) {
                    if (!controller.isCurrent(session)) return@withLock
                    Timber.w(e, "selecting proxy failed")
                    _selectionFailed.tryEmit(Unit)
                }
                if (controller.isCurrent(session)) onRetry()
            }
        }
    }

    fun onTestGroup(group: String) {
        val session = currentGroups() ?: return
        val target = snapshot.value.value?.rows?.firstOrNull { it.name == group } ?: return
        testJobs.remove(group)?.cancel()
        val members = target.nodes.map { it.name }
        groupTests.update { it + (group to GroupTestProgress.start(members)) }
        val job = viewModelScope.launch(start = CoroutineStart.LAZY) {
            val self = coroutineContext.job
            try {
                controller.write(session) {
                    val delayTester = GroupDelayTester(apiForSession(session))
                    delayTester.test(group, target.type, members, target.testUrl).collect { result ->
                        controller.requireCurrent(session)
                        groupTests.update { tests ->
                            val progress = tests[group] ?: return@update tests
                            tests + (group to progress.withResult(result))
                        }
                    }
                }
                onRetry()
            } catch (e: MeowApiException) {
                if (controller.isCurrent(session)) {
                    Timber.w(e, "testing proxy group failed")
                    _testFailed.tryEmit(Unit)
                }
            } finally {
                if (testJobs[group] === self) {
                    testJobs.remove(group)
                    groupTests.update { it - group }
                }
            }
        }
        testJobs[group] = job
        job.start()
    }

    // Editor selection may point to a different profile while this session is running.
    private suspend fun loadDialers(session: ControllerSession): Map<String, String> = try {
        session.profileId?.let { loadProfileYaml(it)?.let(::proxyDialersFromYaml) }.orEmpty()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Timber.w(e, "loading proxy dialers failed")
        emptyMap()
    }

    private fun currentGroups(): ControllerSession? = snapshot.value.let { data ->
        data.session?.takeIf { controller.isCurrent(it) && data.value != null }
    }
}

private fun ProxiesResult.rows(mode: RouteMode?, dialers: Map<String, String>): List<ProxyGroupUi> = visibleGroups(mode).map { group ->
    ProxyGroupUi(
        name = group.name,
        type = group.type,
        now = group.now,
        testUrl = group.testUrl,
        nodes = group.all.map { name ->
            val node = proxies[name]
            val member = groups[name]
            ProxyNodeUi(
                name = name,
                type = node?.type ?: member?.type.orEmpty(),
                delay = NodeDelay.fromHistory(node?.history ?: member?.history.orEmpty()),
                selected = name == group.now,
                dialer = dialers[name].takeIf { node?.providerName == "" },
            )
        }.sortedForGroup(group.type),
    )
}

private fun recordLoadFailure(error: MeowApiException) {
    Timber.w(error, "loading proxy groups failed")
    val code = when (error) {
        is MeowApiException.Http -> error.code
        is MeowApiException.Decode -> 2
        is MeowApiException.Unreachable -> 1
    }
    FaultDiagnostics.record(FaultProcess.UI, FaultKind.PROXY_GROUP_REFRESH, code)
}
