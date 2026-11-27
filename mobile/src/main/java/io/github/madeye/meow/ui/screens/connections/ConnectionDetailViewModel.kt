package io.github.madeye.meow.ui.screens.connections

import androidx.compose.runtime.Immutable
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.madeye.meow.api.Connection
import io.github.madeye.meow.api.ControllerAccess
import io.github.madeye.meow.api.ControllerStatus
import io.github.madeye.meow.vpn.ControllerSession
import io.github.madeye.meow.api.ConnectionNote
import io.github.madeye.meow.api.ConnectionNotes
import io.github.madeye.meow.api.DnsResult
import io.github.madeye.meow.api.MeowApiException
import io.github.madeye.meow.api.ProxiesResult
import io.github.madeye.meow.api.Rule
import io.github.madeye.meow.net.IpGeo
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** The engine's names for a route no listed rule chose. */
enum class UnlistedRoute(val wire: String) {
    /** No rule matched, so the flow went DIRECT. */
    Final("Final"),

    /** Global route mode: everything through the GLOBAL group. */
    Global("Global"),

    /** Direct route mode. */
    Direct("Direct"),
    ;

    companion object {
        fun of(connection: Connection): UnlistedRoute? = entries.firstOrNull { it.wire == connection.rule }
    }
}

/** The far end of a connection, as far as this device can tell. */
sealed interface RemoteIp {
    /**
     * [ip] is where the flow went: the engine's destination IP, or, when the
     * engine dialed a host name DIRECT without reporting one ([fromDnsCache]),
     * what its DNS cache holds for the name. [geo] arrives after [ip].
     */
    data class Known(val ip: String, val fromDnsCache: Boolean = false, val geo: IpGeo? = null) : RemoteIp

    /** The proxy server resolves the host name; this device never learns the address. */
    data object ResolvedByProxy : RemoteIp
}

@Immutable
data class ConnectionDetailUiState(
    /** Null once the connection is in neither list, e.g. after closed ones were cleared. */
    val connection: Connection? = null,
    /** When a poll last listed it, once it has closed; null while it is open. */
    val lastSeenAtMillis: Long? = null,
    /** The matched rule's place in the engine's rule list (0-based), once found. */
    val ruleIndex: Int? = null,
    val ruleRunId: String? = null,
    /** Null until worked out, and when there is nothing to say (no host, rejected…). */
    val remote: RemoteIp? = null,
    /** The display name of the app that opened it, once resolved; null when the engine did not say. */
    val appLabel: String? = null,
    /** How the engine handled it, oldest first; empty until read, and when the engine kept none. */
    val notes: List<ConnectionNote> = emptyList(),
    val status: ControllerStatus = ControllerStatus.Loading,
) {
    val active: Boolean get() = connection != null && lastSeenAtMillis == null
}

/**
 * One connection's detail page: where it went, and which rule sent it there.
 *
 * Reads the same process-scoped [store] as the list, polling it while shown,
 * so a connection that closes under the page turns into its closed row. Its
 * notes are re-read while shown too, until the engine reports it closed or
 * turns out not to record it.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ConnectionDetailViewModel(
    private val id: String,
    private val store: RecentConnectionsStore,
    private val controller: ControllerAccess,
    polling: Flow<ControllerStatus>,
    private val rules: suspend (ControllerSession) -> List<Rule>,
    private val closeConnection: suspend (ControllerSession, String) -> Unit,
    private val proxies: suspend (ControllerSession) -> ProxiesResult,
    /** The engine's DNS cache entries matching a host name. */
    private val dnsCache: suspend (session: ControllerSession, host: String) -> List<DnsResult>,
    private val ipGeo: suspend (ip: String) -> IpGeo,
    /** An installed app's display name by package name. */
    private val appLabel: suspend (packageName: String) -> String,
    /** The engine's notes on a connection; null when it has none to give. */
    private val connectionNotes: suspend (session: ControllerSession, id: String) -> ConnectionNotes?,
    private val notesPollIntervalMillis: Long = NOTES_POLL_INTERVAL_MS,
) : ViewModel() {

    private val ruleIndex = MutableStateFlow<Pair<ControllerSession, Int>?>(null)
    private val remote = MutableStateFlow<RemoteIp?>(null)
    private val app = MutableStateFlow<String?>(null)
    private val notes = MutableStateFlow<List<ConnectionNote>>(emptyList())
    private val _closeFailed = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val closeFailed = _closeFailed.asSharedFlow()

    private var notesComplete = false
    private val reload = MutableStateFlow(0L)

    private val controllerDetails = controller.lifecycle.flatMapLatest { vpn ->
        val session = vpn.session ?: return@flatMapLatest flowOf(Unit)
        flow {
            emit(Unit)
            val connection = firstSeen()
            if (store.runIdOf(id) != session.runId) return@flow
            coroutineScope {
                launch { loadRule(connection, session) }
                launch {
                    if (connection.metadata.destinationIP.isEmpty() && remote.value == null) {
                        val found = remoteIpOf(
                            connection,
                            { controller.read(session) { proxies(session) } },
                            { host -> controller.read(session) { dnsCache(session, host) } },
                        )
                        controller.requireCurrent(session)
                        showRemote(found)
                    }
                }
                launch {
                    while (!notesComplete && refreshNotes(session)) delay(notesPollIntervalMillis)
                }
            }
        }
    }

    private val localDetails = flow {
        emit(Unit)
        val connection = firstSeen()
        coroutineScope {
            launch { connection.appPackage?.let { app.value = appLabel(it) } }
            launch {
                if (connection.metadata.destinationIP.isNotEmpty() && remote.value == null) {
                    showRemote(RemoteIp.Known(connection.metadata.destinationIP))
                }
            }
        }
    }

    val uiState: StateFlow<ConnectionDetailUiState> =
        combine(
            store.lists,
            combine(ruleIndex, controller.lifecycle) { rule, vpn ->
                rule?.takeIf { it.first == vpn.session }
            },
            remote,
            combine(app, notes, ::Pair),
            combine(reload.flatMapLatest { polling }, merge(localDetails, controllerDetails)) { status, _ -> status },
        ) { lists, rule, remoteIp, (label, steps), status ->
            lists.detail(rule?.second).copy(
                remote = remoteIp, appLabel = label, notes = steps, status = status, ruleRunId = rule?.first?.runId,
            )
        }.stateIn(
            viewModelScope, SharingStarted.WhileSubscribed(replayExpirationMillis = 0), store.lists.value.detail(null),
        )

    private suspend fun loadRule(connection: Connection, session: ControllerSession) {
        if (UnlistedRoute.of(connection) != null || connection.rule.isEmpty()) return
        try {
            val index = controller.read(session) { rules(session) }.indexOfMatch(connection)
            if (index != null) ruleIndex.value = session to index
        } catch (_: MeowApiException) { }
    }

    private suspend fun showRemote(found: RemoteIp?) {
        remote.value = found
        if (found is RemoteIp.Known) remote.value = found.copy(geo = ipGeo(found.ip))
    }

    private suspend fun refreshNotes(session: ControllerSession): Boolean {
        val read = try {
            controller.read(session) { connectionNotes(session, id) }
        } catch (_: MeowApiException) {
            return false
        }
        notesComplete = read == null || read.closed || read.notes.isEmpty()
        if (read != null) notes.value = read.notes
        return !notesComplete
    }

    private suspend fun firstSeen(): Connection = store.lists.mapNotNull { it.detail(null).connection }.first()

    fun retry() { reload.update { it + 1 } }

    fun close() {
        val session = controller.session ?: return
        if (store.runIdOf(id) != session.runId) return
        viewModelScope.launch {
            try {
                controller.write(session) { closeConnection(session, id) }
                store.closeLocal(id)
            } catch (_: MeowApiException) {
                if (controller.isCurrent(session)) _closeFailed.tryEmit(Unit)
            }
        }
    }

    private fun ConnectionLists.detail(index: Int?): ConnectionDetailUiState {
        active.firstOrNull { it.id == id }?.let { return ConnectionDetailUiState(it, null, index) }
        recent.firstOrNull { it.connection.id == id }?.let {
            return ConnectionDetailUiState(it.connection, it.lastSeenAtMillis, index)
        }
        return ConnectionDetailUiState(ruleIndex = index)
    }
}

/**
 * Where [connection]'s rule sits in the engine's rule list: the first rule of
 * its type and payload that targets its policy, as matching runs top-down.
 * Null when there is none, e.g. after a config reload.
 */
internal fun List<Rule>.indexOfMatch(connection: Connection): Int? {
    val policy = connection.chains.lastOrNull() ?: return null
    return indexOfFirst {
        it.type == connection.rule && it.payload == connection.rulePayload && it.proxy == policy
    }.takeIf { it >= 0 }
}

/**
 * Where [connection] went, when the engine did not report the address: a host
 * name dialed DIRECT was resolved by the engine, so its DNS cache still holds
 * the answer while the record lives; any other policy hands the name to a
 * proxy server. Null when there is nothing to say, e.g. the flow was rejected
 * or the engine is gone.
 */
internal suspend fun remoteIpOf(
    connection: Connection,
    proxies: suspend () -> ProxiesResult,
    dnsCache: suspend (host: String) -> List<DnsResult>,
): RemoteIp? {
    val meta = connection.metadata
    if (meta.destinationIP.isNotEmpty()) return RemoteIp.Known(meta.destinationIP)
    val host = meta.host.ifEmpty { return null }
    val policy = connection.chains.lastOrNull() ?: return null
    return try {
        when (proxies().leafType(policy)) {
            null, "Reject", "RejectDrop" -> null
            "Direct" -> dnsCache(host).ipOf(host)?.let { RemoteIp.Known(it, fromDnsCache = true) }
            else -> RemoteIp.ResolvedByProxy
        }
    } catch (e: MeowApiException) {
        null
    }
}

/**
 * The type of the proxy [name] currently routes through: a group's selection,
 * followed down to a leaf. Null when [name] is unknown or the groups loop.
 */
internal fun ProxiesResult.leafType(name: String): String? {
    var current = name
    repeat(MAX_GROUP_DEPTH) {
        val group = groups[current] ?: return proxies[current]?.type
        // A group without a single pick (load-balance) stands for its members.
        current = group.now.ifEmpty { return group.type }
    }
    return null
}

private const val MAX_GROUP_DEPTH = 16

private const val NOTES_POLL_INTERVAL_MS = 1_000L

/** The first address the cache holds for exactly [host]; the search also matches substrings. */
internal fun List<DnsResult>.ipOf(host: String): String? =
    firstOrNull { it.name.trimEnd('.').equals(host.trimEnd('.'), ignoreCase = true) && it.ips.isNotEmpty() }
        ?.ips?.first()
