package io.github.madeye.meow.ui.screens.subscribe

import androidx.compose.runtime.Immutable
import io.github.madeye.meow.api.ControllerAccess
import io.github.madeye.meow.api.ControllerStatus
import io.github.madeye.meow.api.RuleProviderInfo
import io.github.madeye.meow.api.controllerStatus
import java.io.IOException
import java.time.Instant
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.update
import io.github.madeye.meow.vpn.ControllerSession
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import timber.log.Timber

/**
 * Whether [yaml] has a top-level `rule-providers:` key, i.e. rule sets the
 * engine downloads. Matched at the start of a line, so an indented key or a
 * comment does not count; a profile saved with a byte-order mark still does.
 */
fun declaresRuleSets(yaml: String): Boolean = RULE_PROVIDERS_KEY.containsMatchIn(yaml)

private val RULE_PROVIDERS_KEY = Regex("^\uFEFF?rule-providers:", RegexOption.MULTILINE)

/**
 * Only an HTTP provider has anything to update. The engine re-reads a File
 * one, but nothing on Android changes that file, and an inline one has
 * nothing to re-read.
 */
private val RuleProviderInfo.isHttp: Boolean
    get() = vehicleType.equals("HTTP", ignoreCase = true)

/**
 * The running engine's HTTP rule sets: how many, and the oldest of their
 * update times, so a subtitle can say every set is at least that fresh.
 * [oldestUpdateMillis] is null when no time parses: the engine sends an empty
 * one for a set it has never fetched.
 */
@Immutable
data class RuleSetSummary(val count: Int, val oldestUpdateMillis: Long?) {
    companion object {
        fun of(providers: List<RuleProviderInfo>): RuleSetSummary {
            val http = providers.filter { it.isHttp }
            return RuleSetSummary(
                count = http.size,
                oldestUpdateMillis = http
                    .mapNotNull { runCatching { Instant.parse(it.updatedAt).toEpochMilli() }.getOrNull() }
                    .minOrNull(),
            )
        }
    }
}

/**
 * What the Subscriptions page's "Update rule sets" row needs. Rule sets are
 * the running engine's state. [profileId] identifies which row can show them.
 * [summary] is null until the engine has listed them.
 */
@Immutable
data class RuleSetsUi(
    val connected: Boolean = false,
    val summary: RuleSetSummary? = null,
    val updating: Boolean = false,
    val profileId: Long? = null,
    val status: ControllerStatus = ControllerStatus.Offline,
) {
    /** Connected, and the engine says there is nothing to update. */
    val nothingToUpdate: Boolean get() = connected && summary?.count == 0
}

/**
 * "Update rule sets", as Surge's "Update External Resources": downloads every
 * HTTP rule set of the running profile again, without waiting for each one's
 * `interval`.
 *
 * Kept out of [SubscribeViewModel], which owns it, so tests can drive it with
 * plain functions in place of the engine. The ViewModel lives on Home's
 * back-stack entry, so an update keeps going when the user leaves the page.
 */
class RuleSetUpdater(
    private val controller: ControllerAccess,
    private val listProviders: suspend (ControllerSession) -> List<RuleProviderInfo>,
    private val updateProvider: suspend (session: ControllerSession, name: String) -> Unit,
) {
    companion object {
        /**
         * Updates in flight at once. Each holds its call open until the
         * engine has downloaded the set, and OkHttp runs five calls per host,
         * so this leaves one for the rest of the app.
         */
        const val UPDATE_CONCURRENCY = 4
    }

    private val reload = MutableStateFlow(0L)
    private val updating = MutableStateFlow<ControllerSession?>(null)
    private val read = controller.observe(
        reload,
        pendingProviders = { providers: List<RuleProviderInfo> -> providers.any { it.isHttp && it.updatedAt.isBlank() } },
    ) { session -> listProviders(session) }

    val state: Flow<RuleSetsUi> = combine(controller.lifecycle, read, updating) { vpn, snapshot, running ->
        val session = vpn.session
        val current = snapshot.takeIf { session != null && it.session == session }
        RuleSetsUi(
            connected = session != null,
            summary = current?.value?.let(RuleSetSummary::of),
            updating = session != null && running == session,
            profileId = session?.profileId,
            status = current?.status ?: vpn.controllerStatus,
        )
    }

    /**
     * Updates every HTTP rule set the engine runs, [UPDATE_CONCURRENCY] at a
     * time, then lists them again for the new times. A failed set keeps the
     * engine's old copy, and the rest still go ahead.
     *
     * Returns what to tell the user, or null when an update is already
     * running: the tap is dropped. Throws when the engine cannot even list
     * the sets. Call it from the main thread, which keeps the running check
     * and the flag that follows it a single step.
     */
    suspend fun updateAll(profileId: Long? = controller.session?.profileId): SubscribeEvent? {
        val session = controller.session?.takeIf { it.profileId == profileId } ?: return null
        if (updating.value == session) return null
        updating.value = session
        try {
            val names = controller.read(session) { listProviders(session) }.filter { it.isHttp }.map { it.name }
            val limiter = Semaphore(UPDATE_CONCURRENCY)
            val failed = coroutineScope {
                names.map { name ->
                    async { limiter.withPermit { update(session, name) } }
                }.awaitAll().count { ok -> !ok }
            }
            controller.requireCurrent(session)
            reload.update { it + 1 }
            return if (failed == 0) {
                SubscribeEvent.RuleSetsUpdated(names.size)
            } else {
                SubscribeEvent.RuleSetsUpdateFailed(failed)
            }
        } finally {
            updating.compareAndSet(session, null)
        }
    }

    private suspend fun update(session: ControllerSession, name: String): Boolean =
        try {
            controller.write(session) { updateProvider(session, name) }
            true
        } catch (e: IOException) {
            controller.requireCurrent(session)
            Timber.w(e, "updating rule set %s failed", name)
            false
        }
}
