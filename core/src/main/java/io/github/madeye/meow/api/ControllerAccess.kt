package io.github.madeye.meow.api

import android.os.SystemClock
import io.github.madeye.meow.bg.BaseService
import io.github.madeye.meow.vpn.ControllerSession
import io.github.madeye.meow.vpn.VpnLifecycle
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.transformLatest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

enum class ControllerStatus { Offline, Loading, Ready, Stale, Failed }

data class ControllerSnapshot<T>(
    val session: ControllerSession? = null,
    val status: ControllerStatus = ControllerStatus.Loading,
    val value: T? = null,
    val waitingForProviders: Boolean = false,
)

/** A successful authenticated GET is itself a readiness check for the resource it reads. */
class ControllerAccess(
    val lifecycle: StateFlow<VpnLifecycle>,
    private val now: () -> Long = SystemClock::elapsedRealtime,
) {
    val session: ControllerSession? get() = lifecycle.value.session

    fun isCurrent(session: ControllerSession): Boolean = this.session == session

    fun requireCurrent(session: ControllerSession) {
        if (!isCurrent(session)) throw CancellationException("VPN session changed")
    }

    /**
     * For idempotent reads only. Use a single bounded window for startup/refused
     * sockets and authenticate afresh on every attempt.
     */
    suspend fun <T> read(session: ControllerSession, get: suspend () -> T): T = inSession(session) {
        val result = withTimeoutOrNull(READ_TIMEOUT_MS) {
            var attempt = 0
            while (true) {
                requireCurrent(session)
                try {
                    val value = get()
                    requireCurrent(session)
                    return@withTimeoutOrNull ReadValue(value)
                } catch (e: MeowApiException) {
                    val backoff = READ_DELAYS.getOrNull(attempt++) ?: throw e
                    if (!retryTransport(session, e, backoff)) throw e
                }
            }
            @Suppress("UNREACHABLE_CODE")
            error("read loop completed")
        } ?: throw MeowApiException.Unreachable(IOException("controller read timed out"))
        result.value
    }

    /** Dispatches a mutation once and ignores an answer from a superseded session. */
    suspend fun <T> write(session: ControllerSession, mutate: suspend () -> T): T = inSession(session, mutate)

    private suspend fun <T> inSession(session: ControllerSession, operation: suspend () -> T): T = coroutineScope {
        requireCurrent(session)
        val invalidation = launch(start = CoroutineStart.UNDISPATCHED) {
            lifecycle.first { it.session != session }
            this@coroutineScope.cancel("VPN session changed")
        }
        try {
            val result = operation()
            requireCurrent(session)
            result
        } finally {
            invalidation.cancel()
        }
    }

    /** Also used by the logs handshake. */
    suspend fun retryTransport(session: ControllerSession, error: Throwable, backoff: Long): Boolean {
        requireCurrent(session)
        when {
            error is MeowApiException.Http && error.code == 401 -> {
                if (!mayRetryAuth(session, error)) return false
                delay(backoff)
                requireCurrent(session)
                return mayRetryAuth(session, error)
            }
            error is MeowApiException.Unreachable ||
                (error is IOException && error !is MeowApiException) -> {
                delay(backoff)
                requireCurrent(session)
                return true
            }
            else -> return false
        }
    }

    private suspend fun mayRetryAuth(session: ControllerSession, error: MeowApiException.Http): Boolean =
        now() - session.connectedAtMillis < AUTH_STARTUP_MS ||
            error.authorizationChanged?.let { changed -> withContext(Dispatchers.IO) { changed() } } == true

    /**
     * Maintains the last successful read within one attachment. Only a configured
     * provider awaiting its first update earns additional reads.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    fun <T : Any> observe(
        refreshes: StateFlow<Long> = MutableStateFlow(0L),
        pendingProviders: (T) -> Boolean = { false },
        onFailure: (MeowApiException) -> Unit = {},
        get: suspend (ControllerSession) -> T,
    ): Flow<ControllerSnapshot<T>> = lifecycle.flatMapLatest { vpn ->
        val session = vpn.session
        if (session == null) {
            flowOf(ControllerSnapshot(status = vpn.controllerStatus))
        } else {
            var last: T? = null
            var failed = false
            refreshes.transformLatest {
                val pendingDelays = PROVIDER_DELAYS.iterator()
                if (last == null) emit(ControllerSnapshot(session))
                do {
                    val value = try {
                        read(session) { get(session) }
                    } catch (e: MeowApiException) {
                        requireCurrent(session)
                        if (!failed) onFailure(e)
                        failed = true
                        val status = if (last == null) ControllerStatus.Failed else ControllerStatus.Stale
                        emit(ControllerSnapshot(session, status, last))
                        break
                    }
                    failed = false
                    last = value
                    val pending = pendingProviders(value)
                    emit(ControllerSnapshot(session, ControllerStatus.Ready, value, pending))
                    if (!pending || !pendingDelays.hasNext()) break
                    delay(pendingDelays.next())
                } while (true)
            }.buffer(0)
        }
    }.buffer(0)

    private data class ReadValue<T>(val value: T)

    private companion object {
        const val AUTH_STARTUP_MS = 1_500L
        const val READ_TIMEOUT_MS = 6_000L
        val READ_DELAYS = listOf(100L, 200L, 400L, 800L, 1_200L, 1_600L)
        val PROVIDER_DELAYS = listOf(1_000L, 2_000L, 4_000L, 8_000L, 15_000L)
    }
}

val VpnLifecycle.controllerStatus: ControllerStatus
    get() = when (state) {
        BaseService.State.Idle, BaseService.State.Connecting, BaseService.State.Connected -> ControllerStatus.Loading
        BaseService.State.Stopped, BaseService.State.Stopping -> ControllerStatus.Offline
    }
