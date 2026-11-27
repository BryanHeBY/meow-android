package io.github.madeye.meow.vpn

import android.content.Context
import android.content.Intent
import io.github.madeye.meow.aidl.MeowConnection
import io.github.madeye.meow.aidl.SessionStats
import io.github.madeye.meow.aidl.TrafficStats
import io.github.madeye.meow.aidl.VpnServiceSnapshot
import io.github.madeye.meow.bg.BaseService
import io.github.madeye.meow.bg.ForwardingControl
import io.github.madeye.meow.net.ProxyProbeTransport
import io.github.madeye.meow.utils.Action
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Turns the AIDL service callbacks into flows the UI can collect.
 *
 * The binding stays activity-scoped, exactly as it was before: binding with
 * `BIND_AUTO_CREATE` from a process-lifetime owner would keep the `:vpn`
 * process alive forever.
 */
class VpnStateRepository(
    private val recorder: DailyTrafficRecorder = DailyTrafficRecorder(),
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) : MeowConnection.Callback, ProxyProbeTransport {

    private val connection = MeowConnection(listenForBandwidth = true)

    /**
     * Records run one at a time, in callback order: the recorder derives deltas
     * from the previous sample, so concurrent or reordered records would lose
     * or double-count traffic.
     */
    private val recordDispatcher = Dispatchers.IO.limitedParallelism(1)

    private val _lifecycle = MutableStateFlow(VpnLifecycle())
    val lifecycle: StateFlow<VpnLifecycle> = _lifecycle.asStateFlow()

    private val _state = MutableStateFlow(BaseService.State.Idle)
    val state: StateFlow<BaseService.State> = _state.asStateFlow()

    private val _traffic = MutableStateFlow(TrafficStats())
    val traffic: StateFlow<TrafficStats> = _traffic.asStateFlow()

    private val _profileName = MutableStateFlow("")
    val profileName: StateFlow<String> = _profileName.asStateFlow()

    private val _meowForwarding = MutableStateFlow(true)
    val meowForwarding = _meowForwarding.asStateFlow()
    private val _overlayForwarding = MutableStateFlow(false)
    val overlayForwarding = _overlayForwarding.asStateFlow()

    override fun forwardingChanged(flags: Int) {
        _meowForwarding.value = flags and ForwardingControl.MEOW != 0
        _overlayForwarding.value = flags and ForwardingControl.ZEROTIER != 0
    }

    suspend fun applyZeroTier(): Int = withContext(Dispatchers.IO) { connection.applyZeroTier() }

    suspend fun setMeowForwarding(enabled: Boolean): Int =
        withContext(Dispatchers.IO) { connection.setMeowForwarding(enabled) }

    /** Service-reported failures, surfaced once each (snackbar, not state). */
    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 4)
    val messages: SharedFlow<String> = _messages.asSharedFlow()

    fun bind(context: Context) = connection.connect(context, this)

    fun unbind(context: Context) = connection.disconnect(context)

    /**
     * Re-reads the binder after a resume. The `:vpn` process can be killed while
     * the app is backgrounded, in which case the last state we saw is stale.
     */
    fun refresh() = connection.refresh()

    fun requestStop(context: Context) {
        context.sendBroadcast(Intent(Action.CLOSE).setPackage(context.packageName))
    }

    override fun lifecycleChanged(binding: Long, snapshot: VpnServiceSnapshot?, msg: String?) {
        val next = if (snapshot == null) {
            VpnLifecycle()
        } else {
            VpnLifecycle(
                state = BaseService.State.entries[snapshot.state],
                binding = binding,
                runId = snapshot.runId,
                profileId = snapshot.profileId,
                profileName = snapshot.profileName,
                connectedAtMillis = snapshot.connectedAtMillis,
            )
        }
        if (next.session != null && next.session != _lifecycle.value.session) recorder.reset()
        _lifecycle.value = next
        _state.value = next.state
        if (next.profileName.isNotEmpty()) _profileName.value = next.profileName
        if (!msg.isNullOrEmpty()) _messages.tryEmit(msg)
    }

    override fun trafficUpdated(profileId: Long, stats: TrafficStats) {
        _traffic.value = stats
        scope.launch(recordDispatcher) { recorder.record(stats) }
    }

    override fun trafficPersisted(profileId: Long) = Unit

    override fun probe(id: Long, proxy: String, kind: String, arg: String): String =
        connection.probeProxy(id, proxy, kind, arg)

    override fun cancel(id: Long) = connection.cancelProxyProbe(id)

    /** See [MeowConnection.setBuiltinDns]; blocks, so not on Main. */
    fun applyBuiltinDns(enabled: Boolean): String? = connection.setBuiltinDns(enabled)

    /** See [MeowConnection.sessionStats]; a binder call, so not on Main. */
    fun sessionStats(): SessionStats? = connection.sessionStats()
}
