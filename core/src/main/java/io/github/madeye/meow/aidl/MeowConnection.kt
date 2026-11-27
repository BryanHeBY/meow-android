package io.github.madeye.meow.aidl

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.RemoteException
import io.github.madeye.meow.bg.ForwardingControl
import io.github.madeye.meow.diagnostics.FaultDiagnostics
import io.github.madeye.meow.diagnostics.FaultKind
import io.github.madeye.meow.diagnostics.FaultProcess
import java.io.IOException
import timber.log.Timber

class MeowConnection(private val listenForBandwidth: Boolean = false) : ServiceConnection {

    interface Callback {
        fun lifecycleChanged(binding: Long, snapshot: VpnServiceSnapshot?, msg: String?)
        fun trafficUpdated(profileId: Long, stats: TrafficStats)
        fun trafficPersisted(profileId: Long)
        fun forwardingChanged(flags: Int)
    }

    private var callback: Callback? = null
    // Volatile: proxy probes read it from IO threads.
    @Volatile private var service: IMeowService? = null
    private var attachment: Attachment? = null
    private var generation = 0L
    private var bound = false
    private var bindContext: Context? = null

    private inner class Attachment(val generation: Long) : IMeowServiceCallback.Stub() {
        private var revision = -1L
        private var messageRevision = -1L

        override fun stateChanged(snapshot: VpnServiceSnapshot?, msg: String?) =
            withAttachment { if (snapshot != null) publish(snapshot, msg) }

        override fun trafficUpdated(profileId: Long, stats: TrafficStats?) =
            withAttachment { if (stats != null) callback?.trafficUpdated(profileId, stats) }

        override fun trafficPersisted(profileId: Long) =
            withAttachment { callback?.trafficPersisted(profileId) }

        override fun forwardingChanged(flags: Int) =
            withAttachment { callback?.forwardingChanged(flags) }

        fun publish(snapshot: VpnServiceSnapshot, msg: String? = null) {
            if (snapshot.revision < revision) return
            val newMessage = !msg.isNullOrEmpty() && messageRevision != snapshot.revision
            if (snapshot.revision == revision && !newMessage) return
            revision = snapshot.revision
            if (newMessage) messageRevision = revision
            callback?.lifecycleChanged(generation, snapshot, msg.takeIf { newMessage })
        }

        private inline fun withAttachment(block: () -> Unit) {
            synchronized(this@MeowConnection) {
                if (attachment === this) block()
            }
        }
    }

    @Synchronized
    fun connect(context: Context, callback: Callback) {
        this.callback = callback
        if (bound) return
        bindContext = context
        val intent = Intent(context, io.github.madeye.meow.bg.VpnService::class.java)
            .setAction(io.github.madeye.meow.utils.Action.SERVICE)
        bound = try {
            context.bindService(intent, this, Context.BIND_AUTO_CREATE)
        } catch (e: SecurityException) {
            // A :vpn launch failure only returns false; the bind throws
            // when it is denied outright. Either way nothing is bound.
            Timber.w(e, "bindService refused")
            false
        }
    }

    @Synchronized
    fun disconnect(context: Context) {
        bindContext = null
        val previous = attachment
        val remote = service
        detach()
        if (previous != null) try {
            remote?.unregisterCallback(previous)
        } catch (_: RemoteException) { }
        if (bound) context.unbindService(this)
        bound = false
        callback = null
    }

    @Synchronized
    override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
        if (!bound) return
        val remote = IMeowService.Stub.asInterface(binder) ?: return
        val current = Attachment(++generation)
        service = remote
        attachment = current
        try {
            remote.registerCallback(current)
            if (listenForBandwidth) remote.startListeningForBandwidth(current, 1000)
            callback?.forwardingChanged(remote.forwardingFlags)
            current.publish(remote.lifecycle)
        } catch (e: RemoteException) {
            Timber.w(e)
            detach()
        }
    }

    @Synchronized
    override fun onServiceDisconnected(name: ComponentName?) {
        if (!bound) return
        FaultDiagnostics.record(FaultProcess.UI, FaultKind.VPN_BINDER_LOST)
        detach()
        // The binding stays registered. Android calls onServiceConnected
        // again when the service process is available.
    }

    @Synchronized
    override fun onBindingDied(name: ComponentName?) {
        val context = bindContext ?: return
        val listener = callback ?: return
        disconnect(context)
        connect(context, listener)
    }

    @Synchronized
    fun refresh() {
        val remote = service ?: return
        try {
            attachment?.publish(remote.lifecycle)
        } catch (e: RemoteException) {
            Timber.w(e)
            detach()
        }
    }

    private fun detach() {
        attachment = null
        service = null
        callback?.forwardingChanged(0)
        callback?.lifecycleChanged(++generation, null, null)
    }

    /**
     * Runs one proxy-detail probe in `:vpn` and returns its JSON answer,
     * blocking until it ends. Throws [IOException] when the service is not
     * bound or its process died mid-probe.
     */
    fun probeProxy(id: Long, proxy: String, kind: String, arg: String): String {
        val service = service ?: throw IOException("the VPN service is not bound")
        return try {
            service.probeProxy(id, proxy, kind, arg)
        } catch (e: RemoteException) {
            throw IOException("the VPN service went away", e)
        } ?: throw IOException("the VPN service gave no answer")
    }

    fun cancelProxyProbe(id: Long) {
        try {
            service?.cancelProxyProbe(id)
        } catch (_: RemoteException) {
            // Gone with its process, and its probes with it.
        }
    }

    /** Saves the DNS preference and applies it to any running VPN. */
    fun setBuiltinDns(enabled: Boolean): String? {
        val service = service ?: throw IOException("The VPN service is unavailable")
        return try {
            service.setBuiltinDns(enabled)
        } catch (e: RemoteException) {
            throw IOException("Could not confirm the DNS change", e)
        }
    }

    fun applyZeroTier(): Int = callForwarding { applyZeroTier() }

    fun setMeowForwarding(enabled: Boolean): Int = callForwarding { setMeowForwarding(enabled) }

    private inline fun callForwarding(call: IMeowService.() -> Int): Int = try {
        service?.call() ?: ForwardingControl.OFFLINE
    } catch (_: RemoteException) {
        // Do not report success or restart automatically on lost IPC.
        ForwardingControl.FAILED
    }

    /** The running session's stats; null when no VPN runs or `:vpn` is not bound. */
    fun sessionStats(): SessionStats? = try {
        service?.sessionStats
    } catch (_: RemoteException) {
        // Gone with its process, and the session with it.
        null
    }
}
