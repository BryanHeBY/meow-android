package io.github.madeye.meow.vpn

import io.github.madeye.meow.bg.BaseService

data class VpnLifecycle(
    val state: BaseService.State = BaseService.State.Idle,
    val binding: Long = 0,
    val runId: String? = null,
    val profileId: Long? = null,
    val profileName: String = "",
    val connectedAtMillis: Long = 0,
) {
    val session: ControllerSession?
        get() = runId?.takeIf { state == BaseService.State.Connected }?.let {
            ControllerSession(binding, it, profileId, connectedAtMillis)
        }
}

/** Binder reconnect invalidates in-flight work even if the engine itself survived. */
data class ControllerSession(
    val binding: Long,
    val runId: String,
    val profileId: Long?,
    val connectedAtMillis: Long,
)
