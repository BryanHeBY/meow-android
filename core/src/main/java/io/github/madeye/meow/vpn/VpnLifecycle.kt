package io.github.madeye.meow.vpn

import io.github.madeye.meow.aidl.ControllerEndpoint
import io.github.madeye.meow.bg.BaseService

data class VpnLifecycle(
    val state: BaseService.State = BaseService.State.Idle,
    val binding: Long = 0,
    val runId: String? = null,
    val profileId: Long? = null,
    val profileName: String = "",
    val controller: ControllerEndpoint? = null,
) {
    val session: ControllerSession?
        get() = if (state != BaseService.State.Connected || runId == null || controller == null) {
            null
        } else {
            ControllerSession(binding, runId, profileId, controller)
        }
}

/** Binder reconnect invalidates in-flight work even if the engine itself survived. */
data class ControllerSession(
    val binding: Long,
    val runId: String,
    val profileId: Long?,
    val controller: ControllerEndpoint,
)
