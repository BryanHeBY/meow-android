package io.github.madeye.meow

import io.github.madeye.meow.aidl.ControllerEndpoint
import io.github.madeye.meow.bg.BaseService.State
import io.github.madeye.meow.vpn.VpnLifecycle

internal fun runningVpn(runId: String, binding: Long = 0, profileId: Long? = null) = VpnLifecycle(
    state = State.Connected,
    binding = binding,
    runId = runId,
    profileId = profileId,
    controller = ControllerEndpoint(22901, "a".repeat(64)),
)
