package io.github.madeye.meow.aidl

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/** The state and engine identity captured together by the VPN service. */
@Parcelize
data class VpnServiceSnapshot(
    val state: Int,
    val revision: Long = 0,
    val runId: String? = null,
    val profileId: Long? = null,
    val profileName: String = "",
    val controller: ControllerEndpoint? = null,
) : Parcelable

/** The app controller address and capability for exactly one engine run. */
@Parcelize
data class ControllerEndpoint(val port: Int, private val capability: String) : Parcelable {
    init {
        require(port in 1..65535 && capability.length == 64 && capability.all { it in '0'..'9' || it in 'a'..'f' }) {
            "Invalid app controller endpoint"
        }
    }

    internal fun authorizationHeader(): String = "Meow-Run $capability"

    override fun toString(): String = "ControllerEndpoint(port=$port)"
}
