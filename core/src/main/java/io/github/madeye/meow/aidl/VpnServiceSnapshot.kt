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
    val connectedAtMillis: Long = 0,
) : Parcelable
