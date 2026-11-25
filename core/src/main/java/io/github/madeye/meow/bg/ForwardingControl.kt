package io.github.madeye.meow.bg

/** Shared Binder result and applied state; master VPN status is independent. */
object ForwardingControl {
    const val APPLIED = 0
    const val FAILED = -1
    const val OFFLINE = 2
    const val REBUILT = 3
    const val STOPPED = 4
    const val INDETERMINATE = 5

    internal const val MEOW = 1
    internal const val ZEROTIER = 2
}

/** Fields set in Builder and allowed to vary without a Meow profile restart.
 * The addresses, family routes, DNS stub and MTU are otherwise fixed by VpnService.
 */
internal data class TunEnvelope(
    val capture: VpnAppCapture,
    val ipv6: Boolean,
    val metered: Boolean,
) {
    fun requiresNewInterface(other: TunEnvelope): Boolean =
        ipv6 != other.ipv6 || metered != other.metered || capture.canonical() != other.capture.canonical()
}

private fun VpnAppCapture.canonical(): VpnAppCapture =
    if (mode == "all" || (mode == "exclude" && packages.isEmpty())) VpnAppCapture("all") else this
