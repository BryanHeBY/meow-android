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

/** IPv4 DNS always enters the TUN. With no IPv6 address, route, DNS server,
 * or allowFamily call, Android blocks IPv6 for the apps covered by the VPN.
 */
internal fun configureVpnIp(
    ipv6: Boolean,
    addAddress: (String, Int) -> Unit,
    addRoute: (String, Int) -> Unit,
    addDnsServer: (String) -> Unit,
) {
    addAddress("172.19.0.1", 30)
    addDnsServer("172.19.0.2")
    addRoute("0.0.0.0", 0)
    if (ipv6) {
        addAddress("fdfe:dcba:9876::1", 126)
        addRoute("::", 0)
    }
}
