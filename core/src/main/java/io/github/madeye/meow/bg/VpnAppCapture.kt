package io.github.madeye.meow.bg

import io.github.madeye.meow.repo.PerAppMode

/** Android has one UID filter, while the TUN dispatcher has one policy per egress. */
internal data class VpnAppCapture(val mode: String, val packages: Set<String> = emptySet()) {
    fun union(other: VpnAppCapture): VpnAppCapture {
        if (mode == "all" || other.mode == "all") return VpnAppCapture("all")
        return when {
            mode == "allow" && other.mode == "allow" -> VpnAppCapture("allow", packages + other.packages)
            mode == "exclude" && other.mode == "exclude" -> VpnAppCapture("exclude", packages intersect other.packages)
            mode == "exclude" -> VpnAppCapture("exclude", packages - other.packages)
            else -> VpnAppCapture("exclude", other.packages - packages)
        }
    }

    companion object {
        fun fromClash(mode: PerAppMode?, packages: Set<String>): VpnAppCapture = when {
            packages.isEmpty() -> VpnAppCapture("all")
            mode == PerAppMode.Proxy -> VpnAppCapture("allow", packages)
            mode == PerAppMode.Bypass -> VpnAppCapture("exclude", packages)
            else -> VpnAppCapture("all")
        }
    }
}
