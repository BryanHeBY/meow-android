package io.github.madeye.meow.bg

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnIpPlanTest {
    @Test
    fun `without IPv6 the VPN still routes IPv4 and DNS, and supplies no IPv6 exception`() {
        assertEquals(
            listOf("address 172.19.0.1/30", "dns 172.19.0.2", "route 0.0.0.0/0"),
            builderCalls(ipv6 = false),
        )
    }

    @Test
    fun `IPv6 adds both the TUN address and default VPN route while DNS stays in the TUN`() {
        assertEquals(
            listOf("address 172.19.0.1/30", "dns 172.19.0.2", "route 0.0.0.0/0",
                "address fdfe:dcba:9876::1/126", "route ::/0"),
            builderCalls(ipv6 = true),
        )
    }

    private fun builderCalls(ipv6: Boolean) = buildList {
        configureVpnIp(
            ipv6,
            { address, prefix -> add("address $address/$prefix") },
            { route, prefix -> add("route $route/$prefix") },
            { dns -> add("dns $dns") },
        )
    }
}
