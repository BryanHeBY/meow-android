package io.github.madeye.meow.bg

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunEnvelopeTest {
    private val all = TunEnvelope(VpnAppCapture("all"), ipv6 = false, metered = false)

    @Test
    fun `all application capture does not change when overlay adds an app subset`() {
        val combined = all.capture.union(VpnAppCapture("allow", setOf("example.app")))
        assertFalse(all.requiresNewInterface(all.copy(capture = combined)))
        assertFalse(all.requiresNewInterface(all.copy(capture = VpnAppCapture("exclude"))))
    }

    @Test
    fun `adding an allowed package requires a new Android interface`() {
        val limited = all.copy(capture = VpnAppCapture("allow", setOf("example.meow")))
        val combined = limited.capture.union(VpnAppCapture("allow", setOf("example.zt")))
        assertTrue(limited.requiresNewInterface(limited.copy(capture = combined)))
        assertTrue(limited.requiresNewInterface(all))
    }

    @Test
    fun `the IPv6 and metered flags are part of the VPN envelope`() {
        assertTrue(all.requiresNewInterface(all.copy(ipv6 = true)))
        assertTrue(all.requiresNewInterface(all.copy(metered = true)))
    }
}
