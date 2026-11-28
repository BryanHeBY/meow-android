package io.github.madeye.meow.bg

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunEnvelopeTest {
    private val all = TunEnvelope(VpnAppCapture("all"), ipv6 = false, metered = false)

    @Test
    fun `native forwarding JSON preserves DNS snapshot and overlay precedence settings`() {
        val overlay = """{"enabled":true,"clash_app_mode":"exclude","clash_packages":["example.app"]}"""
        val base = Json.parseToJsonElement(overlay).jsonObject
        val before = TunPlan(all, overlayEnabled = true, overlayJson = overlay, dnsHijacking = false)
        val next = before.copy(dnsHijacking = true)
        assertFalse(before.envelope.requiresNewInterface(next.envelope))
        for (meow in listOf(false, true)) {
            for (plan in listOf(before, next)) {
                val wire = Json.parseToJsonElement(plan.nativeConfig(meow)).jsonObject
                assertEquals(JsonPrimitive(meow), wire["meow_forwarding"])
                assertEquals(JsonPrimitive(plan.dnsHijacking), wire["dns_hijacking"])
                assertEquals(base.toMap(), wire - setOf("meow_forwarding", "dns_hijacking"))
            }
        }
        val lite = before.copy(overlayEnabled = false, overlayJson = "{}")
        assertEquals(
            mapOf("meow_forwarding" to JsonPrimitive(true), "dns_hijacking" to JsonPrimitive(false)),
            Json.parseToJsonElement(lite.nativeConfig(true)).jsonObject.toMap(),
        )
    }

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
