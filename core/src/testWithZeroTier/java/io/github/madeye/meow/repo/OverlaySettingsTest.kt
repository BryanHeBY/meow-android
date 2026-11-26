package io.github.madeye.meow.repo

import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

class OverlaySettingsTest {
    @Test fun canonicalSettingsRoundTripWithoutChangingOtherAppRules() = runBlocking {
        val root = Files.createTempDirectory("meowz-settings-test").toFile()
        try {
            val store = OverlaySettingsRepository(root)
            assertEquals(OverlaySettings(), store.load())
            val settings = OverlaySettings(
                enabled = true,
                network = " F123456789ABCDEF ",
                routes = listOf(" 10.0.0.0/24 ", "10.0.0.0/24"),
                packages = setOf("com.example"),
                moons = listOf(MoonSetting("ABCDEF1234", "ABCDEF1234")),
            )
            store.save(settings)
            assertEquals(
                settings.copy(
                    network = "f123456789abcdef",
                    routes = listOf("10.0.0.0/24"),
                    moons = listOf(MoonSetting("000000abcdef1234", "abcdef1234")),
                ),
                OverlaySettingsRepository(root).load(),
            )
        } finally { root.deleteRecursively() }
    }

    @Test fun addingOnlySavesThenSelectingSwitchesWithoutDroppingOtherRows() {
        val first = "1234567890abcdef"
        val second = "abcdef1234567890"
        val legacy = OverlaySettings(enabled = true, network = first, routes = listOf("10.8.0.0/24"))
        val saved = requireNotNull(legacy.addNetwork(second.uppercase()))
        assertEquals(listOf(first, second), saved.networkList().map { it.id })
        assertEquals(first, saved.network)
        assertEquals(saved, saved.addNetwork(second))
        assertEquals(emptyList<String>(), saved.activateNetwork(second)?.routes)
        assertEquals(listOf("10.8.0.0/24"), saved.activateNetwork(first)?.routes)
        val removed = saved.removeNetwork(first)
        assertFalse(removed.enabled)
        assertEquals(listOf(second), removed.networkList().map { it.id })
    }

    @Test fun routesAndDnsBelongToSavedNetworkNotTheWholeApp() {
        val fire = "1234567890abcdef"
        val local = "abcdef1234567890"
        val rows = requireNotNull(OverlaySettings().addNetwork(fire, true, "custom", listOf("10.8.0.1")))
        val updated = requireNotNull(rows.addNetwork(local, false, "network"))
        val exit = requireNotNull(updated.activateNetwork(fire))
        assertEquals(true, exit.allowDefault)
        assertEquals("custom", exit.dnsMode)
        assertEquals(listOf("10.8.0.1"), exit.dnsServers)
        val managed = requireNotNull(exit.activateNetwork(local))
        assertFalse(managed.allowDefault)
        assertEquals("network", managed.dnsMode)
        assertEquals(emptyList<String>(), managed.dnsServers)
        assertNull(OverlaySettings.normalizeDns("custom", listOf("01.1.1.1")))
        assertNull(OverlaySettings.normalizeDns("custom", listOf("fe80::1")))
        assertNull(OverlaySettings.normalizeDns("custom", emptyList()))
    }

    @Test fun rejectsMissingJoinDataDefaultRouteAndDuplicateWorld() {
        val base = OverlaySettings(enabled = true, network = "1234567890abcdef")
        assertNotNull(base.validated())
        assertNull(base.copy(network = "").validated())
        assertNull(base.copy(routes = listOf("0.0.0.0/0")).validated())
        assertNull(base.copy(routes = listOf("10.0.0.0/24"), moons = listOf(
            MoonSetting("123456789a", "0123456789"), MoonSetting("000000123456789a", "0123456789"),
        )).validated())
    }
}
