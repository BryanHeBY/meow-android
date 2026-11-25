package io.github.madeye.meow.repo

import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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

    @Test fun rejectsMissingJoinDataDefaultRouteAndDuplicateWorld() {
        val base = OverlaySettings(enabled = true, network = "1234567890abcdef")
        assertNull(base.validated())
        assertNull(base.copy(routes = listOf("0.0.0.0/0")).validated())
        assertNull(base.copy(routes = listOf("10.0.0.0/24"), moons = listOf(
            MoonSetting("123456789a", "0123456789"), MoonSetting("000000123456789a", "0123456789"),
        )).validated())
    }
}
