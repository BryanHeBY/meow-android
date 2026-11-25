package io.github.madeye.meow.bg

import io.github.madeye.meow.repo.PerAppMode
import org.junit.Assert.assertEquals
import org.junit.Test

class VpnAppCaptureTest {
    private fun VpnAppCapture.captures(pkg: String): Boolean = when (mode) {
        "allow" -> pkg in packages
        "exclude" -> pkg !in packages
        else -> true
    }

    @Test
    fun androidCaptureEqualsTheUnionOfBothChannels() {
        val filters = listOf(
            VpnAppCapture("all"),
            VpnAppCapture("allow"),
            VpnAppCapture("exclude"),
            VpnAppCapture("allow", setOf("a", "both")),
            VpnAppCapture("exclude", setOf("b", "both")),
            VpnAppCapture("allow", setOf("b")),
        )
        for (clash in filters) for (zeroTier in filters) {
            for (pkg in listOf("a", "b", "both", "other")) {
                assertEquals(
                    clash.captures(pkg) || zeroTier.captures(pkg),
                    clash.union(zeroTier).captures(pkg),
                )
            }
        }
    }

    @Test
    fun legacyEmptyClashListStillMeansAllApps() {
        for (mode in PerAppMode.entries) {
            assertEquals(VpnAppCapture("all"), VpnAppCapture.fromClash(mode, emptySet()))
        }
    }
}
