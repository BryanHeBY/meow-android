package io.github.madeye.meow.ui.nav

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ZeroTierDestinationTest {
    @Test fun zeroTierIsAUniqueTopLevelDestination() {
        assertEquals(1, TABS.count { it.dest == Dest.ZeroTier })
        assertEquals(TABS.size, TABS.map { it.testTag }.distinct().size)
        assertTrue(TABS.any { it.dest == Dest.Home })
        assertEquals(Dest.ZeroTier, Json.decodeFromString<Dest.ZeroTier>(
            Json.encodeToString(Dest.ZeroTier),
        ))
    }
}
