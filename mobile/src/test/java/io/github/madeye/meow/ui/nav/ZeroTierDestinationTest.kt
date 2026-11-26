package io.github.madeye.meow.ui.nav

import io.github.madeye.meow.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ZeroTierDestinationTest {
    @Test fun zeroTierIsOnlyATopLevelDestinationInTheFullEdition() {
        assertEquals(if (BuildConfig.ZEROTIER) 1 else 0, TABS.count { it.testTag == "tab_zerotier" })
        assertEquals(TABS.size, TABS.map { it.testTag }.distinct().size)
        assertTrue(TABS.any { it.dest == Dest.Home })
    }
}
