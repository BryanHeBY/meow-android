package io.github.madeye.meow.ui.screens.home

import io.github.madeye.meow.BuildConfig
import io.github.madeye.meow.bg.BaseService
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Test

class HomeForwardingTest {
    @Test
    fun `only a connected profiled session with ZeroTier can pause Meow`() {
        val connected = HomeUiState(state = BaseService.State.Connected, hasProfile = true, overlayForwarding = true)
        assertEquals(BuildConfig.ZEROTIER, connected.showMeowForwarding)
        assertEquals(BuildConfig.ZEROTIER, connected.canToggleMeowForwarding)
        assertEquals(BuildConfig.ZEROTIER, connected.copy(meowForwarding = false).canToggleMeowForwarding)
        assertFalse(connected.copy(forwardingChangePending = true).canToggleMeowForwarding)
        assertFalse(connected.copy(overlayForwarding = false).canToggleMeowForwarding)
        assertFalse(connected.copy(hasProfile = false).showMeowForwarding)
        assertFalse(connected.copy(state = BaseService.State.Stopping).showMeowForwarding)
    }
}
