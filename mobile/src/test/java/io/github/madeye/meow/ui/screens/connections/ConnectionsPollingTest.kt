package io.github.madeye.meow.ui.screens.connections

import io.github.madeye.meow.api.Connection
import io.github.madeye.meow.api.ControllerAccess
import io.github.madeye.meow.api.ControllerStatus
import io.github.madeye.meow.api.MeowApiException
import io.github.madeye.meow.vpn.VpnLifecycle
import io.github.madeye.meow.runningVpn
import java.io.IOException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ConnectionsPollingTest {
    @Test
    fun `a transport outage preserves the live list and only a successful empty poll closes it`() = runTest {
        val vpn = MutableStateFlow(runningVpn("one"))
        val controller = ControllerAccess(vpn)
        val store = RecentConnectionsStore(clock = { currentTime })
        val row = Connection(id = "a")
        var next: List<Connection>? = listOf(row)
        var status = ControllerStatus.Loading
        backgroundScope.launch {
            connectionsPolling(controller, store) {
                next ?: throw MeowApiException.Unreachable(IOException("controller delayed"))
            }.collect { status = it }
        }
        runCurrent()
        assertEquals(listOf(row), store.lists.value.active)
        assertEquals(ControllerStatus.Ready, status)

        next = null
        advanceTimeBy(6_000)
        assertEquals(ControllerStatus.Stale, status)
        assertEquals(listOf(row), store.lists.value.active)
        assertTrue(store.lists.value.recent.isEmpty())

        next = listOf(row)
        advanceTimeBy(5_000)
        assertEquals(ControllerStatus.Ready, status)
        assertTrue(store.lists.value.recent.isEmpty())

        next = emptyList()
        advanceTimeBy(1_001)
        assertTrue(store.lists.value.active.isEmpty())
        assertEquals(listOf(row), store.lists.value.recent.map { it.connection })
    }

    @Test
    fun `an attachment loss preserves rows until the service confirms a replacement engine`() = runTest {
        val vpn = MutableStateFlow(runningVpn("one"))
        val controller = ControllerAccess(vpn)
        val store = RecentConnectionsStore(clock = { currentTime })
        val row = Connection(id = "a")
        backgroundScope.launch {
            connectionsPolling(controller, store) {
                if (controller.session?.runId == "one") listOf(row) else emptyList()
            }.collect {}
        }
        runCurrent()
        vpn.value = VpnLifecycle()
        runCurrent()
        assertEquals(listOf(row), store.lists.value.active)
        assertTrue(store.lists.value.recent.isEmpty())

        vpn.value = runningVpn("two", binding = 2)
        runCurrent()
        assertTrue(store.lists.value.active.isEmpty())
        assertEquals("one", store.lists.value.recent.single().runId)
    }
}
