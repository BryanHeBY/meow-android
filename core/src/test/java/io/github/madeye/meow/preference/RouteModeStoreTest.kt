package io.github.madeye.meow.preference

import io.github.madeye.meow.api.RouteMode
import java.io.File
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RouteModeStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun storeFile(): File = File(tmp.root, "route_mode")

    @Test
    fun `nothing saved means follow the profile`() {
        assertNull(RouteModeStore(storeFile()).load())
    }

    @Test
    fun `a save is visible to a separate instance`() {
        // Stands in for the UI process writing and `:vpn` reading.
        RouteModeStore(storeFile()).save(RouteMode.Direct)

        assertEquals(RouteMode.Direct, RouteModeStore(storeFile()).load())
    }

    @Test
    fun `a later save replaces the earlier one`() {
        val store = RouteModeStore(storeFile())
        store.save(RouteMode.Global)
        store.save(RouteMode.Rule)

        assertEquals(RouteMode.Rule, store.load())
        assertFalse(File(tmp.root, "route_mode.tmp").exists())
    }

    @Test
    fun `clear restores the next selected profile mode instead of saving rule`() {
        val file = storeFile()
        val ui = RouteModeStore(file)
        val vpn = RouteModeStore(file)
        ui.save(RouteMode.Rule)
        assertEquals("rule", vpn.load()?.wire.orEmpty())

        ui.clear()
        assertFalse(file.exists())
        assertEquals("", vpn.load()?.wire.orEmpty())
        assertEquals(RouteMode.Global, vpn.load() ?: RouteMode.configured("mode: global"))
        assertEquals(RouteMode.Direct, vpn.load() ?: RouteMode.configured("mode: direct"))

        // Reset is idempotent, and an explicit Home choice can still replace it.
        ui.clear()
        ui.save(RouteMode.Global)
        assertEquals(RouteMode.Global, vpn.load())
    }

    @Test
    fun `clear surfaces a failed removal rather than claiming inheritance`() {
        val file = storeFile()
        check(file.mkdir())
        File(file, "busy").writeText("fixture")
        assertThrows(IOException::class.java) { RouteModeStore(file).clear() }
    }

    @Test
    fun `an unreadable value is ignored`() {
        storeFile().writeText("script")

        assertNull(RouteModeStore(storeFile()).load())
    }
}
