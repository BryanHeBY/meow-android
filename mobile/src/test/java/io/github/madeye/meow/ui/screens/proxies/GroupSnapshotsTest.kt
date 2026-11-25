package io.github.madeye.meow.ui.screens.proxies

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GroupSnapshotsTest {
    @Test
    fun `a transient failure keeps last good rows but a successful empty response clears them`() {
        val store = GroupSnapshots<Long, String>()
        assertTrue(store.switchTo(1))
        store.finish(store.begin(), listOf("Proxy"))
        store.finish(store.begin(), null)
        assertEquals(listOf("Proxy"), store.snapshot.rows)
        assertTrue(store.snapshot.failed)
        store.finish(store.begin(), emptyList())
        assertEquals(emptyList<String>(), store.snapshot.rows)
        assertFalse(store.snapshot.failed)
    }

    @Test
    fun `late results cannot overwrite newer requests or cross stop and profile switch`() {
        val store = GroupSnapshots<Long, String>()
        store.switchTo(1)
        val delayed = store.begin()
        store.finish(store.begin(), listOf("First"))
        assertFalse(store.finish(delayed, null))
        val oldSession = store.begin()
        store.switchTo(null)
        store.switchTo(1)
        assertFalse(store.finish(oldSession, listOf("Old")))
        val previousProfile = store.begin()
        store.switchTo(2)
        assertFalse(store.finish(previousProfile, listOf("Wrong profile")))
        assertTrue(store.snapshot.rows.isEmpty())
    }
}
