package io.github.madeye.meow.preference

import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class BuiltinDnsPreferenceTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun `a failed resolver rebuild leaves the existing DNS preference on disk`() = runBlocking {
        val store = BuiltinDnsStore(File(tmp.root, "builtin_dns"))
        val requested = mutableListOf<Boolean>()
        val preference = BuiltinDnsPreference(store) {
            store.commit(it) { enabled ->
                requested.add(enabled)
                assertTrue(store.load())
                "rule-set: missing"
            }
        }

        assertEquals("rule-set: missing", preference.save(false))
        assertEquals(listOf(false), requested)
        assertTrue(preference.load())
    }

    @Test
    fun `the preference is published only after a successful live apply`() = runBlocking {
        val store = BuiltinDnsStore(File(tmp.root, "builtin_dns"))
        val preference = BuiltinDnsPreference(store) {
            store.commit(it) { enabled ->
                assertFalse(enabled)
                assertTrue(store.load())
                null
            }
        }
        assertNull(preference.save(false))
        assertFalse(preference.load())
    }

    @Test
    fun `a disk publication failure rolls back the live change`() {
        val target = File(tmp.root, "builtin_dns")
        val store = BuiltinDnsStore(target)
        val requested = mutableListOf<Boolean>()
        val failure = store.commit(false) {
            requested.add(it)
            // Remove the staged replacement after live apply to fail publication.
            if (!it) assertTrue(File(target.path + ".tmp").delete())
            null
        }
        assertEquals("Cannot save the DNS preference", failure)
        assertEquals(listOf(false, true), requested)
        assertTrue(store.load())
    }

    @Test
    fun `disk failure preserves a running fallback even when the saved preference is profile DNS`() {
        val target = File(tmp.root, "builtin_dns")
        val store = BuiltinDnsStore(target)
        store.save(false)
        val requested = mutableListOf<Boolean>()
        val failure = store.commit(true, applied = { true }) {
            requested.add(it)
            assertTrue(File(target.path + ".tmp").delete())
            null
        }
        assertEquals("Cannot save the DNS preference", failure)
        assertEquals(listOf(true), requested)
        assertFalse(store.load())
    }
}
