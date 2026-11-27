package io.github.madeye.meow.preference

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import java.io.IOException
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class FakeIpFilterOverrideTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun filterScopeDistinguishesInheritReplacementEmptyAndReset() {
        val store = ConfigurationOverrideStore(temporary.newFolder())
        val global = FakeIpFilterOverride(listOf("+.example.test"), FakeIpFilterMode.BLACKLIST)
        store.save(null, ConfigurationOverride(fakeIpFilter = global))
        store.save(12, ConfigurationOverride(fakeIpFilter = FakeIpFilterOverride(mode = FakeIpFilterMode.WHITELIST)))
        assertEquals(global.copy(mode = FakeIpFilterMode.WHITELIST), store.effective(12).fakeIpFilter)
        assertEquals(global, store.effective(13).fakeIpFilter)
        store.save(12, ConfigurationOverride(fakeIpFilter = FakeIpFilterOverride(emptyList())))
        assertEquals(global.copy(patterns = emptyList()), store.effective(12).fakeIpFilter)
        store.save(12, ConfigurationOverride())
        assertEquals(global, store.effective(12).fakeIpFilter)
        assertThrows(IOException::class.java) {
            store.save(12, ConfigurationOverride(fakeIpFilter = FakeIpFilterOverride(listOf("RULE-SET,private"))))
        }
        assertEquals(global, store.effective(12).fakeIpFilter)
    }

    @Test fun parserAcceptsOnlyDocumentedPatterns() {
        assertEquals(listOf("example.test", "+.lan.test"),
            FakeIpFilterRuntime.parsePatterns("EXAMPLE.TEST.\n+.lan.test"))
        assertEquals(emptyList<String>(), FakeIpFilterRuntime.parsePatterns(""))
        for (text in listOf("a..test", "+.", "*", "RULE-SET,private", "a.test\nA.TEST.", "bad-.test")) {
            assertNull(text, FakeIpFilterRuntime.parsePatterns(text))
        }
    }
}
