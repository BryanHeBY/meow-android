package io.github.madeye.meow.preference

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DnsHostsOverrideTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun independentScopeInheritanceAndReset() {
        val store = ConfigurationOverrideStore(temporary.newFolder())
        val table = mapOf("a.test" to "192.0.2.53", "b.test" to "2001:db8::53")
        store.save(null, ConfigurationOverride(dnsHosts = DnsHostsOverride(table, true)))
        store.save(12, ConfigurationOverride(dnsHosts = DnsHostsOverride(useHosts = false)))
        assertEquals(DnsHostsOverride(table, false), store.effective(12).dnsHosts)
        assertEquals(DnsHostsOverride(table, true), store.effective(13).dnsHosts)
        store.save(12, ConfigurationOverride(dnsHosts = DnsHostsOverride(emptyMap())))
        assertEquals(DnsHostsOverride(emptyMap(), true), store.effective(12).dnsHosts)
        store.save(12, ConfigurationOverride())
        assertEquals(DnsHostsOverride(table, true), store.effective(12).dnsHosts)
    }

    @Test fun parserDoesNotResolveHostnamesAndRejectsInvalidLiterals() {
        assertEquals(mapOf("a.test" to "192.0.2.53", "b.test" to "2001:db8::53"),
            DnsHostsRuntime.parseRows("A.TEST. 192.0.2.53\nb.test 2001:db8::53"))
        assertEquals(emptyMap<String, String>(), DnsHostsRuntime.parseRows(""))
        for (text in listOf("a.test 300.1.1.1", "a.test ::bad::", "a.test example.com",
            "a.test 192.0.2.1\nA.TEST. 192.0.2.2", "*.test 192.0.2.1")) assertNull(text, DnsHostsRuntime.parseRows(text))
    }
}
