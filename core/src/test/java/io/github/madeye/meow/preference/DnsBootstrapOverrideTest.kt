package io.github.madeye.meow.preference

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DnsBootstrapOverrideTest {
    @get:Rule val temp = TemporaryFolder()

    @Test
    fun `numeric transport nonempty and normalized endpoint identity`() {
        val roots = NumericDnsEndpoints.parse("udp://127.0.0.1:53\ntcp://[2001:db8::53]:5353")!!
        assertEquals(roots, NumericDnsEndpoints.fromJson(NumericDnsEndpoints.toJson(roots)))
        for (bad in listOf("", "udp://host.test:53", "https://127.0.0.1:443", "udp://127.0.0.1:53?proxy=N",
            "udp://[2001:db8::53]:53\nudp://[2001:0db8:0:0:0:0:0:53]:53")) {
            assertNull(NumericDnsEndpoints.parse(bad))
        }
        assertEquals(2, NumericDnsEndpoints.parse("udp://[2001:db8::53]:53\nudp://[2001:db8::54]:53")?.size)
    }

    @Test
    fun `next start roots inherit by scope and do not overwrite fallback`() {
        val store = ConfigurationOverrideStore(temp.newFolder())
        val global = store.load()
        val root = NumericDnsEndpoints.parse("udp://127.0.0.1:53")!!
        val profileRoot = NumericDnsEndpoints.parse("tcp://127.0.0.1:5353")!!
        store.saveSection(null, OverrideSection.DNS_BOOTSTRAP, global, global.copy(dnsBootstrap = root))
        val base = store.load(5)
        assertEquals(root, store.effective(5).dnsBootstrap)
        store.saveSection(5, OverrideSection.DNS_FALLBACK, base, base.copy(dnsFallback = DnsFallbackOverride.Disabled))
        store.saveSection(5, OverrideSection.DNS_BOOTSTRAP, base, base.copy(dnsBootstrap = profileRoot))
        assertEquals(DnsWireOverride(fallback = DnsFallbackOverride.Disabled, bootstrap = profileRoot), store.effective(5).dnsWireOverride)
        assertThrows(IOException::class.java) { store.saveSection(5, OverrideSection.DNS_BOOTSTRAP, base, base) }
        val saved = store.load(5)
        store.saveSection(5, OverrideSection.DNS_BOOTSTRAP, saved, saved.copy(dnsBootstrap = null))
        assertEquals(root, store.effective(5).dnsBootstrap)
    }
}
