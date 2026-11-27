package io.github.madeye.meow.preference

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DnsFallbackOverrideTest {
    @get:Rule val temp = TemporaryFolder()

    @Test
    fun `replacing only accepts bounded typed and strict entries`() {
        val endpoints = "udp://127.0.0.1:53\ntcp://[2001:db8::53]:5353"
        val domains = "Example.Test\n+.suffix.test"
        val cidrs = "192.0.2.0/24\n2001:DB8::/32"
        val parsed = requireNotNull(DnsFallbackOverride.parse(endpoints, domains, cidrs))
        assertEquals(listOf("example.test", "+.suffix.test"), parsed.domains)
        assertEquals(listOf("192.0.2.0/24", "2001:db8::/32"), parsed.cidrs)
        assertEquals(parsed, DnsFallbackOverride.fromJson(parsed.toJson()))
        assertEquals("""{"nameserverPolicy":null,"fallback":{"mode":"disabled"}}""",
            DnsWireOverride(fallback = DnsFallbackOverride.Disabled).wire())
        for (bad in listOf("", "udp://example.test:53", "https://127.0.0.1:443", "udp://127.0.0.1:53#P", "tcp://127.0.0.1:053",
            "udp://[2001:db8::53]:53\nudp://[2001:db8:0:0:0:0:0:53]:53")) {
            assertNull(DnsFallbackOverride.parse(bad, domains, cidrs))
        }
        for (bad in listOf("192.0.2.1/24", "2001:db8::1/32", "0.0.0.0/01", "192.0.2.0/64", "::ffff:192.0.2.0/120")) {
            assertNull(DnsFallbackOverride.parse(endpoints, domains, bad))
        }
        assertNull(DnsFallbackOverride.parse(endpoints, domains, "2001:db8::/32\n2001:0db8:0:0:0:0:0:0/32"))
        assertEquals(2, DnsFallbackOverride.parse(endpoints, domains, "2001:db8::/32\n2001:db9::/32")?.cidrs?.size)
        assertNull(DnsFallbackOverride.parse(endpoints, "*.test", cidrs))
        assertNull(DnsFallbackOverride.parse(endpoints, "a..test", cidrs))
    }

    @Test
    fun `whole policy precedence and stale saves cannot erase other sections`() {
        val store = ConfigurationOverrideStore(temp.newFolder())
        val before = store.load()
        val replace = requireNotNull(DnsFallbackOverride.parse("udp://127.0.0.1:53", "", ""))
        store.saveSection(null, OverrideSection.DNS_FALLBACK, before, before.copy(dnsFallback = replace))
        assertEquals(replace, store.effective(5).dnsFallback)
        val profile = store.load(5)
        store.saveSection(5, OverrideSection.DNS_IPV6, profile, profile.copy(dnsIpv6 = true))
        val disabled = profile.copy(dnsFallback = DnsFallbackOverride.Disabled)
        store.saveSection(5, OverrideSection.DNS_FALLBACK, profile, disabled)
        assertEquals(DnsWireOverride(ipv6 = true, fallback = DnsFallbackOverride.Disabled),
            store.effective(5).dnsWireOverride)
        assertThrows(IOException::class.java) { store.saveSection(5, OverrideSection.DNS_FALLBACK, profile, profile) }
        val saved = store.load(5)
        store.saveSection(5, OverrideSection.DNS_FALLBACK, saved, saved.copy(dnsFallback = null))
        assertEquals(replace, store.effective(5).dnsFallback)
        assertEquals(replace, store.effective(6).dnsFallback)
    }
}
