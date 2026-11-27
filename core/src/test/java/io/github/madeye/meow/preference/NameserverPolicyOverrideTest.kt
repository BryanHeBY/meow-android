package io.github.madeye.meow.preference

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class NameserverPolicyOverrideTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun orderedRowsPersistAcrossScopesAndExplicitClear() {
        val store = ConfigurationOverrideStore(temporary.newFolder())
        val rows = NameserverPolicyOverride.parseRows(
            "Example.Test udp://192.0.2.53:53\n+.example.test tcp://[2001:db8::53]:5353",
        )!!
        assertEquals(
            """[{"pattern":"example.test","transport":"UDP","endpoint":"192.0.2.53:53"},{"pattern":"+.example.test","transport":"TCP","endpoint":"[2001:db8::53]:5353"}]""",
            NameserverPolicyOverride.wire(rows),
        )
        store.save(null, ConfigurationOverride(nameserverPolicy = rows))
        assertEquals(rows, store.effective(1).nameserverPolicy)
        store.save(1, ConfigurationOverride(nameserverPolicy = rows.reversed()))
        assertEquals(rows.reversed(), store.effective(1).nameserverPolicy)
        assertEquals(rows, store.effective(2).nameserverPolicy)
        store.save(1, ConfigurationOverride(nameserverPolicy = emptyList()))
        assertEquals(emptyList<NameserverPolicyRow>(), store.effective(1).nameserverPolicy)
        store.save(1, ConfigurationOverride())
        assertEquals(rows, store.effective(1).nameserverPolicy)
        assertEquals("null", NameserverPolicyOverride.wire(null))
        assertEquals("[]", NameserverPolicyOverride.wire(emptyList()))
        assertThrows(IOException::class.java) {
            store.save(1, ConfigurationOverride(nameserverPolicy = rows + rows.first()))
        }
        assertEquals(rows, store.effective(1).nameserverPolicy)
    }

    @Test fun stalePolicyEditorRetainsOtherFieldsAndCannotClobberNewerPolicy() {
        val store = ConfigurationOverrideStore(temporary.newFolder())
        val editorSnapshot = store.load(3)
        val rows = NameserverPolicyOverride.parseRows("x.test udp://127.0.0.1:53")!!
        val later = ConfigurationOverride(ipv6 = Ipv6Override.FORCE_ON,
            coreBehavior = CoreBehaviorOverride(tcpConcurrent = false))
        store.save(3, later)
        assertEquals(later.copy(nameserverPolicy = rows),
            store.saveSection(3, OverrideSection.NAMESERVER_POLICY, editorSnapshot, editorSnapshot.copy(nameserverPolicy = rows)))
        assertThrows(IOException::class.java) {
            store.saveSection(3, OverrideSection.NAMESERVER_POLICY, editorSnapshot, editorSnapshot.copy(nameserverPolicy = emptyList()))
        }
        assertEquals(later.copy(nameserverPolicy = rows), store.load(3))
    }

    @Test fun staleSectionSavesPreserveOtherSectionsInEitherOrderAndScope() {
        val store = ConfigurationOverrideStore(temporary.newFolder())
        val original = ConfigurationOverride()
        val rows = NameserverPolicyOverride.parseRows("x.test udp://127.0.0.1:53")!!
        val withPolicy = original.copy(nameserverPolicy = rows)
        val edits = mapOf(
            OverrideSection.MAIN to original.copy(ipv6 = Ipv6Override.FORCE_OFF),
            OverrideSection.CORE to original.copy(coreBehavior = CoreBehaviorOverride(tcpConcurrent = false)),
            OverrideSection.HOSTS to original.copy(dnsHosts = DnsHostsOverride(useHosts = false)),
            OverrideSection.FAKE_IP to original.copy(fakeIpFilter = FakeIpFilterOverride(emptyList())),
        )
        store.save(null, withPolicy)
        for ((index, edit) in edits.entries.withIndex()) {
            val profile = index.toLong() + 10
            val reverse = profile + 10
            val (section, draft) = edit
            store.saveSection(profile, OverrideSection.NAMESERVER_POLICY, original, withPolicy)
            assertEquals(draft.copy(nameserverPolicy = rows), store.saveSection(profile, section, original, draft))
            store.saveSection(reverse, section, original, draft)
            assertEquals(draft.copy(nameserverPolicy = rows),
                store.saveSection(reverse, OverrideSection.NAMESERVER_POLICY, original, withPolicy))
            assertThrows(IOException::class.java) { store.saveSection(profile, section, original, original) }
            assertEquals(draft.copy(nameserverPolicy = rows), store.load(profile))

            val beforeClear = store.load(profile)
            store.saveSection(profile, OverrideSection.NAMESERVER_POLICY, beforeClear, beforeClear.copy(nameserverPolicy = emptyList()))
            assertEquals(emptyList<NameserverPolicyRow>(),
                store.saveSection(profile, section, beforeClear, original).nameserverPolicy)
            assertEquals(withPolicy, store.load())
            assertEquals(draft.copy(nameserverPolicy = rows), store.load(reverse))
        }
    }

    @Test fun rejectsAmbiguousOrExternalFeaturesWithoutResolvingHosts() {
        for (row in listOf(
            "x.test https://1.1.1.1:443", "x.test udp://dns.example:53",
            "x.test udp://192.0.2.53", "x.test tcp://192.0.2.53:00053",
            "x.test tcp://192.0.2.53:53#node", "x.test udp://192.0.2.53:53?proxy=node",
            "x.test udp://192.0.2.53:0", "x.test udp://192.0.2.53:65536",
            "x.test udp://192.0.2.53:53/path", "x.test tcp://[fe80::1%7]:53",
            "x.test tcp://[::ffff:192.0.2.53]:53", "x.test tcp://0.0.0.0:53",
            "x.test tcp://224.0.0.1:53", "geosite:private udp://192.0.2.53:53",
            "rule-set:private udp://192.0.2.53:53", "*.test udp://192.0.2.53:53",
            "x.test udp://192.0.2.53:53\nX.TEST. tcp://192.0.2.53:53",
        )) assertNull(row, NameserverPolicyOverride.parseRows(row))
    }

    @Test
    fun `DNS IPv6 tri-state is independent and saved with section isolation`() {
        val store = ConfigurationOverrideStore(temporary.newFolder())
        val base = store.load()
        val allowed = base.copy(dnsIpv6 = true)
        store.saveSection(null, OverrideSection.DNS_IPV6, base, allowed)
        assertEquals(true, store.effective(3).dnsIpv6)
        val profile = store.load(3)
        store.saveSection(3, OverrideSection.DNS_IPV6, profile, profile.copy(dnsIpv6 = false))
        assertEquals(false, store.effective(3).dnsIpv6)
        val rows = NameserverPolicyOverride.parseRows("example.test udp://127.0.0.1:53")!!
        store.saveSection(3, OverrideSection.NAMESERVER_POLICY, profile, profile.copy(nameserverPolicy = rows))
        assertEquals(DnsWireOverride(rows, false), store.effective(3).dnsWireOverride)
        assertEquals(base.ipv6, store.effective(3).ipv6)
        val latest = store.load(3)
        store.saveSection(3, OverrideSection.DNS_IPV6, latest, latest.copy(dnsIpv6 = null))
        assertEquals(DnsWireOverride(rows, true), store.effective(3).dnsWireOverride)
    }
}
