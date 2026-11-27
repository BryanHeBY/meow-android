package io.github.madeye.meow.preference

import io.github.madeye.meow.bg.ActiveConfig
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DnsSettingsStoreTest {
    @get:Rule val tmp = TemporaryFolder()
    private val target get() = File(tmp.root, "builtin_dns")
    private val store by lazy { DnsSettingsStore(target) }
    private val first = ActiveConfig(11, "cached profile A")
    private val second = ActiveConfig(12, first.yaml)
    private val named = DnsSettings(
        DnsMode.CUSTOM, listOf(DnsUpstream(DnsTransport.HTTPS, "dns.example/path", DnsEgress.PROXY, "Node")),
    )

    @Test
    fun `never-saved preferences inherit and explicit legacy choices keep their modes`() {
        assertEquals(DnsSettingsStore.Saved(), store.load())
        for ((value, mode) in listOf("builtin" to DnsMode.LEGACY_BUILTIN, "profile" to DnsMode.LEGACY_PROFILE)) {
            target.writeText(value)
            assertEquals(DnsSettingsStore.Saved(DnsSettings(mode)), store.load())
            assertEquals(value, target.readText())
        }
    }

    @Test
    fun `corrupt preferences report an inherit recovery`() {
        for (value in listOf("", "junk", """{"version":2,"mode":"inherit"}""")) {
            target.writeText(value)
            assertEquals(DnsSettingsStore.Saved(invalid = true), store.load())
        }
        target.delete()
        assertTrue(target.mkdir())
        assertEquals(DnsSettingsStore.Saved(invalid = true), store.load())
    }

    @Test
    fun `successful save is visible to another reader and encodes standard JNI fields`() = runBlocking {
        val preference = DnsPreference(store, commit = { wire, selectedId ->
            store.commit(wire, selectedId, { first }, { yaml, _, _ ->
                assertEquals(first.yaml, yaml)
                null
            }) { candidate, settings, staged, destination ->
                assertEquals(first, candidate)
                assertEquals(first.profileId, settings.profileId)
                assertEquals(DnsMode.INHERIT, store.load().settings.mode)
                assertEquals(settings.encode(), staged.readText())
                assertTrue(staged.readText().contains("\"version\":1"))
                assertTrue(staged.readText().contains("\"transport\":\"https\""))
                assertTrue(staged.renameTo(destination))
                null
            }?.name
        }, readStatus = { """{"mode":"custom","runningProfileId":11,"selectedProfileId":12,"applicability":"UNAVAILABLE","issue":"PROFILE_UNAVAILABLE"}""" })
        assertNull(preference.save(named, first.profileId))
        assertEquals(named.copy(profileId = first.profileId), DnsSettingsStore(target).load().settings)
        assertEquals("custom", preference.status()?.mode)
        assertEquals(11L, preference.status()?.runningProfileId)
        assertEquals(12L, preference.status()?.selectedProfileId)
        assertEquals(DnsApplicability.UNAVAILABLE, preference.status()?.applicability)
        assertEquals(DnsIssue.PROFILE_UNAVAILABLE, preference.status()?.issue)
        assertFalse(target.readText().contains("builtin"))
    }

    @Test
    fun `offline named save requires a selected profile and a compatible cached proxy`() {
        target.writeText("builtin")
        fun save(profile: ActiveConfig?) = store.commit(
            named.encode(), profile?.profileId, { profile }, { _, _, _ -> DnsIssue.PROXY_UNAVAILABLE.name },
        ) { _, _, _, _ -> error("Invalid named DNS reached publication") }
        assertEquals(DnsIssue.PROFILE_REQUIRED, save(null))
        assertEquals(DnsIssue.PROXY_UNAVAILABLE, save(first))
        assertEquals("builtin", target.readText())
    }

    @Test
    fun `named settings apply to the saved identity and recheck new cached YAML`() {
        val scoped = named.copy(profileId = first.profileId)
        var checked = 0
        val validate: (String, String, String) -> String? = { yaml, _, _ ->
            checked++
            DnsIssue.PROXY_UNAVAILABLE.name.takeUnless { yaml == first.yaml }
        }
        assertEquals(DnsIssue.PENDING, store.activationIssue(named, first, validate = validate))
        assertNull(store.activationIssue(scoped, first, validate = validate))
        assertEquals(DnsIssue.PROFILE_UNAVAILABLE, store.activationIssue(scoped, second, validate = validate))
        assertNull(store.activationIssue(scoped, first, validate = validate))
        assertEquals(1, checked)
        assertEquals(DnsIssue.PROXY_UNAVAILABLE, store.activationIssue(scoped, first.copy(yaml = "no proxy"), validate = validate))
        assertEquals(2, checked)
    }

    @Test
    fun `named DNS cache distinguishes inherit clear and ordered policy identity`() {
        val scoped = named.copy(profileId = first.profileId)
        val seen = mutableListOf<String>()
        val validate: (String, String, String) -> String? = { _, _, policy ->
            seen.add(policy)
            DnsIssue.RESOLVER_REJECTED.name.takeIf { policy == "null" }
        }
        val rows = NameserverPolicyOverride.parseRows(
            "example.test udp://127.0.0.1:53\n+.example.test tcp://127.0.0.1:54",
        )!!
        assertEquals(DnsIssue.RESOLVER_REJECTED, store.activationIssue(scoped, first, { null }, validate))
        assertNull(store.activationIssue(scoped, first, { emptyList() }, validate))
        assertNull(store.activationIssue(scoped, first, { emptyList() }, validate))
        assertNull(store.activationIssue(scoped, first, { rows }, validate))
        assertNull(store.activationIssue(scoped, first, { rows.reversed() }, validate))
        assertEquals(listOf("null", "[]", NameserverPolicyOverride.wire(rows),
            NameserverPolicyOverride.wire(rows.reversed())), seen)
    }

    @Test
    fun `a switch while a named save checks cached YAML leaves the old choice in place`() {
        target.writeText("profile")
        val selection = AtomicReference(first)
        val checking = CountDownLatch(1)
        val switched = CountDownLatch(1)
        val worker = Executors.newSingleThreadExecutor()
        try {
            val save = worker.submit<DnsIssue?> {
                store.commit(named.encode(), first.profileId, selection::get, { _, _, _ ->
                    checking.countDown()
                    assertTrue(switched.await(3, TimeUnit.SECONDS))
                    null
                }) { _, _, _, _ -> error("Stale named DNS reached publication") }
            }
            assertTrue(checking.await(3, TimeUnit.SECONDS))
            selection.set(second)
            switched.countDown()
            assertEquals(DnsIssue.PROFILE_CHANGED, save.get(3, TimeUnit.SECONDS))
            assertEquals("profile", target.readText())
        } finally {
            worker.shutdownNow()
        }
    }

    @Test
    fun `v1 direct custom stays global and unscoped named DNS stays pending`() {
        val direct = """{"version":1,"mode":"custom","upstreams":[{"transport":"tcp","endpoint":"192.0.2.53","egress":"direct"}]}"""
        target.writeText(direct)
        val savedDirect = store.load().settings
        assertEquals(DnsApplicability.GLOBAL, savedDirect.applicability(first.profileId))
        assertEquals("192.0.2.53", savedDirect.upstreams.single().endpoint)
        assertFalse(savedDirect.encode().contains("profileId"))
        assertEquals(direct, target.readText())
        val oldNamed = """{"version":1,"mode":"custom","upstreams":[{"transport":"tcp","endpoint":"192.0.2.53","egress":"proxy","proxy":"Node"}]}"""
        target.writeText(oldNamed)
        val pending = store.load().settings
        assertEquals(DnsApplicability.PENDING, pending.applicability(first.profileId))
        assertEquals(oldNamed, target.readText())
    }

    @Test
    fun `legacy split remains saved and unavailable`() {
        val oldSplit = """{"version":1,"mode":"split","splitProxy":"Node"}"""
        target.writeText(oldSplit)
        assertEquals(DnsIssue.SPLIT_UNAVAILABLE, store.activationIssue(store.load().settings, first) { _, _, _ ->
            error("Unavailable preset reached candidate validation")
        })
        assertEquals(oldSplit, target.readText())
    }

    @Test
    fun `validation and transaction failures keep the original file and remove the stage`() {
        target.writeText("profile")
        assertNotNull(store.commit("invalid", null, { null }, { _, _, _ -> null }) { _, _, _, _ ->
            error("Reached the native transaction")
        })
        for (failure in listOf(DnsIssue.RESOLVER_REJECTED, DnsIssue.SAVE_FAILED)) {
            assertEquals(failure, store.commit(DnsSettings(DnsMode.CN).encode(), null, { null }, { _, _, _ -> null }) { _, _, staged, destination ->
                assertEquals("profile", destination.readText())
                assertTrue(staged.isFile)
                failure
            })
            assertEquals("profile", target.readText())
            assertEquals(listOf(target.name), tmp.root.list()!!.toList())
        }
    }
}
