package io.github.madeye.meow.preference

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ConfigurationOverrideStoreTest {
    @get:Rule val tmp = TemporaryFolder()
    private val directory get() = File(tmp.root, "configuration_overrides")
    private val store get() = ConfigurationOverrideStore(directory)

    @Test
    fun `missing overrides keep legacy configuration and reuse the existing DNS file`() {
        val existingDns = File(tmp.root, "builtin_dns")
        existingDns.writeText("profile")
        assertEquals(ConfigurationOverride(), store.effective(7L))
        assertEquals(ConfigurationOverride(), store.effective(null))
        assertEquals(DnsMode.LEGACY_PROFILE, DnsSettingsStore(existingDns).load().settings.mode)
        assertEquals("profile", existingDns.readText())
        assertFalse(directory.exists())
    }

    @Test
    fun `profile choices beat global independently and explicit no-block overrides global block`() {
        val global = ConfigurationOverride(Ipv6Override.FORCE_OFF, AppQuicOverride.BLOCK_UDP_443)
        store.save(null, global)
        store.save(7L, ConfigurationOverride(Ipv6Override.FORCE_ON))
        store.save(8L, ConfigurationOverride(appQuic = AppQuicOverride.DO_NOT_BLOCK))
        assertEquals(ConfigurationOverride(Ipv6Override.FORCE_ON, global.appQuic), store.effective(7L))
        assertEquals(ConfigurationOverride(global.ipv6, AppQuicOverride.DO_NOT_BLOCK), store.effective(8L))
        assertEquals(global, store.effective(9L))
        assertTrue(store.effective(7L).blocksAppUdp443)
        assertFalse(store.effective(8L).blocksAppUdp443)
    }

    @Test
    fun `DNS interception defaults on and preserves a frozen explicit profile choice`() {
        assertTrue(store.effective(7L).interceptsPlainDns)
        directory.mkdirs()
        File(directory, "global").writeText("FORCE_OFF\nBLOCK_UDP_443\n")
        assertTrue(store.effective(7L).interceptsPlainDns)
        store.save(null, store.load().copy(dnsHijacking = false))
        assertFalse(store.effective(7L).interceptsPlainDns)
        store.save(7L, ConfigurationOverride(dnsHijacking = true))
        val started = store.effective(7L)
        assertTrue(started.interceptsPlainDns)
        assertFalse(store.effective(8L).interceptsPlainDns)
        store.save(7L, ConfigurationOverride())
        assertFalse(store.effective(7L).interceptsPlainDns)
        assertTrue(started.interceptsPlainDns)
        assertEquals(false, store.load().dnsHijacking)
        store.save(null, ConfigurationOverride())
        assertTrue(store.effective(7L).interceptsPlainDns)
    }

    @Test
    fun `reset only removes the chosen scope`() {
        val global = ConfigurationOverride(Ipv6Override.FORCE_ON, AppQuicOverride.BLOCK_UDP_443)
        val local = ConfigurationOverride(Ipv6Override.FORCE_OFF, AppQuicOverride.DO_NOT_BLOCK)
        store.save(null, global)
        store.save(7L, local)
        store.save(8L, local)

        store.save(7L, ConfigurationOverride())
        assertEquals(global, store.effective(7L))
        assertEquals(local, store.effective(8L))
        store.save(null, ConfigurationOverride())
        assertEquals(ConfigurationOverride(), store.effective(7L))
        assertEquals(local, store.effective(8L))
    }

    @Test
    fun `subscription refresh changes the YAML but keeps override identity and never rewrites source`() {
        val profileId = 17L
        val original = File(tmp.root, "provider.yaml").apply { writeText("ipv6: true\n") }
        store.save(profileId, ConfigurationOverride(Ipv6Override.FORCE_OFF))
        assertEquals("ipv6: true\n", original.readText())

        val refreshed = "ipv6: true\n# downloaded update\n"
        original.writeText(refreshed)
        assertEquals(Ipv6Override.FORCE_OFF, store.effective(profileId).ipv6)
        assertEquals(Ipv6Override.INHERIT, store.effective(profileId + 1).ipv6)
        assertEquals(refreshed, original.readText())
    }

    @Test
    fun `legacy files migrate on save and core values merge independently at startup`() {
        directory.mkdirs()
        File(directory, "global").writeText("FORCE_OFF\nBLOCK_UDP_443\n")
        assertEquals(ConfigurationOverride(Ipv6Override.FORCE_OFF, AppQuicOverride.BLOCK_UDP_443), store.load())
        val global = store.load().copy(coreBehavior = CoreBehaviorOverride(true, true, FindProcessOverride.ALWAYS))
        store.save(null, global)
        assertTrue(File(directory, "global").readText().startsWith("{"))
        val currentRun = store.effective(7L)

        val local = ConfigurationOverride(appQuic = AppQuicOverride.DO_NOT_BLOCK)
        val disabled = CoreBehaviorOverride(false, false, FindProcessOverride.OFF)
        store.save(7L, local.copy(coreBehavior = disabled))
        assertEquals(global, currentRun)
        assertEquals(disabled, store.effective(7L).coreBehavior)
        assertEquals(global.ipv6, store.effective(7L).ipv6)
        assertFalse(store.effective(7L).blocksAppUdp443)

        store.save(7L, local)
        assertEquals(global.coreBehavior, store.effective(7L).coreBehavior)
        assertEquals(local, store.load(7L))
        assertEquals(global, store.effective(8L))
        assertEquals(global, store.load())
    }

    @Test
    fun `unknown version and malformed values cannot be silently overwritten`() {
        directory.mkdirs()
        val file = File(directory, "global")
        for (text in listOf(
            """{"version":2}""",
            """{"version":"1"}""",
            """{"version":1,"coreBehavior":{"tcpConcurrent":42}}""",
            """{"version":1,"coreBehavior":{"findProcessMode":"STRICT"}}""",
            """{"version":1,"dnsHijacking":"false"}""",
            """{"version":1,"dnsHijacking":null}""",
            """{"version":1,"future":true}""",
            "[future format]",
        )) {
            file.writeText(text)
            assertThrows(java.io.IOException::class.java) { store.save(null, ConfigurationOverride()) }
            assertEquals(text, file.readText())
        }
    }
    @Test
    fun logLevelInheritsIndependentlyAndResetsWithoutLosingOtherFields() {
        val root = java.nio.file.Files.createTempDirectory("log-level-override-").toFile()
        try {
            val store = ConfigurationOverrideStore(root)
            val global = CoreBehaviorOverride(logLevel = LogLevelOverride.WARNING)
            val profile = CoreBehaviorOverride(tcpConcurrent = false, logLevel = LogLevelOverride.SILENT)
            store.save(null, ConfigurationOverride(coreBehavior = global))
            store.save(42L, ConfigurationOverride(coreBehavior = profile))
            assertEquals(LogLevelOverride.SILENT, store.effective(42L).coreBehavior.logLevel)
            store.save(42L, ConfigurationOverride(coreBehavior = profile.copy(logLevel = null)))
            assertEquals(LogLevelOverride.WARNING, store.effective(42L).coreBehavior.logLevel)
            assertEquals(false, store.effective(42L).coreBehavior.tcpConcurrent)
            java.io.File(root, "profile-42").writeText("""{"version":1,"coreBehavior":{"logLevel":"TRACE"}}""")
            assertTrue(runCatching { store.load(42L) }.exceptionOrNull() is java.io.IOException)
        } finally {
            root.deleteRecursively()
        }
    }

}
