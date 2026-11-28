package io.github.madeye.meow.ui.screens.overrideconfig

import io.github.madeye.meow.preference.NameserverPolicyOverride
import io.github.madeye.meow.preference.AppQuicOverride
import io.github.madeye.meow.preference.ConfigurationOverride
import io.github.madeye.meow.preference.CoreBehaviorOverride
import io.github.madeye.meow.preference.DnsMode
import io.github.madeye.meow.preference.DnsSettings
import io.github.madeye.meow.preference.FindProcessOverride
import io.github.madeye.meow.preference.Ipv6Override
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OverrideFormTest {
    @Test
    fun `main and core apply only their own draft and reset independently`() {
        val dns = DnsSettings(DnsMode.CN)
        val saved = ConfigurationOverride(
            Ipv6Override.FORCE_ON, AppQuicOverride.BLOCK_UDP_443,
            CoreBehaviorOverride(unifiedDelay = true),
        )
        val coreDraft = CoreBehaviorOverride(false, true, FindProcessOverride.OFF)
        val mainReset = saved.copy(ipv6 = Ipv6Override.INHERIT, appQuic = AppQuicOverride.INHERIT)
        val form = OverrideForm(saved, mainReset.copy(coreBehavior = coreDraft), ConfigurationOverride(), dns)

        assertTrue(form.canSave(OverrideSection.MAIN))
        assertTrue(form.canSave(OverrideSection.CORE))
        assertEquals(mainReset, form.draftFor(OverrideSection.MAIN))
        assertEquals(saved.copy(coreBehavior = coreDraft), form.draftFor(OverrideSection.CORE))

        val coreReset = form.copy(draft = saved.copy(coreBehavior = CoreBehaviorOverride()))
        assertFalse(coreReset.canSave(OverrideSection.MAIN))
        assertTrue(coreReset.canSave(OverrideSection.CORE))
        assertEquals(saved.copy(coreBehavior = CoreBehaviorOverride()), coreReset.draftFor(OverrideSection.CORE))
        assertFalse(coreReset.canSaveDns)
        assertEquals(dns, coreReset.savedDns)
    }
    @Test
    fun dnsInterceptionIsSavedAndResetOnlyInTheMainSection() {
        val original = ConfigurationOverride(coreBehavior = CoreBehaviorOverride(unifiedDelay = true))
        val local = original.copy(dnsHijacking = false, coreBehavior = CoreBehaviorOverride())
        val form = OverrideForm(saved = original, draft = local, global = original, savedDns = null)
        assertTrue(form.canSave(OverrideSection.MAIN))
        assertEquals(original.copy(dnsHijacking = false), form.draftFor(OverrideSection.MAIN))
        assertEquals(original.copy(coreBehavior = CoreBehaviorOverride()), form.draftFor(OverrideSection.CORE))
        val saved = form.afterSectionSave(OverrideSection.MAIN, original.copy(dnsHijacking = false))
        assertFalse(saved.canSave(OverrideSection.MAIN))
        assertFalse(saved.saved.interceptsPlainDns)
        val reset = saved.copy(draft = saved.draft.copy(dnsHijacking = null))
        assertEquals(original, reset.draftFor(OverrideSection.MAIN))
    }

    @Test
    fun sectionMergeKeepsDirtyDraftAndItsOriginalConflictBaseline() {
        val original = ConfigurationOverride()
        val rows = NameserverPolicyOverride.parseRows("x.test udp://127.0.0.1:53")!!
        val localCore = CoreBehaviorOverride(tcpConcurrent = false)
        val externalCore = CoreBehaviorOverride(unifiedDelay = true)
        val ui = OverrideForm(
            saved = original,
            draft = original.copy(coreBehavior = localCore, nameserverPolicy = rows),
            global = original,
            savedDns = null,
            saving = true,
        )
        val persisted = original.copy(nameserverPolicy = rows, coreBehavior = externalCore)
        val refreshed = ui.afterSectionSave(OverrideSection.NAMESERVER_POLICY, persisted)
        assertEquals(persisted, refreshed.saved)
        assertEquals(localCore, refreshed.draft.coreBehavior)
        assertEquals(original.coreBehavior, refreshed.expected.coreBehavior)
        assertEquals(rows, refreshed.expected.nameserverPolicy)
        assertTrue(refreshed.canSave(OverrideSection.CORE))
        assertFalse(refreshed.canSave(OverrideSection.NAMESERVER_POLICY))

        val blank = OverrideForm(saved = original, global = original, savedDns = null)
        val cleanRefreshed = blank.afterSectionSave(OverrideSection.NAMESERVER_POLICY, persisted)
        assertEquals(externalCore, cleanRefreshed.draft.coreBehavior)
        assertEquals(externalCore, cleanRefreshed.expected.coreBehavior)
        assertFalse(cleanRefreshed.canSave(OverrideSection.CORE))
    }
}
