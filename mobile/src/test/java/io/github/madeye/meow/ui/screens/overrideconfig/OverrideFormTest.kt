package io.github.madeye.meow.ui.screens.overrideconfig

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
}
