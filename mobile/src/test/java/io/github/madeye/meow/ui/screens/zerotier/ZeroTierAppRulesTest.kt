package io.github.madeye.meow.ui.screens.zerotier

import io.github.madeye.meow.repo.OverlaySettings
import org.junit.Assert.assertEquals
import org.junit.Test

class ZeroTierAppRulesTest {
    @Test
    fun `allowlist and blocklist use the existing backend keys without touching other overlay options`() {
        val original = OverlaySettings(appMode = "all", packages = setOf("org.old"))
        val selected = setOf("org.new")
        assertEquals(original.copy(appMode = "allow", packages = selected),
            original.withAppRules(ZeroTierAppMode.Allow, selected))
        assertEquals(original.copy(appMode = "exclude", packages = selected),
            original.withAppRules(ZeroTierAppMode.Exclude, selected))
        assertEquals(ZeroTierAppMode.All, ZeroTierAppMode.fromStored("all"))
        assertEquals(ZeroTierAppMode.Allow, ZeroTierAppMode.fromStored("allow"))
        assertEquals(ZeroTierAppMode.Exclude, ZeroTierAppMode.fromStored("exclude"))
    }

    @Test
    fun `a row toggle changes only its own app`() {
        val selected = setOf("org.selected", "org.hidden")
        assertEquals(setOf("org.hidden"), updateAppSelection(selected, "org.selected").toSet())
        assertEquals(selected + "org.new", updateAppSelection(selected, "org.new").toSet())
    }
}
