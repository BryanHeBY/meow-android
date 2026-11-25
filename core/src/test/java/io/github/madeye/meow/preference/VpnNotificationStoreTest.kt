package io.github.madeye.meow.preference

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class VpnNotificationStoreTest {
    @get:Rule val folder = TemporaryFolder()

    @Test fun preferenceIsVisibleToAnotherReaderAndDefaultsToDetails() {
        val file = folder.root.resolve("vpn_notification")
        val ui = VpnNotificationStore(file)
        val vpn = VpnNotificationStore(file)
        assertTrue(vpn.detailsEnabled())
        ui.save(false)
        assertFalse(vpn.detailsEnabled())
        ui.save(true)
        assertTrue(vpn.detailsEnabled())
        file.writeText("malformed")
        assertTrue(vpn.detailsEnabled())
    }
}
