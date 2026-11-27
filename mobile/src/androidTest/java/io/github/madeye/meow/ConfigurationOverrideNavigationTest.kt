package io.github.madeye.meow

import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.semantics.SemanticsProperties
import org.junit.Rule
import org.junit.Test

class ConfigurationOverrideNavigationTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun settingsNetworkOpensTheGlobalFormWithAnUnsavedDraft() {
        compose.onNodeWithTag("tab_settings").performClick()
        compose.onNodeWithTag("dns_mode").assertDoesNotExist()
        compose.onNodeWithTag("configuration_override").performScrollTo().performClick()

        compose.waitUntil(timeoutMillis = 5_000) {
            compose.onAllNodesWithTag("save_configuration_override").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("save_configuration_override").assertIsNotEnabled()
        compose.onNodeWithTag("dns_mode").assertExists()
        val forceOn = compose.onNodeWithTag("override_ipv6_force_on")
        val forceOff = compose.onNodeWithTag("override_ipv6_force_off")
        val checked = forceOn.fetchSemanticsNode().config[SemanticsProperties.Selected]
        (if (checked) forceOff else forceOn).performScrollTo().performClick()
        val save = compose.onNodeWithTag("save_configuration_override")
        save.assertIsEnabled()
        compose.onNodeWithTag("save_dns").assertIsNotEnabled()
    }
}
