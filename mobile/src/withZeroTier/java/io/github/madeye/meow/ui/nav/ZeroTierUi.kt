package io.github.madeye.meow.ui.nav

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import io.github.madeye.meow.R
import io.github.madeye.meow.ui.screens.home.HomeUiState
import io.github.madeye.meow.ui.screens.zerotier.ZeroTierRoute
import io.github.madeye.meow.ui.screens.zerotier.ZeroTierSummary
import io.github.madeye.meow.ui.theme.meow
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
@SerialName("io.github.madeye.meow.ui.nav.Dest.ZeroTier")
internal data object ZeroTierDestination : Dest

internal object ZeroTierUi {
    val tab: TabDestination? =
        TabDestination(ZeroTierDestination, R.string.tab_zerotier, Icons.Filled.Hub, "tab_zerotier")

    @get:StringRes
    val forwardingError: Int?
        get() = R.string.home_meow_forwarding_failed

    @Composable
    fun ForwardingControls(state: HomeUiState, onToggleMeowForwarding: (Boolean) -> Unit) {
        val colors = MaterialTheme.meow
        if (state.showMeowForwarding) {
            HorizontalDivider(color = colors.border, modifier = Modifier.padding(vertical = 14.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                val title = stringResource(R.string.home_meow_forwarding)
                Column(modifier = Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.titleSmall)
                    Text(
                        text = stringResource(
                            if (state.overlayForwarding) R.string.home_meow_forwarding_scope
                            else R.string.home_meow_forwarding_requires_zt,
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.mutedText,
                    )
                }
                Spacer(Modifier.size(12.dp))
                if (state.forwardingChangePending) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                } else {
                    Switch(
                        checked = state.meowForwarding,
                        onCheckedChange = onToggleMeowForwarding,
                        enabled = state.canToggleMeowForwarding,
                        modifier = Modifier
                            .testTag("meow_forwarding_switch")
                            .semantics { contentDescription = title },
                    )
                }
            }
        }
    }

    fun register(graph: NavGraphBuilder, bottomBar: @Composable () -> Unit) {
        graph.composable<ZeroTierDestination> { ZeroTierRoute(bottomBar = bottomBar) }
    }

    fun addHomeSummary(list: LazyListScope, onOpen: () -> Unit) {
        list.item { ZeroTierSummary(onOpen = onOpen) }
    }
}
