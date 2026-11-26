package io.github.madeye.meow.ui.nav

import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Hub
import androidx.compose.runtime.Composable
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import io.github.madeye.meow.R
import io.github.madeye.meow.ui.screens.zerotier.ZeroTierRoute
import io.github.madeye.meow.ui.screens.zerotier.ZeroTierSummary
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
@SerialName("io.github.madeye.meow.ui.nav.Dest.ZeroTier")
internal data object ZeroTierDestination : Dest

internal object ZeroTierUi {
    val tab: TabDestination? =
        TabDestination(ZeroTierDestination, R.string.tab_zerotier, Icons.Filled.Hub, "tab_zerotier")

    fun register(graph: NavGraphBuilder, bottomBar: @Composable () -> Unit) {
        graph.composable<ZeroTierDestination> { ZeroTierRoute(bottomBar = bottomBar) }
    }

    fun addHomeSummary(list: LazyListScope, onOpen: () -> Unit) {
        list.item { ZeroTierSummary(onOpen = onOpen) }
    }
}
