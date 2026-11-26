package io.github.madeye.meow.ui.nav

import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.runtime.Composable
import androidx.navigation.NavGraphBuilder
import io.github.madeye.meow.ui.screens.home.HomeUiState

/** No navigation destination, home card, or ZeroTier screen is compiled in Lite. */
@Suppress("UNUSED_PARAMETER")
internal object ZeroTierUi {
    val tab: TabDestination? = null
    val forwardingError: Int? = null

    @Composable
    fun ForwardingControls(state: HomeUiState, onToggleMeowForwarding: (Boolean) -> Unit) = Unit

    fun register(graph: NavGraphBuilder, bottomBar: @Composable () -> Unit) = Unit
    fun addHomeSummary(list: LazyListScope, onOpen: () -> Unit) = Unit
}
