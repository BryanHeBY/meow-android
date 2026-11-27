package io.github.madeye.meow.ui.screens.advancedconfig

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.madeye.meow.R
import io.github.madeye.meow.api.RouteMode
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.components.SectionHeader
import io.github.madeye.meow.ui.screens.home.HomeViewModel
import io.github.madeye.meow.ui.screens.overrideconfig.Choice

@Composable
internal fun AdvancedRouteModeEditor(owner: HomeViewModel, snackbar: SnackbarHostState) {
    val next by owner.nextRouteMode.collectAsStateWithLifecycle()
    val failed = stringResource(R.string.advanced_route_mode_save_failed)
    LaunchedEffect(owner, snackbar, failed) {
        owner.nextRouteModeSaveFailed.collect { snackbar.showSnackbar(failed) }
    }
    SectionHeader(stringResource(R.string.advanced_route_mode_next))
    GlassCard {
        Text(stringResource(R.string.advanced_route_mode_next_detail), style = MaterialTheme.typography.bodySmall)
        val preference = next
        if (preference != null) {
            Column(Modifier.selectableGroup()) {
                Choice(
                    R.string.override_follow_profile,
                    selected = preference.override == null,
                    enabled = true,
                    modifier = Modifier.testTag("advanced_route_mode_inherit"),
                ) { owner.setNextRouteMode(null) }
                RouteMode.entries.forEach { mode ->
                    Choice(
                        when (mode) {
                            RouteMode.Rule -> R.string.route_mode_rule
                            RouteMode.Global -> R.string.route_mode_global
                            RouteMode.Direct -> R.string.route_mode_direct
                        },
                        selected = preference.override == mode,
                        enabled = true,
                        modifier = Modifier.testTag("advanced_route_mode_${mode.wire}"),
                    ) { owner.setNextRouteMode(mode) }
                }
            }
        }
    }
}
