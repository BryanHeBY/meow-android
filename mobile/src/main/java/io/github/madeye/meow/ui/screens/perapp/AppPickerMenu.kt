package io.github.madeye.meow.ui.screens.perapp

import androidx.compose.foundation.layout.Box
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import io.github.madeye.meow.R
import io.github.madeye.meow.repo.InstalledApp

internal enum class AppSelectionAction { Select, Deselect, Invert }

internal fun updateVisibleSelection(
    selected: Set<String>,
    visible: List<InstalledApp>,
    action: AppSelectionAction,
): Set<String> {
    val visibleIds = visible.mapTo(mutableSetOf()) { it.packageName }
    return when (action) {
        AppSelectionAction.Select -> selected + visible.filterNot { it.isSystem }.map { it.packageName }
        AppSelectionAction.Deselect -> selected - visibleIds
        AppSelectionAction.Invert -> (selected - visibleIds) + (visibleIds - selected)
    }
}

@Composable
internal fun AppPickerMenu(
    state: PerAppUiState,
    onBulkSelection: (AppSelectionAction, List<InstalledApp>) -> Unit,
    onToggleSystemApps: () -> Unit,
    enabled: Boolean = true,
    onExport: (() -> Unit)? = null,
    onImport: (() -> Unit)? = null,
) {
    var menuOpen by remember { mutableStateOf(false) }
    val editing = enabled && !state.loading
    Box {
        IconButton(
            onClick = { menuOpen = true },
            enabled = editing,
            modifier = Modifier.testTag("perapp_options"),
        ) {
            Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.common_more_options))
        }
        DropdownMenu(expanded = menuOpen && editing, onDismissRequest = { menuOpen = false }) {
            val visible = state.visibleApps
            val hasThirdParty = visible.any { !it.isSystem }
            val deselect = visible.any { it.packageName in state.selected } &&
                visible.none { !it.isSystem && it.packageName !in state.selected }
            DropdownMenuItem(
                text = {
                    Text(stringResource(if (deselect) R.string.perapp_deselect_all else R.string.perapp_select_all))
                },
                enabled = deselect || hasThirdParty,
                onClick = {
                    menuOpen = false
                    onBulkSelection(if (deselect) AppSelectionAction.Deselect else AppSelectionAction.Select, visible)
                },
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.perapp_invert_visible)) },
                enabled = visible.isNotEmpty(),
                onClick = {
                    menuOpen = false
                    onBulkSelection(AppSelectionAction.Invert, visible)
                },
            )
            DropdownMenuItem(
                text = {
                    Text(stringResource(if (state.showSystemApps) R.string.perapp_hide_system else R.string.perapp_show_system))
                },
                onClick = onToggleSystemApps,
            )
            if (onExport != null) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.perapp_export)) },
                    onClick = { menuOpen = false; onExport() },
                )
            }
            if (onImport != null) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.perapp_import)) },
                    onClick = { menuOpen = false; onImport() },
                )
            }
        }
    }
}
