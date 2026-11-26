package io.github.madeye.meow.ui.screens.zerotier

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import io.github.madeye.meow.AppGraph
import io.github.madeye.meow.R
import io.github.madeye.meow.repo.OverlaySettings
import io.github.madeye.meow.ui.screens.perapp.AppPicker
import io.github.madeye.meow.ui.screens.perapp.PerAppUiState
import io.github.madeye.meow.ui.theme.meow

internal enum class ZeroTierAppMode(val key: String, @StringRes val label: Int) {
    All("all", R.string.zt_apps_mode_all),
    Allow("allow", R.string.zt_apps_mode_allow),
    Exclude("exclude", R.string.zt_apps_mode_exclude);

    companion object {
        fun fromStored(key: String) = entries.firstOrNull { it.key == key } ?: All
    }
}

internal fun updateAppSelection(selected: Set<String>, packageName: String): ArrayList<String> =
    ArrayList(if (packageName in selected) selected - packageName else selected + packageName)

internal fun OverlaySettings.withAppRules(mode: ZeroTierAppMode, selected: Set<String>): OverlaySettings =
    copy(appMode = mode.key, packages = selected.toSet())

@Composable
internal fun ZeroTierAppRules(
    mode: ZeroTierAppMode,
    state: PerAppUiState,
    busy: Boolean,
    message: String,
    contentPadding: PaddingValues,
    onModeChange: (ZeroTierAppMode) -> Unit,
    onQueryChange: (String) -> Unit,
    onToggle: (String) -> Unit,
) {
    AppPicker(
        state = state,
        contentPadding = contentPadding,
        onQueryChange = onQueryChange,
        onToggleApp = onToggle,
        iconLoader = AppGraph.installedApps::icon,
        modifier = Modifier.testTag("zt_app_picker"),
        editing = !busy,
        showList = mode != ZeroTierAppMode.All,
    ) {
        Text(
            text = stringResource(R.string.zt_apps_scope),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.meow.mutedText,
        )
        ZeroTierAppMode.entries.forEach { option ->
            Row(
                modifier = Modifier.fillMaxWidth().testTag("zt_app_mode_${option.key}").selectable(
                    selected = mode == option,
                    enabled = !busy,
                    role = Role.RadioButton,
                    onClick = { onModeChange(option) },
                ),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = mode == option, onClick = null, enabled = !busy, modifier = Modifier.padding(12.dp))
                Text(stringResource(option.label), style = MaterialTheme.typography.bodyMedium)
            }
        }
        if (mode != ZeroTierAppMode.All) {
            if (mode == ZeroTierAppMode.Allow && state.selected.isEmpty()) {
                Text(
                    text = stringResource(R.string.zt_apps_none_allowed),
                    color = MaterialTheme.meow.mutedText,
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                Text(
                    text = pluralStringResource(R.plurals.perapp_selected, state.selected.size, state.selected.size),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        Text(stringResource(R.string.perapp_restart_required), style = MaterialTheme.typography.bodySmall)
        if (message.isNotBlank()) Text(message, style = MaterialTheme.typography.bodySmall)
    }
}
