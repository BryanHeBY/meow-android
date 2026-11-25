package io.github.madeye.meow.ui.screens.zerotier

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.madeye.meow.AppGraph
import io.github.madeye.meow.R
import io.github.madeye.meow.repo.InstalledApp
import io.github.madeye.meow.repo.OverlaySettings
import io.github.madeye.meow.ui.screens.perapp.AppPicker
import io.github.madeye.meow.ui.screens.perapp.PerAppUiState
import io.github.madeye.meow.ui.theme.meow
import kotlinx.coroutines.CancellationException
import timber.log.Timber

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
    selected: Set<String>,
    busy: Boolean,
    message: String,
    contentPadding: PaddingValues,
    onModeChange: (ZeroTierAppMode) -> Unit,
    onToggle: (String) -> Unit,
    onSave: () -> Unit,
) {
    var search by rememberSaveable { mutableStateOf("") }
    var showSystem by rememberSaveable { mutableStateOf(false) }
    val apps by produceState<List<InstalledApp>?>(null) {
        value = try {
            AppGraph.installedApps.load()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "ZeroTier app list could not be loaded")
            emptyList()
        }
    }
    AppPicker(
        state = PerAppUiState(
            loading = apps == null,
            selected = selected,
            query = search,
            showSystemApps = showSystem,
            apps = apps.orEmpty(),
        ),
        contentPadding = contentPadding,
        onQueryChange = { search = it },
        onToggleApp = onToggle,
        iconLoader = AppGraph.installedApps::icon,
        modifier = Modifier.testTag("zt_app_picker"),
        editing = !busy,
        showList = mode != ZeroTierAppMode.All,
        scrollHeader = true,
    ) {
        Text(
            text = stringResource(R.string.zt_apps_scope),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.meow.mutedText,
        )
        ZeroTierAppMode.entries.forEach { option ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(
                    selected = mode == option,
                    onClick = { onModeChange(option) },
                    enabled = !busy,
                    modifier = Modifier.testTag("zt_app_mode_${option.key}"),
                )
                Text(stringResource(option.label), style = MaterialTheme.typography.bodyMedium)
            }
        }
        if (mode != ZeroTierAppMode.All) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = showSystem, onCheckedChange = { showSystem = it }, enabled = !busy)
                Text(stringResource(R.string.zt_apps_show_system), style = MaterialTheme.typography.bodyMedium)
            }
            if (mode == ZeroTierAppMode.Allow && selected.isEmpty()) {
                Text(
                    text = stringResource(R.string.zt_apps_none_allowed),
                    color = MaterialTheme.meow.mutedText,
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                Text(
                    text = pluralStringResource(R.plurals.perapp_selected, selected.size, selected.size),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        Column(modifier = Modifier.padding(top = 4.dp)) {
            Text(stringResource(R.string.perapp_restart_required), style = MaterialTheme.typography.bodySmall)
            if (message.isNotBlank()) Text(message, style = MaterialTheme.typography.bodySmall)
            Button(onClick = onSave, enabled = !busy, modifier = Modifier.testTag("zt_app_save")) {
                Text(stringResource(R.string.common_save))
            }
        }
    }
}
