package io.github.madeye.meow.ui.screens.advancedconfig

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import io.github.madeye.meow.R
import io.github.madeye.meow.preference.CoreBehaviorOverride
import io.github.madeye.meow.preference.FindProcessOverride
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.components.SectionHeader
import io.github.madeye.meow.ui.screens.overrideconfig.Choice
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideForm
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideProfilePreview
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideSection

internal enum class AdvancedOverridePage(val title: Int, val unavailableReason: Int? = null) {
    INDEX(R.string.advanced_title),
    CORE(R.string.advanced_core_title),
    HOSTS(R.string.advanced_dns_hosts),
    DNS(R.string.override_dns, R.string.advanced_dns_unavailable),
    LISTENERS(R.string.advanced_listeners, R.string.advanced_listeners_unavailable),
    CONTROLLER(R.string.advanced_controller, R.string.advanced_controller_unavailable),
    ROUTING(R.string.advanced_routing, R.string.advanced_routing_unavailable),
    SNIFFER(R.string.advanced_sniffer, R.string.advanced_sniffer_unavailable),
    DATA(R.string.advanced_data, R.string.advanced_data_unavailable),
}

@Composable
internal fun AdvancedOverrideFields(
    page: AdvancedOverridePage,
    form: OverrideForm,
    profile: OverrideProfilePreview?,
    global: Boolean,
    onNavigate: (AdvancedOverridePage) -> Unit,
    onEdit: (CoreBehaviorOverride) -> Unit,
    onSave: () -> Unit,
) {
    when (page) {
        AdvancedOverridePage.INDEX -> GlassCard {
            for (child in AdvancedOverridePage.entries.drop(1)) {
                TextButton(onClick = { onNavigate(child) }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(child.title))
                }
            }
        }
        AdvancedOverridePage.CORE -> CoreBehaviorEditor(form, profile, global, onEdit, onSave)
        else -> GlassCard {
            Text(stringResource(R.string.settings_version_unavailable), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(requireNotNull(page.unavailableReason)), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun CoreBehaviorEditor(
    form: OverrideForm,
    profile: OverrideProfilePreview?,
    global: Boolean,
    onEdit: (CoreBehaviorOverride) -> Unit,
    onSave: () -> Unit,
) {
    val draft = form.draft.coreBehavior
    val enabled = !form.saving
    val inherit = if (global) R.string.override_follow_profile else R.string.override_inherit_global
    val ownerAvailable = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
    val scoped = when {
        !global -> draft.withInherited(form.global.coreBehavior)
        profile == null -> draft
        else -> profile.override?.coreBehavior?.withInherited(draft)
    }
    val effective = scoped?.withInherited(profile?.profileValues?.coreBehavior ?: CoreBehaviorOverride())
    Text(stringResource(R.string.advanced_next_start), style = MaterialTheme.typography.bodySmall)

    BooleanSetting(R.string.advanced_unified_delay, draft.unifiedDelay, inherit, enabled) {
        onEdit(draft.copy(unifiedDelay = it))
    }
    BooleanSetting(R.string.advanced_tcp_concurrent, draft.tcpConcurrent, inherit, enabled) {
        onEdit(draft.copy(tcpConcurrent = it))
    }
    SectionHeader(stringResource(R.string.advanced_find_process))
    GlassCard {
        Text(
            stringResource(if (ownerAvailable) R.string.advanced_process_detail else R.string.advanced_process_sdk),
            style = MaterialTheme.typography.bodySmall,
        )
        val canPickOwner = enabled && ownerAvailable
        Column(Modifier.selectableGroup()) {
            Choice(inherit, draft.findProcessMode == null, canPickOwner) { onEdit(draft.copy(findProcessMode = null)) }
            Choice(R.string.advanced_off, draft.findProcessMode == FindProcessOverride.OFF, canPickOwner) {
                onEdit(draft.copy(findProcessMode = FindProcessOverride.OFF))
            }
            Choice(R.string.advanced_process_always, draft.findProcessMode == FindProcessOverride.ALWAYS, canPickOwner) {
                onEdit(draft.copy(findProcessMode = FindProcessOverride.ALWAYS))
            }
            Choice(R.string.advanced_process_strict, selected = false, enabled = false) {}
        }
        if (ownerAvailable) {
            Text(stringResource(R.string.advanced_process_strict_unavailable), style = MaterialTheme.typography.bodySmall)
        }
    }

    SectionHeader(stringResource(R.string.override_preview))
    GlassCard {
        if (global) profile?.let { Text(it.name, style = MaterialTheme.typography.titleSmall) }
        PreviewValue(R.string.advanced_unified_delay, booleanLabel(effective?.unifiedDelay))
        PreviewValue(R.string.advanced_tcp_concurrent, booleanLabel(effective?.tcpConcurrent))
        val process = when {
            !ownerAvailable -> R.string.settings_version_unavailable
            effective?.findProcessMode == FindProcessOverride.OFF -> R.string.advanced_off
            effective?.findProcessMode == FindProcessOverride.ALWAYS -> R.string.advanced_process_always
            else -> R.string.advanced_preview_unavailable
        }
        PreviewValue(R.string.advanced_find_process, process)
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        TextButton(onClick = { onEdit(CoreBehaviorOverride()) }, enabled = enabled && draft != CoreBehaviorOverride()) {
            Text(stringResource(R.string.override_reset))
        }
        Button(onClick = onSave, enabled = form.canSave(OverrideSection.CORE)) {
            Text(stringResource(R.string.common_save))
        }
    }
}

@Composable
private fun BooleanSetting(title: Int, value: Boolean?, inherit: Int, enabled: Boolean, onEdit: (Boolean?) -> Unit) {
    SectionHeader(stringResource(title))
    GlassCard {
        Column(Modifier.selectableGroup()) {
            Choice(inherit, value == null, enabled) { onEdit(null) }
            Choice(R.string.advanced_on, value == true, enabled) { onEdit(true) }
            Choice(R.string.advanced_off, value == false, enabled) { onEdit(false) }
        }
    }
}

private fun booleanLabel(value: Boolean?): Int = when (value) {
    true -> R.string.advanced_on
    false -> R.string.advanced_off
    null -> R.string.advanced_preview_unavailable
}

@Composable
private fun PreviewValue(title: Int, value: Int) {
    Text(
        stringResource(R.string.advanced_preview_value, stringResource(title), stringResource(value)),
        style = MaterialTheme.typography.bodySmall,
    )
}
