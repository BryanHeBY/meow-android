package io.github.madeye.meow.ui.screens.advancedconfig

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import io.github.madeye.meow.R
import io.github.madeye.meow.preference.DnsHostsOverride
import io.github.madeye.meow.preference.DnsHostsRuntime
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.components.SectionHeader
import io.github.madeye.meow.ui.screens.overrideconfig.Choice
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideForm
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideSection

@Composable
internal fun DnsHostsEditor(
    form: OverrideForm,
    global: Boolean,
    onEdit: (DnsHostsOverride) -> Unit,
    onSave: () -> Unit,
) {
    val draft = form.draft.dnsHosts
    val enabled = !form.saving
    val inherit = if (global) R.string.override_follow_profile else R.string.override_inherit_global
    var text by rememberSaveable {
        mutableStateOf(draft.hosts.orEmpty().entries.joinToString("\n") { "${it.key} ${it.value}" })
    }
    val invalid = draft.hosts != null && DnsHostsRuntime.parseRows(text) == null
    Text(stringResource(R.string.override_next_connection), style = MaterialTheme.typography.bodySmall)
    SectionHeader(stringResource(R.string.advanced_dns_hosts_use))
    GlassCard {
        Column(Modifier.selectableGroup()) {
            Choice(inherit, draft.useHosts == null, enabled) { onEdit(draft.copy(useHosts = null)) }
            Choice(R.string.override_force_on, draft.useHosts == true, enabled) { onEdit(draft.copy(useHosts = true)) }
            Choice(R.string.override_force_off, draft.useHosts == false, enabled) { onEdit(draft.copy(useHosts = false)) }
        }
    }
    SectionHeader(stringResource(R.string.advanced_dns_hosts_table))
    GlassCard {
        Column(Modifier.selectableGroup()) {
            Choice(inherit, draft.hosts == null, enabled) {
                text = ""
                onEdit(draft.copy(hosts = null))
            }
            Choice(R.string.advanced_dns_hosts_replace, draft.hosts != null, enabled) {
                if (draft.hosts == null) {
                    text = ""
                    onEdit(draft.copy(hosts = emptyMap()))
                }
            }
        }
        if (draft.hosts != null) {
            OutlinedTextField(
                value = text,
                onValueChange = { value ->
                    if (value.length <= 32768) {
                        text = value
                        DnsHostsRuntime.parseRows(value)?.let { onEdit(draft.copy(hosts = it)) }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = enabled,
                isError = invalid,
                minLines = 3,
                maxLines = 8,
                label = { Text(stringResource(R.string.advanced_dns_hosts_table)) },
                supportingText = { Text(stringResource(
                    if (invalid) R.string.advanced_dns_hosts_invalid else R.string.advanced_dns_hosts_format,
                )) },
            )
        }
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        TextButton(onClick = { text = ""; onEdit(DnsHostsOverride()) },
            enabled = enabled && draft != DnsHostsOverride()) {
            Text(stringResource(R.string.override_reset))
        }
        Button(onClick = onSave, enabled = !invalid && form.canSave(OverrideSection.HOSTS)) {
            Text(stringResource(R.string.common_save))
        }
    }
}
