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
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import io.github.madeye.meow.R
import io.github.madeye.meow.preference.NameserverPolicyOverride
import io.github.madeye.meow.preference.NameserverPolicyRow
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.components.SectionHeader
import io.github.madeye.meow.ui.screens.overrideconfig.Choice
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideForm
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideSection

@Composable
internal fun NameserverPolicyEditor(
    form: OverrideForm,
    global: Boolean,
    onEdit: (List<NameserverPolicyRow>?) -> Unit,
    onSave: () -> Unit,
) {
    val draft = form.draft.nameserverPolicy
    val enabled = !form.saving
    val inherit = if (global) R.string.override_follow_profile else R.string.override_inherit_global
    var text by remember { mutableStateOf(draft.orEmpty().joinToString("\n") { it.display() }) }
    val invalid = draft != null && NameserverPolicyOverride.parseRows(text) == null
    Text(stringResource(R.string.override_next_connection), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(R.string.advanced_nameserver_policy_detail), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(R.string.advanced_nameserver_policy_routing_note), style = MaterialTheme.typography.bodySmall)
    SectionHeader(stringResource(R.string.advanced_nameserver_policy_rows))
    GlassCard {
        Column(Modifier.selectableGroup()) {
            Choice(inherit, draft == null, enabled) { text = ""; onEdit(null) }
            Choice(R.string.advanced_nameserver_policy_replace, draft != null, enabled) {
                if (draft == null) { text = ""; onEdit(emptyList()) }
            }
        }
        if (draft != null) {
            OutlinedTextField(
                value = text,
                onValueChange = { value ->
                    if (value.length <= 12_288) {
                        text = value
                        NameserverPolicyOverride.parseRows(value)?.let(onEdit)
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = enabled,
                isError = invalid,
                minLines = 3,
                maxLines = 8,
                label = { Text(stringResource(R.string.advanced_nameserver_policy_rows)) },
                supportingText = { Text(stringResource(
                    if (invalid) R.string.advanced_nameserver_policy_invalid else R.string.advanced_nameserver_policy_format,
                )) },
            )
        }
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        TextButton(onClick = { text = ""; onEdit(null) }, enabled = enabled && draft != null) {
            Text(stringResource(R.string.override_reset))
        }
        TextButton(
            onClick = { text = ""; onEdit(emptyList()) },
            enabled = enabled && (draft == null || draft.isNotEmpty() || invalid),
        ) { Text(stringResource(R.string.advanced_nameserver_policy_clear)) }
        Button(onClick = onSave, enabled = !invalid && form.canSave(OverrideSection.NAMESERVER_POLICY)) {
            Text(stringResource(R.string.common_save))
        }
    }
}
