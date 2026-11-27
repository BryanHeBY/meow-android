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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import io.github.madeye.meow.R
import io.github.madeye.meow.preference.NumericDnsEndpoint
import io.github.madeye.meow.preference.NumericDnsEndpoints
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.screens.overrideconfig.Choice
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideForm
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideSection

@Composable
internal fun DnsBootstrapEditor(
    form: OverrideForm,
    global: Boolean,
    onEdit: (List<NumericDnsEndpoint>?) -> Unit,
    onSave: () -> Unit,
) {
    val saved = form.saved.dnsBootstrap
    val value = form.draft.dnsBootstrap
    var replace by remember(saved) { mutableStateOf(value != null) }
    var rows by remember(saved) { mutableStateOf(value.orEmpty().joinToString("\n") { it.display() }) }
    val invalid = replace && NumericDnsEndpoints.parse(rows) == null
    val enabled = !form.saving
    val inherit = if (global) R.string.advanced_dns_mode_default else R.string.override_inherit_global
    Text(stringResource(R.string.advanced_dns_bootstrap_next_connection), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(R.string.advanced_dns_bootstrap_detail), style = MaterialTheme.typography.bodySmall)
    GlassCard {
        Column(Modifier.selectableGroup()) {
            Choice(inherit, !replace, enabled) {
                replace = false
                onEdit(null)
            }
            Choice(R.string.advanced_nameserver_policy_replace, replace, enabled) {
                replace = true
                NumericDnsEndpoints.parse(rows)?.let(onEdit)
            }
        }
        if (replace) {
            OutlinedTextField(
                value = rows,
                onValueChange = { next ->
                    if (next.length <= NumericDnsEndpoints.TEXT_LIMIT) {
                        rows = next
                        NumericDnsEndpoints.parse(next)?.let(onEdit)
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = enabled,
                isError = invalid,
                minLines = 2,
                maxLines = 5,
                label = { Text(stringResource(R.string.advanced_dns_bootstrap_endpoints)) },
                supportingText = if (invalid) {
                    { Text(stringResource(R.string.advanced_dns_bootstrap_invalid)) }
                } else null,
            )
        }
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        Button(onClick = onSave, enabled = !invalid && form.canSave(OverrideSection.DNS_BOOTSTRAP)) {
            Text(stringResource(R.string.common_save))
        }
    }
}
