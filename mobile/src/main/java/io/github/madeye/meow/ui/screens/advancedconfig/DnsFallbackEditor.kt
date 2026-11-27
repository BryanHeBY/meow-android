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
import io.github.madeye.meow.preference.DnsFallbackOverride
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.screens.overrideconfig.Choice
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideForm
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideSection

private enum class FallbackChoice { INHERIT, DISABLED, REPLACE }

@Composable
internal fun DnsFallbackEditor(
    form: OverrideForm,
    global: Boolean,
    onEdit: (DnsFallbackOverride?) -> Unit,
    onSave: () -> Unit,
) {
    val value = form.draft.dnsFallback
    val saved = form.saved.dnsFallback
    var choice by remember(saved) {
        mutableStateOf(when (value) {
            null -> FallbackChoice.INHERIT
            DnsFallbackOverride.Disabled -> FallbackChoice.DISABLED
            is DnsFallbackOverride.Replace -> FallbackChoice.REPLACE
        })
    }
    val replacement = value as? DnsFallbackOverride.Replace
    var upstreams by remember(saved) { mutableStateOf(replacement?.endpoints.orEmpty().joinToString("\n") { it.display() }) }
    var domains by remember(saved) { mutableStateOf(replacement?.domains.orEmpty().joinToString("\n")) }
    var cidrs by remember(saved) { mutableStateOf(replacement?.cidrs.orEmpty().joinToString("\n")) }
    val parsed = DnsFallbackOverride.parse(upstreams, domains, cidrs)
    val invalid = choice == FallbackChoice.REPLACE && parsed == null
    val enabled = !form.saving
    fun applyDraft() {
        when (choice) {
            FallbackChoice.INHERIT -> onEdit(null)
            FallbackChoice.DISABLED -> onEdit(DnsFallbackOverride.Disabled)
            FallbackChoice.REPLACE -> DnsFallbackOverride.parse(upstreams, domains, cidrs)?.let(onEdit)
        }
    }
    Text(stringResource(R.string.advanced_dns_fallback_next_connection), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(R.string.advanced_dns_fallback_detail), style = MaterialTheme.typography.bodySmall)
    GlassCard {
        Column(Modifier.selectableGroup()) {
            val inherit = if (global) R.string.advanced_dns_mode_default else R.string.override_inherit_global
            for ((item, title) in listOf(
                FallbackChoice.INHERIT to inherit,
                FallbackChoice.DISABLED to R.string.advanced_off,
                FallbackChoice.REPLACE to R.string.advanced_nameserver_policy_replace,
            )) {
                Choice(title, choice == item, enabled) { choice = item; applyDraft() }
            }
        }
        if (choice == FallbackChoice.REPLACE) {
            FallbackInput(R.string.advanced_dns_fallback_upstreams, upstreams, 512, enabled) { upstreams = it; applyDraft() }
            FallbackInput(R.string.advanced_dns_fallback_domains, domains, 2048, enabled) { domains = it; applyDraft() }
            FallbackInput(R.string.advanced_dns_fallback_cidrs, cidrs, 896, enabled) { cidrs = it; applyDraft() }
            if (invalid) Text(
                stringResource(R.string.advanced_dns_fallback_invalid), color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        Button(onClick = onSave, enabled = !invalid && form.canSave(OverrideSection.DNS_FALLBACK)) {
            Text(stringResource(R.string.common_save))
        }
    }
}

@Composable
private fun FallbackInput(title: Int, value: String, limit: Int, enabled: Boolean, onEdit: (String) -> Unit) {
    OutlinedTextField(
        value = value, onValueChange = { if (it.length <= limit) onEdit(it) },
        modifier = Modifier.fillMaxWidth(), enabled = enabled, minLines = 2, maxLines = 5,
        label = { Text(stringResource(title)) },
    )
}
