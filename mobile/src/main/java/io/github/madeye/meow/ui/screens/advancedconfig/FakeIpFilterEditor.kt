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
import io.github.madeye.meow.preference.FakeIpFilterMode
import io.github.madeye.meow.preference.FakeIpFilterOverride
import io.github.madeye.meow.preference.FakeIpFilterRuntime
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.components.SectionHeader
import io.github.madeye.meow.ui.screens.overrideconfig.Choice
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideForm
import io.github.madeye.meow.ui.screens.overrideconfig.OverrideSection

@Composable
internal fun FakeIpFilterEditor(
    form: OverrideForm,
    global: Boolean,
    onEdit: (FakeIpFilterOverride) -> Unit,
    onSave: () -> Unit,
) {
    val draft = form.draft.fakeIpFilter
    val enabled = !form.saving
    val inherit = if (global) R.string.override_follow_profile else R.string.override_inherit_global
    var text by remember { mutableStateOf(draft.patterns.orEmpty().joinToString("\n")) }
    val invalid = draft.patterns != null && FakeIpFilterRuntime.parsePatterns(text) == null
    Text(stringResource(R.string.override_next_connection), style = MaterialTheme.typography.bodySmall)
    SectionHeader(stringResource(R.string.advanced_fake_ip_filter_mode))
    GlassCard {
        Column(Modifier.selectableGroup()) {
            Choice(inherit, draft.mode == null, enabled) { onEdit(draft.copy(mode = null)) }
            Choice(R.string.advanced_fake_ip_filter_blacklist, draft.mode == FakeIpFilterMode.BLACKLIST, enabled) {
                onEdit(draft.copy(mode = FakeIpFilterMode.BLACKLIST))
            }
            Choice(R.string.advanced_fake_ip_filter_whitelist, draft.mode == FakeIpFilterMode.WHITELIST, enabled) {
                onEdit(draft.copy(mode = FakeIpFilterMode.WHITELIST))
            }
        }
    }
    SectionHeader(stringResource(R.string.advanced_fake_ip_filter_list))
    GlassCard {
        Column(Modifier.selectableGroup()) {
            Choice(inherit, draft.patterns == null, enabled) {
                text = ""
                onEdit(draft.copy(patterns = null))
            }
            Choice(R.string.advanced_fake_ip_filter_replace, draft.patterns != null, enabled) {
                if (draft.patterns == null) {
                    text = ""
                    onEdit(draft.copy(patterns = emptyList()))
                }
            }
        }
        if (draft.patterns != null) {
            OutlinedTextField(
                value = text,
                onValueChange = { value ->
                    if (value.length <= 32768) {
                        text = value
                        FakeIpFilterRuntime.parsePatterns(value)?.let { onEdit(draft.copy(patterns = it)) }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = enabled,
                isError = invalid,
                minLines = 3,
                maxLines = 8,
                label = { Text(stringResource(R.string.advanced_fake_ip_filter_list)) },
                supportingText = { Text(stringResource(
                    if (invalid) R.string.advanced_fake_ip_filter_invalid else R.string.advanced_fake_ip_filter_format,
                )) },
            )
        }
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        TextButton(onClick = { text = ""; onEdit(FakeIpFilterOverride()) },
            enabled = enabled && draft != FakeIpFilterOverride()) {
            Text(stringResource(R.string.override_reset))
        }
        Button(onClick = onSave, enabled = !invalid && form.canSave(OverrideSection.FAKE_IP)) {
            Text(stringResource(R.string.common_save))
        }
    }
}
