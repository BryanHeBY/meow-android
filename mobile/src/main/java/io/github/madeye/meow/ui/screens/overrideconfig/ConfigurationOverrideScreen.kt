package io.github.madeye.meow.ui.screens.overrideconfig

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.madeye.meow.AppGraph
import io.github.madeye.meow.R
import io.github.madeye.meow.preference.AppQuicOverride
import io.github.madeye.meow.preference.ConfigurationOverride
import io.github.madeye.meow.preference.Ipv6Override
import io.github.madeye.meow.ui.BackButton
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.components.MeowScaffold
import io.github.madeye.meow.ui.components.SectionHeader

internal const val CONFIGURATION_OVERRIDE_TAG = "configuration_override"
internal const val PROFILE_OVERRIDE_TAG = "profile_configuration_override"

@Composable
internal fun ConfigurationOverrideRoute(snackbarHost: SnackbarHostState, onBack: () -> Unit) {
    val viewModel: ConfigurationOverrideViewModel = viewModel(factory = AppGraph.viewModelFactory)
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val (form, profile) = state
    val dnsStatus by viewModel.dnsStatus.collectAsStateWithLifecycle()
    val saving = form?.saving == true
    val global = viewModel.profileId == null

    val saved = stringResource(R.string.override_saved)
    val dnsSaved = stringResource(R.string.override_dns_saved)
    val failed = stringResource(R.string.override_failed)
    val dnsFailed = stringResource(R.string.settings_builtin_dns_failed)
    LaunchedEffect(viewModel) {
        viewModel.events.collect {
            val message = when (it) {
                OverrideEvent.Saved -> saved
                OverrideEvent.DnsSaved -> dnsSaved
                OverrideEvent.SaveFailed -> failed
                is OverrideEvent.DnsFailed -> String.format(dnsFailed, it.issue.message)
            }
            snackbarHost.showSnackbar(message)
        }
    }
    BackHandler(enabled = saving) { }
    MeowScaffold(
        title = stringResource(R.string.override_title),
        navigationIcon = { BackButton { if (!saving) onBack() } },
    ) { padding ->
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState())
                .padding(top = padding.calculateTopPadding(), bottom = padding.calculateBottomPadding() + 24.dp)
                .padding(horizontal = 16.dp)
                .testTag("configuration_override_form"),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            val scope = when {
                global -> R.string.override_global
                profile?.subscription == true -> R.string.override_subscription
                else -> R.string.override_profile
            }
            SectionHeader(stringResource(scope))
            if (!global) profile?.let { Text(it.name, style = MaterialTheme.typography.titleMedium) }
            if (!global && profile == null && form != null) {
                Text(stringResource(R.string.override_profile_unavailable))
            } else if (form != null) {
                form.draftDns?.let {
                    DnsOverrideFields(it, form, profile, dnsStatus, viewModel::editDns) { viewModel.saveDns(profile?.id) }
                }
                OverrideFields(form, profile, global, viewModel::edit, viewModel::save)
            }
        }
    }
    SnackbarHost(snackbarHost)
}

@Composable
private fun OverrideFields(
    form: OverrideForm,
    profile: OverrideProfilePreview?,
    global: Boolean,
    onEdit: (ConfigurationOverride) -> Unit,
    onSave: () -> Unit,
) {
    val draft = form.draft
    val effective = if (global) profile?.override?.withInherited(draft) ?: draft else draft.withInherited(form.global)
    val enabled = !form.saving
    val inherit = if (global) R.string.override_follow_profile else R.string.override_inherit_global
    Text(stringResource(R.string.override_next_connection), style = MaterialTheme.typography.bodySmall)

    SectionHeader(stringResource(R.string.override_ipv6))
    GlassCard(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)) {
        Column(Modifier.selectableGroup()) {
            Choice(inherit, draft.ipv6 == Ipv6Override.INHERIT, enabled) { onEdit(draft.copy(ipv6 = Ipv6Override.INHERIT)) }
            Choice(R.string.override_force_on, draft.ipv6 == Ipv6Override.FORCE_ON, enabled, Modifier.testTag("override_ipv6_force_on")) { onEdit(draft.copy(ipv6 = Ipv6Override.FORCE_ON)) }
            Choice(R.string.override_force_off, draft.ipv6 == Ipv6Override.FORCE_OFF, enabled, Modifier.testTag("override_ipv6_force_off")) { onEdit(draft.copy(ipv6 = Ipv6Override.FORCE_OFF)) }
        }
    }

    SectionHeader(stringResource(R.string.override_quic))
    GlassCard(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)) {
        Text(stringResource(R.string.override_quic_limit), style = MaterialTheme.typography.bodySmall)
        Column(Modifier.selectableGroup()) {
            val noOverride = if (global) R.string.override_quic_no_override else R.string.override_inherit_global
            Choice(noOverride, draft.appQuic == AppQuicOverride.INHERIT, enabled) { onEdit(draft.copy(appQuic = AppQuicOverride.INHERIT)) }
            Choice(R.string.override_quic_block, draft.appQuic == AppQuicOverride.BLOCK_UDP_443, enabled) { onEdit(draft.copy(appQuic = AppQuicOverride.BLOCK_UDP_443)) }
            if (!global) {
                Choice(R.string.override_quic_allow, draft.appQuic == AppQuicOverride.DO_NOT_BLOCK, enabled) { onEdit(draft.copy(appQuic = AppQuicOverride.DO_NOT_BLOCK)) }
            }
        }
    }

    SectionHeader(stringResource(R.string.override_preview))
    GlassCard {
        if (global) profile?.let { Text(it.name, style = MaterialTheme.typography.titleSmall) }
        val ipv6 = when (effective.ipv6) {
            Ipv6Override.FORCE_ON -> R.string.override_ipv6_on
            Ipv6Override.FORCE_OFF -> R.string.override_ipv6_off
            Ipv6Override.INHERIT -> when (profile?.ipv6) {
                1 -> R.string.override_ipv6_on
                0 -> R.string.override_ipv6_off
                -1 -> R.string.override_ipv6_default
                -2 -> R.string.override_ipv6_unavailable
                else -> R.string.override_follow_profile
            }
        }
        Text(stringResource(ipv6), style = MaterialTheme.typography.bodySmall)
        val quic = if (effective.blocksAppUdp443) R.string.override_quic_block else R.string.override_quic_allow
        Text(stringResource(quic), style = MaterialTheme.typography.bodySmall)
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        TextButton(
            onClick = { onEdit(ConfigurationOverride()) },
            enabled = enabled && draft != ConfigurationOverride(),
        ) { Text(stringResource(R.string.override_reset)) }
        Button(onClick = onSave, enabled = form.canSave, modifier = Modifier.testTag("save_configuration_override")) {
            Text(stringResource(R.string.common_save))
        }
    }
}

@Composable
private fun Choice(
    label: Int,
    selected: Boolean,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    Row(
        modifier.fillMaxWidth().selectable(selected, enabled = enabled, role = Role.RadioButton, onClick = onClick)
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null, enabled = enabled)
        Text(stringResource(label), style = MaterialTheme.typography.bodyMedium)
    }
}
