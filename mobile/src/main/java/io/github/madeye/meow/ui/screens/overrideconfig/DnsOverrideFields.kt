package io.github.madeye.meow.ui.screens.overrideconfig

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.madeye.meow.R
import io.github.madeye.meow.preference.DnsEgress
import io.github.madeye.meow.preference.DnsApplicability
import io.github.madeye.meow.preference.DnsMode
import io.github.madeye.meow.preference.DnsSettings
import io.github.madeye.meow.preference.DnsStatus
import io.github.madeye.meow.preference.DnsTransport
import io.github.madeye.meow.preference.DnsUpstream
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.components.SectionHeader

@Composable
internal fun DnsOverrideFields(
    draft: DnsSettings,
    form: OverrideForm,
    selectedProfile: OverrideProfilePreview?,
    status: DnsStatus?,
    onEdit: (DnsSettings) -> Unit,
    onSave: () -> Unit,
) {
    SectionHeader(stringResource(R.string.override_dns))
    val enabled = !form.saving && form.dnsSelectedId == selectedProfile?.id
    val modes = listOf(DnsMode.INHERIT, DnsMode.CN, DnsMode.SPLIT, DnsMode.CUSTOM) +
        listOfNotNull(form.savedDns?.mode?.takeIf { it == DnsMode.LEGACY_PROFILE || it == DnsMode.LEGACY_BUILTIN })
    GlassCard {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            DnsMenu(draft.mode, modes, DnsMode::label, enabled, Modifier.testTag("dns_mode")) { mode ->
                val upstreams = if (mode == DnsMode.CUSTOM && draft.upstreams.isEmpty()) {
                    listOf(DnsUpstream())
                } else draft.upstreams
                onEdit(draft.copy(mode = mode, upstreams = upstreams))
            }
            if (draft.requiresProfile && draft.mode != DnsMode.SPLIT) {
                Text(
                    if (selectedProfile == null) stringResource(R.string.override_dns_select_profile)
                    else stringResource(R.string.override_dns_profile_scope, selectedProfile.name),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Text(stringResource(draft.mode.description()), style = MaterialTheme.typography.bodySmall)
            if (draft.mode == DnsMode.CUSTOM) {
                for ((index, upstream) in draft.upstreams.withIndex()) {
                    UpstreamFields(upstream, enabled, onEdit = { replacement ->
                        val upstreams = draft.upstreams.toMutableList().apply { set(index, replacement) }
                        onEdit(draft.copy(upstreams = upstreams))
                    }, onRemove = if (draft.upstreams.size > 1) {
                        { onEdit(draft.copy(upstreams = draft.upstreams.toMutableList().apply { removeAt(index) })) }
                    } else null)
                }
                TextButton(
                    enabled = enabled && draft.upstreams.size < DnsSettings.MAX_UPSTREAMS,
                    onClick = { onEdit(draft.copy(upstreams = draft.upstreams + DnsUpstream())) },
                ) { Text(stringResource(R.string.override_dns_add)) }
            }
            if (form.invalidDnsPreference) {
                Text(stringResource(R.string.override_dns_preference_invalid), color = MaterialTheme.colorScheme.error)
            }
            AppliedDns(status)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                Button(onClick = onSave, enabled = enabled && form.canSaveDns, modifier = Modifier.testTag("save_dns")) {
                    Text(stringResource(R.string.override_save_dns))
                }
            }
        }
    }
}

@Composable
private fun UpstreamFields(upstream: DnsUpstream, enabled: Boolean, onEdit: (DnsUpstream) -> Unit, onRemove: (() -> Unit)?) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        DnsMenu(upstream.transport, DnsTransport.entries, DnsTransport::label, enabled) {
            onEdit(upstream.copy(transport = it))
        }
        DnsMenu(upstream.egress, DnsEgress.entries, DnsEgress::label, enabled) {
            onEdit(upstream.copy(egress = it))
        }
    }
    OutlinedTextField(
        value = upstream.endpoint,
        onValueChange = { if (it.length <= 512) onEdit(upstream.copy(endpoint = it)) },
        label = { Text(stringResource(R.string.override_dns_endpoint)) },
        placeholder = { Text(if (upstream.transport == DnsTransport.HTTPS) "dns.example/dns-query" else "dns.example") },
        singleLine = true,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
    )
    if (upstream.egress == DnsEgress.PROXY) {
        ProxyName(upstream.proxy, enabled) { onEdit(upstream.copy(proxy = it)) }
    }
    if (onRemove != null) {
        TextButton(enabled = enabled, onClick = onRemove) { Text(stringResource(R.string.override_dns_remove)) }
    }
}

@Composable
private fun ProxyName(name: String, enabled: Boolean, onEdit: (String) -> Unit) {
    OutlinedTextField(
        value = name,
        onValueChange = { if (it.length <= 256) onEdit(it) },
        label = { Text(stringResource(R.string.override_dns_proxy_name)) },
        singleLine = true,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun AppliedDns(status: DnsStatus?) {
    var details by remember { mutableStateOf(false) }
    val applied = when (status?.mode) {
        null -> null
        "inherit" -> DnsMode.INHERIT.label()
        "profile" -> DnsMode.LEGACY_PROFILE.label()
        "builtin" -> DnsMode.LEGACY_BUILTIN.label()
        "cn" -> DnsMode.CN.label()
        "split" -> DnsMode.SPLIT.label()
        "custom" -> DnsMode.CUSTOM.label()
        else -> R.string.override_dns_runtime_config
    }
    when {
        status == null -> Text(stringResource(R.string.override_dns_status_unavailable), style = MaterialTheme.typography.bodySmall)
        applied == null -> Text(stringResource(R.string.override_dns_offline), style = MaterialTheme.typography.bodySmall)
        else -> {
            Text(stringResource(R.string.override_dns_applied, stringResource(applied)), style = MaterialTheme.typography.bodySmall)
            if (status.missingMain) Text(stringResource(R.string.override_dns_missing_main), style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = { details = !details }) {
                Text(stringResource(if (details) R.string.override_dns_hide_upstreams else R.string.override_dns_show_upstreams))
            }
            if (details) {
                val pools = listOf(
                    R.string.override_dns_primary to status.primary,
                    R.string.override_dns_fallback to status.fallback,
                    R.string.override_dns_direct to status.direct,
                    R.string.override_dns_node to status.node,
                    R.string.override_dns_bootstrap to status.bootstrap,
                )
                for ((label, endpoints) in pools) if (endpoints.isNotEmpty()) {
                    Text(stringResource(label), style = MaterialTheme.typography.labelMedium)
                    Text(endpoints.joinToString("\n"), style = MaterialTheme.typography.bodySmall)
                }
                if (status.policyEntries > 0) {
                    Text(stringResource(R.string.override_dns_policy_count, status.policyEntries), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
    if (status?.applicability == DnsApplicability.PENDING && status.issue == null) {
        Text(stringResource(R.string.override_dns_profile_pending), style = MaterialTheme.typography.bodySmall)
    }
    status?.issue?.let { Text(it.message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
}

@Composable
private fun <T> DnsMenu(value: T, choices: List<T>, label: (T) -> Int, enabled: Boolean, modifier: Modifier = Modifier, onEdit: (T) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box(modifier) {
        TextButton(enabled = enabled, onClick = { open = true }) { Text(stringResource(label(value))) }
        DropdownMenu(expanded = open && enabled, onDismissRequest = { open = false }) {
            for (choice in choices) {
                DropdownMenuItem(text = { Text(stringResource(label(choice))) }, onClick = {
                    open = false
                    onEdit(choice)
                })
            }
        }
    }
}

private fun DnsMode.label() = when (this) {
    DnsMode.INHERIT -> R.string.override_dns_inherit
    DnsMode.LEGACY_PROFILE -> R.string.override_dns_legacy_profile
    DnsMode.LEGACY_BUILTIN -> R.string.override_dns_legacy_builtin
    DnsMode.CN -> R.string.override_dns_cn
    DnsMode.SPLIT -> R.string.override_dns_split
    DnsMode.CUSTOM -> R.string.override_dns_custom
}

private fun DnsMode.description() = when (this) {
    DnsMode.INHERIT, DnsMode.LEGACY_PROFILE -> R.string.override_dns_inherit_desc
    DnsMode.LEGACY_BUILTIN -> R.string.settings_builtin_dns_desc
    DnsMode.CN -> R.string.override_dns_cn_desc
    DnsMode.SPLIT -> R.string.override_dns_split_desc
    DnsMode.CUSTOM -> R.string.override_dns_custom_desc
}

private fun DnsTransport.label() = when (this) {
    DnsTransport.UDP -> R.string.override_dns_udp
    DnsTransport.TCP -> R.string.override_dns_tcp
    DnsTransport.TLS -> R.string.override_dns_dot
    DnsTransport.HTTPS -> R.string.override_dns_doh
}

private fun DnsEgress.label() = when (this) {
    DnsEgress.DIRECT -> R.string.override_dns_direct
    DnsEgress.PROXY -> R.string.override_dns_proxy
}
