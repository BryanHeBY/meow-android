package io.github.madeye.meow.ui.screens.diagnostics

import android.content.Intent
import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.madeye.meow.R
import io.github.madeye.meow.diagnostics.FaultDiagnostics
import io.github.madeye.meow.diagnostics.FaultEvent
import io.github.madeye.meow.diagnostics.FaultKind
import io.github.madeye.meow.diagnostics.faultReport
import io.github.madeye.meow.ui.components.GlassCard
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.CancellationException
import timber.log.Timber

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun FaultDiagnosticsScreen(padding: PaddingValues) {
    val context = LocalContext.current
    val dateFormat = remember { DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM) }
    var events by remember { mutableStateOf<List<FaultEvent>>(emptyList()) }
    var busy by remember { mutableStateOf(true) }
    var failed by remember { mutableStateOf(false) }
    var request by remember { mutableStateOf(0) }
    var erase by remember { mutableStateOf(false) }
    var confirmClear by rememberSaveable { mutableStateOf(false) }

    LaunchedEffect(request) {
        busy = true
        failed = false
        try {
            if (erase) {
                FaultDiagnostics.clear()
                events = emptyList()
            }
            events = FaultDiagnostics.read()
        } catch (e: CancellationException) {
            throw e
        } catch (e: RuntimeException) {
            Timber.w(e, "could not load fault diagnostics")
            failed = true
        } finally {
            busy = false
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxWidth().testTag("fault_diagnostics"),
        contentPadding = PaddingValues(
            start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 8.dp,
            bottom = padding.calculateBottomPadding() + 16.dp,
        ),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            GlassCard {
                Text(stringResource(R.string.fault_diagnostics_local), style = MaterialTheme.typography.bodyMedium)
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
                    Text(stringResource(R.string.fault_diagnostics_legacy), style = MaterialTheme.typography.bodySmall)
                }
                FlowRow {
                    TextButton(enabled = !busy, onClick = {
                        busy = true
                        erase = false
                        request++
                    }) { Text(stringResource(R.string.fault_diagnostics_refresh)) }
                    TextButton(enabled = !busy && events.isNotEmpty(), onClick = {
                        val send = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, faultReport(events))
                        }
                        context.startActivity(Intent.createChooser(send, null))
                    }) { Text(stringResource(R.string.fault_diagnostics_export)) }
                    TextButton(enabled = !busy, onClick = { confirmClear = true }) {
                        Text(stringResource(R.string.fault_diagnostics_clear))
                    }
                }
            }
        }
        if (failed || (!busy && events.isEmpty())) {
            item {
                GlassCard {
                    Text(stringResource(
                        if (failed) R.string.fault_diagnostics_read_failed else R.string.fault_diagnostics_empty,
                    ))
                }
            }
        }
        items(events) { entry ->
            GlassCard {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(entry.kind.label()), style = MaterialTheme.typography.titleSmall)
                    Text(
                        "${dateFormat.format(Date(entry.time))}  ·  ${entry.process}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (entry.code != 0) {
                        Text(stringResource(R.string.fault_diagnostics_code, entry.code), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(R.string.fault_diagnostics_clear_title)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmClear = false
                    busy = true
                    erase = true
                    request++
                }) { Text(stringResource(R.string.fault_diagnostics_clear)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) {
                    Text(stringResource(android.R.string.cancel))
                }
            },
        )
    }
}

private fun FaultKind.label(): Int = when (this) {
    FaultKind.JVM_CRASH -> R.string.fault_diagnostics_jvm
    FaultKind.NATIVE_CRASH -> R.string.fault_diagnostics_native
    FaultKind.ANR -> R.string.fault_diagnostics_anr
    FaultKind.LOW_MEMORY -> R.string.fault_diagnostics_memory
    FaultKind.PROCESS_EXIT -> R.string.fault_diagnostics_exit
    FaultKind.VPN_BINDER_LOST -> R.string.fault_diagnostics_binder
    FaultKind.TUN_EXIT -> R.string.fault_diagnostics_tun
    FaultKind.NETWORK_CHANGE -> R.string.fault_diagnostics_network
    FaultKind.PROXY_GROUP_REFRESH -> R.string.fault_diagnostics_groups
}
