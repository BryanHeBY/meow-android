package io.github.madeye.meow.ui.screens.logs

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.VerticalAlignBottom
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.madeye.meow.R
import io.github.madeye.meow.api.ControllerAccess
import io.github.madeye.meow.api.ControllerStatus
import io.github.madeye.meow.api.controllerStatus
import io.github.madeye.meow.api.LogEntry
import io.github.madeye.meow.ui.components.ControllerMessage
import java.io.IOException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import io.github.madeye.meow.api.MeowApi
import io.github.madeye.meow.vpn.ControllerSession
import io.github.madeye.meow.ui.theme.meow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.stateIn

/**
 * Live engine logs.
 *
 * Reads the controller's `/logs` websocket rather than the old `nativeGetLogs`
 * JNI call: that drained a per-process Rust ring buffer from the UI process,
 * while the engine runs in `:vpn` — so it could only ever have returned empty.
 */
data class LogsUiState(
    val logs: List<LogEntry> = emptyList(),
    val status: ControllerStatus = ControllerStatus.Loading,
)

@OptIn(ExperimentalCoroutinesApi::class)
class LogsViewModel(controller: ControllerAccess, apiForSession: (ControllerSession) -> MeowApi) : ViewModel() {
    private val reload = MutableStateFlow(0L)

    val uiState: StateFlow<LogsUiState> = controller.lifecycle.flatMapLatest { vpn ->
        val session = vpn.session ?: return@flatMapLatest flowOf(LogsUiState(status = vpn.controllerStatus))
        reload.flatMapLatest {
            flow {
                var connected = false
                var failures = 0
                var lines = emptyList<LogEntry>()
                emit(LogsUiState())
                try {
                    apiForSession(session).logStream { error, backoff ->
                        controller.requireCurrent(session)
                        if (connected) emit(LogsUiState(lines, ControllerStatus.Stale))
                        (connected || ++failures < MAX_STARTUP_ATTEMPTS) &&
                            controller.retryTransport(session, error, backoff)
                    }.collect { event ->
                        controller.requireCurrent(session)
                        connected = true
                        event.entry?.let { lines = (lines + it).takeLast(MAX_LINES) }
                        emit(LogsUiState(lines, ControllerStatus.Ready))
                    }
                } catch (_: IOException) {
                    controller.requireCurrent(session)
                    emit(LogsUiState(lines, if (connected) ControllerStatus.Stale else ControllerStatus.Failed))
                }
            }
        }.buffer(0)
    }.buffer(0).stateIn(viewModelScope, SharingStarted.WhileSubscribed(replayExpirationMillis = 0), LogsUiState())

    fun retry() { reload.update { it + 1 } }

    private companion object {
        const val MAX_LINES = 500
        const val MAX_STARTUP_ATTEMPTS = 4
    }
}

@Composable
fun LogsScreen(
    state: LogsUiState,
    onRetry: () -> Unit,
    autoScroll: Boolean,
    contentPadding: PaddingValues,
    modifier: Modifier = Modifier,
) {
    val logs = state.logs
    val listState = rememberLazyListState()

    val hasStatus = state.status != ControllerStatus.Ready
    LaunchedEffect(logs.lastOrNull(), autoScroll, hasStatus) {
        if (autoScroll && logs.isNotEmpty()) {
            listState.animateScrollToItem(if (hasStatus) logs.size else logs.lastIndex)
        }
    }

    if (logs.isEmpty()) {
        Box(
            modifier = modifier.fillMaxSize().padding(contentPadding),
            contentAlignment = Alignment.Center,
        ) {
            if (hasStatus) {
                ControllerMessage(state.status, onRetry)
            } else {
                Text(
                    text = stringResource(R.string.logs_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.meow.mutedText,
                )
            }
        }
        return
    }

    LazyColumn(
        state = listState,
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(
            start = 16.dp,
            end = 16.dp,
            top = contentPadding.calculateTopPadding(),
            bottom = contentPadding.calculateBottomPadding() + 16.dp,
        ),
    ) {
        if (hasStatus) item { ControllerMessage(state.status, onRetry) }
        itemsIndexed(logs) { _, entry ->
            val colors = MaterialTheme.meow
            val tint = when (entry.type.lowercase()) {
                "error" -> colors.danger
                "warning", "warn" -> colors.warning
                "info" -> colors.accent
                else -> colors.mutedText
            }
            Text(
                text = "${entry.type.uppercase().padEnd(5)} ${entry.payload}",
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = tint,
                modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
            )
        }
    }
}

@Composable
fun LogsActions(autoScroll: Boolean, onToggleAutoScroll: () -> Unit) {
    IconButton(onClick = onToggleAutoScroll) {
        Icon(
            imageVector = if (autoScroll) Icons.Filled.Pause else Icons.Filled.VerticalAlignBottom,
            contentDescription = stringResource(R.string.logs_auto_scroll),
        )
    }
}
