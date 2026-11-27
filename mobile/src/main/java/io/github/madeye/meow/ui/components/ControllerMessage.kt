package io.github.madeye.meow.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import io.github.madeye.meow.R
import io.github.madeye.meow.api.ControllerStatus
import io.github.madeye.meow.ui.theme.meow

@Composable
internal fun ControllerMessage(status: ControllerStatus, onRetry: (() -> Unit)? = null) {
    val message = when (status) {
        ControllerStatus.Offline -> R.string.controller_offline
        ControllerStatus.Loading -> R.string.controller_loading
        ControllerStatus.Failed -> R.string.controller_failed
        ControllerStatus.Stale -> R.string.controller_stale
        ControllerStatus.Ready -> return
    }
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            stringResource(message),
            color = MaterialTheme.meow.mutedText,
            textAlign = TextAlign.Center,
        )
        if (onRetry != null && (status == ControllerStatus.Failed || status == ControllerStatus.Stale)) {
            TextButton(onClick = onRetry) { Text(stringResource(R.string.common_retry)) }
        }
    }
}
