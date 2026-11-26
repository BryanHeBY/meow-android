package io.github.madeye.meow.ui.screens.zerotier

import android.app.Activity
import android.net.VpnService
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Switch
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.madeye.meow.AppGraph
import io.github.madeye.meow.R
import io.github.madeye.meow.bg.BaseService
import io.github.madeye.meow.bg.ForwardingControl
import io.github.madeye.meow.core.ZeroTierNative
import io.github.madeye.meow.repo.InstalledApp
import io.github.madeye.meow.repo.MoonSetting
import io.github.madeye.meow.repo.OverlaySettings
import io.github.madeye.meow.repo.OverlaySettingsRepository
import io.github.madeye.meow.repo.OverlayStatus
import io.github.madeye.meow.repo.SavedOverlayNetwork
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.components.MeowScaffold
import io.github.madeye.meow.ui.screens.perapp.AppPickerMenu
import io.github.madeye.meow.ui.screens.perapp.PerAppUiState
import io.github.madeye.meow.ui.screens.perapp.updateVisibleSelection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber

@Composable
private fun isChinese(): Boolean =
    LocalContext.current.resources.configuration.locales[0].language == "zh"

@Composable
internal fun ZeroTierSummary(onOpen: () -> Unit) {
    val zh = isChinese()
    val vpn by AppGraph.vpn.state.collectAsStateWithLifecycle()
    val store = remember { OverlaySettingsRepository() }
    var actual by remember { mutableStateOf<OverlayStatus?>(null) }
    LaunchedEffect(vpn) {
        actual = null
        if (vpn == BaseService.State.Connected) {
            while (true) {
                actual = store.runtime()
                delay(1_000)
            }
        }
    }
    GlassCard {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text("ZeroTier", style = MaterialTheme.typography.titleMedium)
                Text(statusText(actual, zh), style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = onOpen) { Text(if (zh) "详情" else "Details") }
        }
    }
}

private fun statusText(state: OverlayStatus?, zh: Boolean): String = when {
    state == null || state.phase == "stopped" -> if (zh) "未连接" else "Disconnected"
    state.phase == "failed" -> if (zh) "ZeroTier 启动失败" else "ZeroTier failed"
    state.phase == "ready" -> (if (zh) "已连接" else "Connected") + (state.ip?.let { " · $it" } ?: "")
    state.sdkStatus == 2 -> if (zh) "等待管理员授权" else "Waiting for administrator authorization"
    state.sdkStatus == 3 -> if (zh) "找不到网络" else "Network not found"
    state.sdkStatus == 4 -> if (zh) "虚拟网卡错误" else "Virtual interface error"
    state.sdkStatus == 5 -> if (zh) "客户端版本过旧" else "Client version too old"
    state.sdkStatus == 6 -> if (zh) "需要额外身份验证" else "Extra authentication required"
    else -> if (zh) "等待网络配置" else "Waiting for network configuration"
}

@Composable
internal fun ZeroTierRoute(bottomBar: @Composable () -> Unit) {
    val zh = isChinese()
    fun tr(en: String, cn: String) = if (zh) cn else en
    val context = LocalContext.current
    val store = remember { OverlaySettingsRepository() }
    val scope = rememberCoroutineScope()
    val vpn by AppGraph.vpn.state.collectAsStateWithLifecycle()
    var config by remember { mutableStateOf(OverlaySettings()) }
    var actual by remember { mutableStateOf<OverlayStatus?>(null) }
    var network by rememberSaveable { mutableStateOf("") }
    var routes by rememberSaveable { mutableStateOf("") }
    var dnsMode by rememberSaveable { mutableStateOf("off") }
    var dns1 by rememberSaveable { mutableStateOf("") }
    var dns2 by rememberSaveable { mutableStateOf("") }
    var defaultRoute by rememberSaveable { mutableStateOf(false) }
    var page by rememberSaveable { mutableStateOf("networks") }
    var detail by rememberSaveable { mutableStateOf("") }
    var rowMenu by remember { mutableStateOf<String?>(null) }
    var removeNetwork by remember { mutableStateOf<String?>(null) }
    var more by remember { mutableStateOf(false) }

    var moonWorld by rememberSaveable { mutableStateOf("") }
    var moonSeed by rememberSaveable { mutableStateOf("") }
    var pendingMoon by remember { mutableStateOf<Pair<String, ByteArray>?>(null) }
    var appMode by rememberSaveable { mutableStateOf(ZeroTierAppMode.All) }
    var appSelection by rememberSaveable { mutableStateOf(arrayListOf<String>()) }
    var loaded by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var info by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        runCatching { store.load() }.onSuccess {
            config = it
            // The add form is independent of the last active network.
        }.onFailure { info = tr("Saved ZeroTier configuration could not be read", "无法读取已保存的 ZeroTier 配置") }
        loaded = true
    }
    LaunchedEffect(vpn) {
        actual = null
        if (vpn == BaseService.State.Connected) {
            while (true) {
                actual = store.runtime()
                delay(1_000)
            }
        }
    }

    fun start() {
        runCatching { io.github.madeye.meow.bg.VpnService.start(context) }.onFailure {
            info = tr("Could not start VPN", "无法启动 VPN")
        }.onSuccess { if (!it) info = tr("Could not start VPN", "无法启动 VPN") }
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) start()
        else info = tr("Android VPN permission was not granted", "未授予 Android VPN 权限")
    }
    fun persist(candidate: OverlaySettings, apply: Boolean, imported: Pair<String, ByteArray>? = null, onSaved: () -> Unit = {}) {
        val normalized = candidate.validated()
        if (normalized == null) {
            info = tr("Check the network ID, IPv4 CIDRs and Moon entries", "请检查网络 ID、IPv4 网段和 Moon 条目")
            return
        }
        scope.launch {
            busy = true
            try {
                if (imported != null) store.stageMoon(imported.first, imported.second)
                store.save(normalized)
                config = normalized
                onSaved()
                info = if (apply) "" else tr("Saved", "已保存")
                if (apply) {
                    if (AppGraph.vpn.state.value != BaseService.State.Stopped &&
                        AppGraph.vpn.state.value != BaseService.State.Idle
                    ) {
                        info = when (AppGraph.vpn.applyZeroTier()) {
                            ForwardingControl.APPLIED, ForwardingControl.STOPPED -> ""
                            ForwardingControl.REBUILT -> tr(
                                "VPN forwarding rebuilt; Meow stayed running. Some connections may reconnect.",
                                "VPN 转发已重建，Meow 内核未重启。部分连接可能重新建立。",
                            )
                            ForwardingControl.INDETERMINATE -> tr(
                                "ZeroTier did not confirm the change. Check its actual status before trying again.",
                                "ZeroTier 未确认此次变更。请先检查实际连接状态，再重试。",
                            )
                            else -> tr(
                                "Saved, but live apply failed. Check VPN status before retrying.",
                                "已保存，但应用到运行中的 VPN 失败。重试前请检查 VPN 状态。",
                            )
                        }
                        return@launch
                    }
                    if (!normalized.enabled && withContext(Dispatchers.IO) { io.github.madeye.meow.Core.currentProfile == null }) {
                        return@launch
                    }
                    val approval = VpnService.prepare(context)
                    if (approval == null) start() else consent.launch(approval)
                }
            } catch (e: java.io.IOException) {
                info = tr("Could not save ZeroTier settings", "无法保存 ZeroTier 设置")
            } catch (e: IllegalStateException) {
                info = tr("Could not apply ZeroTier settings", "无法应用 ZeroTier 设置")
            } finally {
                busy = false
            }
        }
    }

    val chooseMoon = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            busy = true
            try {
                val encoded = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { stream ->
                        val buffer = ByteArray(16_385)
                        var length = 0
                        while (length < buffer.size) {
                            val read = stream.read(buffer, length, buffer.size - length)
                            if (read <= 0) break
                            length += read
                        }
                        if (length in 1..16_384) buffer.copyOf(length) else null
                    }
                }
                val world = encoded?.let { withContext(Dispatchers.Default) { ZeroTierNative.nativeInspectMoon(it) } }
                when {
                    world == null -> info = tr("Invalid or oversized Moon file", "Moon 文件无效或过大")
                    config.moons.any { it.world == world } ->
                        info = tr("Remove the existing entry before replacing that World ID", "请先移除同一 World ID，再重新导入")
                    else -> pendingMoon = world to requireNotNull(encoded)
                }
            } catch (e: java.io.IOException) {
                info = tr("Could not read the Moon file", "无法读取 Moon 文件")
            } catch (e: SecurityException) {
                info = tr("Could not access the Moon file", "无法访问 Moon 文件")
            } finally {
                busy = false
            }
        }
    }
    pendingMoon?.let { candidate ->
        AlertDialog(
            onDismissRequest = { pendingMoon = null },
            title = { Text(tr("Trust this Moon?", "信任此 Moon？")) },
            text = { Text(tr(
                "World ID: ${candidate.first}\nOnly import a file from a source you trust. This trusts the root identities in the file.",
                "World ID：${candidate.first}\n仅导入可信来源的文件。确认后将信任文件中的根节点身份。",
            )) },
            confirmButton = {
                TextButton(onClick = {
                    pendingMoon = null
                    persist(config.copy(moons = config.moons + MoonSetting(candidate.first)), config.enabled && vpn.canStop, candidate)
                }) { Text(tr("Trust and import", "信任并导入")) }
            },
            dismissButton = {
                TextButton(onClick = { pendingMoon = null }) { Text(tr("Cancel", "取消")) }
            },
        )
    }

    fun up() {
        page = "networks"
        more = false
        info = ""
    }
    BackHandler(enabled = page != "networks") { up() }
    fun resetAdd() {
        network = ""
        defaultRoute = false
        dnsMode = "off"
        dns1 = ""
        dns2 = ""
        info = ""
        page = "add"
    }
    fun edit(row: SavedOverlayNetwork) {
        detail = row.id
        defaultRoute = row.allowDefault
        dnsMode = row.dnsMode
        dns1 = row.dnsServers.getOrNull(0).orEmpty()
        dns2 = row.dnsServers.getOrNull(1).orEmpty()
        routes = row.routes.joinToString("\n")
        page = "detail"
        info = ""
    }
    val dnsServers = OverlaySettings.normalizeDns(dnsMode, listOf(dns1, dns2))
    val dnsOptions: @Composable () -> Unit = {
        Text(tr("DNS", "DNS"), style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            for ((mode, label) in listOf("off" to tr("None", "不使用"), "network" to tr("Network", "网络下发"), "custom" to tr("Custom", "自定义"))) {
                FilterChip(selected = dnsMode == mode, onClick = { dnsMode = mode }, label = { Text(label) })
            }
        }
        if (dnsMode == "custom") {
            OutlinedTextField(dns1, { dns1 = it.take(15) }, singleLine = true,
                label = { Text(tr("Primary IPv4 DNS", "首选 IPv4 DNS")) }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(dns2, { dns2 = it.take(15) }, singleLine = true,
                label = { Text(tr("Secondary IPv4 DNS", "备用 IPv4 DNS")) }, modifier = Modifier.fillMaxWidth())
        }
        if (dnsMode != "off") {
            Text(tr("Only for apps allowed by the ZeroTier policy.", "仅适用于 ZeroTier 分应用规则允许的应用。"),
                style = MaterialTheme.typography.bodySmall)
        }
    }
    fun copyId(id: String) {
        context.getSystemService(android.content.ClipboardManager::class.java)
            ?.setPrimaryClip(android.content.ClipData.newPlainText("ZeroTier Network ID", id))
    }
    removeNetwork?.let { id ->
        AlertDialog(
            onDismissRequest = { removeNetwork = null },
            title = { Text(tr("Delete network?", "删除网络？")) },
            text = { Text(id) },
            dismissButton = { TextButton(onClick = { removeNetwork = null }) { Text(tr("Cancel", "取消")) } },
            confirmButton = {
                TextButton(onClick = {
                    removeNetwork = null
                    persist(config.removeNetwork(id), config.enabled && config.network == id && vpn.canStop) { up() }
                }) { Text(tr("Delete", "删除")) }
            },
        )
    }
    var appQuery by rememberSaveable { mutableStateOf("") }
    var showSystemApps by rememberSaveable { mutableStateOf(false) }
    val appPickerState = if (page == "apps") {
        val installed by produceState<List<InstalledApp>?>(null) {
            value = try {
                AppGraph.installedApps.load()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w(e, "ZeroTier app list could not be loaded")
                emptyList()
            }
        }
        PerAppUiState(
            loading = installed == null,
            selected = appSelection.toSet(),
            query = appQuery,
            showSystemApps = showSystemApps,
            apps = installed.orEmpty(),
        )
    } else {
        PerAppUiState()
    }
    val currentNode = actual?.takeIf { config.enabled && it.network == config.network }
    val heading = when (page) {
        "add" -> tr("Join network", "加入网络")
        "detail" -> tr("Network details", "网络详情")
        "moons" -> tr("Moon orbit", "Moon 入轨")
        "peers" -> tr("Peers", "节点列表")
        "apps" -> stringResource(R.string.zt_apps_title)
        else -> "ZeroTier"
    }
    MeowScaffold(
        title = heading,
        navigationIcon = {
            if (page != "networks") TextButton(onClick = ::up) { Text(tr("Back", "返回")) }
        },
        actions = {
            if (page == "networks") {
                TextButton(enabled = loaded && !busy, modifier = Modifier.testTag("zt_add"), onClick = ::resetAdd) { Text("+") }
                TextButton(onClick = { more = true }) { Text("⋮") }
                DropdownMenu(expanded = more, onDismissRequest = { more = false }) {
                    DropdownMenuItem(text = { Text(tr("Peers", "节点列表")) }, onClick = {
                        more = false
                        page = "peers"
                        info = ""
                    })
                    DropdownMenuItem(text = { Text(tr("Moon orbit", "Moon 入轨")) }, onClick = {
                        more = false
                        page = "moons"
                        info = ""
                    })
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.zt_apps_title)) },
                        enabled = loaded && !busy,
                        onClick = {
                            more = false
                            appMode = ZeroTierAppMode.fromStored(config.appMode)
                            appSelection = ArrayList(config.packages)
                            appQuery = ""
                            showSystemApps = false
                            page = "apps"
                            info = ""
                        },
                    )
                }
            } else if (page == "apps") {
                AppPickerMenu(
                    state = appPickerState,
                    enabled = loaded && !busy && appMode != ZeroTierAppMode.All,
                    onBulkSelection = { action, visible ->
                        appSelection = ArrayList(updateVisibleSelection(appSelection.toSet(), visible, action))
                    },
                    onToggleSystemApps = { showSystemApps = !showSystemApps },
                )
                IconButton(
                    onClick = {
                        persist(config.withAppRules(appMode, appSelection.toSet()), false) { up() }
                    },
                    enabled = loaded && !busy && !appPickerState.loading,
                    modifier = Modifier.testTag("zt_app_save"),
                ) {
                    Icon(Icons.Filled.Check, contentDescription = stringResource(R.string.common_save))
                }
            }
        },
        bottomBar = { if (page == "networks") bottomBar() },
    ) { padding ->
        if (page == "apps") {
            ZeroTierAppRules(
                mode = appMode,
                state = appPickerState,
                busy = busy || !loaded,
                message = info,
                contentPadding = padding,
                onModeChange = { appMode = it },
                onQueryChange = { appQuery = it },
                onToggle = { appSelection = updateAppSelection(appSelection.toSet(), it) },
            )
            return@MeowScaffold
        }
        LazyColumn(
            modifier = Modifier.padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (info.isNotEmpty()) item {
                Text(info, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(8.dp))
            }
            if (page == "networks") {
                if (currentNode?.node != null) item {
                    Text("Node ID: " + currentNode.node, modifier = Modifier.padding(vertical = 8.dp))
                }
                if (loaded && config.networkList().isEmpty()) item {
                    Column(Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(tr("No saved networks", "没有已添加的网络"))
                        TextButton(onClick = ::resetAdd) { Text(tr("Add a network", "添加网络")) }
                    }
                }
                items(config.networkList(), key = { it.id }) { row ->
                    val selected = config.enabled && config.network == row.id
                    val runtime = currentNode?.takeIf { it.network == row.id }
                    Column {
                        Row(
                            Modifier.fillMaxWidth().combinedClickable(
                                onClick = { edit(row) },
                                onLongClick = { rowMenu = row.id },
                            ).padding(horizontal = 4.dp, vertical = 9.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Text(runtime?.name ?: row.id, style = MaterialTheme.typography.titleMedium)
                                if (runtime?.name != null) Text(row.id, style = MaterialTheme.typography.bodySmall)
                                val label = if (selected && runtime == null && vpn != BaseService.State.Stopped) {
                                    tr("Connecting", "正在连接")
                                } else statusText(runtime, zh)
                                Text(label, style = MaterialTheme.typography.bodySmall)
                                runtime?.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                            }
                            Switch(
                                checked = selected && vpn != BaseService.State.Stopped,
                                enabled = loaded && !busy,
                                modifier = Modifier.testTag("zt_network_switch"),
                                onCheckedChange = { on ->
                                    val candidate = if (on) config.activateNetwork(row.id) else config.copy(enabled = false)
                                    if (candidate != null) persist(candidate, on || vpn.canStop)
                                },
                            )
                        }
                        HorizontalDivider()
                        DropdownMenu(expanded = rowMenu == row.id, onDismissRequest = { rowMenu = null }) {
                            DropdownMenuItem(text = { Text(tr("Copy network ID", "复制网络 ID")) }, onClick = {
                                rowMenu = null
                                copyId(row.id)
                            })
                            DropdownMenuItem(text = { Text(tr("Delete network", "删除网络")) }, enabled = !busy, onClick = {
                                rowMenu = null
                                removeNetwork = row.id
                            })
                        }
                    }
                }
            }
            if (page == "add") item {
                Column(Modifier.fillMaxWidth().padding(vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    val valid = OverlaySettings.normalizedNetworkId(network)
                    Text(tr("Network ID", "网络 ID"), style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        network, { network = it.take(32) }, singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("zt_network_id"),
                        supportingText = { Text(tr("16 hexadecimal characters", "16 位十六进制字符")) },
                        isError = network.isNotBlank() && network.trim().length >= 16 && valid == null,
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(defaultRoute, { defaultRoute = it }, enabled = valid != null)
                        Text(tr("Route all IPv4 traffic through ZeroTier", "通过 ZeroTier 路由全部 IPv4 流量"))
                    }
                    dnsOptions()
                    Button(enabled = loaded && !busy && valid != null && dnsServers != null, modifier = Modifier.testTag("zt_apply"), onClick = {
                        val id = valid ?: return@Button
                        if (config.networkList().any { it.id == id }) {
                            info = tr("This network is already saved", "该网络已添加")
                        } else {
                            val candidate = config.addNetwork(id, defaultRoute, dnsMode, dnsServers ?: return@Button)
                            if (candidate == null) info = tr("Cannot add another network", "无法添加更多网络")
                            else persist(candidate, false) { up() }
                        }
                    }) { Text(tr("Join network", "加入网络")) }
                }
            }
            if (page == "detail") item {
                val runtime = currentNode?.takeIf { it.network == detail }
                Column(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(runtime?.name ?: detail, style = MaterialTheme.typography.titleLarge)
                    if (runtime?.name != null) Text(detail)
                    Text(statusText(runtime, zh), style = MaterialTheme.typography.titleMedium)
                    runtime?.node?.let { Text("Node ID: $it") }
                    runtime?.ip?.let { Text(tr("Assigned IPv4: $it", "分配的 IPv4：$it")) }
                    runtime?.mac?.let { Text("MAC: $it") }
                    runtime?.mtu?.let { Text("MTU: $it") }
                    runtime?.publicNetwork?.let {
                        Text(if (it) tr("Type: Public", "类型：公开") else tr("Type: Private", "类型：私有"))
                    }
                    runtime?.broadcast?.let {
                        Text(tr("Broadcast", "广播") + ": " + if (it) tr("On", "开启") else tr("Off", "关闭"))
                    }
                    runtime?.bridging?.let {
                        Text(tr("Bridging", "桥接") + ": " + if (it) tr("Allowed", "允许") else tr("Not allowed", "不允许"))
                    }
                    runtime?.nameservers?.takeIf { it.isNotEmpty() }?.let { servers ->
                        Text(tr("DNS servers", "DNS 服务器") + ": " + servers.joinToString())
                    }
                    runtime?.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                    if (!runtime?.managedRoutes.isNullOrEmpty()) {
                        HorizontalDivider()
                        Text(tr("Managed routes", "控制器下发的路由"), style = MaterialTheme.typography.titleMedium)
                        runtime?.managedRoutes?.distinct()?.forEach { Text(it) }
                    }
                    if (!runtime?.effectiveRoutes.isNullOrEmpty()) {
                        Text(tr("Routes handled by MeowZ", "MeowZ 接管的路由"), style = MaterialTheme.typography.titleMedium)
                        runtime?.effectiveRoutes?.forEach { Text(it) }
                    }
                    HorizontalDivider()
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(defaultRoute, { defaultRoute = it }, enabled = !busy)
                        Text(tr("Route all IPv4 traffic through ZeroTier", "通过 ZeroTier 路由全部 IPv4 流量"))
                    }
                    dnsOptions()
                    Text(tr("Advanced", "高级"), style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        routes, { routes = it.take(8192) }, modifier = Modifier.fillMaxWidth(),
                        label = { Text(tr("Limit IPv4 routes", "限制 IPv4 路由")) },
                        supportingText = { Text(tr("Leave blank to follow the controller’s non-default IPv4 routes.", "留空则采用控制器下发的非默认 IPv4 路由。")) },
                    )
                    TextButton(enabled = !busy && dnsServers != null, onClick = {
                        val selected = routes.split('\n', ',', ';').map(String::trim).filter(String::isNotEmpty)
                        val candidate = config.changeNetworkRoutes(detail, selected, defaultRoute, dnsMode, dnsServers ?: emptyList())
                        if (candidate == null) info = tr("Enter valid non-default IPv4 CIDRs", "请输入有效的非默认 IPv4 网段")
                        else persist(candidate, config.enabled && config.network == detail && vpn.canStop)
                    }) { Text(tr("Save", "保存")) }
                    TextButton(onClick = { copyId(detail) }) { Text(tr("Copy network ID", "复制网络 ID")) }
                    TextButton(enabled = !busy, onClick = { removeNetwork = detail }) { Text(tr("Delete network", "删除网络")) }
                }
            }
            if (page == "peers") {
                val peers = currentNode?.peers.orEmpty()
                if (peers.isEmpty()) item {
                    Text(tr("No peers yet", "暂无节点"), modifier = Modifier.padding(12.dp))
                }
                items(peers, key = { it.address }) { peer ->
                    Column(Modifier.fillMaxWidth().padding(vertical = 9.dp)) {
                        Text(peer.address, style = MaterialTheme.typography.titleMedium)
                        val latency = peer.latency?.let { " · $it ms" }.orEmpty()
                        val activity = if (peer.seen) tr("Seen recently", "近期收到数据") else tr("No recent traffic", "近期无流量")
                        Text(peer.role + latency + " · " + activity, style = MaterialTheme.typography.bodySmall)
                        HorizontalDivider()
                    }
                }
            }
            if (page == "moons") item {
                GlassCard {
                    Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(tr("Moon orbit", "Moon 入轨"), style = MaterialTheme.typography.titleMedium)
                        for (entry in config.moons) {
                            Row(
                                Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(entry.world)
                                    Text(
                                        if (entry.seed == null) tr("Imported file", "文件导入") else tr("Manual seed", "手动 Seed"),
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                    val roots = actual?.moons?.firstOrNull { it.world == entry.world }?.roots.orEmpty()
                                    if (roots.isEmpty()) {
                                        Text(tr("World not loaded", "尚未加载 World"), style = MaterialTheme.typography.bodySmall)
                                    } else for (root in roots) {
                                        Text(
                                            root.address + " · " + if (root.recentRx) {
                                                tr("Recently received", "近期收到数据")
                                            } else {
                                                tr("Loaded, no recent packets", "已加载，近期无接收")
                                            },
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                    }
                                }
                                TextButton(enabled = loaded && !busy, onClick = {
                                    persist(config.copy(moons = config.moons.filter { it.world != entry.world }), config.enabled && vpn.canStop)
                                }) { Text(tr("Remove", "移除")) }
                            }
                        }
                        TextButton(
                            enabled = loaded && !busy && config.moons.size < 32,
                            onClick = { chooseMoon.launch(arrayOf("*/*")) },
                        ) { Text(tr("Import .moon file", "导入 .moon 文件")) }
                        OutlinedTextField(moonWorld, { moonWorld = it.take(20) }, label = { Text("World ID") },
                            singleLine = true, modifier = Modifier.fillMaxWidth())
                        OutlinedTextField(moonSeed, { moonSeed = it.take(15) }, label = { Text("Seed") },
                            singleLine = true, modifier = Modifier.fillMaxWidth())
                        TextButton(enabled = loaded && !busy && moonWorld.isNotBlank() && moonSeed.isNotBlank(), onClick = {
                            val moon = MoonSetting(moonWorld, moonSeed).normalized()
                            if (moon == null) info = tr("Invalid World ID or Seed", "World ID 或 Seed 无效")
                            else {
                                persist(config.copy(moons = config.moons.filter { it.world != moon.world } + moon),
                                    config.enabled && vpn.canStop)
                                moonWorld = ""
                                moonSeed = ""
                            }
                        }) { Text(tr("Save Moon", "保存 Moon")) }
                    }
                }
            }
        }
    }
}
