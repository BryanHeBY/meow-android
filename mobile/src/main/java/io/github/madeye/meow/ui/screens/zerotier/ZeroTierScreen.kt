package io.github.madeye.meow.ui.screens.zerotier

import android.app.Activity
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.madeye.meow.AppGraph
import io.github.madeye.meow.bg.BaseService
import io.github.madeye.meow.repo.MoonSetting
import io.github.madeye.meow.repo.OverlaySettings
import io.github.madeye.meow.repo.OverlaySettingsRepository
import io.github.madeye.meow.repo.OverlayStatus
import io.github.madeye.meow.ui.components.GlassCard
import io.github.madeye.meow.ui.components.MeowScaffold
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

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
    var moonWorld by rememberSaveable { mutableStateOf("") }
    var moonSeed by rememberSaveable { mutableStateOf("") }
    var search by rememberSaveable { mutableStateOf("") }
    var showSystem by rememberSaveable { mutableStateOf(false) }
    var showApps by rememberSaveable { mutableStateOf(false) }
    var loaded by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var info by remember { mutableStateOf("") }
    val apps = androidx.compose.runtime.produceState(
        initialValue = emptyList<io.github.madeye.meow.repo.InstalledApp>(),
        key1 = showApps,
    ) {
        if (showApps) value = AppGraph.installedApps.load()
    }.value
    LaunchedEffect(Unit) {
        runCatching { store.load() }.onSuccess {
            config = it
            network = it.network
            routes = it.routes.joinToString("\n")
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
    fun persist(candidate: OverlaySettings, apply: Boolean) {
        val normalized = candidate.validated()
        if (normalized == null) {
            info = tr("Check the network ID, IPv4 CIDRs and Moon entries", "请检查网络 ID、IPv4 网段和 Moon 条目")
            return
        }
        scope.launch {
            busy = true
            try {
                store.save(normalized)
                config = normalized
                info = if (apply) "" else tr("Saved. Reconnect VPN to apply changes.", "已保存，重新连接 VPN 后生效。")
                if (apply) {
                    if (AppGraph.vpn.state.value.canStop) {
                        AppGraph.vpn.requestStop(context)
                        val stopped = withTimeoutOrNull(7_000) { AppGraph.vpn.state.first { it == BaseService.State.Stopped } }
                        if (stopped == null) {
                            info = tr("VPN did not stop. Restart it from Home to apply.", "VPN 未停止，请从首页重新连接以应用设置。")
                            return@launch
                        }
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

    MeowScaffold(title = "ZeroTier", bottomBar = bottomBar) { padding ->
        LazyColumn(
            modifier = Modifier.padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                GlassCard {
                    Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(statusText(actual, zh), style = MaterialTheme.typography.titleMedium)
                        actual?.node?.let { Text("Node ID: $it") }
                        actual?.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                        if (info.isNotEmpty()) Text(info)
                    }
                }
            }
            item {
                GlassCard {
                    Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(tr("Network", "网络"), style = MaterialTheme.typography.titleMedium)
                        OutlinedTextField(
                            network, { network = it.take(32) }, label = { Text(tr("Network ID", "网络 ID")) },
                            singleLine = true, modifier = Modifier.fillMaxWidth().testTag("zt_network_id"),
                        )
                        OutlinedTextField(
                            routes, { routes = it.take(8192) },
                            label = { Text(tr("Approved IPv4 CIDRs", "允许的 IPv4 网段")) },
                            placeholder = { Text("10.42.0.0/24") }, modifier = Modifier.fillMaxWidth(),
                            supportingText = { Text(tr("One CIDR per line. No default route.", "每行一个网段，不允许默认路由。")) },
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(enabled = loaded && !busy, modifier = Modifier.testTag("zt_apply"), onClick = {
                                val selected = routes.split('\n', ',', ';').map(String::trim).filter(String::isNotEmpty)
                                persist(config.copy(enabled = true, network = network, routes = selected), true)
                            }) { Text(tr("Apply and join", "应用并加入")) }
                            TextButton(enabled = loaded && !busy && config.enabled, onClick = {
                                persist(config.copy(enabled = false), vpn.canStop)
                            }) { Text(tr("Disable", "停用")) }
                        }
                        if (!config.enabled && config.network.isNotEmpty()) {
                            TextButton(enabled = loaded && !busy, onClick = {
                                network = ""
                                routes = ""
                                persist(config.copy(network = "", routes = emptyList()), false)
                            }) { Text(tr("Forget saved network", "移除已保存网络")) }
                        }
                    }
                }
            }
            item {
                GlassCard {
                    Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(tr("Moon orbit", "Moon 入轨"), style = MaterialTheme.typography.titleMedium)
                        for (entry in config.moons) {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text(entry.world, Modifier.align(Alignment.CenterVertically))
                                TextButton(enabled = loaded && !busy, onClick = {
                                    persist(config.copy(moons = config.moons.filter { it.world != entry.world }), config.enabled && vpn.canStop)
                                }) { Text(tr("Remove", "移除")) }
                            }
                        }
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
            item {
                GlassCard {
                    Column(Modifier.fillMaxWidth().padding(12.dp)) {
                        Text(tr("ZeroTier app rules", "ZeroTier 分应用规则"), style = MaterialTheme.typography.titleMedium)
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            for ((value, label) in listOf("allow" to tr("Allow", "白名单"), "exclude" to tr("Exclude", "黑名单"), "all" to tr("All", "全部"))) {
                                FilterChip(selected = config.appMode == value, enabled = loaded && !busy,
                                    onClick = { persist(config.copy(appMode = value), false) }, label = { Text(label) })
                            }
                        }
                        TextButton(onClick = { showApps = !showApps }) {
                            Text(tr("Choose apps", "选择应用") + " (${config.packages.size})")
                        }
                        if (showApps) {
                            OutlinedTextField(search, { search = it }, label = { Text(tr("App or package", "应用或包名")) },
                                singleLine = true, modifier = Modifier.fillMaxWidth())
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(showSystem, { showSystem = it })
                                Text(tr("Show system apps", "显示系统应用"))
                            }
                        }
                    }
                }
            }
            if (showApps) {
                val query = search.trim()
                val visible = apps.filter {
                    if (query.isEmpty()) showSystem || it.hasLauncher || !it.isSystem || it.packageName in config.packages
                    else it.label.contains(query, true) || it.packageName.contains(query, true)
                }
                items(visible, key = { it.packageName }) { app ->
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        val checked = app.packageName in config.packages
                        Checkbox(checked, { next ->
                            val list = if (next) config.packages + app.packageName else config.packages - app.packageName
                            persist(config.copy(packages = list), false)
                        }, enabled = loaded && !busy && config.appMode != "all")
                        Column {
                            Text(app.label)
                            Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}
