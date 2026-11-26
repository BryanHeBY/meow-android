package io.github.madeye.meow.repo

import io.github.madeye.meow.Core
import io.github.madeye.meow.core.ZeroTierNative
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class MoonSetting(val world: String, val seed: String? = null) {
    fun normalized(): MoonSetting? {
        val world = world.trim().lowercase()
        val seed = seed?.trim()?.lowercase()
        if (!world.matches(Regex("(?:[0-9a-f]{1,10}|[0-9a-f]{16})")) || world.all { it == '0' }) return null
        if (seed != null && (!seed.matches(Regex("[0-9a-f]{10}")) || seed.all { it == '0' })) return null
        return MoonSetting(world.padStart(16, '0'), seed)
    }
}

@Serializable
data class SavedOverlayNetwork(
    val id: String,
    val routes: List<String> = emptyList(),
    @SerialName("allow_default") val allowDefault: Boolean = false,
    @SerialName("dns_mode") val dnsMode: String = "off",
    @SerialName("dns_servers") val dnsServers: List<String> = emptyList(),
)

@Serializable
data class OverlaySettings(
    val enabled: Boolean = false,
    val network: String = "",
    val routes: List<String> = emptyList(),
    @SerialName("app_mode") val appMode: String = "all",
    val packages: Set<String> = emptySet(),
    val moons: List<MoonSetting> = emptyList(),
    @SerialName("allow_default") val allowDefault: Boolean = false,
    @SerialName("dns_mode") val dnsMode: String = "off",
    @SerialName("dns_servers") val dnsServers: List<String> = emptyList(),
    @SerialName("saved_networks") val savedNetworks: List<SavedOverlayNetwork> = emptyList(),
) {
    /** Older MeowZ builds stored one network without a separate list. */
    fun networkList(): List<SavedOverlayNetwork> =
        if (network.isNotEmpty() && savedNetworks.none { it.id == network }) {
            savedNetworks + SavedOverlayNetwork(network, routes, allowDefault, dnsMode, dnsServers)
        } else savedNetworks

    fun addNetwork(rawId: String, usesDefault: Boolean = false, dns: String = "off", servers: List<String> = emptyList()): OverlaySettings? {
        val id = normalizedNetworkId(rawId) ?: return null
        val known = networkList()
        if (known.any { it.id == id }) return this
        return copy(savedNetworks = known + SavedOverlayNetwork(id, allowDefault = usesDefault, dnsMode = dns, dnsServers = servers)).validated()
    }

    fun activateNetwork(id: String): OverlaySettings? = networkList().firstOrNull { it.id == id }?.let {
        copy(enabled = true, network = it.id, routes = it.routes, allowDefault = it.allowDefault, dnsMode = it.dnsMode, dnsServers = it.dnsServers, savedNetworks = networkList()).validated()
    }

    fun removeNetwork(id: String): OverlaySettings {
        val keep = networkList().filter { it.id != id }
        return if (network == id) copy(enabled = false, network = "", routes = emptyList(), allowDefault = false, dnsMode = "off", dnsServers = emptyList(), savedNetworks = keep)
        else copy(savedNetworks = keep)
    }

    fun changeNetworkRoutes(id: String, routes: List<String>, usesDefault: Boolean = false, dns: String = "off", servers: List<String> = emptyList()): OverlaySettings? {
        val known = networkList()
        if (known.none { it.id == id }) return null
        val updated = known.map { if (it.id == id) it.copy(routes = routes, allowDefault = usesDefault, dnsMode = dns, dnsServers = servers) else it }
        return if (network == id) copy(routes = routes, allowDefault = usesDefault, dnsMode = dns, dnsServers = servers, savedNetworks = updated).validated()
        else copy(savedNetworks = updated).validated()
    }

    fun validated(): OverlaySettings? {
        val normalizedNetwork = network.trim().lowercase()
        if ((enabled || normalizedNetwork.isNotEmpty()) && normalizedNetworkId(normalizedNetwork) == null) return null
        val normalizedRoutes = routes.map(String::trim).filter(String::isNotEmpty).distinct()
        if (normalizedRoutes.size > 128) return null
        if (normalizedRoutes.any { !validRoute(it) }) return null
        val normalizedMoons = moons.map { it.normalized() ?: return null }
        if (normalizedMoons.size > 32 || normalizedMoons.map { it.world }.distinct().size != normalizedMoons.size) return null
        if (appMode !in listOf("allow", "exclude", "all") || packages.size > 4096) return null
        if (packages.any { it.isBlank() || !it.matches(Regex("[a-zA-Z0-9_.]{1,255}")) }) return null
        val servers = normalizeDns(dnsMode, dnsServers) ?: return null
        if (savedNetworks.size > 128) return null
        val saved = savedNetworks.map { row ->
            val id = normalizedNetworkId(row.id) ?: return null
            val list = row.routes.map(String::trim).filter(String::isNotEmpty).distinct()
            if (list.size > 128 || list.any { !validRoute(it) }) return null
            val rowServers = normalizeDns(row.dnsMode, row.dnsServers) ?: return null
            SavedOverlayNetwork(id, list, row.allowDefault, row.dnsMode, rowServers)
        }
        if (saved.map { it.id }.distinct().size != saved.size) return null
        if (saved.any { it.id == normalizedNetwork && (it.routes != normalizedRoutes || it.allowDefault != allowDefault || it.dnsMode != dnsMode || it.dnsServers != servers) }) return null
        return copy(network = normalizedNetwork, routes = normalizedRoutes, moons = normalizedMoons, dnsServers = servers, savedNetworks = saved)
    }

    companion object {
        fun normalizeDns(mode: String, input: List<String>): List<String>? {
            if (mode == "off" || mode == "network") return emptyList()
            if (mode != "custom") return null
            val servers = input.map(String::trim).filter(String::isNotEmpty).distinct()
            if (servers.size !in 1..2) return null
            if (servers.any { address ->
                val parts = address.split('.')
                parts.size != 4 || parts.any { part ->
                    !part.matches(Regex("(?:0|[1-9][0-9]{0,2})")) || part.toIntOrNull() !in 0..255
                }
            }) return null
            return servers
        }
        fun normalizedNetworkId(raw: String): String? = raw.trim().lowercase()
            .takeIf { it.matches(Regex("[0-9a-f]{16}")) && it.any { digit -> digit != '0' } }
    }

    private fun validRoute(text: String): Boolean {
        val pair = text.split('/')
        if (pair.size != 2 || pair[1].toIntOrNull() !in 1..32) return false
        val octets = pair[0].split('.')
        return octets.size == 4 && octets.all { it.matches(Regex("[0-9]{1,3}")) && it.toIntOrNull() in 0..255 }
    }
}

@Serializable
data class OverlayMoonRootStatus(
    val address: String,
    @SerialName("recent_rx") val recentRx: Boolean,
)

@Serializable
data class OverlayMoonStatus(
    val world: String,
    val roots: List<OverlayMoonRootStatus>,
)

@Serializable
data class OverlayPeerStatus(
    val address: String,
    val role: String,
    @SerialName("latency_ms") val latency: Int? = null,
    @SerialName("recent_rx") val seen: Boolean = false,
)

@Serializable
data class OverlayStatus(
    val phase: String,
    val network: String,
    val node: String? = null,
    val ip: String? = null,
    @SerialName("sdk_status") val sdkStatus: Int? = null,
    val error: String? = null,
    val moons: List<OverlayMoonStatus> = emptyList(),
    @SerialName("managed_routes") val managedRoutes: List<String> = emptyList(),
    @SerialName("effective_routes") val effectiveRoutes: List<String> = emptyList(),
    val mac: String? = null,
    val mtu: Int? = null,
    val nameservers: List<String> = emptyList(),
    val name: String? = null,
    @SerialName("public") val publicNetwork: Boolean? = null,
    val broadcast: Boolean? = null,
    val bridging: Boolean? = null,
    val peers: List<OverlayPeerStatus> = emptyList(),
)

class OverlaySettingsRepository(private val root: File = directory) {
    private val json = Json { encodeDefaults = true }
    private val settings get() = root.resolve("settings.json")
    private val status get() = root.resolve("status.json")

    fun hasActiveNetwork(): Boolean = runCatching {
        settings.isFile && json.decodeFromString<OverlaySettings>(settings.readText()).validated()?.enabled == true
    }.getOrDefault(false)

    suspend fun load(): OverlaySettings = withContext(Dispatchers.IO) {
        if (!settings.isFile) OverlaySettings()
        else json.decodeFromString<OverlaySettings>(settings.readText())
    }

    suspend fun runtime(): OverlayStatus? = withContext(Dispatchers.IO) {
        runCatching { json.decodeFromString<OverlayStatus>(status.readText()) }.getOrNull()
    }

    suspend fun save(candidate: OverlaySettings) = withContext(Dispatchers.IO) {
        val effective = requireNotNull(candidate.validated()) { "Invalid ZeroTier settings" }
        check(root.isDirectory || root.mkdirs()) { "Cannot create ZeroTier storage" }
        val temp = File.createTempFile("settings-", ".tmp", root)
        try {
            temp.writeText(json.encodeToString(effective))
            check(temp.renameTo(settings)) { "Cannot save ZeroTier settings" }
        } finally {
            temp.delete()
        }
    }

    suspend fun stageMoon(world: String, bytes: ByteArray) = withContext(Dispatchers.IO) {
        check(bytes.size in 1..16_384 && ZeroTierNative.nativeInspectMoon(bytes) == world) { "Invalid Moon definition" }
        check(root.isDirectory || root.mkdirs()) { "Cannot create ZeroTier storage" }
        val temp = File.createTempFile("moon-import-", ".tmp", root)
        try {
            temp.writeBytes(bytes)
            check(temp.renameTo(root.resolve("imported-$world.moon"))) { "Cannot save Moon definition" }
        } finally {
            temp.delete()
        }
    }

    companion object {
        val directory get() = File(Core.deviceStorage.noBackupFilesDir, "zerotier")
    }
}
