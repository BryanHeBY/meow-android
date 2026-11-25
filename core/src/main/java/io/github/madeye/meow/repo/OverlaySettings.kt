package io.github.madeye.meow.repo

import io.github.madeye.meow.Core
import io.github.madeye.meow.core.MeowCore
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
data class OverlaySettings(
    val enabled: Boolean = false,
    val network: String = "",
    val routes: List<String> = emptyList(),
    @SerialName("app_mode") val appMode: String = "allow",
    val packages: Set<String> = emptySet(),
    val moons: List<MoonSetting> = emptyList(),
) {
    fun validated(): OverlaySettings? {
        val normalizedNetwork = network.trim().lowercase()
        if ((enabled || normalizedNetwork.isNotEmpty()) &&
            (!normalizedNetwork.matches(Regex("[0-9a-f]{16}")) || normalizedNetwork.all { it == '0' })
        ) return null
        val normalizedRoutes = routes.map(String::trim).filter(String::isNotEmpty).distinct()
        if (normalizedRoutes.size > 128 || (enabled && normalizedRoutes.isEmpty())) return null
        if (normalizedRoutes.any { !validRoute(it) }) return null
        val normalizedMoons = moons.map { it.normalized() ?: return null }
        if (normalizedMoons.size > 32 || normalizedMoons.map { it.world }.distinct().size != normalizedMoons.size) return null
        if (appMode !in listOf("allow", "exclude", "all") || packages.size > 4096) return null
        if (packages.any { it.isBlank() || !it.matches(Regex("[a-zA-Z0-9_.]{1,255}")) }) return null
        return copy(network = normalizedNetwork, routes = normalizedRoutes, moons = normalizedMoons)
    }

    private fun validRoute(text: String): Boolean {
        val pair = text.split('/')
        if (pair.size != 2 || pair[1].toIntOrNull() !in 1..32) return false
        val octets = pair[0].split('.')
        return octets.size == 4 && octets.all { it.matches(Regex("[0-9]{1,3}")) && it.toIntOrNull() in 0..255 }
    }
}

@Serializable
data class OverlayStatus(
    val phase: String,
    val network: String,
    val node: String? = null,
    val ip: String? = null,
    @SerialName("sdk_status") val sdkStatus: Int? = null,
    val error: String? = null,
)

class OverlaySettingsRepository(private val root: File = directory) {
    private val json = Json { encodeDefaults = true }
    private val settings get() = root.resolve("settings.json")
    private val status get() = root.resolve("status.json")

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
        check(bytes.size in 1..16_384 && MeowCore.nativeInspectMoon(bytes) == world) { "Invalid Moon definition" }
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
