package io.github.madeye.meow.repo

import io.github.madeye.meow.Core
import io.github.madeye.meow.preference.PerAppConfigStore
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

enum class OverlayAppMode(val key: String) {
    All("all"),
    Allow("allow"),
    Exclude("exclude"),
}

data class OverlayAppConfig(
    val mode: OverlayAppMode = OverlayAppMode.Allow,
    val packages: Set<String> = emptySet(),
)

/**
 * The ZeroTier list is separate from the legacy Clash file and preferences.
 * Missing or unknown data must never implicitly grant access to the overlay.
 */
class OverlayAppRepository(
    private val store: PerAppConfigStore = defaultStore,
) {
    suspend fun load(): OverlayAppConfig = withContext(Dispatchers.IO) { read() }

    /** The VPN process can read this atomically while taking its next policy snapshot. */
    fun read(): OverlayAppConfig {
        val stored = store.load() ?: return OverlayAppConfig()
        val mode = OverlayAppMode.entries.firstOrNull { it.key == stored.mode }
            ?: return OverlayAppConfig()
        if (!stored.packages.all(::isPackageName)) return OverlayAppConfig()
        return OverlayAppConfig(mode, stored.packages)
    }

    suspend fun save(config: OverlayAppConfig) = withContext(Dispatchers.IO) {
        require(config.packages.all(::isPackageName)) { "Invalid package name in overlay selection" }
        store.save(config.mode.key, config.packages)
    }

    private fun isPackageName(value: String): Boolean =
        value.isNotBlank() && value.all { it.isLetterOrDigit() || it == '_' || it == '.' }

    companion object {
        private val defaultStore by lazy {
            PerAppConfigStore(File(Core.deviceStorage.noBackupFilesDir, "per_app_overlay"))
        }
    }
}
