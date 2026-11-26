package io.github.madeye.meow.bg

import io.github.madeye.meow.core.MeowCore
import io.github.madeye.meow.core.ZeroTierNative
import io.github.madeye.meow.repo.OverlaySettingsRepository

internal object OverlayPlatform {
    fun hasActiveNetwork() = OverlaySettingsRepository().hasActiveNetwork()
    fun configText(): String? = OverlaySettingsRepository.directory.resolve("settings.json")
        .takeIf { it.isFile }?.readText()
    fun rootPath() = OverlaySettingsRepository.directory.absolutePath
    fun apply(config: String): Int {
        MeowCore.ensureLoaded()
        return ZeroTierNative.nativeApplyZeroTier(rootPath(), config)
    }
    fun setMeowForwarding(enabled: Boolean): Int {
        MeowCore.ensureLoaded()
        return ZeroTierNative.nativeSetMeowForwarding(enabled)
    }
}
