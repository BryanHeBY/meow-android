package io.github.madeye.meow.preference

import io.github.madeye.meow.Core
import java.io.File
import java.io.IOException

enum class Ipv6Override { INHERIT, FORCE_ON, FORCE_OFF }
enum class AppQuicOverride { INHERIT, BLOCK_UDP_443, DO_NOT_BLOCK }

data class ConfigurationOverride(
    val ipv6: Ipv6Override = Ipv6Override.INHERIT,
    val appQuic: AppQuicOverride = AppQuicOverride.INHERIT,
) {
    fun withInherited(global: ConfigurationOverride) = ConfigurationOverride(
        ipv6.takeUnless { it == Ipv6Override.INHERIT } ?: global.ipv6,
        appQuic.takeUnless { it == AppQuicOverride.INHERIT } ?: global.appQuic,
    )

    val blocksAppUdp443: Boolean get() = appQuic == AppQuicOverride.BLOCK_UDP_443
}

/**
 * A separate file for each scope, read fresh by :vpn at session start. Room IDs
 * survive subscription refreshes and renames. Neither read nor write touches YAML.
 */
class ConfigurationOverrideStore(private val directory: File) {
    private fun file(profileId: Long?) = File(directory, profileId?.let { "profile-$it" } ?: "global")

    fun load(profileId: Long? = null): ConfigurationOverride {
        val lines = try {
            file(profileId).readLines()
        } catch (_: java.io.FileNotFoundException) {
            emptyList()
        }
        return ConfigurationOverride(
            Ipv6Override.entries.firstOrNull { it.name == lines.getOrNull(0) } ?: Ipv6Override.INHERIT,
            AppQuicOverride.entries.firstOrNull { it.name == lines.getOrNull(1) } ?: AppQuicOverride.INHERIT,
        )
    }

    fun effective(profileId: Long?): ConfigurationOverride {
        val global = load()
        return if (profileId == null) global else load(profileId).withInherited(global)
    }

    @Synchronized
    fun save(profileId: Long?, override: ConfigurationOverride) {
        val target = file(profileId)
        if (override == ConfigurationOverride()) {
            if (!target.delete() && target.exists()) throw IOException("Cannot reset configuration override")
            return
        }
        if (!directory.mkdirs() && !directory.isDirectory) throw IOException("Cannot store configuration override")
        val temp = File.createTempFile("override-", ".tmp", directory)
        try {
            temp.writeText("${override.ipv6.name}\n${override.appQuic.name}\n")
            if (!temp.renameTo(target)) throw IOException("Cannot save configuration override")
        } finally {
            temp.delete()
        }
    }

    companion object {
        val default: ConfigurationOverrideStore by lazy {
            ConfigurationOverrideStore(File(Core.deviceStorage.noBackupFilesDir, "configuration_overrides"))
        }
    }
}
