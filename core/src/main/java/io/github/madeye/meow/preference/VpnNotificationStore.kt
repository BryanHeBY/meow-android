package io.github.madeye.meow.preference

import io.github.madeye.meow.Core
import java.io.File
import java.io.IOException

/** Read by the VPN process and written by the settings process. */
class VpnNotificationStore(private val file: File) {
    fun detailsEnabled(): Boolean = try {
        file.readText() != "minimal"
    } catch (_: IOException) {
        true
    }

    @Synchronized
    fun save(details: Boolean) {
        val temporary = File(file.path + ".tmp")
        try {
            temporary.writeText(if (details) "details" else "minimal")
            if (!temporary.renameTo(file)) throw IOException("Cannot save VPN notification mode")
        } finally {
            temporary.delete()
        }
    }

    companion object {
        val default by lazy {
            VpnNotificationStore(File(Core.deviceStorage.noBackupFilesDir, "vpn_notification"))
        }
    }
}
