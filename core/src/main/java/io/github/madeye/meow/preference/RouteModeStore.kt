package io.github.madeye.meow.preference

import io.github.madeye.meow.Core
import io.github.madeye.meow.api.RouteMode
import java.io.File
import java.io.IOException

/**
 * The route mode the user picked on Home or in Advanced settings, replayed into every engine start so
 * it survives reconnects and `:vpn` restarts. Absent when unset,
 * meaning "follow the profile's `mode:`".
 *
 * The UI process writes it and `:vpn` reads it, so it cannot live in
 * [DataStore]: SharedPreferences loads its file once per process and never
 * re-reads it, and `:vpn` stays alive as long as an Activity is bound to the
 * service, so a later engine start would see the value from its first read.
 * A one-line file is read fresh every time.
 */
class RouteModeStore(private val file: File) {

    fun load(): RouteMode? =
        try {
            RouteMode.fromWire(file.readText())
        } catch (_: Exception) {
            // IOException for a missing/gone file; the wide catch keeps an
            // undeclared RuntimeException from aborting MeowInstance.start
            // in :vpn — a lost mode just follows the profile's default.
            null
        }

    fun save(mode: RouteMode) {
        val tmp = File(file.path + ".tmp")
        try {
            tmp.writeText(mode.wire)
            if (!tmp.renameTo(file)) throw IOException("cannot replace $file")
        } finally {
            tmp.delete()
        }
    }

    /** Remove the override so the engine can read the next profile's own mode. */
    fun clear() {
        if (!file.delete() && file.exists()) throw IOException("cannot remove $file")
    }

    companion object {
        val default: RouteModeStore by lazy {
            RouteModeStore(File(Core.deviceStorage.noBackupFilesDir, "route_mode"))
        }
    }
}
