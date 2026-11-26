package io.github.madeye.meow.preference

import io.github.madeye.meow.Core
import java.io.File
import java.io.IOException

/**
 * Settings' "Built-in DNS" switch, replayed into every engine start. On, the
 * engine drops the profile's DNS upstreams for the built-in pool (the
 * default). Only an explicitly saved off value opts into the profile's
 * `dns:` nameservers; missing, unreadable or invalid state stays built-in.
 *
 * Kept in the original one-line file. The VPN process owns writes so it
 * can serialize them with startup. Both processes read the same file.
 */
class BuiltinDnsStore(private val file: File) {

    fun load(): Boolean =
        try {
            file.readText() != PROFILE
        } catch (_: Exception) {
            // IOException for a missing/gone file; the wide catch keeps an
            // undeclared RuntimeException from aborting MeowInstance.start
            // in :vpn — a lost switch restores the built-in default.
            true
        }

    /** Only the VPN process calls these, so a start cannot race a DNS save. */
    @Synchronized
    internal fun <T> withSavedValue(block: (Boolean) -> T): T = block(load())

    /**
     * Prepare the disk write first and publish it only after the existing
     * resolver transaction succeeds. If publication fails, restore the old
     * preference on the live resolver and report the outcome.
     */
    @Synchronized
    internal fun commit(
        enabled: Boolean,
        applied: () -> Boolean? = { null },
        applyLive: (Boolean) -> String?,
    ): String? {
        val previous = load()
        if (enabled == previous) return null
        return try {
            write(enabled) { publish ->
                val rollbackTo = applied() ?: previous
                applyLive(enabled)?.let { return@write it }
                try {
                    publish()
                    null
                } catch (e: IOException) {
                    val rollback = if (rollbackTo == enabled) null else applyLive(rollbackTo)
                    if (rollback == null) e.message else "${e.message}. DNS rollback failed: $rollback"
                }
            }
        } catch (e: IOException) {
            e.message ?: e.javaClass.simpleName
        }
    }

    @Synchronized
    fun save(enabled: Boolean) = write(enabled) { publish -> publish() }

    private fun <T> write(enabled: Boolean, transaction: (() -> Unit) -> T): T {
        val tmp = File(file.path + ".tmp")
        try {
            tmp.writeText(if (enabled) BUILTIN else PROFILE)
            return transaction {
                if (!tmp.renameTo(file)) throw IOException("Cannot save the DNS preference")
            }
        } finally {
            tmp.delete()
        }
    }

    companion object {
        private const val BUILTIN = "builtin"
        private const val PROFILE = "profile"

        val default: BuiltinDnsStore by lazy {
            BuiltinDnsStore(File(Core.deviceStorage.noBackupFilesDir, "builtin_dns"))
        }
    }
}
