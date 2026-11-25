package io.github.madeye.meow.bg

import java.util.Locale
import kotlin.math.abs

/**
 * Turns reads of the engine's cumulative byte counters into the per-second
 * speed the VPN notification shows.
 *
 * Kept apart from [MeowInstance.requestTrafficUpdate] on purpose: that one
 * holds the previous sample for the UI's bandwidth listeners, and a second
 * caller sharing it would cut both windows short. The notification starts a
 * fresh meter each time its ticker resumes, so the first read after the screen
 * comes back on is a baseline rather than one average smeared across the whole
 * time it was off.
 */
internal class SpeedMeter {
    private var lastTx = 0L
    private var lastRx = 0L
    private var lastAtMillis = NO_SAMPLE

    /**
     * Bytes per second each way since the previous call, or `null` while there
     * is nothing to compare against yet.
     *
     * @param nowMillis a monotonic clock (`SystemClock.elapsedRealtime`).
     */
    fun sample(tx: Long, rx: Long, nowMillis: Long): Speed? {
        if (lastAtMillis == NO_SAMPLE) {
            remember(tx, rx, nowMillis)
            return null
        }
        val elapsed = nowMillis - lastAtMillis
        // A clock that did not move would divide by zero; keep the old
        // baseline so the next read still spans a real interval.
        if (elapsed <= 0) return null
        // The counters restart from zero with the engine; a negative delta
        // means that happened in between, not that traffic flowed backwards.
        val speed = Speed(
            up = (tx - lastTx).coerceAtLeast(0) * 1000 / elapsed,
            down = (rx - lastRx).coerceAtLeast(0) * 1000 / elapsed,
        )
        remember(tx, rx, nowMillis)
        return speed
    }

    private fun remember(tx: Long, rx: Long, nowMillis: Long) {
        lastTx = tx
        lastRx = rx
        lastAtMillis = nowMillis
    }

    private companion object {
        const val NO_SAMPLE = Long.MIN_VALUE
    }
}

/** Upload and download speed, in bytes per second. */
internal data class Speed(val up: Long, val down: Long) {

    /** `↑ 1.2 KB/s  ↓ 340 KB/s` — upload first, as on the Home screen. */
    val text: String get() = "↑ ${rate(up)}  ↓ ${rate(down)}"

    companion object {
        val IDLE = Speed(0, 0)

        private val UNITS = arrayOf("B", "KB", "MB", "GB", "TB")

        /**
         * e.g. `1.2 MB/s`. The same ladder as the UI's `Formatters.rate`, which
         * :core cannot reach — the notification and Home must not disagree
         * about the same number.
         */
        fun rate(bytesPerSecond: Long): String = "${amount(bytesPerSecond)}/s"

        fun amount(bytes: Long): String {
            var amount = abs(bytes.toDouble())
            var unit = 0
            while (amount >= 1024 && unit < UNITS.lastIndex) {
                amount /= 1024
                unit++
            }
            val digits = if (unit == 0 || amount >= 100) 0 else 1
            return String.format(Locale.US, "%.${digits}f %s", amount, UNITS[unit])
        }
    }
}

/** A display snapshot; changes below the displayed precision need no re-post. */
internal data class NotificationTraffic(
    val speed: String,
    val uploaded: String,
    val downloaded: String,
    val combined: String,
    val elapsed: String,
) {
    companion object {
        fun from(speed: Speed, tx: Long, rx: Long, elapsedMillis: Long): NotificationTraffic {
            val mins = elapsedMillis.coerceAtLeast(0) / 60_000
            val up = tx.coerceAtLeast(0)
            val down = rx.coerceAtLeast(0)
            return NotificationTraffic(
                speed.text,
                Speed.amount(up),
                Speed.amount(down),
                Speed.amount(up + down.coerceAtMost(Long.MAX_VALUE - up)),
                String.format(Locale.US, "%d:%02d", mins / 60, mins % 60),
            )
        }
    }
}
