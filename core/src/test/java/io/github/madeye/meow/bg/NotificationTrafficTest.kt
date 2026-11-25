package io.github.madeye.meow.bg

import org.junit.Assert.assertEquals
import org.junit.Test

class NotificationTrafficTest {
    @Test
    fun speedAndTotalsUseDifferentUnits() {
        val snapshot = NotificationTraffic.from(Speed(1024, 0), 2048, 1048576, 65 * 60_000L)
        assertEquals("↑ 1.0 KB/s  ↓ 0 B/s", snapshot.speed)
        assertEquals("2.0 KB", snapshot.uploaded)
        assertEquals("1.0 MB", snapshot.downloaded)
        assertEquals("1.0 MB", snapshot.combined)
        assertEquals("1:05", snapshot.elapsed)
    }

    @Test
    fun displayedDurationDoesNotChangeEachSecond() {
        assertEquals(
            NotificationTraffic.from(Speed.IDLE, 123, 456, 5_000),
            NotificationTraffic.from(Speed.IDLE, 123, 456, 6_000),
        )
    }
}
