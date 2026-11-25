package io.github.madeye.meow.diagnostics

import android.app.ApplicationExitInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FaultDiagnosticsTest {
    @Test
    fun `exit history separates processes and does not label user kills as crashes`() {
        val pkg = "io.github.example"
        assertNull(faultFromExit(pkg, "$pkg:other", 1, ApplicationExitInfo.REASON_CRASH, 8))
        assertNull(faultFromExit(pkg, pkg, 0, ApplicationExitInfo.REASON_CRASH, 8))
        for ((reason, expected) in listOf(
            ApplicationExitInfo.REASON_CRASH to FaultKind.JVM_CRASH,
            ApplicationExitInfo.REASON_CRASH_NATIVE to FaultKind.NATIVE_CRASH,
            ApplicationExitInfo.REASON_ANR to FaultKind.ANR,
            ApplicationExitInfo.REASON_LOW_MEMORY to FaultKind.LOW_MEMORY,
            ApplicationExitInfo.REASON_USER_REQUESTED to FaultKind.PROCESS_EXIT,
        )) {
            assertEquals(FaultEvent(1, FaultProcess.UI, expected, reason, 8), faultFromExit(pkg, pkg, 1, reason, 8))
            assertEquals(FaultEvent(1, FaultProcess.VPN, expected, reason, 8), faultFromExit(pkg, "$pkg:vpn", 1, reason, 8))
        }
    }

    @Test
    fun `export contains only fixed labels and numeric fields`() {
        assertEquals(
            "MeowZ fault diagnostics v1\n1970-01-01T00:00:00.001Z  VPN  TUN_EXIT  code=2  pid=8\n",
            faultReport(listOf(FaultEvent(1, FaultProcess.VPN, FaultKind.TUN_EXIT, 2, 8))),
        )
    }
}
