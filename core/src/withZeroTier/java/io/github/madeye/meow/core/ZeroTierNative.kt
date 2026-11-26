package io.github.madeye.meow.core

/** Only the full app links these JNI exports. */
object ZeroTierNative {
    init { MeowCore.ensureLoaded() }

    /** 0 applied, 1 requires rebuilding forwarding, negative leaves the old policy. Off Main. */
    external fun nativeApplyZeroTier(overlayRoot: String, overlayConfig: String): Int
    external fun nativeSetMeowForwarding(enabled: Boolean): Int
    external fun nativeInspectMoon(input: ByteArray): String?
}
