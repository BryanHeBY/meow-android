package io.github.madeye.meow.bg

/** Lite never reads/writes overlay state or calls an overlay JNI entry point. */
internal object OverlayPlatform {
    fun hasActiveNetwork() = false
    fun configText(): String? = null
    fun rootPath() = ""
    fun apply(@Suppress("UNUSED_PARAMETER") config: String) = -1
    fun setMeowForwarding(@Suppress("UNUSED_PARAMETER") enabled: Boolean) = -1
}
