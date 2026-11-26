package io.github.madeye.meow.preference

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** DNS is written by the VPN Binder, which serializes it with engine startup. */
class BuiltinDnsPreference(
    private val store: BuiltinDnsStore = BuiltinDnsStore.default,
    private val commit: (Boolean) -> String?,
) {
    suspend fun load(): Boolean = withContext(Dispatchers.IO) { store.load() }

    /** Null on success, or the live resolver's rejection for the snackbar. */
    suspend fun save(enabled: Boolean): String? = withContext(Dispatchers.IO) { commit(enabled) }
}
