package io.github.madeye.meow.preference

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json

class DnsPreference(
    private val store: DnsSettingsStore = DnsSettingsStore.default,
    private val commit: (String, Long) -> String?,
    private val readStatus: () -> String?,
) {
    suspend fun load(): DnsSettingsStore.Saved = withContext(Dispatchers.IO) { store.load() }

    suspend fun save(settings: DnsSettings, selectedProfileId: Long?): DnsIssue? = withContext(Dispatchers.IO) {
        commit(settings.encode(), selectedProfileId ?: 0)?.let(DnsIssue::fromWire)
    }

    suspend fun status(): DnsStatus? = withContext(Dispatchers.IO) {
        readStatus()?.let { Json.decodeFromString(DnsStatus.serializer(), it) }
    }
}
