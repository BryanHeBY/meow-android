package io.github.madeye.meow.ui.screens.overrideconfig

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.madeye.meow.core.MeowCore
import io.github.madeye.meow.preference.BuiltinDnsPreference
import io.github.madeye.meow.preference.ConfigurationOverride
import io.github.madeye.meow.preference.ConfigurationOverrideStore
import io.github.madeye.meow.repo.ProfileRepository
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber

internal data class OverrideProfilePreview(
    val name: String,
    val subscription: Boolean,
    val ipv6: Int,
    val override: ConfigurationOverride,
)

internal data class OverrideForm(
    val saved: ConfigurationOverride,
    val draft: ConfigurationOverride = saved,
    val global: ConfigurationOverride,
    val savedDns: Boolean?,
    val draftDns: Boolean? = savedDns,
    val saving: Boolean = false,
) {
    val canSave get() = !saving && saved != draft
    val canSaveDns get() = !saving && savedDns != draftDns
}

internal sealed interface OverrideEvent {
    data object Saved : OverrideEvent
    data object DnsSaved : OverrideEvent
    data object SaveFailed : OverrideEvent
    data class DnsFailed(val reason: String) : OverrideEvent
}

internal class ConfigurationOverrideViewModel(
    val profileId: Long?,
    private val store: ConfigurationOverrideStore,
    private val dns: BuiltinDnsPreference,
    profiles: ProfileRepository,
) : ViewModel() {
    private val form = MutableStateFlow<OverrideForm?>(null)
    private val _events = Channel<OverrideEvent>(Channel.BUFFERED)
    val events = _events.receiveAsFlow()

    private val selected = if (profileId == null) profiles.observeSelected() else {
        profiles.observeAll().map { rows -> rows.firstOrNull { it.id == profileId } }
    }
    private val preview = selected
        .map { it?.let { profile -> PreviewSource(profile.id, profile.name, profile.url.isNotEmpty(), profile.yamlContent) } }
        .distinctUntilChanged()
        .map { profile ->
            profile?.let {
                OverrideProfilePreview(
                    it.name,
                    it.subscription,
                    MeowCore.nativeProfileIpv6(it.yaml),
                    if (profileId == null) store.load(it.id) else ConfigurationOverride(),
                )
            }
        }
        .flowOn(Dispatchers.IO)

    val uiState = combine(form, preview, ::Pair)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null to null)

    init {
        viewModelScope.launch {
            try {
                val (saved, global) = withContext(Dispatchers.IO) {
                    store.load(profileId) to if (profileId == null) ConfigurationOverride() else store.load()
                }
                form.value = OverrideForm(saved, global = global, savedDns = if (profileId == null) dns.load() else null)
            } catch (e: IOException) {
                Timber.w(e, "Reading configuration overrides failed")
                _events.send(OverrideEvent.SaveFailed)
            }
        }
    }

    fun edit(value: ConfigurationOverride) {
        val current = form.value ?: return
        if (!current.saving) form.value = current.copy(draft = value)
    }

    fun editDns(enabled: Boolean) {
        val current = form.value ?: return
        if (!current.saving) form.value = current.copy(draftDns = enabled)
    }

    fun save() {
        val current = form.value?.takeIf { it.canSave } ?: return
        form.value = current.copy(saving = true)
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { store.save(profileId, current.draft) }
                form.value = current.copy(saved = current.draft)
                _events.send(OverrideEvent.Saved)
            } catch (e: IOException) {
                Timber.w(e, "Saving configuration override failed")
                form.value = current
                _events.send(OverrideEvent.SaveFailed)
            }
        }
    }

    fun saveDns() {
        val current = form.value?.takeIf { it.canSaveDns } ?: return
        val draft = current.draftDns ?: return
        form.value = current.copy(saving = true)
        viewModelScope.launch {
            val error = try {
                dns.save(draft)
            } catch (e: IOException) {
                Timber.w(e, "Saving the DNS preference could not be confirmed")
                e.message ?: e.javaClass.simpleName
            }
            if (error != null) {
                form.value = current
                _events.send(OverrideEvent.DnsFailed(error))
            } else {
                form.value = current.copy(savedDns = draft)
                _events.send(OverrideEvent.DnsSaved)
            }
        }
    }

    private data class PreviewSource(val id: Long, val name: String, val subscription: Boolean, val yaml: String)
}
