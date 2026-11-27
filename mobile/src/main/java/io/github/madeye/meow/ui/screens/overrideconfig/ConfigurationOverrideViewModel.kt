package io.github.madeye.meow.ui.screens.overrideconfig

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.madeye.meow.preference.DnsPreference
import io.github.madeye.meow.preference.DnsMode
import io.github.madeye.meow.preference.DnsSettings
import io.github.madeye.meow.preference.DnsIssue
import io.github.madeye.meow.preference.ConfigurationOverride
import io.github.madeye.meow.preference.ConfigurationOverrideStore
import io.github.madeye.meow.preference.CoreBehaviorRuntime
import io.github.madeye.meow.preference.ProfileOverrideValues
import io.github.madeye.meow.repo.ProfileRepository
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber

internal data class OverrideProfilePreview(
    val id: Long,
    val name: String,
    val subscription: Boolean,
    val profileValues: ProfileOverrideValues?,
    val override: ConfigurationOverride?,
)

internal data class OverrideForm(
    val saved: ConfigurationOverride,
    val draft: ConfigurationOverride = saved,
    val global: ConfigurationOverride,
    val savedDns: DnsSettings?,
    val draftDns: DnsSettings? = savedDns,
    val dnsSelectedId: Long? = null,
    val invalidDnsPreference: Boolean = false,
    val saving: Boolean = false,
) {
    fun draftFor(section: OverrideSection): ConfigurationOverride = when (section) {
        OverrideSection.MAIN -> saved.copy(ipv6 = draft.ipv6, appQuic = draft.appQuic)
        OverrideSection.CORE -> saved.copy(coreBehavior = draft.coreBehavior)
    }

    fun canSave(section: OverrideSection) = !saving && saved != draftFor(section)
    val canSaveDns get() = !saving && draftDns?.complete == true && draftDns.mode != DnsMode.SPLIT &&
        (invalidDnsPreference || savedDns != draftDns.normalized() ||
            (draftDns.requiresProfile && draftDns.profileId != dnsSelectedId))
}

internal enum class OverrideSection { MAIN, CORE }

internal sealed interface OverrideEvent {
    data object Saved : OverrideEvent
    data object DnsSaved : OverrideEvent
    data object SaveFailed : OverrideEvent
    data class DnsFailed(val issue: DnsIssue) : OverrideEvent
}

internal class ConfigurationOverrideViewModel(
    val profileId: Long?,
    private val store: ConfigurationOverrideStore,
    private val dns: DnsPreference,
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
                    it.id,
                    it.name,
                    it.subscription,
                    CoreBehaviorRuntime.preview(it.yaml),
                    if (profileId == null) readProfileOverride(it.id) else ConfigurationOverride(),
                )
            }
        }
        .flowOn(Dispatchers.IO)

    val uiState = combine(form, preview, ::Pair)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null to null)

    private val dnsGeneration = MutableStateFlow(0)

    @OptIn(ExperimentalCoroutinesApi::class)
    val dnsStatus = dnsGeneration.flatMapLatest {
        flow {
            if (profileId == null) {
                while (true) {
                    emit(dns.status())
                    delay(2_000)
                }
            }
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(), null)

    init {
        viewModelScope.launch {
            try {
                val (saved, global) = withContext(Dispatchers.IO) {
                    store.load(profileId) to if (profileId == null) ConfigurationOverride() else store.load()
                }
                val dnsSaved = if (profileId == null) dns.load() else null
                form.value = OverrideForm(
                    saved, global = global, savedDns = dnsSaved?.settings,
                    invalidDnsPreference = dnsSaved?.invalid == true,
                )
                if (profileId == null) selected.map { it?.id }.distinctUntilChanged().collect { id ->
                    form.update { current ->
                        current?.let { if (it.dnsSelectedId == id) it else it.copy(dnsSelectedId = id, draftDns = it.savedDns) }
                    }
                }
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

    fun editDns(settings: DnsSettings) {
        val current = form.value ?: return
        if (!current.saving) form.value = current.copy(draftDns = settings)
    }

    fun save(section: OverrideSection) {
        val current = form.value?.takeIf { it.canSave(section) } ?: return
        val candidate = current.draftFor(section)
        form.value = current.copy(saving = true)
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { store.save(profileId, candidate) }
                form.update { it?.copy(saved = candidate, saving = false) }
                _events.send(OverrideEvent.Saved)
            } catch (e: IOException) {
                Timber.w(e, "Saving configuration override failed")
                form.update { it?.copy(saving = false) }
                _events.send(OverrideEvent.SaveFailed)
            }
        }
    }

    private fun readProfileOverride(id: Long): ConfigurationOverride? = try {
        store.load(id)
    } catch (e: IOException) {
        Timber.w(e, "Reading selected profile overrides failed")
        null
    }

    fun saveDns(displayedProfileId: Long?) {
        val current = form.value?.takeIf { it.canSaveDns && it.dnsSelectedId == displayedProfileId } ?: return
        val draft = current.draftDns?.normalized() ?: return
        form.value = current.copy(saving = true)
        viewModelScope.launch {
            val error = try {
                dns.save(draft, current.dnsSelectedId)
            } catch (e: IOException) {
                Timber.w(e, "Saving the DNS preference could not be confirmed")
                DnsIssue.SERVICE_UNAVAILABLE
            }
            dnsGeneration.value += 1
            if (error != null) {
                form.update { it?.copy(saving = false) }
                _events.send(OverrideEvent.DnsFailed(error))
            } else {
                val saved = draft.copy(profileId = current.dnsSelectedId.takeIf { draft.requiresProfile })
                form.update { it?.copy(savedDns = saved, draftDns = saved, invalidDnsPreference = false, saving = false) }
                _events.send(OverrideEvent.DnsSaved)
            }
        }
    }

    private data class PreviewSource(val id: Long, val name: String, val subscription: Boolean, val yaml: String)
}
