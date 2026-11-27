package io.github.madeye.meow.preference

import io.github.madeye.meow.Core
import io.github.madeye.meow.bg.ActiveConfig
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException

/** Both processes read the same file. Only the VPN process stages writes. */
class DnsSettingsStore(private val file: File) {
    data class Saved(val settings: DnsSettings = DnsSettings(), val invalid: Boolean = false)

    private data class Check(
        val profile: ActiveConfig,
        val settings: DnsSettings,
        val wireOverride: DnsWireOverride,
        val frozenGeneration: String?,
        val issue: DnsIssue?,
    )

    // Exact profile, settings, and ordered policy (including null vs empty) identify the verdict.
    @Volatile private var checked: Check? = null

    fun load(): Saved = try {
        if (file.length() > DnsSettings.MAX_WIRE_BYTES) Saved(invalid = true) else when (val wire = file.readText()) {
            "builtin" -> Saved(DnsSettings(DnsMode.LEGACY_BUILTIN))
            "profile" -> Saved(DnsSettings(DnsMode.LEGACY_PROFILE))
            else -> Saved(DnsSettings.decode(wire))
        }
    } catch (_: FileNotFoundException) {
        Saved(invalid = file.exists())
    } catch (_: IOException) {
        Saved(invalid = true)
    } catch (_: IllegalArgumentException) {
        Saved(invalid = true)
    }

    /** Serialize a save with the engine reading and applying its startup settings. */
    @Synchronized
    internal fun <T> withSavedValue(block: (DnsSettings) -> T): T = block(load().settings)

    internal fun activationIssue(
        settings: DnsSettings,
        profile: ActiveConfig?,
        policyFor: (ActiveConfig) -> DnsWireOverride? = { null },
        validate: (String, String, String) -> String?,
    ): DnsIssue? = checkActivation(settings, profile, policyFor, validate, fresh = false)

    internal fun statusActivationIssue(
        settings: DnsSettings,
        profile: ActiveConfig?,
        frozenGeneration: String?,
        policyFor: (ActiveConfig) -> DnsWireOverride?,
        validate: (String, String, String) -> String?,
    ): DnsIssue? = checkActivation(settings, profile, policyFor, validate, fresh = false, frozenGeneration = frozenGeneration)

    /** Next generation must not reuse an earlier check of the packaged database. */
    internal fun freshActivationIssue(
        settings: DnsSettings,
        profile: ActiveConfig?,
        policyFor: (ActiveConfig) -> DnsWireOverride?,
        validate: (String, String, String) -> String?,
    ): DnsIssue? = checkActivation(settings, profile, policyFor, validate, fresh = true)

    /** The VPN process starts with its own unset native home (unlike the UI process). */
    internal fun startupActivationIssue(
        settings: DnsSettings,
        profile: ActiveConfig?,
        registerHome: () -> Unit,
        policyFor: (ActiveConfig) -> DnsWireOverride?,
        validate: (String, String, String) -> String?,
    ): DnsIssue? {
        registerHome()
        return freshActivationIssue(settings, profile, policyFor, validate)
    }

    private fun checkActivation(
        settings: DnsSettings,
        profile: ActiveConfig?,
        policyFor: (ActiveConfig) -> DnsWireOverride?,
        validate: (String, String, String) -> String?,
        fresh: Boolean,
        frozenGeneration: String? = null,
    ): DnsIssue? {
        if (settings.mode == DnsMode.SPLIT) return DnsIssue.SPLIT_UNAVAILABLE
        return when (settings.applicability(profile?.profileId)) {
            DnsApplicability.GLOBAL -> if (fresh && profile != null) {
                checkNamed(profile, settings, policyFor, validate, fresh = true, onlyCountry = true)
            } else null
            DnsApplicability.PENDING -> DnsIssue.PENDING
            DnsApplicability.UNAVAILABLE -> DnsIssue.PROFILE_UNAVAILABLE
            DnsApplicability.AVAILABLE -> checkNamed(requireNotNull(profile), settings, policyFor, validate, fresh = fresh,
                frozenGeneration = frozenGeneration)
        }
    }

    private fun checkNamed(
        profile: ActiveConfig,
        settings: DnsSettings,
        policyFor: (ActiveConfig) -> DnsWireOverride?,
        validate: (String, String, String) -> String?,
        fresh: Boolean = false,
        onlyCountry: Boolean = false,
        frozenGeneration: String? = null,
    ): DnsIssue? {
        val policy = try { policyFor(profile)?.snapshot() ?: DnsWireOverride() } catch (_: IOException) { return DnsIssue.INVALID_SETTINGS }
        val countryEnabled = policy.usesFallbackGeoIp
        if (onlyCountry && !countryEnabled) return null
        val recheckReader = fresh && countryEnabled
        val generation = frozenGeneration.takeIf { countryEnabled }
        checked?.takeUnless { recheckReader }?.let {
            if (it.profile == profile && it.settings == settings && it.wireOverride == policy &&
                it.frozenGeneration == generation) return it.issue
        }
        val issue = validate(profile.yaml, settings.encode(), policy.wire())?.let(DnsIssue::fromWire)
        // Availability of the packaged reader or the current VPN generation
        // may change independently of YAML and snapshot values.
        if (issue == DnsIssue.GEOIP_UNAVAILABLE || issue == DnsIssue.PROFILE_CHANGED) {
            if (recheckReader) checked = null
        } else if (!recheckReader) {
            checked = Check(profile, settings, policy, generation, issue)
        }
        return issue
    }

    /** Rust validates/rebuilds before renaming the staged file and publishing the new resolver. */
    @Synchronized
    internal fun commit(
        wire: String,
        expectedProfileId: Long?,
        selected: () -> ActiveConfig?,
        validate: (String, String, String) -> String?,
        policyFor: (ActiveConfig) -> DnsWireOverride? = { null },
        freshExplicitCountry: Boolean = false,
        frozenGeneration: String? = null,
        publish: (ActiveConfig?, DnsSettings, File, File) -> DnsIssue?,
    ): DnsIssue? {
        if (wire.toByteArray().size > DnsSettings.MAX_WIRE_BYTES) return DnsIssue.INVALID_SETTINGS
        val draft = try {
            DnsSettings.decode(wire)
        } catch (_: IllegalArgumentException) {
            return DnsIssue.INVALID_SETTINGS
        }
        if (draft.mode == DnsMode.SPLIT) return DnsIssue.SPLIT_UNAVAILABLE
        val profile = selected()
        if (profile?.profileId != expectedProfileId) return DnsIssue.PROFILE_CHANGED
        if (draft.requiresProfile && profile == null) return DnsIssue.PROFILE_REQUIRED
        val scoped = draft.copy(profileId = profile?.profileId.takeIf { draft.requiresProfile })
        val validated = scoped.encode().toByteArray(Charsets.UTF_8)
        if (validated.size > DnsSettings.MAX_WIRE_BYTES) return DnsIssue.INVALID_SETTINGS
        if (profile != null && scoped.requiresProfile) {
            val issue = checkNamed(profile, scoped, policyFor, validate, fresh = freshExplicitCountry,
                frozenGeneration = frozenGeneration)
            if (selected() != profile) return DnsIssue.PROFILE_CHANGED
            if (issue != null) return issue
        }
        return try {
            val staged = File.createTempFile("dns-", ".tmp", file.absoluteFile.parentFile)
            try {
                staged.outputStream().use {
                    it.write(validated)
                    it.fd.sync()
                }
                if (selected() != profile) DnsIssue.PROFILE_CHANGED else publish(profile, scoped, staged, file)
            } finally {
                staged.delete()
            }
        } catch (_: IOException) {
            DnsIssue.SAVE_FAILED
        }
    }

    companion object {
        val default: DnsSettingsStore by lazy {
            DnsSettingsStore(File(Core.deviceStorage.noBackupFilesDir, "builtin_dns"))
        }
    }
}
