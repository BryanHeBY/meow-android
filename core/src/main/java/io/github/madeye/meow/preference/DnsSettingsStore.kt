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
        val nameserverPolicy: List<NameserverPolicyRow>?,
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
        policyFor: (ActiveConfig) -> List<NameserverPolicyRow>? = { null },
        validate: (String, String, String) -> String?,
    ): DnsIssue? {
        if (settings.mode == DnsMode.SPLIT) return DnsIssue.SPLIT_UNAVAILABLE
        return when (settings.applicability(profile?.profileId)) {
            DnsApplicability.GLOBAL -> null
            DnsApplicability.PENDING -> DnsIssue.PENDING
            DnsApplicability.UNAVAILABLE -> DnsIssue.PROFILE_UNAVAILABLE
            DnsApplicability.AVAILABLE -> checkNamed(requireNotNull(profile), settings, policyFor, validate)
        }
    }

    private fun checkNamed(
        profile: ActiveConfig,
        settings: DnsSettings,
        policyFor: (ActiveConfig) -> List<NameserverPolicyRow>?,
        validate: (String, String, String) -> String?,
    ): DnsIssue? {
        val policy = try { policyFor(profile)?.toList() } catch (_: IOException) { return DnsIssue.INVALID_SETTINGS }
        checked?.let {
            if (it.profile == profile && it.settings == settings && it.nameserverPolicy == policy) return it.issue
        }
        val issue = validate(profile.yaml, settings.encode(), NameserverPolicyOverride.wire(policy))?.let(DnsIssue::fromWire)
        checked = Check(profile, settings, policy, issue)
        return issue
    }

    /** Rust validates/rebuilds before renaming the staged file and publishing the new resolver. */
    @Synchronized
    internal fun commit(
        wire: String,
        expectedProfileId: Long?,
        selected: () -> ActiveConfig?,
        validate: (String, String, String) -> String?,
        policyFor: (ActiveConfig) -> List<NameserverPolicyRow>? = { null },
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
            val issue = checkNamed(profile, scoped, policyFor, validate)
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
