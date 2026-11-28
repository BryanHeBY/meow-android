package io.github.madeye.meow.preference

import io.github.madeye.meow.Core
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive

enum class Ipv6Override { INHERIT, FORCE_ON, FORCE_OFF }
enum class AppQuicOverride { INHERIT, BLOCK_UDP_443, DO_NOT_BLOCK }
enum class FindProcessOverride(val wire: String) { OFF("off"), ALWAYS("always") }
enum class LogLevelOverride(val wire: String) {
    DEBUG("debug"), INFO("info"), WARNING("warning"), ERROR("error"), SILENT("silent"),
}

/** Null means inherit; explicit false is distinct from an inherited value. */
data class CoreBehaviorOverride(
    val unifiedDelay: Boolean? = null,
    val tcpConcurrent: Boolean? = null,
    val findProcessMode: FindProcessOverride? = null,
    val logLevel: LogLevelOverride? = null,
) {
    fun withInherited(global: CoreBehaviorOverride) = CoreBehaviorOverride(
        unifiedDelay ?: global.unifiedDelay,
        tcpConcurrent ?: global.tcpConcurrent,
        findProcessMode ?: global.findProcessMode,
        logLevel ?: global.logLevel,
    )
}

/** The table is replaced as a unit. Null inherits; an empty table clears it. */
data class DnsHostsOverride(val hosts: Map<String, String>? = null, val useHosts: Boolean? = null) {
    fun withInherited(global: DnsHostsOverride) =
        DnsHostsOverride(hosts ?: global.hosts, useHosts ?: global.useHosts)
}

enum class FakeIpFilterMode { BLACKLIST, WHITELIST }

data class FakeIpFilterOverride(val patterns: List<String>? = null, val mode: FakeIpFilterMode? = null) {
    fun withInherited(global: FakeIpFilterOverride) =
        FakeIpFilterOverride(patterns ?: global.patterns, mode ?: global.mode)
}

data class ConfigurationOverride(
    val ipv6: Ipv6Override = Ipv6Override.INHERIT,
    val appQuic: AppQuicOverride = AppQuicOverride.INHERIT,
    val coreBehavior: CoreBehaviorOverride = CoreBehaviorOverride(),
    val dnsHosts: DnsHostsOverride = DnsHostsOverride(),
    val fakeIpFilter: FakeIpFilterOverride = FakeIpFilterOverride(),
    val nameserverPolicy: List<NameserverPolicyRow>? = null,
    val dnsIpv6: Boolean? = null,
    val dnsFallback: DnsFallbackOverride? = null,
    val dnsBootstrap: List<NumericDnsEndpoint>? = null,
    val dnsHijacking: Boolean? = null,
) {
    fun withInherited(global: ConfigurationOverride) = ConfigurationOverride(
        ipv6.takeUnless { it == Ipv6Override.INHERIT } ?: global.ipv6,
        appQuic.takeUnless { it == AppQuicOverride.INHERIT } ?: global.appQuic,
        coreBehavior.withInherited(global.coreBehavior),
        dnsHosts.withInherited(global.dnsHosts),
        fakeIpFilter.withInherited(global.fakeIpFilter),
        nameserverPolicy ?: global.nameserverPolicy,
        dnsIpv6 ?: global.dnsIpv6,
        dnsFallback ?: global.dnsFallback,
        dnsBootstrap ?: global.dnsBootstrap,
        dnsHijacking ?: global.dnsHijacking,
    )

    val dnsWireOverride get() = DnsWireOverride(nameserverPolicy, dnsIpv6, dnsFallback, dnsBootstrap)

    val interceptsPlainDns: Boolean get() = dnsHijacking ?: true

    val blocksAppUdp443: Boolean get() = appQuic == AppQuicOverride.BLOCK_UDP_443
}

/** Both the editor and the store use this section boundary. */
enum class OverrideSection {
    MAIN, CORE, HOSTS, FAKE_IP, NAMESERVER_POLICY, DNS_IPV6, DNS_FALLBACK, DNS_BOOTSTRAP;

    fun patch(target: ConfigurationOverride, source: ConfigurationOverride): ConfigurationOverride = when (this) {
        MAIN -> target.copy(ipv6 = source.ipv6, appQuic = source.appQuic, dnsHijacking = source.dnsHijacking)
        CORE -> target.copy(coreBehavior = source.coreBehavior)
        HOSTS -> target.copy(dnsHosts = source.dnsHosts)
        FAKE_IP -> target.copy(fakeIpFilter = source.fakeIpFilter)
        NAMESERVER_POLICY -> target.copy(nameserverPolicy = source.nameserverPolicy?.toList())
        DNS_IPV6 -> target.copy(dnsIpv6 = source.dnsIpv6)
        DNS_FALLBACK -> target.copy(dnsFallback = source.dnsFallback?.snapshot())
        DNS_BOOTSTRAP -> target.copy(dnsBootstrap = source.dnsBootstrap?.toList())
    }

    fun matches(left: ConfigurationOverride, right: ConfigurationOverride): Boolean =
        patch(right, left) == right
}

/** One file per scope, read fresh in the VPN process. Legacy files migrate on save. */
class ConfigurationOverrideStore(private val directory: File) {
    private fun file(profileId: Long?) = File(directory, profileId?.let { "profile-$it" } ?: "global")

    fun load(profileId: Long? = null): ConfigurationOverride {
        val text = try {
            file(profileId).readText()
        } catch (_: FileNotFoundException) {
            return ConfigurationOverride()
        }
        try {
            if (!text.trimStart().startsWith("{")) {
                val lines = text.trimEnd().lines()
                require(lines.size <= 2) { "unknown legacy override format" }
                val ipv6 = lines[0].takeIf(String::isNotEmpty)?.let(Ipv6Override::valueOf)
                val quic = lines.getOrNull(1)?.takeIf(String::isNotEmpty)?.let(AppQuicOverride::valueOf)
                return ConfigurationOverride(ipv6 ?: Ipv6Override.INHERIT, quic ?: AppQuicOverride.INHERIT)
            }
            val root = Json.parseToJsonElement(text) as? JsonObject ?: error("expected object")
            require(root.keys.all { it in setOf("version", "ipv6", "appQuic", "coreBehavior", "dnsHosts", "fakeIpFilter", "nameserverPolicy", "dnsIpv6", "dnsFallback", "dnsBootstrap", "dnsHijacking") }) { "unknown override field" }
            val version = root["version"]?.jsonPrimitive
            require(version?.isString == false && version.intOrNull == 1) { "unsupported override version" }
            fun enumName(key: String) = root[key]?.jsonPrimitive?.let {
                require(it.isString) { "invalid $key" }
                it.content
            }
            val ipv6 = enumName("ipv6")?.let { Ipv6Override.valueOf(it) } ?: Ipv6Override.INHERIT
            val quic = enumName("appQuic")?.let { AppQuicOverride.valueOf(it) } ?: AppQuicOverride.INHERIT
            val core = (root["coreBehavior"] ?: JsonObject(emptyMap())) as? JsonObject
                ?: error("invalid coreBehavior")
            require(core.keys.all { it in setOf("unifiedDelay", "tcpConcurrent", "findProcessMode", "logLevel") }) { "unknown core field" }
            fun boolean(key: String): Boolean? = core[key]?.jsonPrimitive?.let {
                require(!it.isString) { "invalid $key" }
                it.booleanOrNull ?: error("invalid $key")
            }
            val process = core["findProcessMode"]?.jsonPrimitive?.let {
                require(it.isString) { "invalid findProcessMode" }
                FindProcessOverride.valueOf(it.content)
            }
            val dnsHosts = (root["dnsHosts"] ?: JsonObject(emptyMap())) as? JsonObject
                ?: error("invalid dnsHosts")
            require(dnsHosts.keys.all { it in setOf("hosts", "useHosts") }) { "unknown DNS hosts field" }
            val hosts = dnsHosts["hosts"]?.let { element ->
                (element as? JsonObject ?: error("invalid hosts")).mapValues { (_, value) ->
                    value.jsonPrimitive.also { require(it.isString) }.content
                }
            }
            val useHosts = dnsHosts["useHosts"]?.jsonPrimitive?.let {
                require(!it.isString)
                it.booleanOrNull ?: error("invalid useHosts")
            }
            val logLevel = core["logLevel"]?.jsonPrimitive?.let {
                require(it.isString) { "invalid logLevel" }
                LogLevelOverride.valueOf(it.content)
            }
            val fakeIp = (root["fakeIpFilter"] ?: JsonObject(emptyMap())) as? JsonObject
                ?: error("invalid fakeIpFilter")
            require(fakeIp.keys.all { it in setOf("patterns", "mode") }) { "unknown Fake-IP filter field" }
            val patterns = fakeIp["patterns"]?.let { field ->
                val values = (field as? JsonArray ?: error("invalid Fake-IP patterns")).map {
                    it.jsonPrimitive.also { value -> require(value.isString) }.content
                }
                require(FakeIpFilterRuntime.parsePatterns(values.joinToString("\n")) == values) { "invalid Fake-IP patterns" }
                values
            }
            val filterMode = fakeIp["mode"]?.jsonPrimitive?.let {
                require(it.isString)
                FakeIpFilterMode.valueOf(it.content)
            }
            return ConfigurationOverride(
                ipv6, quic, CoreBehaviorOverride(boolean("unifiedDelay"), boolean("tcpConcurrent"), process, logLevel),
                DnsHostsOverride(hosts, useHosts),
                FakeIpFilterOverride(patterns, filterMode),
                root["nameserverPolicy"]?.let(NameserverPolicyOverride::fromJson),
                root["dnsIpv6"]?.jsonPrimitive?.let {
                    require(!it.isString) { "invalid dnsIpv6" }
                    it.booleanOrNull ?: error("invalid dnsIpv6")
                },
                root["dnsFallback"]?.let(DnsFallbackOverride::fromJson),
                root["dnsBootstrap"]?.let(NumericDnsEndpoints::fromJson),
                root["dnsHijacking"]?.jsonPrimitive?.let {
                    require(!it.isString) { "invalid dnsHijacking" }
                    it.booleanOrNull ?: error("invalid dnsHijacking")
                },
            )
        } catch (e: IllegalArgumentException) {
            throw IOException("Cannot read configuration override", e)
        } catch (e: IllegalStateException) {
            throw IOException("Cannot read configuration override", e)
        }
    }

    fun effective(profileId: Long?): ConfigurationOverride {
        val global = load()
        return if (profileId == null) global else load(profileId).withInherited(global)
    }

    /** Compare only the edited section, then patch it over the latest file. */
    @Synchronized
    fun saveSection(
        profileId: Long?,
        section: OverrideSection,
        expected: ConfigurationOverride,
        draft: ConfigurationOverride,
    ): ConfigurationOverride {
        val latest = load(profileId)
        if (!section.matches(expected, latest)) throw IOException("Configuration override changed while editing")
        return section.patch(latest, draft).also { save(profileId, it) }
    }

    @Synchronized
    fun save(profileId: Long?, override: ConfigurationOverride) {
        if (override.nameserverPolicy?.let { !NameserverPolicyOverride.valid(it) } == true) {
            throw IOException("Cannot save invalid nameserver policy")
        }
        override.fakeIpFilter.patterns?.let { patterns ->
            if (patterns.size > 256 || FakeIpFilterRuntime.parsePatterns(patterns.joinToString("\n")) != patterns) {
                throw IOException("Cannot save invalid Fake-IP filter patterns")
            }
        }
        val target = file(profileId)
        // Do not replace an unknown or malformed format with a lossy older version.
        if (target.exists()) load(profileId)
        if (override == ConfigurationOverride()) {
            if (!target.delete() && target.exists()) throw IOException("Cannot reset configuration override")
            return
        }
        if (!directory.mkdirs() && !directory.isDirectory) throw IOException("Cannot store configuration override")
        val core = buildMap {
            override.coreBehavior.unifiedDelay?.let { put("unifiedDelay", JsonPrimitive(it)) }
            override.coreBehavior.tcpConcurrent?.let { put("tcpConcurrent", JsonPrimitive(it)) }
            override.coreBehavior.findProcessMode?.let { put("findProcessMode", JsonPrimitive(it.name)) }
            override.coreBehavior.logLevel?.let { put("logLevel", JsonPrimitive(it.name)) }
        }
        val root = JsonObject(buildMap {
            put("version", JsonPrimitive(1))
            put("ipv6", JsonPrimitive(override.ipv6.name))
            put("appQuic", JsonPrimitive(override.appQuic.name))
            override.dnsHijacking?.let { put("dnsHijacking", JsonPrimitive(it)) }
            if (core.isNotEmpty()) put("coreBehavior", JsonObject(core))
            val hosts = override.dnsHosts.toJson()
            if (hosts.isNotEmpty()) put("dnsHosts", hosts)
            val fakeIp = override.fakeIpFilter.toJson()
            if (fakeIp.isNotEmpty()) put("fakeIpFilter", fakeIp)
            override.nameserverPolicy?.let { put("nameserverPolicy", NameserverPolicyOverride.toJson(it)) }
            override.dnsIpv6?.let { put("dnsIpv6", JsonPrimitive(it)) }
            override.dnsFallback?.let { put("dnsFallback", it.toJson()) }
            override.dnsBootstrap?.let { put("dnsBootstrap", NumericDnsEndpoints.toJson(it)) }
        })
        val temp = File.createTempFile("override-", ".tmp", directory)
        try {
            temp.writeText(root.toString() + "\n")
            if (!temp.renameTo(target)) throw IOException("Cannot save configuration override")
        } finally {
            temp.delete()
        }
    }

    companion object {
        val default: ConfigurationOverrideStore by lazy {
            ConfigurationOverrideStore(File(Core.deviceStorage.noBackupFilesDir, "configuration_overrides"))
        }
    }
}
