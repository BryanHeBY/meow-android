package io.github.madeye.meow.preference

import kotlinx.serialization.Required
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
enum class DnsMode {
    @SerialName("inherit") INHERIT,
    @SerialName("profile") LEGACY_PROFILE,
    @SerialName("builtin") LEGACY_BUILTIN,
    @SerialName("cn") CN,
    @SerialName("split") SPLIT,
    @SerialName("custom") CUSTOM,
}

@Serializable
enum class DnsTransport {
    @SerialName("udp") UDP,
    @SerialName("tcp") TCP,
    @SerialName("tls") TLS,
    @SerialName("https") HTTPS,
}

@Serializable
enum class DnsEgress {
    @SerialName("direct") DIRECT,
    @SerialName("proxy") PROXY,
}

@Serializable
data class DnsUpstream(
    val transport: DnsTransport = DnsTransport.HTTPS,
    val endpoint: String = "",
    val egress: DnsEgress = DnsEgress.DIRECT,
    val proxy: String = "",
) {
    val complete get() = endpoint.isNotBlank() && (egress == DnsEgress.DIRECT || proxy.isNotBlank())
}

@Serializable
data class DnsSettings(
    val mode: DnsMode = DnsMode.INHERIT,
    val upstreams: List<DnsUpstream> = emptyList(),
    val splitProxy: String = "",
    val profileId: Long? = null,
) {
    @Required private val version: Int = 1

    fun normalized() = copy(
        upstreams = if (mode == DnsMode.CUSTOM) upstreams.map {
            it.copy(endpoint = it.endpoint.trim(), proxy = if (it.egress == DnsEgress.PROXY) it.proxy.trim() else "")
        } else emptyList(),
        splitProxy = if (mode == DnsMode.SPLIT) splitProxy.trim() else "",
        profileId = profileId.takeIf { requiresProfile },
    )

    val requiresProfile get() = mode == DnsMode.SPLIT ||
        (mode == DnsMode.CUSTOM && upstreams.any { it.egress == DnsEgress.PROXY })

    fun applicability(selectedId: Long?) = when {
        !requiresProfile -> DnsApplicability.GLOBAL
        profileId == null -> DnsApplicability.PENDING
        profileId == selectedId -> DnsApplicability.AVAILABLE
        else -> DnsApplicability.UNAVAILABLE
    }

    val complete get() = when (mode) {
        DnsMode.SPLIT -> splitProxy.isNotBlank()
        DnsMode.CUSTOM -> upstreams.size in 1..MAX_UPSTREAMS && upstreams.all { it.complete }
        else -> true
    }

    fun encode(): String = json.encodeToString(serializer(), normalized())

    companion object {
        const val MAX_UPSTREAMS = 6
        const val MAX_WIRE_BYTES = 16_384
        @OptIn(ExperimentalSerializationApi::class)
        private val json = Json {
            encodeDefaults = true
            explicitNulls = false
        }

        fun decode(wire: String): DnsSettings = json.decodeFromString(serializer(), wire).also {
            require(it.version == 1 && it.complete && (it.profileId == null || it.profileId > 0))
        }.normalized()
    }
}

@Serializable
enum class DnsApplicability { GLOBAL, PENDING, AVAILABLE, UNAVAILABLE }

@Serializable
enum class DnsIssue(val message: String) {
    INVALID_SETTINGS("Check the DNS settings and try again."),
    PROFILE_REQUIRED("Select a profile before saving DNS through a named proxy."),
    PROFILE_CHANGED("The selected profile or VPN session changed. Review the DNS settings and try again."),
    PENDING("Review and save the previous named DNS override for the selected profile, or choose another DNS mode."),
    PROFILE_UNAVAILABLE("The saved DNS override belongs to another profile. Reselect that profile or save DNS settings for this selection."),
    PROXY_UNAVAILABLE("Choose a compatible proxy node from the selected profile. Check the name, transport and dialer settings."),
    SPLIT_UNAVAILABLE("Split DNS is unavailable on Android. Choose another DNS mode to connect."),
    RESOLVER_REJECTED("The resolver rejected these DNS settings. Check the profile DNS policies and bootstrap upstreams."),
    SAVE_FAILED("Could not save the DNS settings."),
    SERVICE_UNAVAILABLE("The VPN service is unavailable. Try again."),
    ;

    companion object {
        fun fromWire(code: String): DnsIssue = entries.firstOrNull { it.name == code } ?: SAVE_FAILED
    }
}

@Serializable
data class DnsStatus(
    val mode: String? = null,
    val missingMain: Boolean = false,
    val primary: List<String> = emptyList(),
    val fallback: List<String> = emptyList(),
    val direct: List<String> = emptyList(),
    val node: List<String> = emptyList(),
    val bootstrap: List<String> = emptyList(),
    val policyEntries: Int = 0,
    val runningProfileId: Long? = null,
    val selectedProfileId: Long? = null,
    val applicability: DnsApplicability = DnsApplicability.GLOBAL,
    val issue: DnsIssue? = null,
)
