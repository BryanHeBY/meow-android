package io.github.madeye.meow.preference

import java.net.InetAddress
import java.net.UnknownHostException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

@Serializable
sealed class DnsFallbackOverride {
    @Serializable @SerialName("disabled")
    data object Disabled : DnsFallbackOverride()

    @Serializable @SerialName("replace")
    data class Replace(
        val endpoints: List<NumericDnsEndpoint>,
        val domains: List<String>,
        val cidrs: List<String>,
    ) : DnsFallbackOverride()

    internal fun snapshot(): DnsFallbackOverride = when (this) {
        Disabled -> this
        is Replace -> copy(endpoints = endpoints.toList(), domains = domains.toList(), cidrs = cidrs.toList())
    }

    internal fun toJson(): JsonElement {
        require(valid())
        return codec.encodeToJsonElement(serializer(), this)
    }

    private fun valid() = this == Disabled || (this is Replace &&
        parse(endpoints.joinToString("\n") { it.display() }, domains.joinToString("\n"), cidrs.joinToString("\n")) == this)

    companion object {
        private val codec = Json { classDiscriminator = "mode" }
        internal fun fromJson(element: JsonElement) =
            codec.decodeFromJsonElement(serializer(), element).also { require(it.valid()) }

        fun parse(upstreams: String, domains: String, cidrs: String): Replace? {
            if (upstreams.length > 512 || domains.length > 2048 || cidrs.length > 896) return null
            val endpoints = NumericDnsEndpoints.parse(upstreams) ?: return null
            val domainRows = FakeIpFilterRuntime.parsePatterns(domains) ?: return null
            val cidrRows = lines(cidrs).map { it.lowercase() }
            if (domainRows.size > 8 || cidrRows.size > 16) return null
            val cidrIdentities = cidrRows.map { cidrIdentity(it) ?: return null }
            if (cidrIdentities.toSet().size != cidrIdentities.size) return null
            return Replace(endpoints, domainRows, cidrRows)
        }

        private fun lines(text: String) = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()

        private fun cidrIdentity(row: String): Pair<List<Byte>, Int>? {
            val host = row.substringBefore('/')
            val prefix = row.substringAfter('/', "")
            val bits = prefix.toIntOrNull() ?: return null
            if (prefix != bits.toString() || bits < 0) return null
            val bytes = if (':' in host) {
                if (host.length > 45 || host.any { it !in "0123456789abcdef:." }) return null
                val ip = try { InetAddress.getByName(host) } catch (_: UnknownHostException) { return null }
                if (ip.address.size != 16) return null
                ip.address
            } else {
                val octets = host.split('.')
                if (octets.size != 4) return null
                val values = octets.map { word ->
                    val n = word.toIntOrNull() ?: return null
                    if (word != n.toString() || n !in 0..255) return null
                    n.toByte()
                }
                values.toByteArray()
            }
            if (bits > bytes.size * 8) return null
            if ((bits until bytes.size * 8).any { index ->
                bytes[index / 8].toInt() and (128 ushr (index % 8)) != 0
            }) return null
            return bytes.toList() to bits
        }
    }
}
