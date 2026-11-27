package io.github.madeye.meow.preference

import java.net.InetAddress
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

@Serializable
data class NumericDnsEndpoint(val transport: NameserverPolicyTransport, val endpoint: String) {
    fun display() = "${transport.name.lowercase()}://$endpoint"
}

/** Direct, numeric address roots only; no hostname lookups, proxy tags, or URL options. */
object NumericDnsEndpoints {
    const val TEXT_LIMIT = 512
    private val typedList = ListSerializer(NumericDnsEndpoint.serializer())

    internal fun toJson(value: List<NumericDnsEndpoint>): JsonElement {
        require(valid(value))
        return Json.encodeToJsonElement(typedList, value)
    }

    internal fun fromJson(value: JsonElement): List<NumericDnsEndpoint> =
        Json.decodeFromJsonElement(typedList, value).also { require(valid(it)) }

    internal fun valid(value: List<NumericDnsEndpoint>): Boolean =
        parse(value.joinToString("\n") { it.display() }) == value

    fun parse(text: String): List<NumericDnsEndpoint>? {
        if (text.length > TEXT_LIMIT) return null
        val lines = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        if (lines.size !in 1..8) return null
        val rows = lines.map {
            val transport = when (it.substringBefore("://").lowercase()) {
                "udp" -> NameserverPolicyTransport.UDP
                "tcp" -> NameserverPolicyTransport.TCP
                else -> return null
            }
            val endpoint = it.substringAfter("://", "").lowercase()
            if (!NameserverPolicyOverride.numericEndpoint(endpoint)) return null
            NumericDnsEndpoint(transport, endpoint)
        }
        return rows.takeIf { it.map(::identity).toSet().size == it.size }
    }

    private fun identity(row: NumericDnsEndpoint): Pair<NameserverPolicyTransport, String> {
        val endpoint = row.endpoint
        val host = endpoint.substringBeforeLast(':')
        val port = endpoint.substringAfterLast(':')
        val normalized = if (host.startsWith('[')) {
            InetAddress.getByName(host.removeSurrounding("[", "]")).hostAddress
        } else host
        return row.transport to "$normalized:$port"
    }
}
