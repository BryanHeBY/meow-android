package io.github.madeye.meow.preference

import java.net.InetAddress
import java.net.UnknownHostException
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

@Serializable
enum class NameserverPolicyTransport { UDP, TCP }

@Serializable
data class NameserverPolicyRow(
    val pattern: String,
    val transport: NameserverPolicyTransport,
    val endpoint: String,
) {
    fun display() = "$pattern ${transport.name.lowercase()}://$endpoint"
}

/** The file and JNI share an ordered nullable row list. Null inherits; [] clears. */
object NameserverPolicyOverride {
    private const val MAX_ROWS = 32
    private val rows = ListSerializer(NameserverPolicyRow.serializer())

    internal fun toJson(value: List<NameserverPolicyRow>): JsonElement =
        Json.encodeToJsonElement(rows, value)

    internal fun fromJson(value: JsonElement): List<NameserverPolicyRow> =
        Json.decodeFromJsonElement(rows, value).also { require(valid(it)) }

    fun wire(value: List<NameserverPolicyRow>?): String = value?.let { toJson(it).toString() } ?: "null"

    internal fun valid(value: List<NameserverPolicyRow>): Boolean =
        value.size <= MAX_ROWS && parseRows(value.joinToString("\n") { it.display() }) == value

    fun parseRows(text: String): List<NameserverPolicyRow>? {
        if (text.length > 12_288) return null
        val rows = mutableListOf<NameserverPolicyRow>()
        val seen = mutableSetOf<String>()
        for (line in text.lineSequence()) {
            if (line.isBlank()) continue
            val columns = line.trim().split(Regex("\\s+"))
            if (columns.size != 2 || rows.size == MAX_ROWS) return null
            val pattern = FakeIpFilterRuntime.parsePatterns(columns[0])?.singleOrNull() ?: return null
            if (!seen.add(pattern)) return null
            val endpoint = columns[1].substringAfter("://", "")
            val transport = when (columns[1].substringBefore("://").lowercase()) {
                "udp" -> NameserverPolicyTransport.UDP
                "tcp" -> NameserverPolicyTransport.TCP
                else -> return null
            }
            if (!numericEndpoint(endpoint)) return null
            rows += NameserverPolicyRow(pattern, transport, endpoint.lowercase())
        }
        return rows
    }

    internal fun numericEndpoint(endpoint: String): Boolean {
        val portText = endpoint.substringAfterLast(':', "")
        if (portText.isEmpty() || !portText.all { it in '0'..'9' } ||
            (portText.length > 1 && portText.startsWith('0')) ||
            portText.toIntOrNull()?.let { it in 1..65535 } != true
        ) return false
        val host = endpoint.substringBeforeLast(':', "")
        if (host.startsWith('[') && host.endsWith(']')) {
            val v6 = host.substring(1, host.length - 1)
            if (':' !in v6 || v6.length > 45 ||
                !v6.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
            ) return false
            // A colon forces the numeric parser; no hostname resolution.
            val ip = try { InetAddress.getByName(v6) } catch (_: UnknownHostException) { return false }
            return !ip.isAnyLocalAddress && !ip.isMulticastAddress && !ip.isLinkLocalAddress &&
                ip.hostAddress != "255.255.255.255" && ip.address.size == 16
        }
        val fields = host.split('.')
        if (fields.size != 4 || fields.any {
            it.isEmpty() || !it.all { c -> c in '0'..'9' } ||
                (it.length > 1 && it.startsWith('0')) || it.toIntOrNull()?.let { n -> n in 0..255 } != true
        }) return false
        val first = fields.first().toInt()
        return first !in 224..239 && host != "0.0.0.0" && host != "255.255.255.255"
    }
}
