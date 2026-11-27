package io.github.madeye.meow.preference

import io.github.madeye.meow.core.MeowCore
import java.net.InetAddress
import java.net.UnknownHostException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal fun DnsHostsOverride.toJson(): JsonObject = JsonObject(buildMap {
    hosts?.let { put("hosts", JsonObject(it.mapValues { entry -> JsonPrimitive(entry.value) })) }
    useHosts?.let { put("useHosts", JsonPrimitive(it)) }
})

object DnsHostsRuntime {
    fun apply(yaml: String, override: DnsHostsOverride, builtinDns: Boolean = false): String =
        if (override == DnsHostsOverride()) yaml
        else MeowCore.nativeOverrideDnsHosts(yaml, override.toJson().toString(), builtinDns)

    /** Editable rows are exact DNS names and literal addresses, one pair per line. */
    fun parseRows(text: String): Map<String, String>? {
        if (text.length > 32768) return null
        val hosts = linkedMapOf<String, String>()
        for (line in text.lineSequence()) {
            if (line.isBlank()) continue
            val pair = line.trim().split(Regex("\\s+"))
            if (pair.size != 2) return null
            val (name, address) = pair
            val normalized = name.lowercase().removeSuffix(".")
            if (normalized.isEmpty() || normalized.length > 253 ||
                !normalized.split('.').all { label ->
                    label.length in 1..63 && label.first() != '-' && label.last() != '-' &&
                        label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
                } || normalized in hosts || address.length > 45 ||
                !isLiteral(address)
            ) return null
            if (hosts.size == 256) return null
            hosts[normalized] = address
        }
        return hosts
    }

    private fun isLiteral(address: String): Boolean {
        if (':' in address) {
            if (!address.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) return false
            // A colon forces the numeric IPv6 parser. No hostname resolution.
            return try {
                InetAddress.getByName(address)
                true
            } catch (_: UnknownHostException) {
                false
            }
        }
        val octets = address.split('.')
        return octets.size == 4 && octets.all {
            it.isNotEmpty() && it.all { c -> c in '0'..'9' } &&
                (it.length == 1 || !it.startsWith('0')) && (it.toIntOrNull()?.let { value -> value in 0..255 } == true)
        }
    }
}
