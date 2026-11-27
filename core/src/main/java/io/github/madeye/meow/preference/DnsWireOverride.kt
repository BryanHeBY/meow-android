package io.github.madeye.meow.preference

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Startup DNS shaping; independent of outbound IPv6 and frozen for a running resolver. */
data class DnsWireOverride(
    val nameserverPolicy: List<NameserverPolicyRow>? = null,
    val ipv6: Boolean? = null,
    val fallback: DnsFallbackOverride? = null,
    val bootstrap: List<NumericDnsEndpoint>? = null,
) {
    fun snapshot(): DnsWireOverride = copy(nameserverPolicy = nameserverPolicy?.toList(), fallback = fallback?.snapshot(), bootstrap = bootstrap?.toList())

    fun wire(): String = if (ipv6 == null && fallback == null && bootstrap == null) NameserverPolicyOverride.wire(nameserverPolicy)
    else buildJsonObject {
        put("nameserverPolicy", nameserverPolicy?.let(NameserverPolicyOverride::toJson) ?: JsonNull)
        ipv6?.let { put("ipv6", it) }
        fallback?.let { put("fallback", it.toJson()) }
        bootstrap?.let { put("bootstrap", NumericDnsEndpoints.toJson(it)) }
    }.toString()
}
