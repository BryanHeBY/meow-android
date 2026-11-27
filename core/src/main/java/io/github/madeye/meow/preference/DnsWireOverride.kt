package io.github.madeye.meow.preference

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Startup DNS shaping; independent of outbound IPv6 and frozen for a running resolver. */
data class DnsWireOverride(
    val nameserverPolicy: List<NameserverPolicyRow>? = null,
    val ipv6: Boolean? = null,
) {
    fun snapshot(): DnsWireOverride = copy(nameserverPolicy = nameserverPolicy?.toList())

    fun wire(): String = if (ipv6 == null) NameserverPolicyOverride.wire(nameserverPolicy)
    else buildJsonObject {
        put("nameserverPolicy", nameserverPolicy?.let(NameserverPolicyOverride::toJson) ?: JsonNull)
        put("ipv6", ipv6)
    }.toString()
}
