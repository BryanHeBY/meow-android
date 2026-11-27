package io.github.madeye.meow.preference

import io.github.madeye.meow.core.MeowCore
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal fun FakeIpFilterOverride.toJson(): JsonObject = JsonObject(buildMap {
    patterns?.let { put("patterns", JsonArray(it.map(::JsonPrimitive))) }
    mode?.let { put("mode", JsonPrimitive(it.name)) }
})

object FakeIpFilterRuntime {
    fun apply(yaml: String, override: FakeIpFilterOverride, builtinDns: Boolean = false): String =
        if (override == FakeIpFilterOverride()) yaml
        else MeowCore.nativeOverrideFakeIpFilter(yaml, override.toJson().toString(), builtinDns)

    /** Exact DNS names, and +. suffix patterns including the base name. */
    fun parsePatterns(text: String): List<String>? {
        if (text.length > 32768) return null
        val patterns = linkedSetOf<String>()
        for (line in text.lineSequence()) {
            val pattern = line.trim().lowercase().removeSuffix(".")
            if (line.isBlank()) continue
            val domain = pattern.removePrefix("+.")
            if (domain.isEmpty() || domain.length > 253 ||
                !domain.split('.').all { label ->
                    label.length in 1..63 && label.first() != '-' && label.last() != '-' &&
                        label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
                } || !patterns.add(pattern) || patterns.size > 256
            ) return null
        }
        return patterns.toList()
    }
}
