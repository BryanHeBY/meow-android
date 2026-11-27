package io.github.madeye.meow.preference

import io.github.madeye.meow.core.MeowCore
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

data class ProfileOverrideValues(val ipv6: Boolean?, val coreBehavior: CoreBehaviorOverride)

/** Adapter for the runtime copy, to be called after scope merging and before loading. */
object CoreBehaviorRuntime {
    fun apply(yaml: String, override: CoreBehaviorOverride): String {
        if (override == CoreBehaviorOverride()) return yaml
        val options = JsonObject(buildMap {
            override.unifiedDelay?.let { put("unifiedDelay", JsonPrimitive(it)) }
            override.tcpConcurrent?.let { put("tcpConcurrent", JsonPrimitive(it)) }
            override.findProcessMode?.let { put("findProcessMode", JsonPrimitive(it.wire)) }
        })
        return MeowCore.nativeOverrideCoreBehavior(yaml, options.toString())
    }

    /** The profile's startup values before saved overrides. Performs no provider or DNS I/O. */
    fun preview(yaml: String): ProfileOverrideValues? {
        val result = MeowCore.nativePreviewProfileOverrides(yaml) ?: return null
        val fields = Json.parseToJsonElement(result).jsonObject
        val processMode = fields.getValue("findProcessMode").jsonPrimitive.content
        return ProfileOverrideValues(
            fields.getValue("ipv6").takeUnless { it == JsonNull }?.jsonPrimitive?.boolean,
            CoreBehaviorOverride(
                fields.getValue("unifiedDelay").jsonPrimitive.boolean,
                fields.getValue("tcpConcurrent").jsonPrimitive.boolean,
                FindProcessOverride.entries.first { it.wire == processMode },
            ),
        )
    }
}
