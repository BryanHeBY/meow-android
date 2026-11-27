package io.github.madeye.meow.api

import io.github.madeye.meow.aidl.ByteTotals
import io.github.madeye.meow.aidl.ControllerEndpoint
import io.github.madeye.meow.vpn.ControllerSession
import java.io.IOException
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.retryWhen
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Dispatcher
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import timber.log.Timber

/** Client for one endpoint of the Clash-compatible controller. */
class MeowApi private constructor(
    private val baseUrl: HttpUrl,
    private val clients: Clients,
    private val json: Json,
    private val authorization: String?,
) {
    /** An explicit controller URL, for protocol fixtures. App callers use [SessionFactory]. */
    internal constructor(
        baseUrl: HttpUrl = DEFAULT_BASE_URL.toHttpUrl(),
        baseClient: OkHttpClient = defaultClient(),
        json: Json = MeowJson,
        secret: String? = null,
    ) : this(baseUrl, Clients(baseClient), json, secret?.takeIf(String::isNotEmpty)?.let { "Bearer $it" })

    class SessionFactory(baseClient: OkHttpClient = defaultClient(), private val json: Json = MeowJson) {
        private val clients = Clients(baseClient)

        fun forSession(session: ControllerSession): MeowApi = forEndpoint(session.controller)

        internal fun forEndpoint(endpoint: ControllerEndpoint): MeowApi = MeowApi(
            LOOPBACK.newBuilder().port(endpoint.port).build(), clients, json, endpoint.authorizationHeader(),
        )
    }

    private val client: OkHttpClient get() = clients.client

    companion object {
        private const val DEFAULT_BASE_URL = "http://127.0.0.1:9090"
        private val LOOPBACK = DEFAULT_BASE_URL.toHttpUrl()

        /**
         * Probe target for the delay endpoints when a group sets no testUrl:
         * the engine's own health-check default (mihomo's and sing-box's too).
         * A node keeps one alive flag and delay whatever URL measured them,
         * and url-test / fallback / load-balance groups pick by them, so a
         * manual test should probe what the health check probes. HTTPS, as the
         * engine verifies the certificate: over plain HTTP a transit-path
         * hijack or captive portal could answer in the endpoint's place.
         */
        const val DELAY_TEST_URL = "https://www.gstatic.com/generate_204"

        /**
         * Delay probes in flight at once. Each can hold its call open for the
         * full probe timeout, so a large group is worked through in waves.
         */
        const val PROBE_CONCURRENCY = 8

        /** Wait before the one retry of a probe the engine answered 503. */
        private const val DELAY_PROBE_RETRY_MS = 500L

        /** Same page size as meow-ios's DNS screen (and the engine's default). */
        const val DNS_RESULTS_LIMIT = 256

        private val JSON_MEDIA = "application/json".toMediaType()

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            // Never route loopback through a system proxy — installing proxies
            // is this app's entire job, and honouring one here would loop.
            .proxy(Proxy.NO_PROXY)
            .connectTimeout(2, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .followRedirects(false)
            // Keeps the /logs socket from being reaped while idle.
            .pingInterval(20, TimeUnit.SECONDS)
            .build()
    }

    /**
     * Delay probes get their own dispatcher. OkHttp runs at most five calls per
     * host by default, so sharing [client]'s would cap a group test below
     * [PROBE_CONCURRENCY] and queue every other API call behind probes that
     * can each take seconds to time out.
     */
    private class Clients(val client: OkHttpClient) {
        val probeDispatcher by lazy { Dispatcher().apply { maxRequestsPerHost = PROBE_CONCURRENCY } }
        // The engine answers only after download, with up to 15 s to connect and 60 s to read.
        val providerUpdate by lazy { client.newBuilder().readTimeout(90, TimeUnit.SECONDS).build() }
        val groupOrder by lazy { client.newBuilder().callTimeout(1, TimeUnit.SECONDS).build() }
    }

    // -------------------------------------------------------------------------
    // Proxies
    // -------------------------------------------------------------------------

    /** `/proxies`, plus the profile's group order from [proxyGroupOrder]. */
    suspend fun proxies(): ProxiesResult {
        val body = get("/proxies", operation = "proxies")
        val result = decode("proxies") { ProxiesResult.parse(json.parseToJsonElement(body).jsonObject) }
        return result.copy(groupOrder = proxyGroupOrder())
    }

    /**
     * Group names in `proxy-groups:` order. `/proxies` is a map and has lost
     * that order; `/api/proxy-groups` lists the engine's parsed copy of the
     * profile instead. Re-read on every call rather than cached: a config
     * reload changes it without telling this client, and it is one loopback
     * round trip.
     *
     * Best effort: the order is cosmetic, so a failure here sorts the groups
     * by name instead of failing a group list that is otherwise complete.
     */
    private suspend fun proxyGroupOrder(): List<String> =
        try {
            val body = get("/api/proxy-groups", operation = "proxyGroups", client = clients.groupOrder)
            decode("proxyGroups") {
                json.decodeFromString(ListSerializer(ConfiguredGroup.serializer()), body)
                    .map { it.name }
                    .filter { it.isNotEmpty() }
            }
        } catch (e: IOException) {
            // This also covers older engines that do not expose the cosmetic
            // ordering endpoint: the proxy map is still useful and can be
            // sorted by name. Logged because the only symptom, groups sorted
            // by name, looks deliberate on screen.
            Timber.w(e, "loading proxy group order failed; sorting groups by name")
            emptyList()
        }

    /** One proxy or group by name, for its detail page. */
    suspend fun proxy(name: String): ProxyInfo {
        val request = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegment("proxies").addPathSegment(name).build())
            .build()
        val body = execute(request, "proxy")
        return decode("proxy") { ProxyInfo.parse(json.parseToJsonElement(body).jsonObject) }
    }

    suspend fun selectProxy(group: String, name: String) {
        val payload = json.encodeToString(
            JsonObject.serializer(),
            JsonObject(mapOf("name" to kotlinx.serialization.json.JsonPrimitive(name))),
        )
        val request = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegment("proxies").addPathSegment(group).build())
            .put(payload.toRequestBody(JSON_MEDIA))
            .build()
        execute(request, "selectProxy", okCodes = setOf(200, 204))
    }

    /**
     * Returns an url-test or fallback group to automatic selection, dropping a
     * member pinned through [selectProxy]. Selectors have nothing to unpin and
     * answer 400.
     */
    suspend fun unfixProxy(group: String) {
        val request = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegment("proxies").addPathSegment(group).build())
            .delete()
            .build()
        execute(request, "unfixProxy", okCodes = setOf(200, 204))
    }

    suspend fun testProxyDelay(
        name: String,
        url: String = DELAY_TEST_URL,
        timeoutMs: Int = GroupDelayTester.PROBE_TIMEOUT_MS,
    ): Int {
        val requestUrl = baseUrl.newBuilder()
            .addPathSegment("proxies").addPathSegment(name).addPathSegment("delay")
            .addQueryParameter("url", url)
            .addQueryParameter("timeout", timeoutMs.toString())
            .build()
        // The engine answers only once the probe ends, so the read has to
        // outlast the probe's own timeout.
        val scoped = client.newBuilder()
            .dispatcher(clients.probeDispatcher)
            .readTimeout(timeoutMs + 5_000L, TimeUnit.MILLISECONDS)
            .build()
        val request = Request.Builder().url(requestUrl).build()
        // A 503 is any failure but a timeout (UrlTestError::Transport): a DNS
        // or dial blip, but also REJECT, a wrong password or a TLS error,
        // which a retry only repeats, and every failed attempt records a 0 in
        // the node's delay history. So one retry, not a ramp.
        val body = try {
            execute(request, "testProxyDelay", client = scoped)
        } catch (e: MeowApiException.Http) {
            if (e.code != 503) throw e
            delay(DELAY_PROBE_RETRY_MS)
            execute(request, "testProxyDelay", client = scoped)
        }
        return decode("testProxyDelay") {
            json.parseToJsonElement(body).jsonObject["delay"]?.jsonPrimitive?.intOrNull ?: 0
        }
    }

    /**
     * Probes every member of a group. The default timeout is far longer than the
     * client's read timeout, so this call gets its own timeout budget.
     */
    suspend fun testGroupDelay(
        group: String,
        url: String = DELAY_TEST_URL,
        timeoutMs: Int = 60_000,
    ): Map<String, Int> {
        val requestUrl = baseUrl.newBuilder()
            .addPathSegment("group").addPathSegment(group).addPathSegment("delay")
            .addQueryParameter("url", url)
            .addQueryParameter("timeout", timeoutMs.toString())
            .build()
        val scoped = client.newBuilder()
            .callTimeout(timeoutMs + 5_000L, TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMs + 5_000L, TimeUnit.MILLISECONDS)
            .build()
        val body = execute(Request.Builder().url(requestUrl).build(), "testGroupDelay", client = scoped)
        // Success is a flat name -> delay map; failures come back as
        // {"message": "..."}, so non-numeric values are dropped rather than
        // blowing up the whole result.
        return decode("testGroupDelay") {
            json.parseToJsonElement(body).jsonObject.mapNotNull { (key, value) ->
                value.jsonPrimitive.intOrNull?.let { key to it }
            }.toMap()
        }
    }

    // -------------------------------------------------------------------------
    // Proxy providers
    // -------------------------------------------------------------------------

    /** Configured proxy providers and their current node health. */
    suspend fun proxyProviders(): List<ProxyProvider> {
        val body = get("/providers/proxies", operation = "proxyProviders")
        return decode("proxyProviders") {
            ProxyProvidersResult.parse(json.parseToJsonElement(body).jsonObject).providers
        }
    }

    /** Runs the provider's configured health check for every node. */
    suspend fun healthCheckProxyProvider(name: String) {
        val request = Request.Builder()
            .url(
                baseUrl.newBuilder()
                    .addPathSegment("providers").addPathSegment("proxies").addPathSegment(name)
                    .addPathSegment("healthcheck").build(),
            )
            .get()
            .build()
        // A provider without a health-check answers 204 without probing.
        execute(request, "healthCheckProxyProvider", okCodes = setOf(200, 204), client = clients.providerUpdate)
    }

    /** Probes one provider node, recording the result in the engine. */
    suspend fun testProxyProviderDelay(
        provider: String,
        name: String,
        url: String = DELAY_TEST_URL,
        timeoutMs: Int = GroupDelayTester.PROBE_TIMEOUT_MS,
        expectedStatus: String? = null,
    ): Int {
        val requestUrl = baseUrl.newBuilder()
            .addPathSegment("providers").addPathSegment("proxies").addPathSegment(provider)
            .addPathSegment(name).addPathSegment("healthcheck")
            .addQueryParameter("url", url)
            .addQueryParameter("timeout", timeoutMs.toString())
            .apply { if (!expectedStatus.isNullOrBlank()) addQueryParameter("expected", expectedStatus) }
            .build()
        val scoped = client.newBuilder()
            .callTimeout(timeoutMs + 5_000L, TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMs + 5_000L, TimeUnit.MILLISECONDS)
            .build()
        val body = execute(Request.Builder().url(requestUrl).get().build(), "testProxyProviderDelay", client = scoped)
        return decode("testProxyProviderDelay") {
            json.parseToJsonElement(body).jsonObject["delay"]?.jsonPrimitive?.intOrNull ?: 0
        }
    }

    // -------------------------------------------------------------------------
    // Rules / connections / configs
    // -------------------------------------------------------------------------

    suspend fun rules(): List<Rule> {
        val body = get("/rules", operation = "rules")
        return decode("rules") { json.decodeFromString(RulesResponse.serializer(), body).rules }
    }

    /**
     * The profile's `rule-providers:`, sorted by name, case-insensitively.
     * The engine keeps them in a map and sends that map as is, so the order
     * the config declares them in is gone by the time it arrives; sorting
     * keeps the list from reshuffling between refreshes. A value without a
     * name of its own takes its map key.
     */
    suspend fun ruleProviders(): List<RuleProviderInfo> {
        val body = get("/providers/rules", operation = "ruleProviders")
        return decode("ruleProviders") {
            json.decodeFromString(RuleProvidersResponse.serializer(), body).providers
                .map { (key, provider) -> if (provider.name.isBlank()) provider.copy(name = key) else provider }
                .sortedWith(
                    compareBy<RuleProviderInfo, String>(String.CASE_INSENSITIVE_ORDER) { it.name }
                        // Names differing only in case must not swap places between refreshes.
                        .thenBy { it.name },
                )
        }
    }

    /**
     * Re-downloads an HTTP rule provider; the engine re-reads a File one and
     * has nothing to do for an inline one. It answers only once that is done:
     * 204, 404 for a name it does not know, 503 when the download failed. Both
     * failures surface as [MeowApiException.Http].
     */
    suspend fun updateRuleProvider(name: String) {
        val request = Request.Builder()
            .url(
                baseUrl.newBuilder()
                    .addPathSegment("providers").addPathSegment("rules").addPathSegment(name)
                    .build(),
            )
            .put(ByteArray(0).toRequestBody())
            .build()
        execute(request, "updateRuleProvider", okCodes = setOf(200, 204), client = clients.providerUpdate)
    }

    suspend fun connections(): ConnectionsSnapshot {
        val body = get("/connections", operation = "connections")
        return decode("connections") {
            json.decodeFromString(ConnectionsSnapshot.serializer(), body)
        }
    }

    /**
     * How the engine handled one connection, step by step. Null when the
     * engine no longer knows it (closed without notes, or closed long enough
     * ago to have left its history) or predates the endpoint.
     */
    suspend fun connectionNotes(id: String): ConnectionNotes? {
        val request = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegment("connections").addPathSegment(id).build())
            .build()
        val body = try {
            execute(request, "connectionNotes")
        } catch (e: MeowApiException.Http) {
            // 405: an engine with only DELETE on the route.
            if (e.code == 404 || e.code == 405) return null
            throw e
        }
        return decode("connectionNotes") { json.decodeFromString(ConnectionNotes.serializer(), body) }
    }

    suspend fun closeConnection(id: String) {
        val request = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegment("connections").addPathSegment(id).build())
            .delete()
            .build()
        execute(request, "closeConnection", okCodes = setOf(200, 204))
    }

    suspend fun closeAllConnections() {
        val request = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegment("connections").build())
            .delete()
            .build()
        execute(request, "closeAllConnections", okCodes = setOf(200, 204))
    }

    suspend fun configs(): RuntimeConfig {
        val body = get("/configs", operation = "configs")
        return decode("configs") { json.decodeFromString(RuntimeConfig.serializer(), body) }
    }

    suspend fun patchConfigs(patch: JsonObject) {
        val request = Request.Builder()
            .url(baseUrl.newBuilder().addPathSegment("configs").build())
            .patch(json.encodeToString(JsonObject.serializer(), patch).toRequestBody(JSON_MEDIA))
            .build()
        execute(request, "patchConfigs", okCodes = setOf(200, 204))
    }

    /** Switches routing for new flows; open connections keep their route. */
    suspend fun setMode(mode: RouteMode) {
        patchConfigs(JsonObject(mapOf("mode" to kotlinx.serialization.json.JsonPrimitive(mode.wire))))
    }

    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------

    /**
     * What each proxy carried since the engine started, by name; a group's
     * traffic counts at the member that carried it. Null for an engine that
     * predates `GET /statistics`.
     */
    suspend fun proxyTraffic(): Map<String, ByteTotals>? {
        val body = try {
            get("/statistics", operation = "statistics")
        } catch (e: MeowApiException.Http) {
            if (e.code == 404) return null
            throw e
        }
        return decode("statistics") { json.decodeFromString(StatisticsResponse.serializer(), body).proxies }
    }

    // -------------------------------------------------------------------------
    // DNS
    // -------------------------------------------------------------------------

    /**
     * The engine's DNS cache. [search] is matched by the engine, against the
     * name, the answer IPs and the upstream, case-insensitively; [limit] caps
     * the entries returned (the engine clamps it to 1024).
     */
    suspend fun dnsResults(search: String? = null, limit: Int = DNS_RESULTS_LIMIT): List<DnsResult> {
        val url = baseUrl.newBuilder()
            .addPathSegment("dns").addPathSegment("results")
            .addQueryParameter("limit", limit.toString())
            .apply { if (!search.isNullOrBlank()) addQueryParameter("search", search.trim()) }
            .build()
        val body = execute(Request.Builder().url(url).build(), "dnsResults")
        return decode("dnsResults") {
            json.decodeFromString(ListSerializer(DnsResult.serializer()), body)
        }
    }

    // -------------------------------------------------------------------------
    // Streams
    // -------------------------------------------------------------------------

    /**
     * Live engine logs.
     *
     * This replaces the old `getLogs` JNI call, which could never have worked
     * from the UI process: the Rust ring buffer it drains is a per-process
     * `static`, and the engine lives in `:vpn`. The WebSocket crosses the
     * process boundary over loopback, so it sees the real log stream.
     */
    fun logs(level: String = "info"): Flow<LogEntry> = logStream(level) { cause, backoff ->
        if (cause !is IOException || cause is MeowApiException.Http) return@logStream false
        delay(backoff)
        true
    }.mapNotNull { it.entry }

    /** An empty event marks an authenticated upgrade, even when no log lines are emitted. */
    fun logStream(
        level: String = "info",
        retry: suspend (Throwable, Long) -> Boolean,
    ): Flow<LogStreamEvent> {
        val url = baseUrl.newBuilder()
            .scheme(if (baseUrl.isHttps) "https" else "http")
            .addPathSegment("logs")
            .addQueryParameter("level", level)
            .build()
        val attemptOffset = java.util.concurrent.atomic.AtomicInteger(0)
        return callbackFlow {
            val request = Request.Builder().url(url)
                .authenticate()
                .build()
            val socket = client.newWebSocket(
                request,
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        trySend(LogStreamEvent())
                    }

                    override fun onMessage(webSocket: WebSocket, text: String) {
                        attemptOffset.set(0)
                        // A single malformed frame must not tear down the stream.
                        val parsed = try {
                            json.decodeFromString(LogEntry.serializer(), text)
                        } catch (e: Exception) {
                            return
                        }
                        trySend(LogStreamEvent(parsed))
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        close(if (response == null) t else MeowApiException.Http("logs", response.code))
                    }

                    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                        // OkHttp does not answer a peer close frame for us; without
                        // this the socket lingers and onClosed never arrives.
                        webSocket.close(code, null)
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        // A clean close still means "reconnect": the engine
                        // drops the socket on restart, and the stream is
                        // supposed to outlive that. Completing normally here
                        // would end the flow for good, since retryWhen below
                        // only sees exceptions.
                        close(StreamClosed(code, reason))
                    }
                },
            )
            awaitClose { socket.cancel() }
        }.retryWhen { cause, _ ->
            if (cause is kotlinx.coroutines.CancellationException) return@retryWhen false
            val attempt = attemptOffset.getAndIncrement().coerceAtMost(6)
            // 500ms doubling to a 30s ceiling — same ramp as the Dart client.
            retry(cause, (500L shl attempt).coerceAtMost(30_000L))
        }
    }

    // -------------------------------------------------------------------------
    // Plumbing
    // -------------------------------------------------------------------------

    private suspend fun get(path: String, operation: String, client: OkHttpClient = this.client): String {
        val url = baseUrl.newBuilder()
            .addPathSegments(path.trimStart('/'))
            .build()
        return execute(Request.Builder().url(url).build(), operation, client = client)
    }

    private suspend fun execute(
        request: Request,
        operation: String,
        okCodes: Set<Int> = setOf(200),
        client: OkHttpClient = this.client,
    ): String {
        val authenticated = request.newBuilder()
            .header("Connection", "close")
            .authenticate()
            .build()
        return try {
            client.newCall(authenticated).awaitBody {
                if (it.code !in okCodes) throw MeowApiException.Http(operation, it.code)
                it.body?.string().orEmpty()
            }
        } catch (e: MeowApiException) {
            throw e
        } catch (e: IOException) {
            // Reading the response body can fail after the headers arrive.
            throw MeowApiException.Unreachable(e)
        }
    }

    private fun Request.Builder.authenticate(): Request.Builder =
        if (authorization == null) this else header("Authorization", authorization)

    private inline fun <T> decode(operation: String, block: () -> T): T =
        try {
            block()
        } catch (e: Exception) {
            throw MeowApiException.Decode(operation, e)
        }
}

/**
 * Lenient by design: the engine is the source of truth and adds fields between
 * releases, so unknown keys must never fail a response the UI could have used.
 */
val MeowJson: Json = Json {
    ignoreUnknownKeys = true
    isLenient = true
    explicitNulls = false
    coerceInputValues = true
}

data class LogStreamEvent(val entry: LogEntry? = null)

/** Signals that the peer hung up, so the stream re-dials rather than ending. */
private class StreamClosed(code: Int, reason: String) :
    IOException("websocket closed ($code${if (reason.isEmpty()) "" else ": $reason"})")

private suspend fun Call.awaitBody(read: (Response) -> String): String = suspendCancellableCoroutine { cont ->
    cont.invokeOnCancellation { cancel() }
    enqueue(object : Callback {
        override fun onResponse(call: Call, response: Response) {
            response.use {
                if (cont.isActive) {
                    try {
                        cont.resume(read(response))
                    } catch (e: IOException) {
                        cont.resumeWithException(e)
                    }
                }
            }
        }

        override fun onFailure(call: Call, e: IOException) {
            if (!cont.isCancelled) cont.resumeWithException(e)
        }
    })
}
