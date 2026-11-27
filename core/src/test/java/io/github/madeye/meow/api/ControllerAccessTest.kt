package io.github.madeye.meow.api

import io.github.madeye.meow.aidl.ControllerEndpoint
import io.github.madeye.meow.aidl.VpnServiceSnapshot
import io.github.madeye.meow.bg.BaseService.State
import io.github.madeye.meow.vpn.VpnLifecycle
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ControllerAccessTest {

    @Test
    fun `visible reads wait through startup and then display a valid empty list`() = runTest {
        val lifecycle = MutableStateFlow(VpnLifecycle(state = State.Connecting))
        val controller = ControllerAccess(lifecycle)
        val snapshots = mutableListOf<ControllerSnapshot<List<Rule>>>()
        var calls = 0
        backgroundScope.launch {
            controller.observe {
                if (++calls <= 2) throw offline()
                emptyList<Rule>()
            }.collect(snapshots::add)
        }
        runCurrent()
        assertEquals(0, calls)
        assertEquals(ControllerStatus.Loading, snapshots.last().status)

        lifecycle.value = VpnLifecycle(state = State.Connected, runId = "missing endpoint")
        runCurrent()
        assertEquals(0, calls)
        assertEquals(ControllerStatus.Loading, snapshots.last().status)

        lifecycle.value = started()
        advanceTimeBy(350)
        assertEquals(3, calls)
        assertEquals(ControllerStatus.Ready, snapshots.last().status)
        assertEquals(emptyList<Rule>(), snapshots.last().value)
        advanceTimeBy(60_000)
        assertEquals("A truly empty configuration needs no follow-up", 3, calls)
    }

    @Test
    fun `bad auth fails immediately even at startup`() = runTest {
        val controller = ControllerAccess(MutableStateFlow(started()))
        val rejected = MeowApiException.Http("rules", 401)
        var calls = 0
        val read = runCatching { controller.read(controller.session!!) { calls++; throw rejected } }
        assertEquals(rejected, read.exceptionOrNull())
        assertEquals(1, calls)
    }

    @Test
    fun `queued requests cannot use a same-profile replacement before Binder reports it`() = runBlocking {
        val first = started()
        val second = started(runId = "second", cap = 'b') // The OS may reuse the same port.
        val lifecycle = MutableStateFlow(first)
        val controller = ControllerAccess(lifecycle)
        val old = requireNotNull(first.session)
        val replacement = requireNotNull(second.session)
        val nativeRun = AtomicReference(old)
        val entered = CompletableDeferred<Unit>()
        val release = CountDownLatch(1)
        val writes = AtomicInteger()
        val rejected = AtomicInteger()
        val dispatcher = okhttp3.Dispatcher().apply { maxRequests = 1 }
        val sharedProfileSecret = "profile-authored-secret"
        val client = MeowApi.defaultClient().newBuilder().dispatcher(dispatcher)
            .addInterceptor { chain ->
                val request = chain.request()
                if (request.url.port == 9090) {
                    val status = if (request.header("Authorization") == "Bearer $sharedProfileSecret") 200 else 401
                    return@addInterceptor response(request, status, """{"rules":[]}""")
                }
                if (!entered.isCompleted) {
                    entered.complete(Unit)
                    if (!release.await(3, TimeUnit.SECONDS)) throw IOException("test request held too long")
                }
                val native = nativeRun.get()
                val authorized = request.url.port == native.controller.port &&
                    request.header("Authorization") == native.controller.authorizationHeader()
                if (!authorized) {
                    rejected.incrementAndGet()
                    response(request, 401)
                } else if (request.method == "PUT") {
                    writes.incrementAndGet()
                    response(request, 204)
                } else {
                    response(request, 200, """{"rules":[]}""")
                }
            }.build()
        val factory = MeowApi.SessionFactory(client)
        val dashboard = MeowApi(baseClient = client, secret = sharedProfileSecret)

        try {
            withTimeout(5_000) {
                assertEquals(emptyList<Rule>(), dashboard.rules())
                val failedRead = async {
                    controller.observe { factory.forSession(it).rules() }.first { it.status == ControllerStatus.Failed }
                }
                entered.await()
                val write = async(start = CoroutineStart.UNDISPATCHED) {
                    runCatching { controller.write(old) { factory.forSession(old).selectProxy("G", "A") } }
                }
                assertEquals(1, dispatcher.queuedCallsCount())

                nativeRun.set(replacement)
                release.countDown()
                assertEquals(401, (write.await().exceptionOrNull() as MeowApiException.Http).code)
                val failed = failedRead.await()
                assertEquals(old, controller.session)
                assertEquals(null, failed.value)
                assertEquals(2, rejected.get())
                assertEquals(0, writes.get())
                assertEquals(emptyList<Rule>(), dashboard.rules())

                lifecycle.value = second
                val empty = controller.observe { factory.forSession(it).rules() }.first { it.status == ControllerStatus.Ready }
                assertEquals(replacement, empty.session)
                assertEquals(emptyList<Rule>(), empty.value)
                controller.write(replacement) { factory.forSession(replacement).selectProxy("G", "B") }
                assertEquals(1, writes.get())
            }
        } finally {
            release.countDown()
            dispatcher.executorService.shutdownNow()
        }
    }

    @Test
    fun `Binder replacement cancels a held HTTP call and ignores its late success`() = runBlocking {
        val lifecycle = MutableStateFlow(started())
        val controller = ControllerAccess(lifecycle)
        val old = requireNotNull(controller.session)
        val release = CountDownLatch(1)
        val entered = CompletableDeferred<okhttp3.Call>()
        val finished = CompletableDeferred<Unit>()
        val client = MeowApi.defaultClient().newBuilder().addInterceptor { chain ->
            val request = chain.request()
            if (request.url.port == old.controller.port) {
                entered.complete(chain.call())
                try {
                    if (!release.await(3, TimeUnit.SECONDS)) throw IOException("test request held too long")
                    response(request, 200, """{"rules":[{"type":"Match","proxy":"old"}]}""")
                } finally {
                    finished.complete(Unit)
                }
            } else {
                response(request, 200, """{"rules":[]}""")
            }
        }.build()
        val factory = MeowApi.SessionFactory(client)

        try {
            withTimeout(5_000) {
                val displayed = async {
                    controller.observe { factory.forSession(it).rules() }.first { it.status == ControllerStatus.Ready }
                }
                val call = entered.await()
                lifecycle.value = started(runId = "second", port = 22002, cap = 'b')
                val current = displayed.await()
                assertTrue(call.isCanceled())
                assertEquals("second", current.session?.runId)
                assertEquals(emptyList<Rule>(), current.value)
                release.countDown()
                finished.await()
            }
        } finally {
            release.countDown()
            client.dispatcher.executorService.shutdownNow()
        }
    }

    @Test
    fun `capability stays out of state diagnostics failures and request URL`() = runBlocking {
        val cap = "a".repeat(64)
        val running = started()
        val session = requireNotNull(running.session)
        val client = MeowApi.defaultClient().newBuilder().addInterceptor { chain ->
            val request = chain.request()
            assertEquals("Meow-Run $cap", request.header("Authorization"))
            assertEquals("http://127.0.0.1:22001/rules", request.url.toString())
            response(request, 401)
        }.build()
        try {
            val error = runCatching { MeowApi.SessionFactory(client).forSession(session).rules() }.exceptionOrNull()
            assertTrue(error is MeowApiException.Http)
            val binder = VpnServiceSnapshot(state = State.Connected.ordinal, controller = running.controller)
            for (diagnostic in listOf(running, session, session.controller, binder, error)) {
                assertFalse(diagnostic.toString().contains(cap))
            }
        } finally {
            client.dispatcher.executorService.shutdownNow()
        }
    }

    @Test
    fun `logs authenticate its upgrade with the session capability`() = runBlocking {
        val session = requireNotNull(started().session)
        val checked = CompletableDeferred<Boolean>()
        val client = MeowApi.defaultClient().newBuilder().addInterceptor { chain ->
            val request = chain.request()
            checked.complete(request.url.port == session.controller.port &&
                request.url.encodedPath == "/logs" && request.url.queryParameter("token") == null &&
                request.header("Upgrade") == "websocket" &&
                request.header("Authorization") == session.controller.authorizationHeader())
            response(request, 401)
        }.build()
        try {
            withTimeout(2_000) {
                val failure = runCatching {
                    MeowApi.SessionFactory(client).forSession(session).logStream { _, _ -> false }.first()
                }.exceptionOrNull()
                assertEquals(401, (failure as MeowApiException.Http).code)
                assertTrue(checked.await())
            }
        } finally {
            client.dispatcher.executorService.shutdownNow()
        }
    }

    @Test
    fun `a wrong envelope is a protocol error and does not become an empty snapshot`() = runBlocking {
        val api = MeowApi(
            baseClient = OkHttpClient.Builder().addInterceptor { chain ->
                Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                    .code(200).message("test").body("{}".toResponseBody()).build()
            }.build(),
        )
        val controller = ControllerAccess(MutableStateFlow(started()))
        val session = controller.session!!
        for (read in listOf<suspend () -> Any>(api::proxies, api::rules, api::connections, api::proxyProviders)) {
            assertTrue(runCatching { controller.read(session, read) }.exceptionOrNull() is MeowApiException.Decode)
        }
    }

    @Test
    fun `deferred providers get follow-up reads and a permanently deferred one is bounded`() = runTest {
        val controller = ControllerAccess(MutableStateFlow(started()))
        var calls = 0
        var available = false
        val refresh = MutableStateFlow(0L)
        val snapshots = mutableListOf<ControllerSnapshot<ProxyProvider>>()
        backgroundScope.launch {
            controller.observe(refresh, ProxyProvider::awaitingFirstUpdate) {
                calls++
                provider(available)
            }.collect(snapshots::add)
        }
        runCurrent()
        assertTrue(snapshots.last().waitingForProviders)
        assertEquals(ControllerStatus.Ready, snapshots.last().status)
        available = true
        advanceTimeBy(1_100)
        assertFalse(snapshots.last().waitingForProviders)
        assertEquals("updated", snapshots.last().value?.updatedAt)
        assertEquals(2, calls)

        available = false
        refresh.value++
        advanceTimeBy(90_000)
        assertEquals(8, calls)
        assertEquals(ControllerStatus.Ready, snapshots.last().status)
        assertTrue(snapshots.last().waitingForProviders)
    }

    @Test
    fun `same profile restart and binder reconnect both discard a late read`() = runTest {
        val lifecycle = MutableStateFlow(started())
        val controller = ControllerAccess(lifecycle)
        val old = controller.session!!
        val reply = CompletableDeferred<String>()
        val snapshots = mutableListOf<ControllerSnapshot<String>>()
        backgroundScope.launch {
            controller.observe { session ->
                if (session == old) withContext(NonCancellable) { reply.await() } else session.runId
            }.collect(snapshots::add)
        }
        runCurrent()
        lifecycle.value = VpnLifecycle(state = State.Stopping)
        runCurrent()
        lifecycle.value = started(runId = "second")
        reply.complete("old reply")
        runCurrent()
        assertEquals("second", snapshots.last().value)
        assertFalse(snapshots.any { it.value == "old reply" })
        val beforeBind = controller.session!!
        lifecycle.value = started(runId = "second", binding = 2)
        runCurrent()
        assertNotEquals(beforeBind, snapshots.last().session)
        assertEquals(beforeBind.runId, snapshots.last().session?.runId)
    }

    @Test
    fun `failed refresh retains last good data from the current session`() = runTest {
        val controller = ControllerAccess(MutableStateFlow(started()))
        val refresh = MutableStateFlow(0L)
        var mode = "first"
        val snapshots = mutableListOf<ControllerSnapshot<String>>()
        backgroundScope.launch {
            controller.observe(refresh) {
                if (mode == "broken") throw MeowApiException.Http("configs", 500)
                mode
            }.collect(snapshots::add)
        }
        runCurrent()
        assertEquals("first", snapshots.last().value)
        mode = "broken"
        refresh.value++
        runCurrent()
        assertEquals("first", snapshots.last().value)
        assertEquals(ControllerStatus.Stale, snapshots.last().status)
        mode = "restored"
        refresh.value++
        runCurrent()
        assertEquals("restored", snapshots.last().value)
        assertEquals(ControllerStatus.Ready, snapshots.last().status)
    }

    @Test
    fun `a controller outage during a group test does not turn into a node timeout`() = runBlocking {
        val api = MeowApi(
            baseClient = OkHttpClient.Builder().addInterceptor { throw IOException("controller disconnected") }.build(),
        )
        val outcome = runCatching { GroupDelayTester(api).test("group", "Selector", listOf("node")).toList() }
        assertTrue(outcome.exceptionOrNull() is MeowApiException.Unreachable)
    }

    private fun started(runId: String = "first", binding: Long = 1, port: Int = 22001, cap: Char = 'a') =
        VpnLifecycle(state = State.Connected, binding = binding, runId = runId, profileId = 9L,
            controller = ControllerEndpoint(port, cap.toString().repeat(64)))

    private fun response(request: Request, code: Int, body: String = "") =
        Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(code)
            .message("test").body(body.toResponseBody()).build()

    private fun offline() = MeowApiException.Unreachable(IOException("listener delayed"))

    private fun provider(updated: Boolean) = ProxyProvider(
        name = "test", vehicleType = "HTTP", nodes = emptyList(), testUrl = "",
        expectedStatus = "", updatedAt = "updated".takeIf { updated }, usage = null,
    )
}
