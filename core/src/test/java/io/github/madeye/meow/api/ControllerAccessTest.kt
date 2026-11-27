package io.github.madeye.meow.api

import io.github.madeye.meow.bg.BaseService.State
import io.github.madeye.meow.vpn.VpnLifecycle
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Protocol
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
        val controller = ControllerAccess(lifecycle) { currentTime }
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

        lifecycle.value = started()
        advanceTimeBy(350)
        assertEquals(3, calls)
        assertEquals(ControllerStatus.Ready, snapshots.last().status)
        assertEquals(emptyList<Rule>(), snapshots.last().value)
        advanceTimeBy(60_000)
        assertEquals("A truly empty configuration needs no follow-up", 3, calls)
    }

    @Test
    fun `stable bad auth stops soon after startup and fails immediately on later reads`() = runTest {
        val controller = ControllerAccess(MutableStateFlow(started())) { currentTime }
        val rejected = MeowApiException.Http("rules", 401)
        var calls = 0
        val read = async {
            runCatching { controller.read(controller.session!!) { calls++; throw rejected } }
        }
        advanceTimeBy(2_000)
        assertEquals(rejected, read.await().exceptionOrNull())
        assertTrue(calls in 2..6)
        val oldCount = calls
        val later = runCatching { controller.read(controller.session!!) { calls++; throw rejected } }
        assertEquals(rejected, later.exceptionOrNull())
        assertEquals(oldCount + 1, calls)
    }

    @Test
    fun `a changed bearer recovers an authenticated GET even after the startup window`() = runBlocking {
        val secret = AtomicReference("old")
        val headers = CopyOnWriteArrayList<String>()
        val api = MeowApi(
            baseClient = OkHttpClient.Builder().addInterceptor { chain ->
                val request = chain.request()
                val bearer = request.header("Authorization").orEmpty()
                headers += bearer
                assertEquals("GET", request.method)
                assertEquals("127.0.0.1", request.url.host)
                if (bearer == "Bearer old") secret.set("current")
                Response.Builder().request(request).protocol(Protocol.HTTP_1_1)
                    .code(if (bearer == "Bearer current") 200 else 401)
                    .message("test")
                    .body("""{"rules":[]}""".toResponseBody()).build()
            }.build(),
            secret = secret::get,
        )
        val controller = ControllerAccess(MutableStateFlow(started())) { 5_000L }

        val result = withTimeout(3_000) {
            controller.observe { api.rules() }.first { it.status == ControllerStatus.Ready }
        }
        assertEquals(emptyList<Rule>(), result.value)
        assertEquals(listOf("Bearer old", "Bearer current"), headers.toList())
    }

    @Test
    fun `a wrong envelope is a protocol error and does not become an empty snapshot`() = runBlocking {
        val api = MeowApi(
            baseClient = OkHttpClient.Builder().addInterceptor { chain ->
                Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1)
                    .code(200).message("test").body("{}".toResponseBody()).build()
            }.build(),
        )
        val controller = ControllerAccess(MutableStateFlow(started())) { 5_000L }
        val session = controller.session!!
        for (read in listOf<suspend () -> Any>(api::proxies, api::rules, api::connections, api::proxyProviders)) {
            assertTrue(runCatching { controller.read(session, read) }.exceptionOrNull() is MeowApiException.Decode)
        }
    }

    @Test
    fun `deferred providers get follow-up reads and a permanently deferred one is bounded`() = runTest {
        val controller = ControllerAccess(MutableStateFlow(started())) { currentTime }
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
        val controller = ControllerAccess(lifecycle) { currentTime }
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
        val controller = ControllerAccess(MutableStateFlow(started())) { currentTime }
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

    private fun started(runId: String = "first", binding: Long = 1) =
        VpnLifecycle(state = State.Connected, binding = binding, runId = runId, profileId = 9L)

    private fun offline() = MeowApiException.Unreachable(IOException("listener delayed"))

    private fun provider(updated: Boolean) = ProxyProvider(
        name = "test", vehicleType = "HTTP", nodes = emptyList(), testUrl = "",
        expectedStatus = "", updatedAt = "updated".takeIf { updated }, usage = null,
    )
}
