package io.github.madeye.meow.ui.screens.proxies

import androidx.lifecycle.viewModelScope
import io.github.madeye.meow.api.ControllerAccess
import io.github.madeye.meow.api.ControllerStatus
import io.github.madeye.meow.api.MeowApi
import io.github.madeye.meow.bg.BaseService.State
import io.github.madeye.meow.database.ClashProfile
import io.github.madeye.meow.runningVpn
import io.github.madeye.meow.vpn.VpnLifecycle
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ProxyGroupsReadinessTest {
    private val lifecycle = MutableStateFlow(VpnLifecycle(state = State.Connecting, profileId = 9))
    private val selected = MutableStateFlow<ClashProfile?>(ClashProfile(id = 99, name = "Selected"))
    private val writes = AtomicInteger()
    private val configs = AtomicInteger()
    private val selectedEvents = CopyOnWriteArrayList<String>()
    private val saved = CopyOnWriteArrayList<Pair<Long, String>>()
    private lateinit var viewModel: ProxyGroupsViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(Dispatchers.Unconfined)
    }

    @After
    fun tearDown() {
        runBlocking {
            if (::viewModel.isInitialized) viewModel.viewModelScope.coroutineContext.job.cancelAndJoin()
        }
        Dispatchers.resetMain()
    }

    @Test
    fun `startup recovery and a rejected selection show feedback without replaying or saving the PUT`() = runBlocking {
        show(selectionCode = { 400 }, failFirstConfig = true)
        assertTrue(viewModel.uiState.value.groups.isEmpty())
        assertEquals(0, configs.get())
        lifecycle.value = running("first")
        awaitGroups()
        assertTrue(configs.get() >= 2)

        val notice = async(start = CoroutineStart.UNDISPATCHED) {
            withTimeout(3_000) { viewModel.selectionFailed.first() }
        }
        viewModel.onSelectNode("Proxy", "b")
        notice.await()
        awaitGroups()

        assertEquals(1, writes.get())
        assertTrue(saved.isEmpty())
        assertTrue(selectedEvents.isEmpty())
        assertEquals("a", viewModel.uiState.value.groups.single().now)
    }

    @Test
    fun `a successful pick is saved against the running profile even when selection changed`() = runBlocking {
        show(selectionCode = { 204 })
        lifecycle.value = running("first")
        awaitGroups()
        viewModel.onSelectNode("Proxy", "b")
        withTimeout(3_000) {
            while (saved.isEmpty()) kotlinx.coroutines.delay(5)
        }
        assertEquals(listOf(9L to "b"), saved.toList())
    }

    @Test
    fun `a listener that recovers with no groups becomes ready with no available actions`() = runBlocking {
        show(selectionCode = { 204 }, failFirstConfig = true, emptyGroups = true)
        assertEquals(0, configs.get())
        lifecycle.value = running("first")
        val empty = withTimeout(3_000) { viewModel.uiState.first { it.status == ControllerStatus.Ready } }
        assertEquals(2, configs.get())
        assertTrue(empty.groups.isEmpty())
        viewModel.onSelectNode("Proxy", "b")
        viewModel.onTestGroup("Proxy")
        assertEquals(0, writes.get())
        assertTrue(saved.isEmpty())
    }

    @Test
    fun `a successful PUT response from before a same profile restart has no completion side effects`() = runBlocking {
        val requested = CountDownLatch(1)
        val release = CountDownLatch(1)
        val answered = CountDownLatch(1)
        show(selectionCode = {
            requested.countDown()
            check(release.await(4, TimeUnit.SECONDS))
            answered.countDown()
            204
        })
        lifecycle.value = running("first")
        awaitGroups()
        viewModel.onSelectNode("Proxy", "b")
        try {
            withContext(Dispatchers.IO) { assertTrue(requested.await(3, TimeUnit.SECONDS)) }
            lifecycle.value = VpnLifecycle(state = State.Stopping)
            lifecycle.value = running("second")
            awaitGroups()
        } finally {
            release.countDown()
        }
        withContext(Dispatchers.IO) { assertTrue(answered.await(3, TimeUnit.SECONDS)) }
        assertEquals(1, writes.get())
        assertTrue(saved.isEmpty())
        assertTrue(selectedEvents.isEmpty())
    }

    private fun show(selectionCode: () -> Int, failFirstConfig: Boolean = false, emptyGroups: Boolean = false) {
        val api = MeowApi.SessionFactory(
            baseClient = OkHttpClient.Builder().addInterceptor { chain ->
                val request = chain.request()
                val (code, body) = when {
                    request.method == "PUT" -> {
                        writes.incrementAndGet()
                        selectionCode() to ""
                    }
                    request.url.encodedPath == "/configs" -> {
                        if (configs.incrementAndGet() == 1 && failFirstConfig) throw IOException("not listening")
                        200 to """{"mode":"rule"}"""
                    }
                    request.url.encodedPath == "/providers/proxies" -> 200 to """{"providers":{}}"""
                    request.url.encodedPath == "/api/proxy-groups" -> 200 to "[]"
                    emptyGroups -> 200 to """{"proxies":{}}"""
                    else -> 200 to """{"proxies":{"Proxy":{"type":"Selector","all":["a","b"],"now":"a"}}}"""
                }
                Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(code)
                    .message("test").body(body.toResponseBody()).build()
            }.build(),
        )
        viewModel = ProxyGroupsViewModel(
            ControllerAccess(lifecycle), selected, api::forSession, {}, { selectedEvents += it },
            { id, node, isCurrent -> if (isCurrent()) saved += id to node },
        )
        viewModel.viewModelScope.launch { viewModel.uiState.collect {} }
    }

    private suspend fun awaitGroups() = withTimeout(3_000) {
        viewModel.uiState.first { it.status == ControllerStatus.Ready && it.groups.isNotEmpty() }
    }

    private fun running(id: String) = runningVpn(id, profileId = 9)
}
