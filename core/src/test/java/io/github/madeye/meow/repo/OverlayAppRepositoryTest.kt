package io.github.madeye.meow.repo

import io.github.madeye.meow.preference.PerAppConfigStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class OverlayAppRepositoryTest {
    @get:Rule
    val folder = TemporaryFolder()

    @Test
    fun missingAndUnknownPolicyAuthorizeNoApps() {
        val store = PerAppConfigStore(folder.root.resolve("overlay"))
        val repository = OverlayAppRepository(store)
        assertEquals(OverlayAppConfig(OverlayAppMode.Allow, emptySet()), repository.read())
        store.save("future", setOf("com.example.ssh"))
        assertEquals(OverlayAppConfig(OverlayAppMode.Allow, emptySet()), repository.read())
    }

    @Test
    fun preservesAnEmptyAllowListAndKeepsLegacyClashSettingsSeparate() = runBlocking {
        val old = PerAppConfigStore(folder.root.resolve("per_app"))
        old.save("bypass", setOf("com.example.bank"))
        val repository = OverlayAppRepository(PerAppConfigStore(folder.root.resolve("per_app_overlay")))
        repository.save(OverlayAppConfig(OverlayAppMode.Exclude, setOf("com.example.browser")))
        assertEquals(OverlayAppConfig(OverlayAppMode.Exclude, setOf("com.example.browser")), repository.load())
        repository.save(OverlayAppConfig(OverlayAppMode.Allow, emptySet()))
        assertEquals(OverlayAppConfig(OverlayAppMode.Allow, emptySet()), repository.load())
        assertEquals(PerAppConfigStore.Stored("bypass", setOf("com.example.bank")), old.load())
    }
}
