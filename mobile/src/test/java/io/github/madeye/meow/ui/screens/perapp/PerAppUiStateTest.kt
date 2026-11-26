package io.github.madeye.meow.ui.screens.perapp

import io.github.madeye.meow.repo.InstalledApp
import org.junit.Assert.assertEquals
import org.junit.Test

class PerAppUiStateTest {
    private val store = InstalledApp("com.android.vending", "Google Play Store", isSystem = true, hasLauncher = true)
    private val services = InstalledApp("com.google.android.gms", "Google Play services", isSystem = true)
    private val browser = InstalledApp("com.example.browser", "Browser", isSystem = false)
    private val state = PerAppUiState(apps = listOf(store, services, browser))

    @Test
    fun launcherSystemAppsRemainVisibleByDefault() {
        assertEquals(listOf(store, browser), state.visibleApps)
        assertEquals(listOf(store, services, browser), state.copy(showSystemApps = true).visibleApps)
    }

    @Test
    fun searchCanFindHiddenSystemPackagesByLabelAndPackage() {
        assertEquals(listOf(services), state.copy(query = "  play services ").visibleApps)
        assertEquals(listOf(services), state.copy(query = "com.google.android.gms").visibleApps)
        assertEquals(listOf(store, browser), state.copy(query = "  ").visibleApps)
    }

    @Test
    fun selectedSystemPackagesStayVisibleWithoutBroadeningOtherRows() {
        assertEquals(listOf(store, services, browser), state.copy(selected = setOf(services.packageName)).visibleApps)
        assertEquals(listOf(browser), state.copy(selected = setOf(services.packageName), query = "browser").visibleApps)
    }

    @Test
    fun invertUsesTheVisibleSnapshotAndPreservesHiddenSelections() {
        val selected = setOf(browser.packageName, "com.example.hidden")
        val visible = state.copy(selected = selected).visibleApps
        assertEquals(
            setOf(store.packageName, "com.example.hidden"),
            updateVisibleSelection(selected, visible, AppSelectionAction.Invert),
        )
        val searched = state.copy(query = "play services").visibleApps
        assertEquals(
            selected + services.packageName,
            updateVisibleSelection(selected, searched, AppSelectionAction.Invert),
        )
        assertEquals(selected, updateVisibleSelection(selected, emptyList(), AppSelectionAction.Invert))
    }

    @Test
    fun selectAllStillAvoidsNewSystemPackagesAndDeselectClearsVisibleOnly() {
        val selected = setOf(services.packageName)
        val visible = listOf(store, browser)
        val all = updateVisibleSelection(selected, visible, AppSelectionAction.Select)
        assertEquals(selected + browser.packageName, all)
        assertEquals(selected, updateVisibleSelection(all, visible, AppSelectionAction.Deselect))
    }

}
