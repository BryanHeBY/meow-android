package io.github.madeye.meow.ui.screens.proxies

/** Session-scoped last good data. A failed fetch is not a successful empty list. */
internal class GroupSnapshots<K, T> {
    data class Snapshot<K, T>(val session: K?, val rows: List<T> = emptyList(), val failed: Boolean = false)

    var snapshot = Snapshot<K, T>(null)
        private set
    private var revision = 0L

    fun switchTo(session: K?): Boolean {
        if (snapshot.session == session) return false
        revision++
        snapshot = Snapshot(session)
        return true
    }

    fun begin(): Long = ++revision

    fun finish(ticket: Long, rows: List<T>?): Boolean {
        if (ticket != revision || snapshot.session == null) return false
        snapshot = if (rows == null) snapshot.copy(failed = true) else snapshot.copy(rows = rows, failed = false)
        return true
    }
}
