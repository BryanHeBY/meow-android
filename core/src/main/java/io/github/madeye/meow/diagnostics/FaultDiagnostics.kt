package io.github.madeye.meow.diagnostics

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Build
import androidx.annotation.RequiresApi
import io.github.madeye.meow.Core
import java.io.File
import java.time.Instant
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber

enum class FaultProcess { UI, VPN }

enum class FaultKind {
    JVM_CRASH, NATIVE_CRASH, ANR, LOW_MEMORY, PROCESS_EXIT,
    VPN_BINDER_LOST, TUN_EXIT, NETWORK_CHANGE, PROXY_GROUP_REFRESH,
}

data class FaultEvent(
    val time: Long,
    val process: FaultProcess,
    val kind: FaultKind,
    val code: Int = 0,
    val pid: Int = 0,
)

/** Only fixed event labels and numbers. No exception messages, addresses or profile data. */
fun faultReport(events: List<FaultEvent>): String = buildString {
    appendLine("MeowZ fault diagnostics v1")
    for (event in events) {
        appendLine("${Instant.ofEpochMilli(event.time)}  ${event.process}  ${event.kind}  code=${event.code}  pid=${event.pid}")
    }
}

/** Small, bounded cross-process journal, separate from profile and engine log storage. */
object FaultDiagnostics {
    private val database by lazy { Journal(Core.app) }
    private val queue = Channel<FaultEvent>(capacity = 64, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val writer by lazy {
        scope.launch {
            for (event in queue) {
                try {
                    database.insert(listOf(event))
                } catch (e: RuntimeException) {
                    Timber.w(e, "fault journal write failed")
                }
            }
        }
    }

    fun record(process: FaultProcess, kind: FaultKind, code: Int = 0) {
        if (writer.isActive) {
            queue.trySend(FaultEvent(System.currentTimeMillis(), process, kind, code, android.os.Process.myPid()))
        }
    }

    suspend fun read(): List<FaultEvent> = withContext(Dispatchers.IO) {
        importExitHistory()
        database.read()
    }

    suspend fun clear() = withContext(Dispatchers.IO) { database.clear(System.currentTimeMillis()) }

    private fun importExitHistory() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
        val exits = try {
            exitHistory(Core.app)
        } catch (e: RuntimeException) {
            Timber.w(e, "Android process exit history not available")
            return
        }
        database.insert(exits)
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun exitHistory(context: Context): List<FaultEvent> {
        val manager = context.getSystemService(ActivityManager::class.java) ?: return emptyList()
        return manager.getHistoricalProcessExitReasons(context.packageName, 0, MAX_EVENTS).mapNotNull { exit ->
            faultFromExit(context.packageName, exit.processName, exit.timestamp, exit.reason, exit.pid)
        }
    }

    private class Journal(context: Context) : SQLiteOpenHelper(
        context, File(context.noBackupFilesDir, "fault-diagnostics.db").absolutePath, null, 1,
    ) {
        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL("CREATE TABLE events (id INTEGER PRIMARY KEY, time INTEGER NOT NULL, process TEXT NOT NULL, " +
                "kind TEXT NOT NULL, code INTEGER NOT NULL, pid INTEGER NOT NULL, UNIQUE(time, process, kind, code, pid))")
            db.execSQL("CREATE TABLE settings (id INTEGER PRIMARY KEY, cleared INTEGER NOT NULL)")
            db.execSQL("INSERT INTO settings VALUES (1, 0)")
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

        fun insert(events: List<FaultEvent>) {
            if (events.isEmpty()) return
            val db = writableDatabase
            db.beginTransaction()
            try {
                val cutoff = db.rawQuery("SELECT cleared FROM settings WHERE id = 1", null).use {
                    check(it.moveToFirst())
                    it.getLong(0)
                }
                for (event in events) {
                    if (event.time <= cutoff) continue
                    val values = ContentValues().apply {
                        put("time", event.time)
                        put("process", event.process.name)
                        put("kind", event.kind.name)
                        put("code", event.code)
                        put("pid", event.pid)
                    }
                    db.insertWithOnConflict("events", null, values, SQLiteDatabase.CONFLICT_IGNORE)
                }
                db.execSQL("DELETE FROM events WHERE id IN " +
                    "(SELECT id FROM events ORDER BY time DESC, id DESC LIMIT -1 OFFSET $MAX_EVENTS)")
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        }

        fun read(): List<FaultEvent> = readableDatabase.rawQuery(
            "SELECT time, process, kind, code, pid FROM events ORDER BY time DESC, id DESC LIMIT $MAX_EVENTS", null,
        ).use { cursor ->
            buildList {
                while (cursor.moveToNext()) {
                    val process = FaultProcess.entries.firstOrNull { it.name == cursor.getString(1) } ?: continue
                    val kind = FaultKind.entries.firstOrNull { it.name == cursor.getString(2) } ?: continue
                    add(FaultEvent(cursor.getLong(0), process, kind, cursor.getInt(3), cursor.getInt(4)))
                }
            }
        }

        fun clear(now: Long) {
            val db = writableDatabase
            db.beginTransaction()
            try {
                db.delete("events", null, null)
                // Android's own history cannot be deleted by the app.
                db.execSQL("UPDATE settings SET cleared = MAX(cleared, ?) WHERE id = 1", arrayOf<Any>(now))
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        }
    }

    private const val MAX_EVENTS = 128
}

/** Kept free of Android service calls so exit attribution can be tested on the host. */
internal fun faultFromExit(packageName: String, processName: String?, time: Long, reason: Int, pid: Int): FaultEvent? {
    if (time <= 0) return null
    val process = when (processName) {
        packageName -> FaultProcess.UI
        "$packageName:vpn" -> FaultProcess.VPN
        else -> return null
    }
    val kind = when (reason) {
        ApplicationExitInfo.REASON_CRASH -> FaultKind.JVM_CRASH
        ApplicationExitInfo.REASON_CRASH_NATIVE -> FaultKind.NATIVE_CRASH
        ApplicationExitInfo.REASON_ANR -> FaultKind.ANR
        ApplicationExitInfo.REASON_LOW_MEMORY -> FaultKind.LOW_MEMORY
        else -> FaultKind.PROCESS_EXIT
    }
    return FaultEvent(time, process, kind, reason, pid)
}
