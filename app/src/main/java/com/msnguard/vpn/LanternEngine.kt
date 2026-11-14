package com.msnguard.vpn

import android.content.Context
import android.util.Log
import com.msnguard.lantern.Lanternbridge
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Isolated adapter for the public Lantern/Radiance engine.
 *
 * Radiance is built with its novpn tag and binds only a loopback mixed
 * HTTP/SOCKS listener. This app remains the only owner of Android VpnService
 * and the device TUN. The existing Hev engine forwards that TUN to this SOCKS
 * listener; no second Android VPN service is created.
 */
object LanternEngine {
    const val SOCKS_PORT = 1831
    private const val TAG = "LanternEngine"
    private const val CONNECT_TIMEOUT_SECONDS = 180L

    @Volatile private var initialized = false
    @Volatile private var lastError = ""

    @Synchronized
    fun initialize(context: Context): Boolean {
        if (initialized) return true
        return try {
            val root = File(context.applicationContext.filesDir, "lantern-radiance")
            val data = File(root, "data")
            val logs = File(root, "logs")
            check(data.mkdirs() || data.isDirectory) { "Could not create Lantern data directory" }
            check(logs.mkdirs() || logs.isDirectory) { "Could not create Lantern log directory" }
            Lanternbridge.init(data.absolutePath, logs.absolutePath, "127.0.0.1:$SOCKS_PORT")
            initialized = true
            lastError = ""
            ConnectionLog.record("Lantern: Radiance initialized (novpn, loopback SOCKS $SOCKS_PORT)")
            true
        } catch (error: Throwable) {
            lastError = error.message ?: error.javaClass.simpleName
            ConnectionLog.record("Lantern: initialization failed: $lastError")
            Log.e(TAG, "Radiance initialization failed", error)
            false
        }
    }

    /** Blocking call: invoke only from MsnGuardVpnService's worker thread. */
    fun connect(context: Context): Boolean {
        if (!initialize(context)) return false
        return try {
            ConnectionLog.record("Lantern: waiting for public server configuration and auto-selection")
            Lanternbridge.connect(CONNECT_TIMEOUT_SECONDS)
            val deadline = android.os.SystemClock.elapsedRealtime() + 10_000L
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                if (isSocksReady()) {
                    lastError = ""
                    ConnectionLog.record("Lantern: public server connected; local SOCKS listener is ready")
                    return true
                }
                Thread.sleep(150L)
            }
            error("Radiance reported connected but its loopback SOCKS listener did not open")
        } catch (error: Throwable) {
            lastError = runCatching { Lanternbridge.lastError() }
                .getOrNull()
                ?.takeIf { it.isNotBlank() }
                ?: (error.message ?: error.javaClass.simpleName)
            ConnectionLog.record("Lantern: connect failed: $lastError")
            Log.e(TAG, "Radiance connect failed", error)
            false
        }
    }

    /** Stop only the Radiance tunnel; keep its backend ready for a reconnect. */
    fun disconnect() {
        if (!initialized) return
        try {
            Lanternbridge.disconnect()
            ConnectionLog.record("Lantern: Radiance tunnel disconnected")
        } catch (error: Throwable) {
            ConnectionLog.record("Lantern: disconnect error: ${error.message}")
            Log.w(TAG, "Radiance disconnect failed", error)
        }
    }

    val isRunning: Boolean
        get() = initialized && runCatching {
            Lanternbridge.status().equals("connected", ignoreCase = true)
        }.getOrDefault(false)

    fun isSocksReady(): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress("127.0.0.1", SOCKS_PORT), 350)
        }
        true
    } catch (_: Throwable) {
        false
    }

    /** Cumulative byte counters from Radiance's active connection tracker. */
    fun trafficCounters(): Pair<Long, Long> = try {
        val json = JSONObject(Lanternbridge.trafficJSON())
        json.optLong("tx", 0L) to json.optLong("rx", 0L)
    } catch (_: Throwable) {
        0L to 0L
    }

    fun errorMessage(): String = lastError.ifBlank {
        runCatching { Lanternbridge.lastError() }.getOrNull().orEmpty()
    }

    /** Process-lifetime cleanup hook; not used for ordinary disconnects. */
    @Synchronized
    fun shutdown() {
        if (!initialized) return
        runCatching { Lanternbridge.shutdown() }
        initialized = false
        lastError = ""
    }
}
