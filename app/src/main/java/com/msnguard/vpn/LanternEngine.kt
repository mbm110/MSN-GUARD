package com.msnguard.vpn

import android.content.Context
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Public Lantern transport backed by a separate Android PIE executable.
 *
 * Radiance is built with its novpn tag and exposes a loopback-only mixed
 * HTTP/SOCKS listener. This app remains the only owner of Android VpnService
 * and the device TUN. The existing Hev engine forwards that TUN to the local
 * SOCKS listener. A separate process is intentional: Psiphon's gomobile AAR
 * already owns libgojni.so and go.Seq classes, so another gomobile AAR would
 * collide with it.
 */
object LanternEngine {
    const val SOCKS_PORT = 1831
    private const val CONTROL_PORT = 1832
    private const val TAG = "LanternEngine"
    private const val CONNECT_TIMEOUT_SECONDS = 180L
    private const val CONTROL_READY_TIMEOUT_MS = 10_000L

    private val running = AtomicBoolean(false)
    private val processLock = Any()

    @Volatile private var stopRequested = false
    @Volatile private var process: Process? = null
    @Volatile private var logThread: Thread? = null
    @Volatile private var stopThread: Thread? = null
    @Volatile private var controlToken = ""
    @Volatile private var controlSocketPath = ""
    @Volatile private var lastError = ""

    private fun binary(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, "liblantern.so")

    private fun newControlToken(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /** Clear the previous stop latch before a fresh connection attempt. */
    fun armForStart() {
        stopRequested = false
        lastError = ""
    }

    /** Blocking connect: call only from MsnGuardVpnService's worker thread. */
    fun connect(context: Context): Boolean {
        armForStart()
        return try {
            if (!startProcess(context)) return false
            if (stopRequested) return false
            ConnectionLog.record("Lantern: waiting for public server configuration and auto-selection")
            val response = request(
                method = "POST",
                path = "/connect",
                body = JSONObject().put("timeout_seconds", CONNECT_TIMEOUT_SECONDS),
                timeoutMs = 190_000,
            )
            if (!response.optBoolean("ok")) {
                error(response.optString("error").ifBlank { "Radiance could not connect to a public server" })
            }

            running.set(true)
            val deadline = android.os.SystemClock.elapsedRealtime() + 10_000L
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                if (stopRequested) return false
                if (isRunning && isSocksReady()) {
                    lastError = ""
                    ConnectionLog.record("Lantern: public server connected; local SOCKS listener is ready")
                    return true
                }
                Thread.sleep(150L)
            }
            error("Radiance reported connected but its loopback SOCKS listener did not open")
        } catch (error: Throwable) {
            lastError = error.message ?: error.javaClass.simpleName
            ConnectionLog.record("Lantern: connect failed: $lastError")
            Log.e(TAG, "Radiance connect failed", error)
            false
        }
    }

    private fun startProcess(context: Context): Boolean {
        awaitPreviousStop()
        synchronized(processLock) {
            if (stopRequested) return false
            if (process?.isAlive == true) return true

            val bin = binary(context)
            if (!bin.exists()) {
                lastError = "Lantern sidecar binary is missing at ${bin.absolutePath}"
                ConnectionLog.record("Lantern: $lastError")
                return false
            }

            val root = File(context.applicationContext.filesDir, "lantern-radiance")
            val data = File(root, "data")
            val logs = File(root, "logs")
            if (!(data.mkdirs() || data.isDirectory) || !(logs.mkdirs() || logs.isDirectory)) {
                lastError = "Could not create Lantern private data/log directories"
                return false
            }

            val token = newControlToken()
            val controlPath = File(root, "control.sock").absolutePath
            val builder = ProcessBuilder(
                bin.absolutePath,
                "--data-dir", data.absolutePath,
                "--log-dir", logs.absolutePath,
                "--socks-address", "127.0.0.1:$SOCKS_PORT",
                "--control-socket", controlPath,
                "--control-token", token,
            )
            builder.directory(root)
            builder.redirectErrorStream(true)
            builder.environment()["HOME"] = context.filesDir.absolutePath

            val started = try {
                builder.start()
            } catch (error: Throwable) {
                lastError = "Could not start Lantern sidecar: ${error.message}"
                ConnectionLog.record("Lantern: $lastError")
                Log.e(TAG, "Sidecar exec failed", error)
                return false
            }

            if (stopRequested) {
                started.destroy()
                runCatching {
                    if (!started.waitFor(3, TimeUnit.SECONDS)) started.destroyForcibly()
                }
                return false
            }
            process = started
            controlToken = token
            controlSocketPath = controlPath
            running.set(false)

            logThread = Thread({
                try {
                    BufferedReader(InputStreamReader(started.inputStream)).forEachLine { line ->
                        if (line.isNotBlank()) {
                            val lower = line.lowercase()
                            if (lower.contains("error") || lower.contains("warn") || lower.contains("connected")) {
                                if (lower.contains("error")) lastError = line.take(500)
                                ConnectionLog.record("Lantern/Radiance: ${line.take(700)}")
                            }
                        }
                    }
                } catch (_: Exception) {
                }
            }, "lantern-log").apply {
                isDaemon = true
                start()
            }
        }

        return awaitControlReady()
    }

    private fun awaitControlReady(): Boolean {
        val deadline = android.os.SystemClock.elapsedRealtime() + CONTROL_READY_TIMEOUT_MS
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            if (stopRequested) return false
            if (process?.isAlive != true) {
                lastError = "Lantern sidecar exited before its control API became ready"
                return false
            }
            val ready = runCatching {
                request("GET", "/health", timeoutMs = 500).optBoolean("ok")
            }.getOrDefault(false)
            if (ready) {
                ConnectionLog.record("Lantern: sidecar control API ready on 127.0.0.1:$CONTROL_PORT")
                return true
            }
            Thread.sleep(120L)
        }
        lastError = "Lantern sidecar control API did not become ready"
        return false
    }

    private fun request(
        method: String,
        path: String,
        body: JSONObject? = null,
        timeoutMs: Int = 700,
    ): JSONObject {
        val token = controlToken
        val socketPath = controlSocketPath
        check(token.isNotBlank() && socketPath.isNotBlank()) {
            "Lantern control socket is unavailable"
        }
        return LocalSocket().use { socket ->
            socket.soTimeout = timeoutMs
            socket.connect(LocalSocketAddress(socketPath, LocalSocketAddress.Namespace.FILESYSTEM))
            val request = JSONObject()
                .put("method", method)
                .put("path", path)
                .put("token", token)
            if (body != null) request.put("body", body)
            socket.outputStream.write((request.toString() + "\n").toByteArray(Charsets.UTF_8))
            socket.outputStream.flush()
            val response = BufferedReader(InputStreamReader(socket.inputStream)).readLine()
            check(!response.isNullOrBlank()) { "Lantern sidecar returned an empty control response" }
            JSONObject(response)
        }
    }

    /** Cancel a blocking connect and signal the sidecar to shut down. */
    fun cancelConnect() {
        stopRequested = true
        running.set(false)
        if (process?.isAlive == true) {
            // Cancel the blocking ConnectVPN call without stopping the SOCKS
            // process yet. stopTunnel tears down Hev/TUN first, then
            // disconnectAsync terminates the sidecar.
            runCatching { request("POST", "/cancel", timeoutMs = 300) }
        }
    }

    /**
     * Stop the process off the Android service main thread. Android's native
     * library extraction grants execute permission to lib*.so when legacy
     * packaging is enabled; this file is executed, never dlopen'd.
     */
    fun disconnectAsync() {
        cancelConnect()
        synchronized(processLock) {
            val proc = process
            process = null
            controlToken = ""
            controlSocketPath = ""
            if (proc == null) return
            val oldLogThread = logThread
            logThread = null
            val thread = Thread({
                try {
                    if (proc.isAlive && !proc.waitFor(3, TimeUnit.SECONDS)) {
                        proc.destroyForcibly()
                        proc.waitFor(2, TimeUnit.SECONDS)
                    }
                } catch (_: Exception) {
                    try { proc.destroyForcibly() } catch (_: Exception) {}
                }
                try { oldLogThread?.join(500L) } catch (_: Exception) {}
                synchronized(processLock) {
                    if (stopThread === Thread.currentThread()) stopThread = null
                }
            }, "lantern-stop").apply { isDaemon = true }
            stopThread = thread
            thread.start()
        }
    }

    private fun awaitPreviousStop() {
        val pending = stopThread
        if (pending != null && pending.isAlive) {
            pending.join(6_000L)
            check(!pending.isAlive) { "Previous Lantern process is still shutting down" }
        }
    }

    val isRunning: Boolean
        get() {
            if (!running.get() || process?.isAlive != true) return false
            return runCatching {
                request("GET", "/status", timeoutMs = 350)
                    .optString("status")
                    .equals("connected", ignoreCase = true)
            }.getOrDefault(false)
        }

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
        val json = request("GET", "/traffic", timeoutMs = 700)
        json.optLong("tx", 0L) to json.optLong("rx", 0L)
    } catch (_: Throwable) {
        0L to 0L
    }

    fun errorMessage(): String = lastError.ifBlank {
        runCatching { request("GET", "/status", timeoutMs = 500).optString("error") }
            .getOrNull()
            .orEmpty()
    }

    /** Process-lifetime cleanup hook. */
    fun shutdown() {
        disconnectAsync()
    }
}
