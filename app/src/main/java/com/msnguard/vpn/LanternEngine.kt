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
import java.util.concurrent.atomic.AtomicLong

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
    private val generation = AtomicLong(0L)
    private val generationLock = Any()
    private val processLock = Any()

    /**
     * True between a tunnel connect attempt's arm and its final cleanup.
     * The idle-sidecar reaper must NEVER kill the process while this is set —
     * a list-only boot and a tunnel connect share startProcess, and an activity
     * destroyed mid-connect (rotation, back-out) would otherwise tear down a
     * connect that is seconds from going live.
     */
    @Volatile private var tunnelAttemptActive = false

    /** Last time any picker surface (list/selection/ping) actually used the sidecar. */
    private val lastSidecarUse = AtomicLong(0L)

    /** Idle reaper cadence and how long a list-only sidecar may sit untouched. */
    private const val SIDECAR_IDLE_TICK_MS = 30_000L
    private const val SIDECAR_IDLE_TIMEOUT_MS = 4 * 60_000L

    @Volatile private var idleReaper: Thread? = null

    @Volatile private var stopRequested = false
    @Volatile private var process: Process? = null
    @Volatile private var logThread: Thread? = null
    @Volatile private var stopThread: Thread? = null
    @Volatile private var controlToken = ""
    @Volatile private var controlSocketPath = ""
    @Volatile private var sidecarPort: Int = 0
    @Volatile private var lastError = ""

    private fun binary(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, "liblantern.so")

    private fun newControlToken(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /** Clear the previous stop latch before a fresh connection attempt. */
    fun armForStart(): Long = synchronized(generationLock) {
        stopRequested = false
        running.set(false)
        lastError = ""
        generation.incrementAndGet()
    }

    /** True only while this exact queued/start attempt still owns the engine. */
    fun isCurrent(attempt: Long): Boolean =
        generation.get() == attempt && !stopRequested

    /** True while this attempt's own failure/stop cleanup still owns the engine. */
    fun isStoppingAttempt(attempt: Long): Boolean =
        generation.get() == attempt + 1L && stopRequested

    /** Blocking connect: call only from MsnGuardVpnService's worker thread. */
    fun connect(context: Context, attempt: Long): Boolean {
        tunnelAttemptActive = true
        return try {
            connectInner(context, attempt)
        } finally {
            tunnelAttemptActive = false
        }
    }

    private fun connectInner(context: Context, attempt: Long): Boolean {
        return try {
            if (!isCurrent(attempt)) return false
            if (!startProcess(context, attempt)) return false
            if (!isCurrent(attempt)) return false
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
            if (!isCurrent(attempt)) return false

            running.set(true)
            val deadline = android.os.SystemClock.elapsedRealtime() + 10_000L
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                if (!isCurrent(attempt)) return false
                if (isRunning && isSocksReady()) {
                    lastError = ""
                    ConnectionLog.record("Lantern: public server connected; local SOCKS listener is ready")
                    applyDeferredSelection(context)
                    return true
                }
                Thread.sleep(150L)
            }
            error("Radiance reported connected but its loopback SOCKS listener did not open")
        } catch (error: Throwable) {
            if (!isCurrent(attempt)) return false
            lastError = error.message ?: error.javaClass.simpleName
            ConnectionLog.record("Lantern: connect failed: $lastError")
            Log.e(TAG, "Radiance connect failed", error)
            false
        }
    }

    private fun startProcess(context: Context, attempt: Long): Boolean {
        val startupOutput = java.util.ArrayDeque<String>()
        awaitPreviousStop()
        synchronized(processLock) {
            if (!isCurrent(attempt)) return false
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
            // Use a dedicated loopback TCP control endpoint. Android's
            // abstract LocalSocket and Go's abstract Unix listener did not
            // establish a working handshake on the target device. The bearer
            // token remains the per-process capability.
            val controlPath = "127.0.0.1:0"
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
            // Executed PIEs do not inherit the app's Java native-loader namespace.
            // Make packaged dependencies visible to Android's executable linker.
            builder.environment()["LD_LIBRARY_PATH"] = context.applicationInfo.nativeLibraryDir
            // 3.2.50 revert: the sidecar again presents NO country identity, so
            // Lantern geo-serves the IR pool (3x Frankfurt + 1x Amsterdam,
            // tags suffixed "-ir-free-") — the field-tested fast servers. The
            // 3.2.49 global-pool draw (country override → Milan/Ashburn/...)
            // worked but its throughput on the user's line was poor; the IR
            // pool is the one to ship.

            val started = try {
                builder.start()
            } catch (error: Throwable) {
                lastError = "Could not start Lantern sidecar: ${error.message}"
                ConnectionLog.record("Lantern: $lastError")
                Log.e(TAG, "Sidecar exec failed", error)
                return false
            }

            if (!isCurrent(attempt)) {
                started.destroy()
                runCatching {
                    if (!started.waitFor(3, TimeUnit.SECONDS)) started.destroyForcibly()
                }
                return false
            }
            process = started
            controlToken = token
            controlSocketPath = ""
            sidecarPort = 0
            running.set(false)

            logThread = Thread({
                try {
                    BufferedReader(InputStreamReader(started.inputStream)).forEachLine { line ->
                        if (line.isNotBlank()) {
                            synchronized(startupOutput) {
                                if (startupOutput.size >= 12) startupOutput.removeFirst()
                                startupOutput.addLast(line.replace(token, "[REDACTED]").take(500))
                            }
                                            val portMatch = Regex("LANTERN_CONTROL_PORT=(\\d+)").find(line)
                            if (portMatch != null) {
                                val port = portMatch.groupValues[1].toIntOrNull() ?: 0
                                if (port in 1..65535) {
                                    sidecarPort = port
                                    controlSocketPath = "127.0.0.1:$port"
                                    ConnectionLog.record("Lantern: sidecar control port selected $port")
                                }
                            }
                            val lower = line.lowercase()
                            if (lower.contains("error") || lower.contains("warn") || lower.contains("connected")) {
                                // Spam gate: radiance/sing-box repeat identical errors
                                // (e.g. "missing fakeip record" per connection) with only
                                // ids/durations varying. Cap repeats so the in-app log
                                // stays readable; the full stream still reaches logcat.
                                if (shouldEmitSidecarLine(lower)) {
                                    if (lower.contains("error")) lastError = line.take(500)
                                    ConnectionLog.record("Lantern/Radiance: ${line.take(700)}")
                                }
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

        val ready = awaitControlReady(attempt)
        if (!ready && isCurrent(attempt) && process?.isAlive != true) {
            logThread?.join(500L)
            val output = synchronized(startupOutput) { startupOutput.joinToString(" | ") }
            val exit = runCatching { process?.exitValue() }.getOrNull()
            lastError = "Lantern sidecar exited (code=$exit) before control ready: $output"
            ConnectionLog.record(lastError)
        }
        return ready
    }

    private fun awaitControlReady(attempt: Long): Boolean {
        val deadline = android.os.SystemClock.elapsedRealtime() + CONTROL_READY_TIMEOUT_MS
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            if (!isCurrent(attempt)) return false
            if (process?.isAlive != true) {
                lastError = "Lantern sidecar exited before its control API became ready"
                return false
            }
            // The sidecar binds port 0 and publishes the selected port on
            // stdout. Do not probe a stale/empty endpoint while that marker is
            // still in flight; that was the source of repeated "socket not
            // created" messages on otherwise live Radiance processes.
            if (controlSocketPath.isBlank()) {
                Thread.sleep(120L)
                continue
            }
            val health = runCatching {
                request("GET", "/health", timeoutMs = 1500)
            }
            val response = health.getOrNull()
            val ready = response?.optBoolean("ok") == true
            if (!ready) {
                val detail = if (health.isFailure) {
                    health.exceptionOrNull()?.message ?: "unknown socket error"
                } else {
                    "response=${response?.toString()?.take(400) ?: "empty"}"
                }
                lastError = "Lantern control /health not ready: $detail"
                ConnectionLog.record("Lantern: /health not ready: $detail")
            }
            if (ready) {
                ConnectionLog.record("Lantern: private sidecar control socket ready")
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
        val request = JSONObject()
            .put("method", method)
            .put("path", path)
            .put("token", token)
        if (body != null) request.put("body", body)

        // The current sidecar uses an ephemeral loopback TCP listener. Do not
        // construct or close an unused LocalSocket on this path: Android's
        // LocalSocket reports "socket not created" for that unused object,
        // masking a valid TCP control connection as a readiness failure.
        if (socketPath.startsWith("127.0.0.1:")) {
            val port = socketPath.substringAfter(':').toInt()
            return Socket().use { tcp ->
                tcp.soTimeout = timeoutMs
                tcp.connect(InetSocketAddress("127.0.0.1", port), timeoutMs)
                tcp.outputStream.write((request.toString() + "\n").toByteArray(Charsets.UTF_8))
                tcp.outputStream.flush()
                val response = BufferedReader(InputStreamReader(tcp.inputStream)).readLine()
                check(!response.isNullOrBlank()) { "Lantern sidecar returned an empty control response" }
                JSONObject(response)
            }
        }

        return LocalSocket().use { socket ->
            socket.soTimeout = timeoutMs
            val namespace = if (socketPath.startsWith("@")) {
                LocalSocketAddress.Namespace.ABSTRACT
            } else {
                LocalSocketAddress.Namespace.FILESYSTEM
            }
            socket.connect(LocalSocketAddress(socketPath.removePrefix("@"), namespace))
            socket.outputStream.write((request.toString() + "\n").toByteArray(Charsets.UTF_8))
            socket.outputStream.flush()
            val response = BufferedReader(InputStreamReader(socket.inputStream)).readLine()
            check(!response.isNullOrBlank()) { "Lantern sidecar returned an empty control response" }
            JSONObject(response)
        }
    }

    /** Cancel this exact attempt without terminating the sidecar yet. */
    fun cancelConnect(attempt: Long): Boolean = synchronized(generationLock) {
        if (generation.get() != attempt || stopRequested) return@synchronized false
        generation.incrementAndGet()
        stopRequested = true
        running.set(false)
        cancelSidecarConnectLocked()
        true
    }

    /** Invalidate any current attempt; used by the authoritative service stop path. */
    fun cancelConnect() = synchronized(generationLock) {
        generation.incrementAndGet()
        stopRequested = true
        running.set(false)
        cancelSidecarConnectLocked()
    }

    private fun cancelSidecarConnectLocked() {
        if (process?.isAlive == true) {
            // Cancel ConnectVPN without stopping the SOCKS process yet. The
            // service tears down Hev/TUN first, then disconnectAsync terminates it.
            runCatching { request("POST", "/cancel", timeoutMs = 300) }
        }
    }

    /**
     * Stop the process off the Android service main thread. Android's native
     * library extraction grants execute permission to lib*.so when legacy
     * packaging is enabled; this file is executed, never dlopen'd.
     */
    fun disconnectAsync() {
        synchronized(generationLock) {
            if (!stopRequested) {
                generation.incrementAndGet()
                stopRequested = true
                running.set(false)
                cancelSidecarConnectLocked()
            }
            stopProcessLocked()
        }
    }

    /** Stop only if the attempt that requested teardown still owns this generation. */
    fun disconnectAsync(attempt: Long) {
        synchronized(generationLock) {
            if (generation.get() != attempt + 1L || !stopRequested) return
            stopProcessLocked()
        }
    }

    private fun stopProcessLocked() {
        running.set(false)
        synchronized(processLock) {
            val proc = process
            process = null
            controlToken = ""
            controlSocketPath = ""
            if (proc == null) return
            val oldLogThread = logThread
            logThread = null
            runCatching { proc.destroy() }
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

    /**
     * Cumulative byte counters from Radiance's active connection tracker.
     *
     * NULL on failure, never (0, 0): a failed /traffic read used to be reported
     * as zero counters, which the pipeline's rebase guard read as a counter
     * reset — zeroing the speed baseline and painting "0 B/s" on the main
     * screen while the tunnel carried traffic (the "Telegram is loading but
     * Speed shows 0" report; the control request times out exactly when the
     * tunnel is busiest). Callers must SKIP a null sample, not feed it in.
     */
    fun trafficCountersOrNull(): Pair<Long, Long>? = try {
        val json = request("GET", "/traffic", timeoutMs = 1_500)
        json.optLong("tx", 0L) to json.optLong("rx", 0L)
    } catch (_: Throwable) {
        null
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

    /** Record that a picker surface is actively using the sidecar. */
    private fun touchSidecarUse() {
        lastSidecarUse.set(android.os.SystemClock.elapsedRealtime())
    }

    /**
     * Stop a LIST-ONLY sidecar — the no-TUN boot from the offline server
     * picker. A live Lantern tunnel (running) or an in-flight connect attempt
     * owns the process and is left strictly alone. Safe to call from anywhere
     * at any time: every destructive path is guarded.
     */
    fun stopIdleListOnly() {
        if (tunnelAttemptActive || running.get()) return
        if (process?.isAlive != true) return
        ConnectionLog.record("Lantern: stopping idle list-only sidecar")
        disconnectAsync()
    }

    /**
     * One daemon reaper per sidecar boot: while the tunnel is up or a picker
     * surface keeps touching the sidecar it does nothing; after the idle
     * timeout with no owner it stops the bare process. Without this the
     * Radiance core — which probes servers continuously — would outlive the
     * picker for the lifetime of the app process, burning battery and mobile
     * data (v3.2.27 audit).
     */
    private fun ensureIdleReaper() {
        synchronized(processLock) {
            if (idleReaper?.isAlive == true) return
            val thread = Thread({
                touchSidecarUse()
                try {
                    while (true) {
                        Thread.sleep(SIDECAR_IDLE_TICK_MS)
                        if (process?.isAlive != true) break
                        if (tunnelAttemptActive || running.get()) {
                            touchSidecarUse()
                            continue
                        }
                        val idleFor = android.os.SystemClock.elapsedRealtime() - lastSidecarUse.get()
                        if (idleFor >= SIDECAR_IDLE_TIMEOUT_MS) {
                            ConnectionLog.record("Lantern: list-only sidecar idle ${(idleFor / 1000L)}s — stopping")
                            disconnectAsync()
                            break
                        }
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }, "lantern-idle-reaper").apply { isDaemon = true }
            idleReaper = thread
            thread.start()
        }
    }

    // ---- Server selection & probe surface for the settings screen ----

    /** Current server list + ping data; null when the sidecar is not running. */
    fun serversSnapshot(timeoutMs: Int = 2_000): JSONObject? {
        if (controlToken.isBlank() || controlSocketPath.isBlank()) return null
        touchSidecarUse()
        // The control response wraps the payload in "data".
        return runCatching { request("GET", "/servers", timeoutMs = timeoutMs) }
            .getOrNull()?.optJSONObject("data")
    }

    /** Select a server by tag ("" = automatic fastest). Returns an error or null on success. */
    fun selectServer(tag: String): String? {
        if (controlToken.isBlank() || controlSocketPath.isBlank()) return "Lantern is not connected"
        touchSidecarUse()
        val response = runCatching {
            request("POST", "/select", JSONObject().put("tag", tag), timeoutMs = 4_000)
        }.getOrNull()
        // A null response means the sidecar is down: the caller keeps the
        // stored preference and it is applied right after the next connect.
        response ?: return "Lantern is not connected"
        return if (response.optBoolean("ok")) null
        else response.optString("error").ifBlank { "server selection failed" }
    }

    /** Re-probe every server's latency. Returns an error or null on success. */
    fun refreshServerPings(): String? {
        if (controlToken.isBlank() || controlSocketPath.isBlank()) return "Lantern is not connected"
        touchSidecarUse()
        val response = runCatching {
            request("POST", "/ping", JSONObject(), timeoutMs = 95_000)
        }.getOrNull()
        return if (response != null && response.optBoolean("ok")) null
        else response?.optString("error")?.ifBlank { "server probe failed" } ?: "server probe failed"
    }

    /** True when the control endpoint answers /health. */
    private fun controlAlive(timeoutMs: Int): Boolean =
        controlToken.isNotBlank() && controlSocketPath.isNotBlank() &&
            runCatching { request("GET", "/health", timeoutMs = timeoutMs) }.isSuccess

    /**
     * Boot the sidecar WITHOUT connecting the tunnel — official-app parity:
     * the Lantern core runs while its VPN is off, so the server list and live
     * pings stay available offline. Idempotent: a live sidecar (connected or
     * list-only) is reused, and connect() reuses a list-only sidecar because
     * startProcess is a no-op while the process is alive.
     */
    fun ensureSidecar(context: Context): Boolean {
        if (controlAlive(800)) return true
        // Another start (a connect or an earlier list boot) may be in flight;
        // wait for its control API instead of racing it with a new attempt.
        if (process?.isAlive == true) {
            val deadline = android.os.SystemClock.elapsedRealtime() + 15_000L
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                if (process?.isAlive != true) break
                if (controlSocketPath.isNotBlank() && controlAlive(1500)) return true
                Thread.sleep(200L)
            }
            return controlAlive(1500)
        }
        val attempt = armForStart()
        if (!startProcess(context, attempt)) return false
        // Control readiness only — no /connect, no TUN. Radiance fetches its
        // config and probes servers directly (the app is outside the VPN), so
        // /servers and /ping answer with live data.
        val ready = awaitControlReady(attempt)
        if (ready) ensureIdleReaper()
        return ready
    }

    /** The stored server choice ("" = auto), shared with the settings screen. */
    const val SELECTED_SERVER_PREF = "lantern_selected_server"

    fun storedServerSelection(context: Context): String =
        context.profiled().getString(SELECTED_SERVER_PREF, "") ?: ""

    fun storeServerSelection(context: Context, tag: String) {
        context.profiled().edit().putString(SELECTED_SERVER_PREF, tag).apply()
    }

    /**
     * Apply the stored server choice right after a successful connect, when the
     * sidecar can act on it. Selections made while disconnected only persist
     * the preference; this is where they take effect.
     */
    private fun applyDeferredSelection(context: Context) {
        val tag = storedServerSelection(context)
        if (tag.isBlank()) return // auto needs no deferred apply
        val error = selectServer(tag)
        if (error != null) {
            ConnectionLog.record("Lantern: deferred server selection failed: $error")
        } else {
            ConnectionLog.record("Lantern: pinned server selection applied after connect")
        }
    }

    // ---- Sidecar log spam gate ----

    /**
     * Collapses per-line noise into one key: digit runs (timestamps, ids,
     * durations, ports, versions) become '#', bracketed values (domains,
     * addresses) become '[]'. The real spam — "no available network
     * interface" / "missing fakeip record for <ip>" — repeats with only
     * those parts varying, so it lands on a single key.
     */
    private val sidecarDigitsRegex = Regex("\\d+")

    private val sidecarBracketRegex = Regex("\\[[^\\]]{0,60}\\]")

    /** Window start (elapsed ms) per normalized message; pruned to stay bounded. */
    private val logRepeatWindow = HashMap<String, Long>()

    private val logRepeatCounts = HashMap<String, Int>()

    /**
     * Rate-limit repeated identical sidecar lines. The first three
     * occurrences of a message inside a 60-second window are logged; further
     * repeats are suppressed until the window rolls over. The raw stream is
     * unaffected — this only gates the in-app connection log.
     */
    private fun shouldEmitSidecarLine(lower: String): Boolean = synchronized(logRepeatWindow) {
        val now = android.os.SystemClock.elapsedRealtime()
        val key = sidecarBracketRegex
            .replace(sidecarDigitsRegex.replace(lower, "#"), "[]")
            .take(140)
        val start = logRepeatWindow[key]
        if (start == null || now - start > 60_000L) {
            if (logRepeatWindow.size >= 48) {
                val oldest = logRepeatWindow.entries.minByOrNull { it.value }?.key
                if (oldest != null) {
                    logRepeatWindow.remove(oldest)
                    logRepeatCounts.remove(oldest)
                }
            }
            logRepeatWindow[key] = now
            logRepeatCounts[key] = 1
            true
        } else {
            val count = (logRepeatCounts[key] ?: 0) + 1
            logRepeatCounts[key] = count
            count <= 3
        }
    }
}
