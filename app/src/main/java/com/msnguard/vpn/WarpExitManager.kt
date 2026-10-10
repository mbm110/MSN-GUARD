package com.msnguard.vpn

import android.content.Context
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Xray sidecar for MASQUE/MIM exit only (Warp Setting).
 * Isolated from SHARD: own port (1826), own process, own config dir.
 * Used only when currentProtocol in {masque,mim} and warpExitIsCustom.
 * Chain: aether --upstream socks5://127.0.0.1:1826 --> xray SOCKS 1826 --> user's VLESS (gRPC/ws/etc) --> exit.
 */
object WarpExitManager {
    private const val TAG = "WarpExit"
    const val SOCKS_PORT = 1826
    private val running = AtomicBoolean(false)
    @Volatile private var process: Process? = null
    @Volatile private var logThread: Thread? = null
    @Volatile var activeLabel: String = ""
        private set
    @Volatile var lastError: String = ""
        private set
    val isRunning: Boolean get() = running.get() && process?.isAlive == true

    private fun binary(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, "libxray.so")

    private fun launch(context: Context, configFile: File): Boolean {
        val bin = binary(context)
        if (!bin.exists()) {
            lastError = "xray binary missing"
            ConnectionLog.record("$TAG binary missing at ${bin.absolutePath}")
            return false
        }
        val pb = ProcessBuilder(bin.absolutePath, "run", "-c", configFile.absolutePath)
        pb.directory(configFile.parentFile)
        pb.redirectErrorStream(true)
        pb.environment()["HOME"] = context.filesDir.absolutePath
        pb.environment()["XRAY_LOCATION_ASSET"] = configFile.parent
        val p = try { pb.start() } catch (e: Exception) {
            lastError = "could not start xray: ${e.message}"
            ConnectionLog.record("$TAG exec failed: ${e.message}")
            return false
        }
        process = p
        logThread = Thread({
            try {
                BufferedReader(InputStreamReader(p.inputStream)).forEachLine { line ->
                    if (line.isNotBlank() && !isNoise(line)) ConnectionLog.record("$TAG $line")
                }
            } catch (_: Exception) {}
        }, "warpexit-log").apply { isDaemon = true; start() }
        return true
    }

    private fun isNoise(line: String): Boolean =
        line.contains("is deprecated, not recommended") ||
        line.contains("deprecated, will be removed soon") ||
        line.contains("[in >> proxy]") ||
        line.contains("A unified platform for anti-censorship") ||
        line.contains("infra/conf/serial: Reading config")

    fun stop() {
        running.set(false)
        activeLabel = ""
        val proc = process
        try { proc?.destroy() } catch (_: Exception) {}
        Thread({
            try {
                if (proc != null && proc.isAlive && !proc.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) proc.destroyForcibly()
            } catch (_: Exception) {}
            if (process === proc) { process = null; logThread = null }
            running.set(false)
        }, "warpexit-stop").start()
    }

    fun start(context: Context, vlessUrl: String): Boolean {
        stop()
        lastError = ""
        activeLabel = vlessUrl.take(48)
        val node = ShardConfigs.parse(vlessUrl).firstOrNull()
        if (node == null) {
            lastError = "could not parse VLESS (unsupported type?)"
            ConnectionLog.record("$TAG parse failed for ${vlessUrl.take(80)}")
            return false
        }
        val listenHost = "127.0.0.1"
        val port = SOCKS_PORT
        val logLevel = "warning"
        val config = ShardConfigs.tunnelConfig(context, node, listenHost, port, logLevel)
        val configFile = ShardConfigs.writeConfig(context, "warpexit.json", config)
        if (!launch(context, configFile)) return false
        if (awaitListener(port, timeoutMs = 8000)) {
            running.set(true)
            ConnectionLog.record("$TAG up on $port via ${LogRedactor.nodeTag(node.key)}")
            return true
        }
        lastError = "listener $port never came up"
        ConnectionLog.record("$TAG port $port never opened")
        stop()
        return false
    }

    private fun awaitListener(port: Int, timeoutMs: Long): Boolean {
        val deadline = android.os.SystemClock.elapsedRealtime() + timeoutMs
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            if (process?.isAlive != true) return false
            try {
                Socket().use { s -> s.connect(InetSocketAddress("127.0.0.1", port), 400); return true }
            } catch (_: Exception) {}
            try { Thread.sleep(200) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); return false }
        }
        return false
    }
}
