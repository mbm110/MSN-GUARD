package com.msnguard.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.util.Log
import java.net.NetworkInterface
import java.util.concurrent.TimeUnit

/**
 * Outer-path MTU search — AetherST engine, 1:1.
 *
 * Reference: immaghzbad/AetherST — AutoDetectRepository.probeMtu +
 * Platform.android.execPing/getInterfaceMtu. Every constant and
 * code path below mirrors that repository so the numbers the user
 * sees are the same numbers that app would have produced on the
 * same carrier link.
 *
 * Why outer path: the app excludes its own package from the TUN
 * (addDisallowedApplication), so `ping -M do` from this process
 * rides the carrier even while a tunnel is up.
 *
 * Exact steps (same as AetherST):
 *  - ICMP_TARGET = 1.1.1.1 for every method
 *  - localMtu = ConnectivityManager.getLinkProperties(activeNetwork)
 *               .interfaceName → NetworkInterface.mtu ?: 1500,
 *               coerced to 1280..9000, then capped to 1500 for the
 *               binary search. Falls back to 1500 without Context.
 *  - ICMP_OVERHEAD = 28, payload = totalSize - 28
 *  - testMtu(n) = ping -c 1 -s <payload> -M do -W 1 1.1.1.1  with a
 *               900 ms wait (dontFragment=true). Returns false on
 *               any exception.
 *  - if testMtu(2000) == true → carrier ignores DF → return 1280
 *  - binary search low=1200 high=min(localMtu,1500), each trial
 *               capped the same way, 90 ms gap, bestPathMtu tracks
 *               the largest size that answered.
 *  - optimal = (bestPathMtu - 60).coerceIn(1100, 1460)
 *
 * SHARD/Psiphon/Tor are MSN-only methods that the reference app does
 * not ship — they keep their local-termination ceilings (SHARD 512
 * behind its WebSocket leg, tun2socks 1500) and never probe.
 */
object MtuProbe {

    private const val TAG = "MtuProbe"

    private const val ICMP_OVERHEAD = 28
    private const val ICMP_TARGET = "1.1.1.1"
    private const val PROBE_TIMEOUT_MS = 900
    private const val OVERHEAD = 60

    val LOCAL_TERMINATION = setOf(
        MtuConfig.Method.PSIPHON,
        MtuConfig.Method.TOR,
    )

    data class Result(
        val method: MtuConfig.Method,
        val outerPathMtu: Int?,
        val inner: Int?,
        val localTermination: Boolean,
        val probes: Int,
    )

    fun measure(
        context: Context,
        method: MtuConfig.Method,
        onProgress: (Int) -> Unit = {},
    ): Result {
        if (method == MtuConfig.Method.SHARD) {
            return Result(method, null, MtuConfig.DEFAULT_SHARD, true, 0)
        }
        if (method in LOCAL_TERMINATION) {
            return Result(method, null, MtuConfig.MAX_MTU, true, 0)
        }

        val localMtu = getInterfaceMtu(context)
        Log.i(TAG, "local interface MTU=$localMtu for ${method.title}")

        var probes = 0
        fun testMtu(totalSize: Int): Boolean {
            val payload = totalSize - ICMP_OVERHEAD
            if (payload < 0) return true
            probes++
            onProgress(totalSize)
            return execPing(ICMP_TARGET, payload, PROBE_TIMEOUT_MS, dontFragment = true)
        }

        if (testMtu(2000)) {
            Log.w(TAG, "DF bit ignored on this path, using safe 1280")
            return Result(method, 1280, 1280, false, probes)
        }

        var low = 1200
        var high = localMtu.coerceAtMost(1500)
        var bestPathMtu = 1200

        while (low <= high) {
            val mid = (low + high) / 2
            val ok = testMtu(mid)
            if (ok) {
                bestPathMtu = mid
                low = mid + 1
            } else {
                high = mid - 1
            }
            try {
                Thread.sleep(90)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }

        val optimal = (bestPathMtu - OVERHEAD).coerceIn(1100, 1460)
        Log.i(TAG, "${method.title}: pathMtu=$bestPathMtu optimal=$optimal after $probes probes localMtu=$localMtu")
        return Result(method, bestPathMtu, optimal, false, probes)
    }

    /** Back-compat fallback when no Context is available — same engine, localMtu=1500. */
    fun measure(
        method: MtuConfig.Method,
        onProgress: (Int) -> Unit = {},
    ): Result {
        if (method == MtuConfig.Method.SHARD) return Result(method, null, MtuConfig.DEFAULT_SHARD, true, 0)
        if (method in LOCAL_TERMINATION) return Result(method, null, MtuConfig.MAX_MTU, true, 0)
        var probes = 0
        fun testMtu(totalSize: Int): Boolean {
            val payload = totalSize - ICMP_OVERHEAD
            if (payload < 0) return true
            probes++
            onProgress(totalSize)
            return execPing(ICMP_TARGET, payload, PROBE_TIMEOUT_MS, dontFragment = true)
        }
        if (testMtu(2000)) return Result(method, 1280, 1280, false, probes)
        var low = 1200
        var high = 1500
        var best = 1200
        while (low <= high) {
            val mid = (low + high) / 2
            if (testMtu(mid)) {
                best = mid
                low = mid + 1
            } else high = mid - 1
            try {
                Thread.sleep(90)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
        val optimal = (best - OVERHEAD).coerceIn(1100, 1460)
        return Result(method, best, optimal, false, probes)
    }

    private fun getInterfaceMtu(context: Context): Int = try {
        @Suppress("MissingPermission")
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        @Suppress("MissingPermission")
        val lp = cm.getLinkProperties(cm.activeNetwork)
        val ifaceName = lp?.interfaceName
        val mtu = if (ifaceName != null) NetworkInterface.getByName(ifaceName)?.mtu ?: 1500 else 1500
        mtu.coerceIn(1280, 9000)
    } catch (_: Exception) {
        1500
    }

    private fun execPing(host: String, size: Int, timeoutMs: Int, dontFragment: Boolean): Boolean {
        val sanitized = host.trim()
        if (sanitized.isEmpty() || sanitized.length > 253) return false
        return try {
            val timeoutSec = (timeoutMs / 1000).coerceAtLeast(1)
            val pb = if (dontFragment) {
                ProcessBuilder("ping", "-c", "1", "-s", size.toString(), "-M", "do", "-W", timeoutSec.toString(), sanitized)
            } else {
                ProcessBuilder("ping", "-c", "1", "-s", size.toString(), "-W", timeoutSec.toString(), sanitized)
            }
            pb.redirectErrorStream(true)
            val proc = pb.start()
            val done = proc.waitFor(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            if (!done) {
                proc.destroyForcibly()
                false
            } else proc.exitValue() == 0
        } catch (_: Exception) {
            false
        }
    }
}
