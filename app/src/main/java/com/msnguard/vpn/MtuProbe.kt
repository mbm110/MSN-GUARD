package com.msnguard.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.util.Log
import java.net.NetworkInterface
import java.util.concurrent.TimeUnit

/**
 * Per-method outer-path MTU search.
 *
 * Why per-method overhead: the three WARP families stack framing differently
 * — WireGuard wraps once, MASQUE twice (QUIC inside a WARP tunnel inside
 * MASQUE), WoW three times. A flat 60 for all of them made the scanner hand
 * back the same number for every method — 1440 on a 1500-byte link — which
 * is the WireGuard figure and far too large for MASQUE or WoW.
 *
 * Why a safety margin: on many filtered networks ICMP-with-DF is answered at
 * sizes where UDP/QUIC is already being dropped, so a probe that lands exactly
 * on the measured boundary produces an MTU that connects but cannot open a
 * page. Subtracting headroom costs a little throughput and removes that class
 * of failure.
 *
 * Why the floor: below 1280 nothing moves on the carriers this app is used on
 * — 1280 is also the IPv6 minimum, so it is the lowest defensible MTU.
 *
 * The search always runs on the carrier link: the app excludes its own package
 * from the TUN (addDisallowedApplication), so `ping -M do` from this process
 * rides the carrier even while a tunnel is up.
 *
 * Steps:
 *  - ICMP_TARGET = 1.1.1.1, ICMP_OVERHEAD = 28 (IP 20 + ICMP 8)
 *  - localMtu = ConnectivityManager.getLinkProperties(activeNetwork)
 *               .interfaceName → NetworkInterface.mtu ?: 1500
 *  - if testMtu(2000) answers → the carrier ignores DF → SCAN_FLOOR (safe)
 *  - binary search 1200..min(localMtu,1500), 900 ms per probe, 90 ms gap
 *  - optimal = (bestPathMtu - overhead - SAFETY_MARGIN), snapped down to a
 *    16-byte boundary, clamped to [SCAN_FLOOR, SCAN_CEIL]
 *  - SHARD is additionally capped at its WebSocket-leg ceiling: the pooled
 *    nodes drop any UDP datagram larger than that, so a larger TUN MTU makes
 *    QUIC probe a dead path while chat still works
 *
 * Psiphon/Tor are TCP-based: they re-segment, so their constraint is the
 * outer path rather than a hard per-packet expansion. A TCP-based method
 * behind a 1500-byte carrier still cannot carry a full-size segment end to
 * end on a filtered network, so they probe too — with a much smaller
 * per-packet cost — and the floor protects them.
 *
 * The result is NOT persisted: the caller decides whether to keep it
 * (the MTU dialog's Apply button is the only write path).
 */
object MtuProbe {

    private const val TAG = "MtuProbe"

    private const val ICMP_OVERHEAD = 28
    private const val ICMP_TARGET = "1.1.1.1"
    private const val PROBE_TIMEOUT_MS = 900

    /** Never propose below this — the measured floor on Iranian carriers. */
    const val SCAN_FLOOR = 1280

    /** Highest MTU worth proposing inside a 1500-byte outer path. */
    const val SCAN_CEIL = 1460

    /**
     * Headroom for the ICMP-answers-but-UDP-drops asymmetry. Costs a little
     * throughput, removes the "connects but no page opens" case.
     */
    private const val SAFETY_MARGIN = 32

    /** Snaps the result down to a 16-byte boundary. */
    private const val SNAP = 16

    /**
     * Bytes each method wraps around an inner packet on the wire. These are
     * framing costs measured on a live 1500-byte path: WireGuard 60 = 20 IP +
     * 8 UDP + 32 WG, exact; the two- and three-layer WARP chains cost
     * correspondingly more per layer.
     */
    private val OVERHEAD = mapOf(
        MtuConfig.Method.MASQUE to 196,
        MtuConfig.Method.WIREGUARD to 60,
        MtuConfig.Method.WOW to 280,
        MtuConfig.Method.PSIPHON to 40,
        MtuConfig.Method.TOR to 100,
        MtuConfig.Method.SHARD to 70,
    )

    /**
     * SHARD's pooled nodes sit behind a WebSocket leg that drops any datagram
     * whose payload crosses this size, so the inner MTU must stay under it no
     * matter what the outer path measured.
     */
    private const val SHARD_WEBSOCKET_CEILING = 512

    data class Result(
        val method: MtuConfig.Method,
        val outerPathMtu: Int?,
        val inner: Int?,
        val probes: Int,
        /** True when the SHARD WebSocket ceiling, not the path, set the value. */
        val capped: Boolean = false,
    )

    fun measure(
        context: Context,
        method: MtuConfig.Method,
        onProgress: (Int) -> Unit = {},
    ): Result {
        val localMtu = getInterfaceMtu(context)
        Log.i(TAG, "${method.title}: local interface MTU=$localMtu")

        var probes = 0
        fun testMtu(totalSize: Int): Boolean {
            val payload = totalSize - ICMP_OVERHEAD
            if (payload < 0) return true
            probes++
            onProgress(totalSize)
            return execPing(ICMP_TARGET, payload, PROBE_TIMEOUT_MS, dontFragment = true)
        }

        // A path that answers a 2000-byte DF probe is ignoring the bit — the
        // search would report a meaningless ceiling.
        if (testMtu(2000)) {
            Log.w(TAG, "${method.title}: DF ignored on this path, using safe $SCAN_FLOOR")
            return Result(method, 2000, SCAN_FLOOR, probes)
        }

        var low = 1200
        var high = localMtu.coerceAtMost(1500)
        var bestPathMtu = 1200

        while (low <= high) {
            val mid = (low + high) / 2
            if (testMtu(mid)) {
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

        val overhead = OVERHEAD[method] ?: 0
        var optimal = bestPathMtu - overhead - SAFETY_MARGIN
        optimal -= optimal % SNAP
        optimal = optimal.coerceIn(SCAN_FLOOR, SCAN_CEIL)

        if (method == MtuConfig.Method.SHARD && optimal > SHARD_WEBSOCKET_CEILING) {
            Log.i(TAG, "${method.title}: path allows $optimal but the WebSocket leg caps at $SHARD_WEBSOCKET_CEILING")
            return Result(method, bestPathMtu, SHARD_WEBSOCKET_CEILING, probes, capped = true)
        }

        Log.i(TAG, "${method.title}: pathMtu=$bestPathMtu overhead=$overhead optimal=$optimal after $probes probes localMtu=$localMtu")
        return Result(method, bestPathMtu, optimal, probes)
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
