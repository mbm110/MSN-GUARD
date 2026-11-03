package com.msnguard.vpn

import android.content.Context

/**
 * MTU Automatic Scan — the connect-time arm of the MTU screen's switch.
 *
 * ## What it owns
 * The MTU screen toggle (`mtu_automatic_scan`, default ON) decides WHO picks
 * the tun MTU for a connect:
 *
 *  - **ON**: measure the outer wire for THIS method right before the tunnel is
 *    built ([MtuProbe.measure] — ICMP with DF over the carrier link, the same
 *    scan the per-method "Scan the best value" button runs), log the pair
 *    (found / path / probes), and use it for the TUN builder AND the engine's
 *    env ([CoreConfig] reads MTU through [MtuConfig.get], which forwards to the
 *    session record). Nothing is persisted: each connect measures again, per
 *    the brief "همیشه قبل از هر اتصال اسکن کند".
 *  - **OFF**: nothing here runs. Every consumer reads the stored/default value
 *    exactly like before this object existed, and the manual rows are editable.
 *
 * ## Isolation guarantees
 *  - Scans run on the connect worker thread (every start*Tunnel is already
 *    on `worker`), never the main thread; worst case ~10 s (11 × 0.9 s probes)
 *    before Builder.establish — the same cost the manual scan shows.
 *  - The session record lives ONE connect: [startTunnel] clears it and each
 *    start path records only its own method, so a chain rung (its env is built
 *    per rung) never sees a plain connect's number — the outer transport keeps
 *    its stored engine MTU, the inner leg's TUN gets its own scan. No engine
 *    env, TUN builder, or scan-timing change for anything else.
 *  - If no scan value lands (probes all dead, ping missing), every consumer
 *    falls back to the exact pre-feature value, so a dead network degrades to
 *    today's behaviour instead of to a broken connect.
 *
 * Methods the screen lists map to the same seven [MtuConfig.Method] entries —
 * MASQUE covers masque AND masque-over-masque (mim), WOW covers gool, and the
 * Psiphon/Tor entries are scanned for BOTH plain and over-WARP legs.
 */
object MtuAutoScan {

    private const val PREF = "mtu_automatic_scan"
    private const val DEFAULT_ON = true

    fun enabled(context: Context): Boolean =
        context.profiled().getBoolean(PREF, DEFAULT_ON)

    fun setEnabled(context: Context, on: Boolean) {
        context.profiled().edit().putBoolean(PREF, on).commit()
    }

    /** Manual edits must be immediately visible to the settings screen. */
    @Synchronized
    fun clearSessionValue(method: MtuConfig.Method) {
        session.remove(method)
    }

    /**
     * Scan results for the CURRENT connect attempt. One method → one number;
     * cleared by [markSessionStart] at the top of every connect, so stale
     * values can never cross into a different transport or session.
     */
    private val session = HashMap<MtuConfig.Method, Int>()

    @Synchronized
    fun sessionValue(method: MtuConfig.Method): Int? = session[method]

    /** Drop every recorded scan — called once per connect, before any path reads MTU. */
    @Synchronized
    fun markSessionStart() {
        session.clear()
    }

    /**
     * Measure and record the tun MTU for [method]; never throws.
     *
     * Becomes the connect's number via two legs: this return value (the TUN
     * builder call sites) and the session record ([MtuConfig.get] forwards to
     * it, which is what [CoreConfig] reads for the engine env keys), so the TUN
     * and the engine cannot disagree about the same transport.
     */
    @Synchronized
    fun tunMtu(context: Context, method: MtuConfig.Method, fallback: Int): Int {
        if (!enabled(context)) return fallback
        val r = try {
            MtuProbe.measure(context, method)
        } catch (e: Throwable) {
            ConnectionLog.record("MTU: auto scan for ${method.title} crashed (${e.message ?: "unknown"}) — using $fallback")
            null
        }
        val found = r?.inner
        if (found == null) {
            ConnectionLog.record("MTU: auto scan for ${method.title} found nothing — using $fallback")
            return fallback
        }
        session[method] = found
        ConnectionLog.record(
            "MTU: auto scan ${method.title} → $found found and applying" +
                " (path ${r?.outerPathMtu ?: "—"}, ${r?.probes ?: 0} probes)"
        )
        return found
    }
}
