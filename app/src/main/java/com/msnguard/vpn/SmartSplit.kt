package com.msnguard.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.telephony.TelephonyManager
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Smart Split: which traffic goes direct-with-fragmentation, and how hard to fragment.
 *
 * ## What this feature is
 *
 * SHARD sends every packet through the node. That is correct for Telegram and for
 * sanctioned services, which refuse an Iranian exit IP outright — but it is a
 * needless detour for a site that is merely SNI-blocked. YouTube, Instagram and
 * WhatsApp are not sanctioned; they are blocked on the way out, and a fragmented
 * TLS handshake straight from the phone reaches them at the carrier's own speed
 * with no extra hop.
 *
 * So Smart Split runs both legs in one xray process: fragmented-direct for
 * filtered sites, the node for Telegram and sanctioned ones. See
 * [ShardConfigs.tunnelConfig] for the rule table that expresses it.
 *
 * ## Why the fragment profile has to be measured, not chosen
 *
 * The fragmenter has one tuning knob that decides whether it works at all on a
 * given carrier: how long to stall between fragments. Upstream ships two profiles
 * that differ in *nothing else*:
 *
 * ```
 *   PATIENT  delays = ["1"]                             ~0.4 s of stalling
 *   STUBBORN delays = ["1"×9,"400", "1"×9,"400", …]      16-21 s of stalling
 * ```
 *
 * On MCI (همراه اول) PATIENT works and STUBBORN opens nothing. On another
 * carrier whose DPI holds a longer reassembly window it is the other way round.
 * There is no way to know from outside which one a user needs, and the choice is
 * not a preference — it is a measurable fact about their ISP. So the app measures
 * it once per network and never shows the words to the user.
 *
 * Measured cost of getting it wrong, from a server with no DPI in the path at all
 * (i.e. pure overhead, five runs each):
 *
 * ```
 *                probe      page load     3 MB download
 *   PATIENT      0.73 s       0.84 s        3.1 MB/s
 *   STUBBORN     1.96 s       2.05 s        1.5 MB/s
 * ```
 *
 * STUBBORN is not stronger, it is more patient. Where PATIENT already works,
 * picking STUBBORN halves the user's throughput for nothing.
 *
 * ## The two traps in the probe, both of which produce a confident wrong answer
 *
 * **1. It must be HTTPS on 443.** [ShardProbe] targets `/generate_204` on port
 * **80**, which is right for its own job (is this node alive) and wrong for this
 * one. Plain HTTP carries no TLS ClientHello, so the `tlshello` fragment mask
 * never fires and the measurement says nothing about whether fragmentation beats
 * the DPI. A profile can pass a port-80 probe and still open no TLS site.
 *
 * **2. The target must be a blocked SNI.** `cp.cloudflare.com` and
 * `www.gstatic.com` are not filtered in Iran; they answer whether or not the
 * fragmenter works, so they measure latency only. [PROBE_HOSTS] are hosts the
 * censor actually inspects, which is what makes a pass meaningful.
 *
 * A third, subtler one: **the timeout budget must differ per profile.** STUBBORN
 * legitimately needs 16-21 s for a full payload. One shared short budget rejects
 * it on every network and the feature looks permanently broken. Hence
 * [FragmentProfile.probeBudgetMs].
 */
object SmartSplit {

    private const val TAG = "SmartSplit"

    private const val PREFS = "settings"

    /**
     * Master switch. ON by default.
     *
     * Default-on is a deliberate choice with a real trade-off. The gain only exists
     * on a censored carrier: a filtered site reached by fragmented TLS straight from
     * the phone avoids the node hop entirely. On a clean link the same path measures
     * *slower* than the node (5.2 vs 8.2 MB/s), so for a user nobody is blocking
     * this is a small loss.
     *
     * What makes default-on safe is that it is gated on a measurement rather than on
     * hope: if neither fragment profile can carry a blocked SNI, the profile is
     * recorded as unavailable for that network and the session falls back to the
     * historical all-through-the-node config. So the worst case is the old
     * behaviour, arrived at automatically.
     */
    const val ENABLED_PREF = "smart_split_enabled"

    /**
     * Stored when neither profile worked, so the probe is not repeated on every
     * connect for a carrier whose DPI fragmentation does not beat.
     *
     * A separate sentinel rather than "absent", because absent means "not yet
     * measured" and those two must lead to different behaviour.
     */
    private const val NO_PROFILE = "none"

    /** Prefix for the per-network measured profile, e.g. `smart_split_profile_cell:43211`. */
    private const val PROFILE_PREFIX = "smart_split_profile_"

    /**
     * How hard to fragment. The user never sees these names.
     *
     * `delays` is the only difference, and it is expressed here rather than in the
     * config builder because the probe has to be able to hand a specific profile
     * to a specific candidate config.
     *
     * [key] is a storage key, not a label: it goes into preferences and must stay
     * stable across versions, and it must never reach a user-visible surface. The
     * in-app log prints [attempt] instead — see [SmartSplit]'s note on why the
     * mechanism is deliberately invisible.
     */
    enum class FragmentProfile(
        /** Stored in preferences; must stay stable across versions. Never displayed. */
        val key: String,
        /** The `delays` array for both fragment masks. */
        val delays: List<String>,
        /**
         * Probe budget for THIS profile.
         *
         * Not one shared constant: STUBBORN's own stalling accounts for most of
         * its budget, and judging it by PATIENT's clock would fail it everywhere.
         */
        val probeBudgetMs: Int,
    ) {
        PATIENT("patient", listOf("1"), 6_000),

        /**
         * 400 ms every tenth fragment, 31 entries, consumed cyclically by the
         * fork's fragmenter. Copied from upstream's `high_delay` profile — the
         * shape matters, not just the numbers: three stalls spread through the
         * array is what defeats a long reassembly window without making every
         * single fragment slow.
         */
        STUBBORN(
            "stubborn",
            buildList {
                repeat(3) {
                    repeat(9) { add("1") }
                    add("400")
                }
                add("1")
            },
            25_000,
        ),
        ;

        /**
         * What the in-app log calls this attempt: "attempt 1 of 2", never the key.
         *
         * The log is a user-visible surface — it is on the troubleshooting page and
         * the user reads it and forwards it. Printing `patient`/`stubborn` there
         * would hand the user two words to have an opinion about, which is the one
         * thing this feature is designed to avoid. The ordinal still identifies the
         * attempt uniquely for support purposes.
         */
        val attempt: String get() = "attempt ${ordinal + 1} of ${entries.size}"

        companion object {
            fun byKey(key: String?): FragmentProfile? = entries.firstOrNull { it.key == key }
        }
    }

    /**
     * Hosts to probe, in order. Every one is SNI-blocked in Iran.
     *
     * Three different operators, so one company's outage cannot be read as "the
     * fragmenter does not work here". A 200 or a 301 both count: `twitter.com`
     * answers 301 to `/` and that response already proves the handshake completed
     * past the point the DPI inspects.
     */
    private val PROBE_HOSTS = listOf("www.instagram.com", "www.youtube.com", "twitter.com")

    /** Is Smart Split on? Default ON — see [ENABLED_PREF] for the trade-off. */
    fun enabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(ENABLED_PREF, true)

    fun setEnabled(context: Context, value: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(ENABLED_PREF, value).apply()
    }

    /**
     * Cache key for the measured profile: the carrier, not the SSID.
     *
     * `TelephonyManager.simOperator` is MCC+MNC and needs no permission — MCI is
     * 43211, Irancell 43235, Rightel 43220. That is exactly the granularity that
     * matters, because the DPI box belongs to the carrier.
     *
     * On Wi-Fi the upstream ISP is not discoverable without location permission,
     * which this app does not ask for and should not start asking for over a
     * fragment setting. So all Wi-Fi shares one key and the measurement is simply
     * redone when the user moves to a network where it is wrong. That is a worse
     * cache but an honest one; guessing per-SSID without being able to see the ISP
     * would fragment the cache without improving it.
     */
    private fun networkKey(context: Context): String {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return "unknown"
        val capabilities = runCatching {
            manager.getNetworkCapabilities(manager.activeNetwork)
        }.getOrNull()
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) return "wifi"
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) return "eth"
        val operator = runCatching {
            (context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager)
                ?.simOperator.orEmpty()
        }.getOrDefault("")
        return if (operator.isNotEmpty()) "cell:$operator" else "cell"
    }

    /**
     * The profile already measured for this network, or null if never measured.
     *
     * Null also covers the [NO_PROFILE] sentinel: for every caller that wants to
     * *use* a profile, "measured as impossible here" and "not measured" are both
     * "no profile". Only [measuredUnavailable] distinguishes them.
     */
    fun cachedProfile(context: Context): FragmentProfile? {
        val stored = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(PROFILE_PREFIX + networkKey(context), null)
        return FragmentProfile.byKey(stored)
    }

    /**
     * True when this network was probed and neither profile worked.
     *
     * Distinct from `cachedProfile() == null`, which is also true before the first
     * probe. Without the distinction the app would re-probe on every connect for
     * exactly the carriers where probing is known to be futile — paying the full
     * budget twice per session for no possible gain.
     */
    fun measuredUnavailable(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(PROFILE_PREFIX + networkKey(context), null) == NO_PROFILE

    /** Persist a successful measurement for this network. */
    fun remember(context: Context, profile: FragmentProfile) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(PROFILE_PREFIX + networkKey(context), profile.key).apply()
        ConnectionLog.record("$TAG tuned for this network (${profile.attempt})")
    }

    /** Persist "fragmentation does not work on this network". */
    fun recordNoProfile(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(PROFILE_PREFIX + networkKey(context), NO_PROFILE).apply()
    }

    /** Drop every measurement, so the next connect re-probes. For the settings row. */
    fun forgetMeasurements(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val editor = prefs.edit()
        prefs.all.keys.filter { it.startsWith(PROFILE_PREFIX) }.forEach { editor.remove(it) }
        editor.apply()
        ConnectionLog.record("$TAG measurements cleared; next connect will re-probe")
    }

    /**
     * What the settings row shows: the measurement, in the user's terms.
     *
     * Deliberately does not print PATIENT/STUBBORN. The user asked never to see
     * them, and they describe an implementation detail of the fragmenter, not a
     * choice anyone can act on.
     */
    fun summary(context: Context): String = when {
        !enabled(context) -> "Off"
        measuredUnavailable(context) -> "On · not effective on this network"
        cachedProfile(context) == null -> "On · will measure this network"
        else -> "On · tuned for this network"
    }

    /**
     * One HTTPS request through [socksPort] to a blocked SNI. True when it survived.
     *
     * Written by hand on top of a raw SOCKS5 CONNECT for the same reason
     * [ShardProbe] is: `HttpURLConnection` with a `java.net.Proxy` resolves the
     * host on the carrier link first, so on a network with poisoned DNS a working
     * path scores as dead.
     *
     * The TLS handshake is the measurement. Once `startHandshake()` returns, the
     * ClientHello has been fragmented, sent, and answered — which is precisely the
     * thing the DPI is supposed to have blocked. The HTTP request that follows only
     * confirms the session carries data.
     */
    fun probeThroughSocks(socksPort: Int, timeoutMs: Int): Boolean {
        for (host in PROBE_HOSTS) {
            if (probeOne(socksPort, host, timeoutMs)) return true
        }
        return false
    }

    private fun probeOne(socksPort: Int, host: String, timeoutMs: Int): Boolean {
        var raw: Socket? = null
        try {
            raw = Socket()
            raw.tcpNoDelay = true
            raw.soTimeout = timeoutMs
            raw.connect(InetSocketAddress("127.0.0.1", socksPort), 3_000)
            val output = raw.getOutputStream()
            val input = raw.getInputStream()

            output.write(byteArrayOf(0x05, 0x01, 0x00))
            output.flush()
            val greeting = readExactly(input, 2) ?: return false
            if (greeting[0] != 0x05.toByte() || greeting[1] != 0x00.toByte()) return false

            // ATYP=3, hostname: the name must travel inside the tunnel so xray's
            // sniffer and the routing rules see it — an IP here would be routed by
            // geoip alone and the domain rules would never fire.
            val hostBytes = host.toByteArray(Charsets.US_ASCII)
            val request = ByteArray(7 + hostBytes.size)
            request[0] = 0x05
            request[1] = 0x01
            request[2] = 0x00
            request[3] = 0x03
            request[4] = hostBytes.size.toByte()
            System.arraycopy(hostBytes, 0, request, 5, hostBytes.size)
            request[5 + hostBytes.size] = 0x01 // 443 >> 8
            request[6 + hostBytes.size] = 0xBB.toByte() // 443 & 0xFF
            output.write(request)
            output.flush()

            val reply = readExactly(input, 4) ?: return false
            if (reply[1] != 0x00.toByte()) return false
            val addressLength = when (reply[3].toInt() and 0xFF) {
                0x01 -> 4
                0x04 -> 16
                0x03 -> (readExactly(input, 1)?.get(0)?.toInt()?.and(0xFF)) ?: return false
                else -> return false
            }
            readExactly(input, addressLength + 2) ?: return false

            // TLS over the established stream. createSocket(Socket, host, port,
            // autoClose) is the layering form; the SNI is [host], which is the
            // whole point of the exercise.
            val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(raw, host, 443, false) as SSLSocket
            tls.soTimeout = timeoutMs
            tls.startHandshake()
            val tlsOut = tls.outputStream
            tlsOut.write(
                (
                    "HEAD / HTTP/1.1\r\n" +
                        "Host: $host\r\n" +
                        "User-Agent: Mozilla/5.0\r\n" +
                        "Accept: */*\r\n" +
                        "Connection: close\r\n\r\n"
                    ).toByteArray(Charsets.US_ASCII)
            )
            tlsOut.flush()
            val status = readStatusLine(tls.inputStream) ?: return false
            // Any HTTP response at all means the fragmented handshake got through.
            // 301 is what twitter.com answers and it is as good a pass as 200.
            return status.startsWith("HTTP/")
        } catch (_: Exception) {
            return false
        } finally {
            runCatching { raw?.close() }
        }
    }

    private fun readStatusLine(input: InputStream): String? {
        val builder = StringBuilder(64)
        while (builder.length < 128) {
            val byte = input.read()
            if (byte < 0) return builder.takeIf { it.isNotEmpty() }?.toString()
            if (byte == '\n'.code) return builder.toString()
            if (byte != '\r'.code) builder.append(byte.toChar())
        }
        return builder.toString()
    }

    private fun readExactly(input: InputStream, count: Int): ByteArray? {
        val buffer = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = input.read(buffer, read, count - read)
            if (n < 0) return null
            read += n
        }
        return buffer
    }
}
