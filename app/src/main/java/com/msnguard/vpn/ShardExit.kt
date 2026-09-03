package com.msnguard.vpn

import android.content.Context
import java.io.File
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Does the exit behind a node get served by the destination, or refused?
 *
 * ## The problem this solves, and the one it deliberately does not
 *
 * A node can be fast, healthy, and carry every byte correctly, and the site at
 * the far end can still refuse it. [ShardProbe] cannot see that: it asks "did a
 * request survive this tunnel", and the answer is yes. The destination's own
 * verdict is a separate fact, and for one destination it is the whole story —
 * Gemini answers a signed-out landing page that says the service is not
 * available in the caller's country, with HTTP 200 and a full-size body. Nothing
 * at the transport layer distinguishes that from success.
 *
 * Measured on the live pool from a VPS, one node at a time: 22 of 33 exits are
 * served, 4 are refused, the rest are dead or unreachable. So the pool is mostly
 * fine and this check exists for the minority case.
 *
 * ## Why this is not [ShardReach], which was reverted in v1.7.13
 *
 * The previous attempt at the same problem gated the *race* on the destination's
 * verdict: every candidate had to prove itself before it could win. Two things
 * went wrong in the field and both are structural, not tuning:
 *
 *  * It cost ~2.5 s on **every** connect, because the check ran inside the
 *    connect path. The user's one standing requirement for this whole area is
 *    that connect speed must not regress.
 *  * The signal it used (a cookie on a plain-HTTP 301) was validated from a VPS
 *    and answered "refused" for all 12 candidates on a real phone, so the gate
 *    rejected the entire pool and then fell back — paying the cost and deciding
 *    nothing.
 *
 * This class inverts both choices:
 *
 *  * **Nothing runs before the tunnel is up.** The first check happens
 *    [MsnGuardVpnService.SHARD_EXIT_DELAY_S] seconds after CONNECTED, on the
 *    scheduler that is otherwise idle, and it tests the node already carrying
 *    traffic — through the live SOCKS port, so no second process exists.
 *  * **The winner is never re-chosen.** When the live node is refused, the
 *    Google group alone is moved to a second node. Everything else — Telegram,
 *    the sanctioned set, and every direct path — stays exactly where it was.
 *  * **The signal was validated with the code that ships.** See [Verdict].
 *
 * ## Cost
 *
 * One HTTPS request per session in the common case, ~33 KB, once, 20 s after
 * connect. That is the entire budget when the live node is served — which is the
 * majority of the pool. Only a refused node pays more: one short-lived probe
 * process over up to [PROBE_CANDIDATES] nodes, then one relaunch of the tunnel
 * process behind the unchanged SOCKS port.
 *
 * The result is remembered per node, so the second connect on the same pool
 * builds the right config immediately and pays nothing at all.
 */
object ShardExit {

    private const val TAG = "ShardExit"

    private const val PREFS = "shard_exit"

    /**
     * Which node currently owns the Google group, as a [ShardNode.key].
     *
     * Stored separately from the per-node verdicts because it is the answer to a
     * different question: the verdicts say what each exit does, this says which
     * one was chosen. Read by [ShardManager.start] to build the config right the
     * first time.
     */
    private const val CHOSEN_PREF = "chosen"

    /**
     * How long a verdict is trusted, in ms.
     *
     * Twelve hours, because the thing being measured changes on the *destination's*
     * schedule, not ours: an exit IP moves in or out of Google's refused set when
     * its reputation changes, which is days, not minutes. Shorter than that only
     * buys re-probing a fact that has not moved; much longer and a user whose node
     * became usable would keep taking a needless second hop.
     */
    private const val FRESH_MS = 12L * 60 * 60 * 1000

    /**
     * How many alternatives to probe when the live node is refused.
     *
     * Six, not twelve. The measured hit rate is 22 in 33, so six ranked
     * candidates miss with probability under one percent — and this runs on a
     * metered link with the tunnel already up, where a wide fan-out is pure cost.
     */
    private const val PROBE_CANDIDATES = 6

    /** Base port for the exit-probe process. Clear of the race's 21100-21199. */
    private const val PROBE_BASE_PORT = 21200

    /** Budget for one exit check, in ms. Generous: this is off the connect path. */
    private const val PROBE_TIMEOUT_MS = 20_000

    /**
     * What the destination said about an exit.
     *
     * ## How the marker was chosen, and why it is a body match rather than a header
     *
     * Every candidate signal that lives in the response *envelope* was measured
     * and rejected. The status is 200 either way. The headers are byte-identical
     * apart from lengths. A plain-HTTP 301 carries a cookie that separates the
     * two classes from a server and does not from a phone — that is the v1.7.12
     * failure. What is left is the page's own bootstrap state.
     *
     * ```
     *   served:   …"BJ3e":"https://docs.google.com/picker","FL1an":false,"FdrFJe":…
     *   refused:  …"BJ3e":"https://docs.google.com/picker","FL1an":true, "FdrFJe":…
     * ```
     *
     * Measured over 8 exits of both kinds: the flag sits at a stable offset near
     * 4 KB into the body, `false` on every served exit and `true` on every
     * refused one, with no overlap. The human-readable wall text ("not currently
     * supported in your country") is **not** in the HTML at all — it is rendered
     * from this flag — so matching the sentence the user sees would never work.
     *
     * The country code Google assigns the caller is also in the page, and it is
     * the more satisfying signal, but it appears ~217 KB in. That is 6× the data
     * for a fact this flag already carries.
     *
     * ## UNKNOWN is not REFUSED
     *
     * A timeout, a TLS failure, a redirect somewhere unexpected: all UNKNOWN.
     * The v1.7.12 gate treated "I could not tell" as "reject" and thereby
     * condemned a working pool. Nothing in this class acts on UNKNOWN.
     */
    enum class Verdict { SERVED, REFUSED, UNKNOWN }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Stored as `verdict:whenMillis`, so freshness is per node. */
    private fun stored(context: Context, node: ShardNode): Pair<Verdict, Long>? {
        val raw = prefs(context).getString(node.key, null) ?: return null
        val parts = raw.split(':')
        val verdict = when (parts.getOrNull(0)) {
            "s" -> Verdict.SERVED
            "r" -> Verdict.REFUSED
            else -> return null
        }
        return verdict to (parts.getOrNull(1)?.toLongOrNull() ?: 0L)
    }

    private fun remember(context: Context, node: ShardNode, verdict: Verdict) {
        if (verdict == Verdict.UNKNOWN) return
        val code = if (verdict == Verdict.SERVED) "s" else "r"
        prefs(context).edit()
            .putString(node.key, "$code:${System.currentTimeMillis()}")
            .apply()
    }

    /**
     * The fresh verdict for [node], or null when unmeasured or stale.
     *
     * Private: everything that needs a verdict goes through [chosenExit] or
     * [evaluate], and keeping the raw accessor internal is what stops a caller
     * from treating a stale or UNKNOWN reading as a decision.
     */
    private fun freshVerdict(context: Context, node: ShardNode): Verdict? {
        val (verdict, at) = stored(context, node) ?: return null
        if (System.currentTimeMillis() - at > FRESH_MS) return null
        return verdict
    }

    /**
     * The node that should carry the Google group, or null for "the live node".
     *
     * Null is the answer in every ordinary case: either the live node is fine, or
     * nothing has been measured yet. Only a stored choice that is still in the
     * pool and still fresh produces a node here, which is what lets [start] build
     * a correct config with no probing at all.
     */
    fun chosenExit(context: Context, pool: List<ShardNode>): ShardNode? {
        val key = prefs(context).getString(CHOSEN_PREF, null) ?: return null
        val node = pool.firstOrNull { it.key == key } ?: return null
        return if (freshVerdict(context, node) == Verdict.SERVED) node else null
    }

    private fun setChosen(context: Context, node: ShardNode?) {
        val editor = prefs(context).edit()
        if (node == null) editor.remove(CHOSEN_PREF) else editor.putString(CHOSEN_PREF, node.key)
        editor.apply()
    }

    /** Forget everything. For the settings row that resets the transport. */
    fun clear(context: Context) {
        prefs(context).edit().clear().apply()
    }

    /**
     * Drop verdicts for nodes that left the pool, exactly as [ShardHealth.prune] does.
     *
     * Without it this file grows forever: the publisher's nodes rotate daily.
     * [CHOSEN_PREF] is skipped explicitly — it is not a node key and pruning it
     * would throw the choice away on every refresh.
     */
    fun prune(context: Context, pool: List<ShardNode>) {
        val live = pool.map { it.key }.toSet()
        val editor = prefs(context).edit()
        prefs(context).all.keys.forEach { key ->
            if (key != CHOSEN_PREF && key !in live) editor.remove(key)
        }
        editor.apply()
    }

    /**
     * The whole post-connect decision, run once per session off the connect path.
     *
     * Returns true when the caller should relaunch the tunnel to apply a second
     * exit — i.e. when the live node is refused AND an alternative was found. In
     * every other case it returns false, having either confirmed the live node or
     * learned nothing, and the session is left completely untouched.
     *
     * @param socksPort the live tunnel's own port, so the common case needs no
     *   second process.
     */
    fun evaluate(context: Context, live: ShardNode, socksPort: Int, pool: List<ShardNode>): Boolean {
        val known = freshVerdict(context, live)
        val verdict = known ?: check(socksPort).also { remember(context, live, it) }
        when (verdict) {
            Verdict.SERVED -> {
                // The live node is fine, so there is nothing to split. Clearing the
                // stored choice matters: a user who moves from a refused node to a
                // served one must stop paying for the second hop.
                if (prefs(context).contains(CHOSEN_PREF)) setChosen(context, null)
                ConnectionLog.record("$TAG exit check served")
                return false
            }
            Verdict.UNKNOWN -> {
                // Explicitly does nothing. See [Verdict].
                ConnectionLog.record("$TAG exit check inconclusive; unchanged")
                return false
            }
            Verdict.REFUSED -> Unit
        }
        ConnectionLog.record("$TAG exit check refused — looking for a second exit")

        // Anything already known-served and still in the pool is free to use.
        val ranked = ShardHealth.rank(context, pool).filter { it.key != live.key }
        ranked.firstOrNull { freshVerdict(context, it) == Verdict.SERVED }?.let { cached ->
            setChosen(context, cached)
            ConnectionLog.record("$TAG second exit known: ${LogRedactor.nodeTag(cached.key)}")
            return true
        }

        val candidates = ranked
            .filter { freshVerdict(context, it) != Verdict.REFUSED }
            .take(PROBE_CANDIDATES)
        if (candidates.isEmpty()) {
            ConnectionLog.record("$TAG no candidate for a second exit")
            return false
        }
        val found = probePool(context, candidates)
        if (found == null) {
            ConnectionLog.record("$TAG no second exit answered")
            return false
        }
        setChosen(context, found)
        ConnectionLog.record("$TAG second exit selected: ${LogRedactor.nodeTag(found.key)}")
        return true
    }

    /**
     * Probe [candidates] through their own short-lived process and return the first
     * served one.
     *
     * Deliberately does not touch [ShardManager]'s process handle. The tunnel is
     * running while this executes, and borrowing `ShardManager.launch` would
     * overwrite the field the watchdog and [ShardManager.stop] both read — the
     * tunnel's own process would be leaked and the next teardown would kill the
     * wrong thing. So this owns its `Process` from start to finish.
     *
     * Sequential rather than raced. The tunnel is already carrying the user's
     * traffic; opening six TLS sessions to Google beside it to save a few seconds
     * of a background task is the wrong trade.
     */
    private fun probePool(context: Context, candidates: List<ShardNode>): ShardNode? {
        val binary = File(context.applicationInfo.nativeLibraryDir, "libxray.so")
        if (!binary.exists()) return null
        val config = ShardConfigs.probeConfig(candidates, PROBE_BASE_PORT)
        val configFile = ShardConfigs.writeConfig(context, "exit-probe.json", config)
        val process = try {
            ProcessBuilder(binary.absolutePath, "run", "-c", configFile.absolutePath).apply {
                directory(configFile.parentFile)
                redirectErrorStream(true)
                environment()["HOME"] = context.filesDir.absolutePath
                environment()["XRAY_LOCATION_ASSET"] = configFile.parent
            }.start()
        } catch (e: Exception) {
            ConnectionLog.record("$TAG exit probe could not start: ${e.message}")
            return null
        }
        // Drained and discarded: a process whose stdout fills the pipe buffer stops
        // serving. Nothing it says is worth logging here.
        Thread({
            runCatching { process.inputStream.use { stream -> while (stream.read() >= 0) Unit } }
        }, "shard-exit-log").apply { isDaemon = true }.start()

        try {
            val deadline = System.currentTimeMillis() + 4000
            var ready = false
            while (System.currentTimeMillis() < deadline) {
                if (portAccepts(PROBE_BASE_PORT, 300)) {
                    ready = true
                    break
                }
                Thread.sleep(100)
            }
            if (!ready) return null

            candidates.forEachIndexed { index, node ->
                val verdict = check(PROBE_BASE_PORT + index)
                remember(context, node, verdict)
                if (verdict == Verdict.SERVED) return node
            }
            return null
        } catch (e: Exception) {
            ConnectionLog.record("$TAG exit probe failed: ${e.message}")
            return null
        } finally {
            runCatching {
                process.destroy()
                if (!process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                    process.destroyForcibly()
                }
            }
            runCatching { configFile.delete() }
        }
    }

    private fun portAccepts(port: Int, timeoutMs: Int): Boolean = try {
        Socket().use {
            it.connect(InetSocketAddress("127.0.0.1", port), timeoutMs)
            true
        }
    } catch (_: Exception) {
        false
    }

    // --- the check itself ---------------------------------------------------

    private const val CHECK_HOST = "gemini.google.com"

    private const val CHECK_PATH = "/app"

    /**
     * How much body to read before giving up on finding the marker.
     *
     * The flag was measured at ~4 KB into the *decoded* body on every exit of both
     * kinds. 48 KB is an order of magnitude of headroom for a layout change,
     * while still being a small fraction of the 840 KB page — and the socket is
     * closed the instant the marker is found, so the common case transfers far
     * less than this.
     */
    private const val READ_CAP = 48 * 1024

    /**
     * A mobile Chrome UA, and it is not decoration.
     *
     * Google serves a different bootstrap to clients it does not recognise, and
     * that variant does not carry the flag at all — the check would return UNKNOWN
     * for every node. The `Accept-Language` header is here for the same reason.
     *
     * `Accept-Encoding: identity` is the load-bearing one: this class scans raw
     * bytes for a literal, and a gzipped body contains no literals. Asking for an
     * uncompressed page costs bandwidth that the [READ_CAP] already bounds, and
     * buys not having to ship an inflater into the scan path.
     */
    private const val UA = "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36"

    private val SERVED_MARKER = "\"FL1an\":false".toByteArray(Charsets.US_ASCII)

    private val REFUSED_MARKER = "\"FL1an\":true".toByteArray(Charsets.US_ASCII)

    /**
     * Ask the destination what it thinks of the exit behind [socksPort].
     *
     * Hand-rolled SOCKS5 + JSSE for the same reason [ShardProbe] and
     * [SmartSplit.probeOne] are: `HttpURLConnection` with a `java.net.Proxy`
     * resolves the host on the carrier link before connecting, so on a network
     * with poisoned DNS a perfectly good exit scores as unreachable. ATYP=3 sends
     * the name through the tunnel, which is also how the app's real traffic goes.
     *
     * Validated against the live pool with a byte-for-byte twin of this routine
     * (`gem_probe_twin.py`): 6 nodes, 6 correct verdicts, 0.8-4.8 s each. Three
     * were served (32-33 KB, marker ~16 KB in), two refused on the flag, and the
     * phone's own node refused via a 302 to `/sorry/` after 579 bytes — the
     * cheapest possible answer, and the reason that redirect is handled as a
     * verdict rather than an error.
     */
    fun check(socksPort: Int): Verdict {
        var raw: Socket? = null
        try {
            raw = Socket()
            raw.tcpNoDelay = true
            raw.soTimeout = PROBE_TIMEOUT_MS
            raw.connect(InetSocketAddress("127.0.0.1", socksPort), 3_000)
            val output = raw.getOutputStream()
            val input = raw.getInputStream()

            output.write(byteArrayOf(0x05, 0x01, 0x00))
            output.flush()
            val greeting = readExactly(input, 2) ?: return Verdict.UNKNOWN
            if (greeting[0] != 0x05.toByte() || greeting[1] != 0x00.toByte()) return Verdict.UNKNOWN

            val hostBytes = CHECK_HOST.toByteArray(Charsets.US_ASCII)
            val request = ByteArray(7 + hostBytes.size)
            request[0] = 0x05
            request[1] = 0x01
            request[2] = 0x00
            request[3] = 0x03
            request[4] = hostBytes.size.toByte()
            System.arraycopy(hostBytes, 0, request, 5, hostBytes.size)
            request[5 + hostBytes.size] = 0x01 // 443 ushr 8
            request[6 + hostBytes.size] = 0xBB.toByte() // 443 and 0xFF
            output.write(request)
            output.flush()

            val reply = readExactly(input, 4) ?: return Verdict.UNKNOWN
            if (reply[1] != 0x00.toByte()) return Verdict.UNKNOWN
            val addressLength = when (reply[3].toInt() and 0xFF) {
                0x01 -> 4
                0x04 -> 16
                0x03 -> (readExactly(input, 1)?.get(0)?.toInt()?.and(0xFF)) ?: return Verdict.UNKNOWN
                else -> return Verdict.UNKNOWN
            }
            readExactly(input, addressLength + 2) ?: return Verdict.UNKNOWN

            val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(raw, CHECK_HOST, 443, false) as SSLSocket
            tls.soTimeout = PROBE_TIMEOUT_MS
            tls.startHandshake()
            tls.outputStream.apply {
                write(
                    (
                        "GET $CHECK_PATH HTTP/1.1\r\n" +
                            "Host: $CHECK_HOST\r\n" +
                            "User-Agent: $UA\r\n" +
                            "Accept: text/html\r\n" +
                            "Accept-Language: en-US,en;q=0.9\r\n" +
                            "Accept-Encoding: identity\r\n" +
                            "Connection: close\r\n\r\n"
                        ).toByteArray(Charsets.US_ASCII)
                )
                flush()
            }
            return readVerdict(tls.inputStream)
        } catch (_: Exception) {
            return Verdict.UNKNOWN
        } finally {
            runCatching { raw?.close() }
        }
    }

    /**
     * Read headers, then scan the body for the flag.
     *
     * A 302 to Google's `/sorry/` is REFUSED and not UNKNOWN: that is the
     * anti-abuse challenge, which a phone cannot solve inside a tunnel, so for the
     * purpose of "can this exit open Gemini" it is a no. Measured on three nodes
     * of the live pool, all three shared-IP Cloudflare Workers exits.
     *
     * The body is de-chunked when the response says it is chunked. Skipping that
     * would work by luck: the marker usually lands inside the first chunk, and a
     * chunk-size line falling in the middle of the literal would flip the verdict
     * to UNKNOWN at random. Measured both framings in the field — 200 with
     * `Transfer-Encoding: chunked` from one path and plain from another.
     */
    private fun readVerdict(input: InputStream): Verdict {
        val head = readHead(input) ?: return Verdict.UNKNOWN
        val status = head.substringBefore("\r\n")
        if (status.contains(" 301") || status.contains(" 302")) {
            val location = head.split("\r\n")
                .firstOrNull { it.startsWith("location:", ignoreCase = true) }
                ?.substringAfter(':')
                ?.trim()
                .orEmpty()
            return if (location.contains("/sorry/")) Verdict.REFUSED else Verdict.UNKNOWN
        }
        if (!status.contains(" 200")) return Verdict.UNKNOWN
        val chunked = head.lineSequence().any {
            it.startsWith("transfer-encoding:", ignoreCase = true) && it.contains("chunked", true)
        }
        return scanBody(input, chunked)
    }

    /**
     * Read up to the blank line. Returns the header block, or null if it never ends.
     *
     * The 64 KB cap is not arbitrary padding. Gemini's served response carries a
     * header block of ~28.7 KB — the CSP alone enumerates every `google.<tld>` —
     * measured on four served exits (28.2-28.7 KB). A 16 KB cap, which looks
     * generous for HTTP, silently returns null for exactly the nodes this class
     * exists to find: every good exit would score UNKNOWN and the feature would
     * never engage. Refused exits are the small ones (~0.6 KB).
     */
    private fun readHead(input: InputStream): String? {
        val buffer = StringBuilder(2048)
        var state = 0
        while (buffer.length < 64 * 1024) {
            val byte = input.read()
            if (byte < 0) return null
            val ch = byte.toChar()
            buffer.append(ch)
            state = when {
                ch == '\r' -> if (state == 2) 3 else 1
                ch == '\n' -> if (state == 1) 2 else if (state == 3) 4 else 0
                else -> 0
            }
            if (state == 4) return buffer.toString()
        }
        return null
    }

    /**
     * Scan for whichever marker appears first, within [READ_CAP] decoded bytes.
     *
     * A sliding window rather than an accumulated buffer: only the last
     * `marker length - 1` bytes need to survive across reads, so this holds a few
     * dozen bytes instead of tens of kilobytes on a phone.
     */
    private fun scanBody(input: InputStream, chunked: Boolean): Verdict {
        val keep = maxOf(SERVED_MARKER.size, REFUSED_MARKER.size) - 1
        val window = StringBuilder(keep + 8192)
        var consumed = 0
        val chunk = ByteArray(8192)

        // Chunked framing: the size line, then that many bytes, then CRLF. Written
        // as a small state machine so one read can span any number of chunks.
        var remaining = if (chunked) -1 else Int.MAX_VALUE
        val sizeLine = StringBuilder(16)

        while (consumed < READ_CAP) {
            val read = input.read(chunk)
            if (read < 0) return Verdict.UNKNOWN
            var index = 0
            while (index < read) {
                if (remaining == -1) {
                    // Reading a chunk-size line.
                    val ch = chunk[index++].toInt().toChar()
                    if (ch == '\n') {
                        val hex = sizeLine.toString().substringBefore(';').trim()
                        sizeLine.setLength(0)
                        if (hex.isEmpty()) continue
                        remaining = hex.toIntOrNull(16) ?: return Verdict.UNKNOWN
                        if (remaining == 0) return Verdict.UNKNOWN
                    } else if (ch != '\r') {
                        if (sizeLine.length < 16) sizeLine.append(ch)
                    }
                    continue
                }
                val take = minOf(remaining, read - index)
                for (i in index until index + take) window.append(chunk[i].toInt().toChar())
                consumed += take
                index += take
                if (remaining != Int.MAX_VALUE) {
                    remaining -= take
                    // Chunk finished: the trailing CRLF is skipped by returning to
                    // the size-line state, which ignores stray CR and LF.
                    if (remaining == 0) remaining = -1
                }
                val verdict = markerIn(window)
                if (verdict != null) return verdict
                if (window.length > keep) window.delete(0, window.length - keep)
                if (consumed >= READ_CAP) break
            }
        }
        return Verdict.UNKNOWN
    }

    private fun markerIn(window: StringBuilder): Verdict? {
        val text = window
        if (text.indexOf("\"FL1an\":false") >= 0) return Verdict.SERVED
        if (text.indexOf("\"FL1an\":true") >= 0) return Verdict.REFUSED
        return null
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
