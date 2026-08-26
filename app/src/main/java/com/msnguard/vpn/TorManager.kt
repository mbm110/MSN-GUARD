package com.msnguard.vpn

import android.content.Context
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the Tor process and its pluggable transport.
 *
 * ## Shape of a Tor session in this app
 *
 * ```
 *   TUN ─► tun2socks ─► TorSocksFront ─► libtor.so SocksPort ─► circuit
 *                            └─ DNS ──► libtor.so DNSPort
 *                                       libtor.so ─► libobfs4proxy.so (PT)
 * ```
 *
 * Both native files are executed as **processes**, not loaded as libraries.
 * That is forced, not chosen: the built `libtor.so` exports no `tor_run_main`
 * (verified against the CI artifact — its dynamic symbol table has no `tor_*`
 * entry at all), so there is nothing to `dlopen` and call. It has to be
 * `exec`'d, which in turn is why `useLegacyPackaging = true` is set in
 * `app/build.gradle.kts`: without it AGP 8 leaves the libraries compressed
 * inside the APK and never writes them to `nativeLibraryDir`, so there is no
 * executable file on disk to launch.
 *
 * ## Why the transports are one binary
 *
 * `libobfs4proxy.so` is lyrebird 0.8.1, which carries obfs4, meek_lite,
 * snowflake and webtunnel in a single executable. It is launched once per
 * session with every transport we might need, and it announces a separate SOCKS
 * port per transport on stdout (`CMETHOD <name> socks5 <host:port>`). Tor is
 * then told about those ports directly. We launch it ourselves rather than
 * letting Tor `exec` it, because Tor's own PT launcher is the part most likely
 * to be blocked by SELinux on a given vendor ROM.
 */
object TorManager {

    private const val TAG = "TorManager"

    /**
     * Ports Tor binds. Chosen to sit clear of [CoreConfig.SOCKS_PORT] (1819) and
     * [CoreConfig.CHAIN_SOCKS_PORT] (1820), which the Rust core and Psiphon own.
     */
    const val FRONT_SOCKS_PORT = 1821
    private const val TOR_SOCKS_PORT = 1822
    private const val TOR_DNS_PORT = 1823

    /** Preference key holding the user's choice of [TorMode]. */
    const val MODE_PREF = "tor_mode"

    /**
     * Whether Tor should ride inside a WARP tunnel (Tor-over-WARP).
     *
     * A separate key from the Psiphon chain's `chain_armed`, deliberately. They
     * are two independent features that happen to share a mechanism, and one
     * switch for both would mean arming the chain for Psiphon silently changed
     * how Tor connects — a setting the user never touched altering a transport
     * they did not select.
     *
     * Defaults ON for the same reason the Psiphon chain does: on the carriers
     * this app exists for, Tor's own dials are what get blocked, and the WARP
     * rung that carries them is remembered per device so the search is paid once.
     */
    const val CHAIN_ARMED_PREF = "tor_chain_armed"
    const val CHAIN_ARMED_DEFAULT = true

    /**
     * Which rung of the AUTO ladder last carried a working circuit.
     *
     * Same idea as [CoreConfig.PLAIN_WORKING_TRANSPORT_PREF] for Psiphon: a
     * device on a carrier that blocks direct Tor pays the 30-second direct
     * timeout once, not on every connect.
     *
     * Two keys, one per shape of the session — see [winnerPref]. A rung that
     * works from inside WARP is not evidence that it works on the bare carrier,
     * or the other way round: the whole reason for chaining is that the carrier
     * blocks what WARP carries fine. Sharing one key would have each mode
     * overwrite the other's memory and send the next connect to a rung with no
     * evidence behind it at all.
     */
    private const val WINNER_PREF = "tor_winning_mode"
    private const val WINNER_PREF_CHAINED = "tor_winning_mode_chained"

    private fun winnerPref(chained: Boolean): String =
        if (chained) WINNER_PREF_CHAINED else WINNER_PREF

    /**
     * How long to wait for lyrebird's `CMETHODS DONE`.
     *
     * It is a local process doing no network work at startup, so this only ever
     * expires when the binary is broken or blocked from executing.
     */
    private const val PT_HANDSHAKE_TIMEOUT_S = 10L

    /**
     * How long a rung may sit at the **same percentage** before it is escalated.
     *
     * This replaced a fixed per-rung budget, which is what made every transport
     * look broken on a network where they were all working. Field log, one
     * attempt per rung, ladder order:
     *
     * ```
     *   Direct    45% reached,          killed at its 90s deadline
     *   Meek      45% in 5s, then 50%,  killed at its 60s deadline
     *   obfs4     45% in 23s, then 50%, killed at its 60s deadline
     *   Snowflake 45% in 15s, then 50%, killed at its 60s deadline
     * ```
     *
     * Every rung reached "asking for relay descriptors" (45%) and moved into
     * "loading relay descriptors" (50%). Getting there means the transport
     * carried a TLS handshake, a consensus download and an authority-cert
     * download — the transport was never the problem. What did not fit in 60s is
     * the descriptor download that follows, which is the long pole on a slow
     * link and costs an HTTP round trip per cell over meek. Not one rung
     * reported an error; all four reported a deadline.
     *
     * SlipNet has no per-transport timeout at all — its `startClient` returns as
     * soon as tor is spawned and the UI waits as long as the user tolerates.
     * That is why it connects on this network while we declared failure.
     *
     * So bound the thing that actually distinguishes a blocked transport from a
     * slow one: absence of movement. 90s and not less, because the descriptor
     * phase advances in batches and a single batch over meek can legitimately
     * take that long — a 45s window would have killed the field log's Meek rung
     * *earlier* than the old fixed budget did.
     */
    private const val STALL_TIMEOUT_S = 90L

    /**
     * Absolute ceiling per rung, however well it is progressing.
     *
     * Only a backstop against a transport that dribbles one percent a minute
     * forever. Bridges get longer than direct because the slow phase is the
     * descriptor download and on a bridge rung that runs over the bridge.
     *
     * Worst case for the whole AUTO ladder is now bounded by the stall detector,
     * not by these: four blocked transports cost 4 × 90s, not 4 × ceiling.
     */
    private const val DIRECT_TIMEOUT_S = 150L
    private const val BRIDGE_TIMEOUT_S = 300L

    /** Poll interval while waiting for bootstrap. */
    private const val BOOTSTRAP_POLL_MS = 250L

    /**
     * The connection modes offered in the UI.
     *
     * [AUTO] is not a transport — it walks the others in order. The rest are
     * single-transport modes for a user who already knows what works on their
     * SIM and does not want to pay for failed attempts.
     */
    enum class TorMode(
        val key: String,
        val label: String,
        val description: String,
    ) {
        AUTO("auto", "Auto", "Tries each method until one connects"),
        DIRECT("direct", "Direct", "No bridge; fastest where Tor is not blocked"),
        OBFS4("obfs4", "obfs4", "Bridge that hides Tor's traffic shape"),
        MEEK("meek", "Meek", "Rides a CDN; slow but hard to block"),
        SNOWFLAKE("snowflake", "Snowflake", "Volunteer WebRTC proxies");

        companion object {
            fun from(key: String?): TorMode =
                entries.firstOrNull { it.key == key } ?: AUTO
        }
    }

    /** One rung of the AUTO ladder. */
    private class Rung(val mode: TorMode, val timeoutSeconds: Long)

    /**
     * Ladder order, as specified: Direct → Meek → obfs4 → Snowflake.
     *
     * Direct first because when it works it is both fastest to connect and
     * fastest to use. Meek next: it works nearly everywhere because it looks
     * like HTTPS to a CDN, but every cell pays an HTTP round trip, so it is the
     * preferred bridge ahead of obfs4. obfs4 after that — plain TCP
     * obfuscation, fast once connected, but its public bridges are the first
     * thing a censor scans for. Snowflake last: finding a volunteer proxy
     * through a broker is the highest-variance step of the four.
     */
    private val ladder = listOf(
        Rung(TorMode.DIRECT, DIRECT_TIMEOUT_S),
        Rung(TorMode.MEEK, BRIDGE_TIMEOUT_S),
        Rung(TorMode.OBFS4, BRIDGE_TIMEOUT_S),
        Rung(TorMode.SNOWFLAKE, BRIDGE_TIMEOUT_S),
    )

    /**
     * The modes that may run inside WARP, in ladder order: Direct, then Meek.
     *
     * Measured on the VPS through a real SOCKS5 proxy, tor 0.4.6.10 / lyrebird
     * 0.0.13, with the app's own bridge lines:
     *
     * ```
     *   Direct    via proxy         100% in 12-15s, then 42s with the country picker on
     *   meek_lite via TOR_PT_PROXY  100% in 36s, 75 CDN dials all crossing the proxy
     *   obfs4     via proxy          10% / 85% — and 85% vs 10% flipped between two
     *                                runs of the SAME bridge with no proxy at all
     *   Snowflake                    never tested through a proxy
     * ```
     *
     * So obfs4 and Snowflake are excluded, and the reason is the absence of
     * evidence rather than evidence of harm. obfs4 was never shown to be hurt by
     * the proxy — it was never shown to work reliably *at all* on these bridges,
     * which is worse: chaining it would put an unpredictable rung inside a
     * tunnel that costs a second handshake, and any failure would then be
     * unattributable between the two layers. Snowflake has its own broker and
     * WebRTC dials that a SOCKS5 CONNECT cannot carry.
     *
     * Both remain fully available **unchained** — they are still rungs 3 and 4 of
     * [ladder], and pinning them in settings still works. This list only decides
     * what a chained session is allowed to try.
     */
    private val chainedLadder = listOf(
        Rung(TorMode.DIRECT, DIRECT_TIMEOUT_S),
        Rung(TorMode.MEEK, BRIDGE_TIMEOUT_S),
    )

    /** Whether [mode] can run inside the WARP chain at all. */
    fun isChainable(mode: TorMode): Boolean =
        mode == TorMode.AUTO || chainedLadder.any { it.mode == mode }

    /**
     * Whether the next Tor connect should ride inside WARP.
     *
     * Reads the switch, but also refuses for the two transports that cannot be
     * chained: with obfs4 or Snowflake pinned there is nothing the chain could
     * carry, so arming it would either be ignored silently or break the pin. The
     * UI mirrors this rule so the switch is never lit for a mode it cannot apply
     * to.
     */
    fun chainArmed(context: Context): Boolean =
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean(CHAIN_ARMED_PREF, CHAIN_ARMED_DEFAULT) &&
            isChainable(selectedMode(context))

    /**
     * The SOCKS5 proxy every dial of this session must go through, or null.
     *
     * Set once by the service before [start] when the outer WARP leg is up, and
     * cleared on [stop]. Held here rather than passed through [start] because
     * [writeTorrc] and [startPt] both need it and neither is on the caller's
     * side of the API.
     */
    @Volatile
    private var upstreamProxy: String? = null

    /** Point this session's dials at `host:port`, or clear with null. */
    fun useUpstreamProxy(hostPort: String?) {
        upstreamProxy = hostPort
    }

    @Volatile
    private var torProcess: Process? = null

    @Volatile
    private var ptProcess: Process? = null

    private val stopping = AtomicBoolean(false)

    @Volatile
    private var bootstrapPercent: Int = 0

    @Volatile
    private var lastLoggedPercent: Int = -1

    /** Transport → "host:port" as announced by lyrebird. */
    private val ptMethods = mutableMapOf<String, String>()

    /** The mode that actually produced a bootstrapped circuit, for the UI. */
    @Volatile
    var activeMode: TorMode? = null
        private set

    /** True while a Tor session is up — the UI's probe must use our front port. */
    val isTorActive: Boolean get() = activeMode != null

    val isRunning: Boolean
        get() = torProcess?.isAlive == true

    /** 0..100, for the connecting screen. */
    val progress: Int
        get() = bootstrapPercent

    fun selectedMode(context: Context): TorMode =
        TorMode.from(
            context.getSharedPreferences("settings", Context.MODE_PRIVATE)
                .getString(MODE_PREF, TorMode.AUTO.key)
        )

    // ------------------------------------------------------------------ torrc

    /**
     * Which lyrebird transports a mode needs.
     *
     * Direct needs none. Everything else names exactly one, so lyrebird is not
     * asked to stand up listeners nobody will dial.
     */
    private fun transportFor(mode: TorMode): String? = when (mode) {
        TorMode.DIRECT, TorMode.AUTO -> null
        TorMode.OBFS4 -> "obfs4"
        TorMode.MEEK -> "meek_lite"
        TorMode.SNOWFLAKE -> "snowflake"
    }

    private fun bridgeLinesFor(mode: TorMode): List<String> = when (mode) {
        TorMode.OBFS4 -> TorBridges.OBFS4
        TorMode.MEEK -> TorBridges.MEEK
        TorMode.SNOWFLAKE -> TorBridges.SNOWFLAKE
        else -> emptyList()
    }

    /**
     * Copy the GeoIP databases out of assets into real files Tor can open.
     *
     * Necessary because `GeoIPFile` takes a filesystem path and Android assets
     * are not files — they live inside the APK. Copied once and reused: the IPv4
     * database is 6.4 MB, so re-copying on every connect would be a pointless
     * 6.4 MB write each time.
     *
     * Freshness is keyed on the app's own versionCode rather than on file size.
     * AGP stores these assets deflated, which makes `openFd` throw and leaves no
     * cheap way to learn the real asset length — so a size check would silently
     * keep a stale database after an update that added a country to the picker.
     * The stamp costs one small file and cannot get that wrong.
     *
     * Returns the directory holding both files, or null when the copy failed.
     * Null is not fatal on its own — see [writeTorrc], which then omits the
     * country preference rather than shipping a torrc that cannot work.
     */
    private fun geoipDir(context: Context): File? {
        val dir = File(context.filesDir, "geoip").apply { mkdirs() }
        val v4 = File(dir, "geoip")
        val v6 = File(dir, "geoip6")
        val stamp = File(dir, "unpacked-version")

        val version = runCatching {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(context.packageName, 0).versionCode.toString()
        }.getOrDefault("0")

        val current = runCatching { stamp.readText().trim() }.getOrDefault("")
        if (current == version && v4.length() > 0 && v6.exists()) return dir

        for ((asset, target) in listOf("geoip" to v4, "geoip6" to v6)) {
            val copied = runCatching {
                context.assets.open(asset).use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
            }
            if (copied.isFailure) {
                ConnectionLog.record(
                    "$TAG could not unpack $asset: ${copied.exceptionOrNull()?.message}"
                )
                return null
            }
        }
        runCatching { stamp.writeText(version) }
        return dir.takeIf { v4.length() > 0 && v6.exists() }
    }

    /**
     * Write the torrc for one attempt.
     *
     * Notable choices, all of them about a phone on a censored network rather
     * than a desktop:
     *
     *  - **`GeoIPFile` is mandatory whenever a country is preferred.** Without a
     *    GeoIP database Tor cannot map a country to relays, so `ExitNodes {cc}`
     *    resolves to an empty set and bootstrap stalls forever — measured at
     *    45-50% and never recovering, which is exactly the 1.4.3 bug. The
     *    databases are therefore bundled, filtered down to the countries the
     *    picker offers (6.4 MB on disk, 1.8 MB in the APK). See
     *    `tools/filter-geoip.py`.
     *  - **`AvoidDiskWrites 1`** keeps Tor's caches in RAM and flushes on clean
     *    shutdown only. Less flash wear and less wakeup work while backgrounded.
     *  - **`DormantClientTimeout`** raised from Tor's 24-hour default to 4 weeks.
     *    On the default, Tor shuts itself down after a day idle and the next
     *    connect pays a full bootstrap — which over meek or snowflake is minutes.
     *  - **`NumEntryGuards 1`** and re-drawing the guard on direct mode. Tor
     *    normally sticks to a chosen guard for weeks, which is right for
     *    anonymity and wrong here: one unreachable guard would make every
     *    connect attempt fail identically. Bridge modes do **not** get the
     *    redraw — see [keepTorState].
     *  - **`Socks5Proxy` only without a transport.** Tor refuses to start when a
     *    proxy and a **managed** `ClientTransportPlugin` are both configured:
     *    measured on 0.4.6.10, `You have configured an external proxy with
     *    another proxy type` then `Invalid client transport line`, exit before
     *    the first bootstrap line. So on the direct rung the proxy goes in the
     *    torrc, and on a bridge rung it must NOT — the PT is told instead, via
     *    `TOR_PT_PROXY` in [startPt]. That is not a workaround but the correct
     *    layering: with `UseBridges 1` tor's OR connections terminate at the PT's
     *    local listener and the PT makes the real outbound dial, so the PT is the
     *    only process that needs to know about the chain. Verified end to end —
     *    meek reached 100% in 36s with all 75 of its CDN dials crossing the proxy,
     *    against 0 crossings on the same run without the variable.
     */
    private fun writeTorrc(context: Context, dataDir: File, mode: TorMode): File {
        val torrc = File(dataDir, "torrc")
        val transport = transportFor(mode)
        val bridges = bridgeLinesFor(mode)
        // No transport means no PT process, which is the only case where the
        // proxy belongs in the torrc — see the note above.
        val proxyGoesInTorrc = transport == null && bridges.isEmpty()

        val text = buildString {
            appendLine("SocksPort 127.0.0.1:$TOR_SOCKS_PORT")
            appendLine("DNSPort 127.0.0.1:$TOR_DNS_PORT")
            appendLine("DataDirectory ${dataDir.absolutePath}")
            // Everything Tor might otherwise offer to the network. This is a
            // client and only ever a client.
            appendLine("ClientOnly 1")
            appendLine("SocksPolicy accept 127.0.0.0/8")
            appendLine("SocksPolicy reject *")
            // `info`, not `notice`, deliberately.
            //
            // Two field devices reported tor dying at 0% with nothing in the log
            // but "exited". At `notice` tor is silent about everything it does
            // between reading the config and opening its first connection, which
            // is exactly the window where these deaths happen. SlipNet ships
            // `Log info stdout` and its logs name the failing step; ours did not.
            //
            // The volume does not reach the user: info lines are only kept in the
            // in-memory tail below and replayed into the 100-line in-app log when
            // a rung actually fails. A successful bootstrap records the same five
            // percentage lines it always did.
            appendLine("Log info stdout")
            // Tor's own default is 0 (scrub addresses from logs). SlipNet sets
            // this and it is why its logs name the bridge that failed while ours
            // said only "general SOCKS server failure". Our in-app log is 100
            // lines shown to one user about their own connection, so there is no
            // third party to protect — and without it a dead bridge is invisible.
            appendLine("SafeLogging 0")
            appendLine("AvoidDiskWrites 1")
            appendLine("DormantClientTimeout 2419200")
            appendLine("ClientBootstrapConsensusAuthorityDownloadInitialDelay 0")
            appendLine("NumEntryGuards 1")
            appendLine("LearnCircuitBuildTimeout 0")
            // Meek pays an HTTP round trip per cell, so the default 60s is not
            // enough for a three-hop handshake over it.
            appendLine(
                "CircuitBuildTimeout " + if (mode == TorMode.MEEK || mode == TorMode.SNOWFLAKE) 120 else 60
            )
            // Short keepalive so an idle HTTP-based transport does not have its
            // bridge connection closed between Tor's own keepalive cells.
            appendLine("KeepalivePeriod 30")
            appendLine("ClientUseIPv4 1")
            appendLine("ClientUseIPv6 1")
            appendLine("ClientPreferIPv6ORPort auto")

            // Tor-over-WARP, direct rung only. On a bridge rung this line makes
            // tor reject its own transport line and exit, so the proxy is handed
            // to the PT instead (TOR_PT_PROXY, see startPt).
            upstreamProxy?.let { proxy ->
                if (proxyGoesInTorrc) appendLine("Socks5Proxy $proxy")
            }

            // Preferred exit country, when the user picked one.
            //
            // Both the GeoIP path and the country line are written together, or
            // neither is. Tor cannot resolve {cc} to relays without the database:
            // the candidate set comes out empty and bootstrap stalls at 45-50%
            // forever, which is exactly how 1.4.3 broke. So if unpacking the
            // database failed, the preference is dropped and the connection is
            // allowed to succeed without it — a wrong country beats no tunnel.
            //
            // StrictNodes 0 deliberately: it makes this a preference tor
            // abandons when it cannot build a circuit in that country, which is
            // the same contract the Psiphon "Preferred country" row advertises.
            // StrictNodes 1 would turn a country with a handful of exits into
            // "no connection at all" whenever those exits are busy or down —
            // measured: {gr} with StrictNodes 1 sat at 45% for 42 minutes.
            //
            // Verified with the filtered database actually shipped: FR DE NL RO
            // SE CA all bootstrapped 100% in 4-6s and the exit address really
            // geolocated in the requested country, 6/6.
            val region = TorRegions.selected(context)
            if (region != null) {
                val geoip = geoipDir(context)
                if (geoip != null) {
                    appendLine("GeoIPFile ${File(geoip, "geoip").absolutePath}")
                    appendLine("GeoIPv6File ${File(geoip, "geoip6").absolutePath}")
                    appendLine("ExitNodes {${region.lowercase()}}")
                    appendLine("StrictNodes 0")
                } else {
                    ConnectionLog.record(
                        "$TAG GeoIP data unavailable — ignoring the $region exit preference"
                    )
                }
            }

            if (transport != null && bridges.isNotEmpty()) {
                appendLine("UseBridges 1")
                val listener = ptMethods[transport]
                if (listener != null) {
                    appendLine("ClientTransportPlugin $transport socks5 $listener")
                }
                bridges.forEach { appendLine("Bridge $it") }
            }
        }

        torrc.writeText(text)
        return torrc
    }

    // --------------------------------------------------------------- lyrebird

    private fun nativeFile(context: Context, name: String): File =
        File(context.applicationInfo.nativeLibraryDir, name)

    /**
     * Launch lyrebird as a managed pluggable transport and learn its ports.
     *
     * The environment variables are the PT spec's client-side contract. Two are
     * worth calling out:
     *
     *  - `TOR_PT_EXIT_ON_STDIN_CLOSE=1` makes lyrebird exit when our process
     *    dies. Without it, killing the app can leave an orphan PT holding its
     *    listener, and the next connect fails to bind.
     *  - `TOR_PT_STATE_LOCATION` must end in a separator; lyrebird writes its
     *    obfs4 bridge state there.
     *  - `TOR_PT_PROXY` is how a bridge rung joins the WARP chain. It is the PT,
     *    not tor, that makes the real outbound connection when `UseBridges 1` is
     *    set, so this is the only place a chained bridge rung can be told about
     *    the outer tunnel — and putting `Socks5Proxy` in the torrc instead makes
     *    tor refuse to start (see [writeTorrc]). Measured: with the variable set,
     *    all 75 of meek's CDN dials crossed the proxy and tor bootstrapped in
     *    36s; without it, 0 crossed.
     *
     * Returns true only when the transport actually registered a SOCKS port. A
     * live process that registered nothing is a failure — it would leave Tor
     * with a `ClientTransportPlugin` line pointing nowhere.
     */
    private fun startPt(context: Context, dataDir: File, transport: String): Boolean {
        ptMethods.clear()

        val binary = nativeFile(context, "libobfs4proxy.so")
        if (!binary.exists()) {
            ConnectionLog.record("$TAG PT binary missing at ${binary.absolutePath}")
            return false
        }

        val stateDir = File(dataDir, "pt_state").apply { mkdirs() }

        val builder = ProcessBuilder(binary.absolutePath)
        builder.environment().apply {
            put("TOR_PT_MANAGED_TRANSPORT_VER", "1")
            put("TOR_PT_CLIENT_TRANSPORTS", transport)
            put("TOR_PT_STATE_LOCATION", stateDir.absolutePath + "/")
            put("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
            put("HOME", dataDir.absolutePath)
            upstreamProxy?.let { proxy -> put("TOR_PT_PROXY", "socks5://$proxy") }
        }

        val process = try {
            builder.start()
        } catch (e: Exception) {
            ConnectionLog.record("$TAG could not exec PT: ${e.message}")
            return false
        }
        ptProcess = process

        val done = CountDownLatch(1)

        Thread({
            try {
                BufferedReader(InputStreamReader(process.inputStream)).forEachLine { raw ->
                    val line = raw.trim()
                    when {
                        line.startsWith("CMETHOD ") -> {
                            // CMETHOD <transport> socks5 <host:port>
                            val parts = line.split(Regex("\\s+"))
                            if (parts.size >= 4) {
                                ptMethods[parts[1]] = parts[3]
                                ConnectionLog.record("$TAG PT $transport on ${parts[3]}")
                            }
                        }
                        line == "CMETHODS DONE" -> done.countDown()
                        line.startsWith("CMETHOD-ERROR ") ||
                            line.startsWith("ENV-ERROR ") ||
                            line.startsWith("VERSION-ERROR ") -> {
                            ConnectionLog.record("$TAG PT error: $line")
                            done.countDown()
                        }
                    }
                }
            } catch (_: Exception) {
            } finally {
                // If the process died before announcing, do not hang the caller
                // for the full handshake timeout.
                done.countDown()
            }
        }, "tor-pt-stdout").apply { isDaemon = true }.start()

        // lyrebird's stderr is where its own diagnostics go. Drained so a full
        // pipe buffer cannot block the process, and dropped otherwise.
        Thread({
            try {
                BufferedReader(InputStreamReader(process.errorStream)).forEachLine { }
            } catch (_: Exception) {
            }
        }, "tor-pt-stderr").apply { isDaemon = true }.start()

        done.await(PT_HANDSHAKE_TIMEOUT_S, TimeUnit.SECONDS)

        if (ptMethods[transport] == null) {
            ConnectionLog.record("$TAG PT $transport did not register a listener")
            stopPt()
            return false
        }
        return true
    }

    private fun stopPt() {
        ptProcess?.let { process ->
            try {
                // Closing stdin is the documented way to ask a managed PT to
                // exit; destroy() is the fallback for one that ignores it.
                process.outputStream.close()
            } catch (_: Exception) {
            }
            try {
                process.destroy()
            } catch (_: Exception) {
            }
        }
        ptProcess = null
        ptMethods.clear()
    }

    // ------------------------------------------------------------ one attempt

    /**
     * Start Tor once with one mode and wait for a full bootstrap.
     *
     * Returns true only at `Bootstrapped 100%`. Anything less is a failure the
     * caller escalates from — a partially bootstrapped Tor cannot carry traffic,
     * so treating, say, 80% as success is how you ship a "connected" button that
     * does nothing.
     *
     * Only `state`/`lock` deletion policy lives here: see [keepTorState], the
     * caches are deliberately kept between attempts so a warm retry does not
     * re-download the consensus. The field log's 61%-at-30s Direct run was on a
     * cold cache; SlipNet connects in seconds because it keeps that cache warm.
     */
    private fun attempt(context: Context, dataDir: File, mode: TorMode, timeoutSeconds: Long): Boolean {
        bootstrapPercent = 0
        lastLoggedPercent = -1

        // Clear the process lock, and on direct mode only, force a fresh guard
        // draw. Bridge rungs keep their guard entries: tor dials every
        // configured bridge anyway, so the entries cost nothing and the cached
        // bridge descriptor they point at saves a handshake.
        keepTorState(dataDir, mode)

        val transport = transportFor(mode)
        if (transport != null && !startPt(context, dataDir, transport)) {
            return false
        }

        val torrc = writeTorrc(context, dataDir, mode)

        val binary = nativeFile(context, "libtor.so")
        if (!binary.exists()) {
            ConnectionLog.record("$TAG tor binary missing at ${binary.absolutePath}")
            stopPt()
            return false
        }
        // Once per attempt, and only when something is already wrong, this is the
        // difference between "tor died" and knowing why. A field device ran all
        // four rungs in one second with no reason logged; without the ABI and the
        // on-disk size there is no way to tell a wrong-ABI binary, a truncated
        // extraction and a killed process apart from a log alone.
        if (!binary.canExecute()) {
            ConnectionLog.record(
                "$TAG tor binary is not executable — ${binary.length()} bytes, " +
                    "abi ${android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "?"}"
            )
        }

        val builder = ProcessBuilder(binary.absolutePath, "-f", torrc.absolutePath)
        builder.redirectErrorStream(true)
        builder.environment()["HOME"] = dataDir.absolutePath

        val process = try {
            builder.start()
        } catch (e: Exception) {
            ConnectionLog.record("$TAG could not exec tor: ${e.message}")
            stopPt()
            return false
        }
        torProcess = process

        val bootstrapped = CountDownLatch(1)

        // Raw tail of everything the child printed, kept verbatim BEFORE the
        // warn/err filter. When tor dies at startup the reason is usually a
        // dynamic-linker abort ("CANNOT LINK EXECUTABLE ...") which carries
        // neither "[warn]" nor "[err]" — filtering those away is how two field
        // devices managed to die at 0% with zero explanation in the log.
        val rawTail = java.util.ArrayDeque<String>(24)

        // Timestamp of the last percentage *increase*, which is what the stall
        // detector measures. An atomic rather than a plain `var` because the
        // stdout reader thread writes it and this thread reads it; `@Volatile`
        // is not allowed on a local, and a captured `var` would be boxed in a
        // non-thread-safe Ref.
        val lastProgressMs = java.util.concurrent.atomic.AtomicLong(System.currentTimeMillis())

        Thread({
            try {
                BufferedReader(InputStreamReader(process.inputStream)).forEachLine { line ->
                    synchronized(rawTail) {
                        if (rawTail.size >= 24) rawTail.pollFirst()
                        rawTail.addLast(line)
                    }
                    val match = Regex("Bootstrapped (\\d+)%").find(line)
                    if (match != null) {
                        val percent = match.groupValues[1].toIntOrNull() ?: 0
                        if (percent > bootstrapPercent) {
                            lastProgressMs.set(System.currentTimeMillis())
                        }
                        bootstrapPercent = percent
                        // Log every 20% instead of all 15 notices: the in-app log
                        // is 100 lines total and a full bootstrap would flood it.
                        if (percent / 20 > lastLoggedPercent / 20) {
                            lastLoggedPercent = percent
                            ConnectionLog.record("$TAG ${mode.label}: bootstrapped $percent%")
                        }
                        if (percent >= 100) bootstrapped.countDown()
                    } else if (line.contains("[warn]") || line.contains("[err]")) {
                        val text = line.substringAfter("] ").take(160)
                        // Tor re-emits some notices on a timer, and the in-app log
                        // is a 100-line ring buffer: fifteen copies of the same
                        // advisory push out everything that explains the failure.
                        // The field log lost its whole bootstrap history to the
                        // SOCKS5-hostname advisory alone, reposted every 5s.
                        if (!isRepetitiveNotice(text)) ConnectionLog.record("$TAG $text")
                    }
                }
            } catch (_: Exception) {
            } finally {
                // Tor exited. Unblock rather than let the caller sit out the
                // whole timeout on a dead process.
                bootstrapped.countDown()
            }
        }, "tor-stdout").apply { isDaemon = true }.start()

        // Wait in short slices so a stall can be noticed while it is happening.
        // The old code did one `await(timeoutSeconds)`, which is why a rung that
        // was still climbing got killed at a fixed deadline and a rung that was
        // dead on arrival held the ladder for the full budget. Both cases are
        // now decided by whether the percentage is still moving.
        val startedMs = System.currentTimeMillis()
        val deadlineMs = startedMs + timeoutSeconds * 1_000
        var stalled = false
        while (!bootstrapped.await(BOOTSTRAP_POLL_MS, TimeUnit.MILLISECONDS)) {
            if (stopping.get()) break
            if (!process.isAlive) break
            val now = System.currentTimeMillis()
            if (now - lastProgressMs.get() > STALL_TIMEOUT_S * 1_000) {
                stalled = true
                break
            }
            if (now > deadlineMs) break
        }

        val reached = bootstrapPercent >= 100

        if (!reached || !process.isAlive) {
            // Give a dying process a moment to be reaped before classifying.
            //
            // The stdout thread counts the latch down in its `finally`, so a tor
            // that dies instantly releases the wait on the FIRST poll — while
            // `isAlive` can still be true for a few ms. That raced into the
            // `else` branch and printed "hit the 300s ceiling at 0%" one second
            // after the rung started, in the field logs from two devices. The
            // ceiling was never reached; tor had already exited.
            if (!process.isAlive || bootstrapPercent == 0) {
                runCatching { process.waitFor(400, TimeUnit.MILLISECONDS) }
            }
            val exitCode = try {
                if (process.isAlive) null else process.exitValue()
            } catch (_: Exception) {
                null
            }
            val elapsedS = (System.currentTimeMillis() - startedMs) / 1_000
            val why = when {
                exitCode != null -> "tor exited at $bootstrapPercent% (exit $exitCode)"
                stalled -> "stalled ${STALL_TIMEOUT_S}s at $bootstrapPercent%"
                // Report the time actually spent, not the budget. A rung cut short
                // by stopping.get() or by the outer leg dropping used to be labelled
                // "hit the 150s ceiling" after 22 seconds, which sent the last
                // investigation down the wrong path entirely.
                elapsedS >= timeoutSeconds -> "hit the ${timeoutSeconds}s ceiling at $bootstrapPercent%"
                else -> "gave up after ${elapsedS}s at $bootstrapPercent% (budget ${timeoutSeconds}s)"
            }
            ConnectionLog.record("$TAG ${mode.label} failed — $why")
            // A tor that never printed a single bootstrap line told us nothing.
            // Replay what it actually said so the next field log carries the
            // linker/permission/config error instead of a bare "exited at 0%".
            if (bootstrapPercent == 0) {
                val tail = synchronized(rawTail) { rawTail.toList() }
                if (tail.isEmpty()) {
                    ConnectionLog.record("$TAG tor printed nothing before dying")
                } else {
                    // With `Log info stdout` the tail is mostly routine startup
                    // chatter. Anything tor itself flagged is what explains the
                    // death, so those lines are replayed first and the plain tail
                    // is only used when tor flagged nothing at all.
                    val flagged = tail.filter { it.contains("[warn]") || it.contains("[err]") }
                    val replay = if (flagged.isNotEmpty()) flagged.takeLast(6) else tail.takeLast(6)
                    replay.forEach { ConnectionLog.record("$TAG tor: ${it.take(160)}") }
                }
            }
            stopTorProcess()
            stopPt()
            return false
        }

        ConnectionLog.record("$TAG ${mode.label} bootstrapped")
        return true
    }

    /**
     * Reset the guard choice without nuking the directory cache.
     *
     * Only for [TorMode.DIRECT]. Verified on tor 0.4.6.10 (two runs, 2 dead
     * bridges listed ahead of 2 live ones): with `UseBridges 1` tor dials
     * **every** configured bridge regardless of `NumEntryGuards`, reaching a
     * live one in both `NumEntryGuards 1` and `3`. So there is no dead-guard
     * lockout to fix on the bridge rungs, and stripping their guard entries only
     * throws away the cached bridge descriptor and forces a fresh handshake —
     * the opposite of what we want on the rung that is already the slow one.
     *
     * Two bugs lived here before. The filter tested `startsWith("GuardEntry")`,
     * but tor writes the key as `Guard ` (guard-spec A.5: `Guard in=default
     * rsa_id=… sampled_on=…`), so it matched nothing and the whole function was
     * a no-op — dumped the state file from a real run and counted 20 `Guard `
     * lines, 0 `GuardEntry`. And it ran for every mode, not just direct.
     *
     * Stripping the lines is safe: tor re-samples a full guard set and
     * re-bootstrapped to 100% in 4s on the edited file, with no parse warning.
     */
    private fun keepTorState(dataDir: File, mode: TorMode) {
        // `lock` is Tor's process lock; it must always go or the new process
        // refuses to start thinking another tor is running.
        File(dataDir, "lock").delete()

        if (mode != TorMode.DIRECT) return

        val state = File(dataDir, "state")
        if (!state.exists()) return
        runCatching {
            val lines = state.readLines().filter { !it.startsWith("Guard ") }
            state.writeText(lines.joinToString("\n") + "\n")
        }
    }

    // ------------------------------------------------------------- log hygiene

    /**
     * Notices tor repeats on a timer, which must not be logged every time.
     *
     * The in-app log is a 100-entry ring buffer. In the 1.4.1 field log the
     * SOCKS5-hostname advisory was reposted every five seconds and, within two
     * minutes, had evicted every line that explained why the earlier rungs
     * failed. Filtering by prefix rather than deduplicating exact strings
     * because tor varies the port number inside the same message.
     *
     * Only advisories are listed here — anything that names a failure is kept.
     */
    private val REPETITIVE_NOTICES = listOf(
        // Expected by design: tun2socks hands tor an IP, not a hostname, because
        // DNS is resolved separately through DNSPort. Advisory, not a fault.
        "Your application (using socks5 to port",
        // Emitted once per new circuit on some builds.
        "Tried for 120 seconds to get a connection to",
    )

    private fun isRepetitiveNotice(text: String): Boolean =
        REPETITIVE_NOTICES.any { text.startsWith(it) }

    private fun stopTorProcess() {
        torProcess?.let { process ->
            try {
                process.destroy()
            } catch (_: Exception) {
            }
            try {
                // Tor unwinds quickly on SIGTERM; this only bounds the wait so a
                // restart cannot race a still-listening old process for the port.
                process.waitFor(3, TimeUnit.SECONDS)
            } catch (_: Exception) {
            }
        }
        torProcess = null
    }

    // ------------------------------------------------------------ public API

    /**
     * Bring Tor up, honouring the user's mode choice.
     *
     * Blocking — call it from the service's worker thread, never the main one.
     * In AUTO it can legitimately take minutes, since that is four rungs of
     * bootstrap timeouts on a fully censored network.
     *
     * On success [FRONT_SOCKS_PORT] is a live SOCKS5 server for tun2socks to
     * dial, with DNS already wired to Tor's DNSPort.
     *
     * When [useUpstreamProxy] has been given a proxy, this is a chained session:
     * the ladder shrinks to [chainedLadder] (Direct, then Meek) and the winner is
     * remembered under its own key. Nothing else about the sequence changes.
     */
    fun start(context: Context): Boolean {
        stopping.set(false)
        activeMode = null

        val dataDir = File(context.filesDir, "tor_data").apply { mkdirs() }
        val selected = selectedMode(context)
        val chained = upstreamProxy != null
        // Direct and Meek only inside the chain. AUTO takes the short ladder;
        // a pinned obfs4/Snowflake cannot get here at all, because the service
        // does not raise an outer leg for a mode chainArmed() rejects.
        val rungs = if (chained) chainedLadder else ladder

        val order: List<Rung> = if (selected != TorMode.AUTO) {
            // An explicit choice is exactly that: one attempt, no silent
            // fallback to a transport the user did not pick.
            listOf(Rung(selected, if (selected == TorMode.DIRECT) DIRECT_TIMEOUT_S else BRIDGE_TIMEOUT_S))
        } else {
            // Start from whatever last worked on this device, then continue
            // through the rest of the ladder. The remembered rung is retried
            // first rather than exclusively, so a bridge that has since been
            // blocked still escalates.
            val remembered = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
                .getString(winnerPref(chained), null)
                ?.let { key -> rungs.firstOrNull { it.mode.key == key } }
            if (remembered == null) rungs else listOf(remembered) + rungs.filter { it !== remembered }
        }

        if (chained) {
            ConnectionLog.record(
                "$TAG chained: trying ${order.joinToString(" → ") { it.mode.label }} inside WARP"
            )
        }

        for (rung in order) {
            if (stopping.get()) return false
            ConnectionLog.record("$TAG trying ${rung.mode.label} (${rung.timeoutSeconds}s)")
            if (!attempt(context, dataDir, rung.mode, rung.timeoutSeconds)) continue

            if (!TorSocksFront.start(FRONT_SOCKS_PORT, TOR_SOCKS_PORT, TOR_DNS_PORT)) {
                // The circuit is fine but nothing can use it, so this is a hard
                // failure rather than a reason to try another transport.
                ConnectionLog.record("$TAG front-end failed to bind; aborting")
                stopTorProcess()
                stopPt()
                return false
            }

            activeMode = rung.mode
            if (selected == TorMode.AUTO) {
                context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit()
                    .putString(winnerPref(chained), rung.mode.key).apply()
            }
            return true
        }

        ConnectionLog.record("$TAG all modes failed")
        return false
    }

    /**
     * Tear everything down, in the reverse of the order it came up.
     *
     * Front-end first: it holds sockets pointing at Tor, and closing them before
     * Tor dies means no thread is blocked reading from a process that is going
     * away.
     */
    fun stop() {
        stopping.set(true)
        TorSocksFront.stop()
        stopTorProcess()
        stopPt()
        bootstrapPercent = 0
        activeMode = null
        // Cleared here, not by the service: a chained session that ends must not
        // leave the proxy armed for the next connect, which could be an unchained
        // one — that would write Socks5Proxy pointing at a dead listener.
        upstreamProxy = null
    }
}
