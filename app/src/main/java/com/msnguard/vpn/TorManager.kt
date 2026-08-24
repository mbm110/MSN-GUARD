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
     * Which rung of the AUTO ladder last carried a working circuit.
     *
     * Same idea as [CoreConfig.PLAIN_WORKING_TRANSPORT_PREF] for Psiphon: a
     * device on a carrier that blocks direct Tor pays the 30-second direct
     * timeout once, not on every connect.
     */
    private const val WINNER_PREF = "tor_winning_mode"

    /**
     * How long to wait for lyrebird's `CMETHODS DONE`.
     *
     * It is a local process doing no network work at startup, so this only ever
     * expires when the binary is broken or blocked from executing.
     */
    private const val PT_HANDSHAKE_TIMEOUT_S = 10L

    /**
     * How long each ladder rung gets to reach 100% bootstrap.
     *
     * Direct gets 90s. Its first-ever run on a device has no cached directory
     * data and can spend most of that downloading a consensus over a throttled
     * link — the field log shows 61% at the old 30s cutoff on a rung that was
     * minutes from finishing. With warm state it is a few seconds; the budget
     * exists for the cold case, not the warm one.
     */
    private const val DIRECT_TIMEOUT_S = 90L
    private const val BRIDGE_TIMEOUT_S = 60L

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
     * Write the torrc for one attempt.
     *
     * Notable choices, all of them about a phone on a censored network rather
     * than a desktop:
     *
     *  - **No `GeoIPFile`.** The geoip databases are 24 MB uncompressed and are
     *    only needed for `ExitNodes {cc}` country selection, which this app does
     *    not offer for Tor. Tor logs a harmless notice about them being absent
     *    and works normally. Bundling them would have doubled the size cost of
     *    the whole feature for a feature nobody asked for.
     *  - **`AvoidDiskWrites 1`** keeps Tor's caches in RAM and flushes on clean
     *    shutdown only. Less flash wear and less wakeup work while backgrounded.
     *  - **`DormantClientTimeout`** raised from Tor's 24-hour default to 4 weeks.
     *    On the default, Tor shuts itself down after a day idle and the next
     *    connect pays a full bootstrap — which over meek or snowflake is minutes.
     *  - **`NumEntryGuards 1`** and deleting `state` before each attempt. Tor
     *    normally sticks to a chosen guard for weeks, which is right for
     *    anonymity and wrong here: one unreachable guard would make every
     *    connect attempt fail identically. Re-drawing gives a fresh guard each
     *    try. This is a deliberate trade of guard stability for reachability.
     *  - **No `Socks5Proxy`.** Tor refuses to start when both a proxy and a
     *    `ClientTransportPlugin` are configured (`config.c` logs "external proxy
     *    with another proxy type" and does `goto err`), so chaining Tor behind
     *    another tunnel is not wired up here at all.
     */
    private fun writeTorrc(context: Context, dataDir: File, mode: TorMode): File {
        val torrc = File(dataDir, "torrc")
        val transport = transportFor(mode)
        val bridges = bridgeLinesFor(mode)

        val text = buildString {
            appendLine("SocksPort 127.0.0.1:$TOR_SOCKS_PORT")
            appendLine("DNSPort 127.0.0.1:$TOR_DNS_PORT")
            appendLine("DataDirectory ${dataDir.absolutePath}")
            // Everything Tor might otherwise offer to the network. This is a
            // client and only ever a client.
            appendLine("ClientOnly 1")
            appendLine("SocksPolicy accept 127.0.0.0/8")
            appendLine("SocksPolicy reject *")
            appendLine("Log notice stdout")
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

        // Fresh guard draw, but keep everything else. `state` holds the guard
        // list AND the directory-cache bookmarks; deleting it wholesale (the
        // old behaviour) threw away the cached consensus with it and forced a
        // full directory fetch per attempt — minutes on a bad link. Deleting
        // just the guard entry inside forces the redraw NumEntryGuards exists
        // for while the descriptor caches stay warm.
        keepTorState(dataDir)

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

        Thread({
            try {
                BufferedReader(InputStreamReader(process.inputStream)).forEachLine { line ->
                    val match = Regex("Bootstrapped (\\d+)%").find(line)
                    if (match != null) {
                        val percent = match.groupValues[1].toIntOrNull() ?: 0
                        bootstrapPercent = percent
                        // Log every 20% instead of all 15 notices: the in-app log
                        // is 100 lines total and a full bootstrap would flood it.
                        if (percent / 20 > lastLoggedPercent / 20) {
                            lastLoggedPercent = percent
                            ConnectionLog.record("$TAG ${mode.label}: bootstrapped $percent%")
                        }
                        if (percent >= 100) bootstrapped.countDown()
                    } else if (line.contains("[warn]") || line.contains("[err]")) {
                        ConnectionLog.record("$TAG ${line.substringAfter("] ").take(160)}")
                    }
                }
            } catch (_: Exception) {
            } finally {
                // Tor exited. Unblock rather than let the caller sit out the
                // whole timeout on a dead process.
                bootstrapped.countDown()
            }
        }, "tor-stdout").apply { isDaemon = true }.start()

        val reached = bootstrapped.await(timeoutSeconds, TimeUnit.SECONDS) && bootstrapPercent >= 100

        if (!reached || !process.isAlive) {
            ConnectionLog.record(
                "$TAG ${mode.label} failed at $bootstrapPercent% after ${timeoutSeconds}s"
            )
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
     * Tor's `state` file holds two unrelated things: the entry-guard selection
     * and the bookmarks into the cached consensus/descriptors. Deleting the
     * whole file (what we used to do) forces a full directory refetch on every
     * attempt — that is the difference between SlipNet's 3-second connect and
     * our 30-second failure. Editing just the GuardLines out keeps the cache
     * warm while still forcing a fresh guard draw, which is the only reason we
     * were deleting it (NumEntryGuards 1 + a dead guard would otherwise fail
     * every attempt identically).
     */
    private fun keepTorState(dataDir: File) {
        val state = File(dataDir, "state")
        if (!state.exists()) return
        runCatching {
            val lines = state.readLines().filter { !it.startsWith("GuardEntry") }
            state.writeText(lines.joinToString("\n") + "\n")
        }
        // `lock` is Tor's process lock; it must go or the new process refuses
        // to start thinking another tor is running.
        File(dataDir, "lock").delete()
    }

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
     */
    fun start(context: Context): Boolean {
        stopping.set(false)
        activeMode = null

        val dataDir = File(context.filesDir, "tor_data").apply { mkdirs() }
        val selected = selectedMode(context)

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
                .getString(WINNER_PREF, null)
                ?.let { key -> ladder.firstOrNull { it.mode.key == key } }
            if (remembered == null) ladder else listOf(remembered) + ladder.filter { it !== remembered }
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
                    .putString(WINNER_PREF, rung.mode.key).apply()
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
    }
}
