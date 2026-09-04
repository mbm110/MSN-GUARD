package com.msnguard.vpn

import android.content.Context
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the xray process and picks the node to connect through.
 *
 * ## Shape of a SHARD session
 *
 * ```
 *   TUN ─► tun2socks ─► libxray.so SOCKS 1824 ─► VLESS/ws/TLS ─► Cloudflare ─► exit
 *              └─ UDP + DNS ──► same listener (UDP ASSOCIATE)
 * ```
 *
 * Unlike Tor, no front proxy is needed. xray's SOCKS inbound implements UDP
 * ASSOCIATE properly — verified against the real binary on the live pool: the
 * associate was granted and DNS answered over it. That is what lets this
 * transport reuse the Psiphon-shaped path (tun2socks straight at a SOCKS port)
 * and inherit VPN mode, SOCKS mode, Share over LAN, split tunnelling and the kill
 * switch with no new plumbing.
 *
 * ## Why a process and not a library
 *
 * `libv2ray.aar` cannot ship next to `app/libs/psiphontunnel-2.0.39.aar`. Both
 * are gomobile builds: both carry `jni/<abi>/libgojni.so` and 12 identical
 * `go/Seq*` classes. Gradle would keep one and the other Go runtime would break.
 * Exec'ing the binary sidesteps the collision entirely, and it is the pattern
 * already proven in this app by `libtor.so`.
 *
 * That is also why `useLegacyPackaging = true` must stay set: without it AGP 8
 * leaves native libs compressed inside the APK and never writes them to
 * `nativeLibraryDir`, so there is no executable file on disk to launch.
 */
object ShardManager {

    private const val TAG = "ShardManager"

    /**
     * The live tunnel's SOCKS port.
     *
     * Chosen clear of every port already claimed in this app: 1819 core, 1820
     * chain, 1821 Tor front, 1822 Tor SOCKS, 1823 Tor DNS.
     */
    const val SOCKS_PORT = 1824

    /**
     * The port the live process is actually listening on.
     *
     * [SOCKS_PORT] in VPN mode, where [ShardSocksFront] dials it on a fixed number.
     * In SOCKS-proxy mode it is the user's chosen port instead, because there the
     * listener is what the user points other apps at — so everything that dials the
     * tunnel (the health probe, the rotation check) has to read this rather than the
     * constant.
     */
    @Volatile
    var listenPort: Int = SOCKS_PORT
        private set

    /**
     * First port of the probe block. The race binds one inbound per candidate,
     * `PROBE_BASE_PORT + i`, and they exist only while the race runs.
     */
    private const val PROBE_BASE_PORT = 21100

    /**
     * How many nodes race at once.
     *
     * Not the whole pool: 45 simultaneous TLS handshakes on a phone is a
     * self-inflicted congestion problem, and the measured cost of racing the top
     * slice is already low. 12 is a compromise between covering enough of the
     * pool that a bad day still finds a winner, and not opening more sockets than
     * a carrier link can handle at once.
     */
    private const val RACE_WIDTH = 12

    /**
     * Per-probe deadline in ms.
     *
     * Working nodes in the live pool measured 727–5735 ms, with the bulk under
     * 3.6 s. 5 s admits nearly all of them while cutting off the ones that would
     * make the connect feel broken; a node slower than that is better replaced.
     */
    private const val PROBE_TIMEOUT_MS = 5_000

    /** Overall budget for the race, after which we take whatever we have. */
    private const val RACE_BUDGET_MS = 12_000L

    /**
     * How many [RACE_WIDTH]-sized slices a connect will try before giving up.
     *
     * Three, i.e. up to 36 paths and a worst case of ~36 s before the connect
     * reports failure. Two was enough when the pool was 28 entries; with the edge
     * expansion it is 100+, and the whole point of those extra paths is that a
     * blocked edge can be raced past rather than fallen at.
     */
    private const val MAX_RACE_SLICES = 3

    private val running = AtomicBoolean(false)

    @Volatile
    private var process: Process? = null

    @Volatile
    private var logThread: Thread? = null

    /** The node the live tunnel is using, for the UI and the log. */
    @Volatile
    var activeNode: ShardNode? = null
        private set

    /** Last error, so the service can report something specific. */
    @Volatile
    var lastError: String = ""
        private set

    val isRunning: Boolean
        get() = running.get() && process?.isAlive == true

    private fun binary(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, "libxray.so")

    /**
     * Launch xray with [configFile].
     *
     * `-c` takes the path; the binary needs no geoip.dat or geosite.dat, which was
     * verified by running it in a directory containing nothing but itself and the
     * config. That saves ~27 MB of assets we would otherwise have had to ship.
     */
    private fun launch(context: Context, configFile: File, tag: String): Boolean {
        val binary = binary(context)
        if (!binary.exists()) {
            lastError = "xray binary missing"
            ConnectionLog.record("$TAG binary missing at ${binary.absolutePath}")
            return false
        }
        val builder = ProcessBuilder(binary.absolutePath, "run", "-c", configFile.absolutePath)
        builder.directory(configFile.parentFile)
        builder.redirectErrorStream(true)
        builder.environment()["HOME"] = context.filesDir.absolutePath
        // xray writes its asset lookups relative to this; pointing it at our own
        // private dir keeps it from probing /sdcard paths it cannot read.
        builder.environment()["XRAY_LOCATION_ASSET"] = configFile.parent

        val started = try {
            builder.start()
        } catch (e: Exception) {
            lastError = "could not start xray: ${e.message}"
            ConnectionLog.record("$TAG exec failed: ${e.message}")
            return false
        }
        process = started

        // Drained on a thread whatever the log level: a process whose stdout fills
        // the pipe buffer blocks in write() and stops forwarding traffic. That is
        // a silent stall, so the reader is not optional.
        //
        // Drained is not the same as recorded. Two classes of line are read and
        // thrown away rather than logged:
        //
        //  * xray's start-up deprecation warnings, which it emits before the log
        //    level applies — one per outbound, so 45 of them per race — and which
        //    say nothing about this session.
        //  * anything left over from the access log if a future config re-enables it.
        //
        // Verified against the real binary: with `access:"none"` the only remaining
        // repeat offenders are these warnings, and a field log showed 168 of them
        // from probe processes alone.
        logThread = Thread({
            try {
                BufferedReader(InputStreamReader(started.inputStream)).forEachLine { line ->
                    if (line.isNotBlank() && !isNoise(line)) ConnectionLog.record("$tag $line")
                }
            } catch (_: Exception) {
                // Process gone; nothing to report.
            }
        }, "shard-log").apply { isDaemon = true }.also { it.start() }

        return true
    }

    /**
     * xray output that is noise by construction.
     *
     * Matched on substrings rather than log level because the deprecation warnings
     * are emitted during config parsing, before `loglevel` takes effect — so no
     * setting suppresses them and they have to be dropped on this side.
     */
    private fun isNoise(line: String): Boolean =
        line.contains("is deprecated, not recommended") ||
            line.contains("deprecated, will be removed soon") ||
            line.contains("[in >> proxy]") ||
            line.contains("A unified platform for anti-censorship") ||
            line.contains("infra/conf/serial: Reading config")

    /** Stop the process and forget the session. */
    @Synchronized
    fun stop() {
        running.set(false)
        activeNode = null
        process?.let { proc ->
            try {
                proc.destroy()
                // Give it a moment to close its listeners before anything tries to
                // bind them again; a leftover listener makes the next connect fail
                // with "address already in use".
                if (!proc.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                    proc.destroyForcibly()
                }
            } catch (_: Exception) {
            }
        }
        process = null
        logThread = null
    }

    /** True when the local SOCKS port is accepting, i.e. the tunnel is usable. */
    private fun portAccepts(port: Int, timeoutMs: Int): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress("127.0.0.1", port), timeoutMs)
            true
        }
    } catch (_: Exception) {
        false
    }

    /**
     * Unpack the trimmed geo databases next to the config, if they are not there.
     *
     * `XRAY_LOCATION_ASSET` is set to the config's own directory by [launch], and
     * xray resolves `geosite:`/`geoip:` against files in that directory only. On
     * Android there is no fallback: the desktop search path
     * (`/usr/local/share/xray`, `/usr/share/xray`, `/opt/share/xray`) does not
     * exist, so a missing file is not a warning but a hard startup failure —
     * `failed to check code X from geosite.dat > EOF` — and every Smart Split
     * config would die at launch.
     *
     * The pair shipped in `assets/` is trimmed to exactly the categories
     * [ShardConfigs] names: 6 KB and 37 KB instead of 11 MB and 17 MB. Re-run
     * `trim-geodata.py` whenever a rule gains a new `geosite:`/`geoip:` tag,
     * because a tag that is not in the file is that same hard failure.
     *
     * Version-stamped like [TorManager]'s geoip unpack, so an upgrade that ships a
     * different trim replaces the old files instead of silently keeping them.
     *
     * @return true when both files are present and non-empty.
     */
    private fun unpackGeoAssets(context: Context, dir: File): Boolean {
        val geosite = File(dir, "geosite.dat")
        val geoip = File(dir, "geoip.dat")
        val stamp = File(dir, "geo-version")
        val version = runCatching {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(context.packageName, 0).versionCode.toString()
        }.getOrDefault("0")
        val current = runCatching { stamp.readText().trim() }.getOrDefault("")
        if (current == version && geosite.length() > 0 && geoip.length() > 0) return true

        for ((asset, target) in listOf("geosite.dat" to geosite, "geoip.dat" to geoip)) {
            val copied = runCatching {
                context.assets.open(asset).use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
            }
            if (copied.isFailure) {
                ConnectionLog.record(
                    "$TAG could not unpack $asset: ${copied.exceptionOrNull()?.message}"
                )
                return false
            }
        }
        runCatching { stamp.writeText(version) }
        return geosite.length() > 0 && geoip.length() > 0
    }

    /**
     * Bring the SHARD tunnel up. Blocking; call from the service's worker thread.
     *
     * Two phases, both needed: race a slice of the pool to find a node that works
     * right now, then relaunch with only that node so the live process holds one
     * outbound instead of all of them.
     *
     * ## Why no protect() call
     *
     * xray is a child process, so its sockets cannot be handed to
     * `VpnService.protect()` — that call takes a file descriptor from this process.
     * It does not need to be: a child inherits our UID, and
     * `applySplitTunneling()` calls `addDisallowedApplication(packageName)` in
     * every mode, which excludes the whole UID from the TUN. So xray's connection
     * to the node leaves over the carrier link and there is no routing loop. This
     * is exactly how the Tor process already works in this app.
     *
     * @param verboseLog raises the tunnel process's log level for troubleshooting.
     * @return true when the local SOCKS port is up and carrying traffic.
     *
     * ## Smart Split: why the profile is decided by relaunching, not by asking
     *
     * The fragmenter's `delays` array lives in the outbound, so a profile is a
     * property of a running config, not something switchable at runtime. Measuring
     * it therefore means: write config A, bring it up, put one real HTTPS request
     * through it, and if that fails write config B and do it again. Verified against
     * the real binary — both configs parse, bind and route identically apart from
     * the delays.
     *
     * The cost is bounded and paid once per network: [SmartSplit.cachedProfile]
     * short-circuits every later connect, so the second launch only ever happens on
     * a carrier the app has not yet measured.
     *
     * If neither profile carries a blocked SNI, fragmentation does not defeat this
     * DPI, and the fallback is the historical node-only config. Enabling the split
     * regardless would send every non-sanctioned site down a direct path the censor
     * closes — a working tunnel turned into a broken one by an optimisation.
     */
    @Synchronized
    fun start(
        context: Context,
        verboseLog: Boolean = false,
        port: Int = SOCKS_PORT,
    ): Boolean {
        stop()
        lastError = ""
        listenPort = port

        // Expanded across the known-good CDN edges before anything else looks at
        // it: see [ShardEdges]. The subscription's own address is kept, so this can
        // only add paths, never remove one that was working.
        val pool = ShardEdges.expand(context, ShardSubscription.nodes(context))
        if (pool.isEmpty()) {
            lastError = "no nodes available"
            ConnectionLog.record("$TAG pool empty — cache and seed both unusable")
            return false
        }
        ShardHealth.prune(context, pool)

        // Ranked, then sliced: the race is over the nodes most likely to work, in
        // the order most likely to be fast. Diversified so one endpoint's variants
        // cannot occupy the whole slice — see [diversify].
        val ranked = diversify(ShardHealth.rank(context, pool))
        // Nothing in a slice answering is not a failed connect: on a bad day the
        // known-good nodes may all be saturated while an untried one is fine, and
        // since the pool is now edge-expanded there are several times more slices
        // available than before. Bounded at [MAX_RACE_SLICES] so a genuinely dead
        // network fails in a predictable time rather than grinding through
        // everything — each slice costs up to RACE_BUDGET_MS.
        var raced: ShardNode? = null
        for (slice in 0 until MAX_RACE_SLICES) {
            val candidates = ranked.drop(slice * RACE_WIDTH).take(RACE_WIDTH)
            if (candidates.isEmpty()) break
            raced = race(context, candidates)
            if (raced != null) break
        }
        val winner = raced ?: return false

        // Wildcard only when the user asked for LAN sharing. The port is fixed
        // either way: unlike the Rust core and Psiphon, SHARD's listener is also
        // what tun2socks dials, so it cannot move to a user-chosen port.
        val listenHost = if (CoreConfig.lanSharingEnabled(context)) "0.0.0.0" else "127.0.0.1"
        val logLevel = if (verboseLog) "info" else "warning"

        // Smart Split, when the user has it on: bring the tunnel up with a fragment
        // profile and keep the first one that carries a blocked SNI. Returns true
        // when the tunnel is up and split; false means fall through to node-only.
        if (startSmartSplit(context, winner, listenHost, port, logLevel)) return true

        val config = ShardConfigs.tunnelConfig(
            context,
            winner,
            listenHost,
            port,
            logLevel,
        )
        val configFile = ShardConfigs.writeConfig(context, "tunnel.json", config)
        if (!launch(context, configFile, TAG)) return false

        // Wait for the listener rather than assume it. Reporting CONNECTED before
        // the port accepts would let tun2socks start into a closed port, which the
        // user experiences as a tunnel that connects and passes nothing.
        if (awaitListener(port)) {
            running.set(true)
            activeNode = winner
            ConnectionLog.record("$TAG up on $port via ${LogRedactor.nodeTag(winner.key)}")
            logLanSharing(context, listenHost, port)
            return true
        }
        lastError = "tunnel listener never came up"
        ConnectionLog.record("$TAG tunnel port $port never opened")
        stop()
        return false
    }

    /**
     * Try to bring the tunnel up with Smart Split. True when it is up and split.
     *
     * Ordered cheapest-first by [SmartSplit.FragmentProfile.entries]: the patient
     * profile is tried before the stubborn one, so a network where both work gets
     * the fast one. A cached measurement skips the loop and is trusted without
     * re-probing — that is the point of caching it.
     *
     * False is not an error. It means either the user has the feature off, or this
     * network was already measured as one fragmentation does not beat, or every
     * candidate failed. All three cases end with [start] launching the node-only
     * config, which is what the user had before this feature existed.
     */
    private fun startSmartSplit(
        context: Context,
        winner: ShardNode,
        listenHost: String,
        port: Int,
        logLevel: String,
    ): Boolean {
        if (!SmartSplit.enabled(context)) return false
        if (SmartSplit.measuredUnavailable(context)) {
            ConnectionLog.record("$TAG Smart Split not effective on this network; node-only")
            return false
        }
        // The geo databases must be on disk before the first split config is
        // launched: without them xray dies at startup on the first `geosite:` rule.
        val configDir = File(context.filesDir, "shard").apply { mkdirs() }
        if (!unpackGeoAssets(context, configDir)) {
            ConnectionLog.record("$TAG Smart Split skipped: geo assets unavailable")
            return false
        }

        val cached = SmartSplit.cachedProfile(context)
        val candidates = if (cached != null) {
            listOf(cached)
        } else {
            SmartSplit.FragmentProfile.entries.toList()
        }
        for (profile in candidates) {
            ConnectionLog.record("$TAG Smart Split: tuning, ${profile.attempt}")
            val splitConfig = ShardConfigs.tunnelConfig(
                context, winner, listenHost, port, logLevel, smartSplit = profile,
            )
            val splitFile = ShardConfigs.writeConfig(context, "tunnel.json", splitConfig)
            if (!launch(context, splitFile, TAG)) continue
            if (!awaitListener(port)) {
                stop()
                continue
            }
            // The measurement: a real fragmented TLS handshake to a host the censor
            // inspects. Not a latency ping — see [SmartSplit] for why a port-80 or
            // whitelisted-host probe returns a confident wrong answer.
            val ok = cached != null ||
                SmartSplit.probeThroughSocks(port, profile.probeBudgetMs)
            if (ok) {
                if (cached == null) SmartSplit.remember(context, profile)
                running.set(true)
                activeNode = winner
                ConnectionLog.record("$TAG up on $port via ${LogRedactor.nodeTag(winner.key)} · Smart Split active")
                logLanSharing(context, listenHost, port)
                return true
            }
            ConnectionLog.record("$TAG Smart Split: ${profile.attempt} did not carry a blocked site")
            stop()
        }
        // Neither profile worked: remembered, so the next connect on this network
        // does not pay the probe budget again.
        SmartSplit.recordNoProfile(context)
        ConnectionLog.record("$TAG Smart Split unavailable here; using node for everything")
        return false
    }

    /**
     * Block until [port] accepts, the process dies, or 6 s pass.
     *
     * Extracted because Smart Split launches the same process up to three times and
     * every one of them needs the same wait. Returns false rather than throwing, so
     * a caller can simply try the next candidate.
     */
    private fun awaitListener(port: Int): Boolean {
        val deadline = System.currentTimeMillis() + 6000
        while (System.currentTimeMillis() < deadline) {
            if (portAccepts(port, 400)) return true
            if (process?.isAlive != true) return false
            Thread.sleep(120)
        }
        return false
    }

    private fun logLanSharing(context: Context, listenHost: String, port: Int) {
        if (listenHost == "127.0.0.1") return
        ConnectionLog.record(
            "$TAG LAN sharing on: SOCKS $port and " +
                "HTTP ${CoreConfig.HTTP_PROXY_PORT} are reachable from the local network"
        )
    }

    /**
     * Reorder a ranked pool so consecutive entries are different endpoints.
     *
     * Necessary because [ShardEdges] turns one endpoint into several entries that
     * share a credential and differ only by edge IP. Their health scores are
     * naturally similar, so a plain ranking clusters them — and a 12-wide race
     * would then spend all twelve slots on two or three endpoints. If those
     * endpoints are dead (a revoked UUID, a deleted worker), every slot is wasted
     * and the connect fails with a pool that had dozens of live alternatives.
     *
     * Round-robins by endpoint identity instead: the best variant of endpoint A,
     * then of B, then of C, and only after every endpoint has had a turn does the
     * second variant of A appear. Relative order within an endpoint is preserved,
     * so the health memory still decides which edge is tried first for it.
     */
    private fun diversify(ranked: List<ShardNode>): List<ShardNode> {
        // Identity excludes the address deliberately — that is what varies between
        // variants of the same endpoint. Port is included because 443 and 8080 on
        // one host are genuinely different paths through the CDN.
        val groups = LinkedHashMap<String, MutableList<ShardNode>>()
        ranked.forEach { node ->
            val identity = "${node.protocol}|${node.credential}|${node.host}|${node.path}|${node.port}"
            groups.getOrPut(identity) { mutableListOf() }.add(node)
        }
        val out = ArrayList<ShardNode>(ranked.size)
        var round = 0
        while (out.size < ranked.size) {
            var addedThisRound = false
            groups.values.forEach { variants ->
                variants.getOrNull(round)?.let {
                    out.add(it)
                    addedThisRound = true
                }
            }
            // Guards against an infinite loop if the accounting is ever wrong.
            if (!addedThisRound) break
            round++
        }
        return out
    }

    /**
     * Switch to another node without tearing the VPN down.
     *
     * Called by the service's watchdog when the current node stops answering. The
     * TUN interface, tun2socks and the SOCKS port all stay exactly as they are —
     * only the process behind the port is replaced — so the user sees a stall of a
     * second or two rather than a disconnect. This is the "test after connecting,
     * not only before" behaviour: a race winner can die 30 seconds later when its
     * owner rotates the UUID, and that must not end the session.
     *
     * @return true when a different node is now serving the port.
     */
    @Synchronized
    fun rotate(context: Context, verboseLog: Boolean = false): Boolean {
        val previous = activeNode
        val port = listenPort
        previous?.let { ShardHealth.recordFailure(context, it) }
        ConnectionLog.record("$TAG rotating away from ${previous?.let { LogRedactor.nodeTag(it.key) } ?: "unknown"}")
        // start() re-ranks, and the failure just recorded pushes the dead node
        // down, so the same node is not chosen again immediately. The port is
        // carried over explicitly: it must not silently revert to the default
        // under a proxy-mode session whose clients are pointed at another one.
        return start(context, verboseLog, port)
    }

    /**
     * Is the live tunnel still carrying traffic?
     *
     * Checked through the real SOCKS port with a real request, because a process
     * that is alive and a port that accepts prove nothing about whether the node
     * on the far side still works.
     */
    fun isHealthy(): Boolean = isRunning && ShardProbe.check(listenPort, PROBE_TIMEOUT_MS)

    /**
     * Race [candidates] and return the first node that carries a real request.
     *
     * This is the Hiddify-style behaviour the user asked for: it does not wait for
     * every node to report a delay, it takes the first success and abandons the
     * rest. Measured on the live pool — a winner in 760–864 ms across three runs,
     * against 82 s to probe all 28 nodes sequentially.
     *
     * The probe is a real HTTP request through the node's own SOCKS inbound, not a
     * TCP ping. TCP ping was measured to be useless here: every node in the pool
     * resolves to the same Cloudflare edge, so `connect()` always succeeds and
     * tells us nothing about whether the node's worker and UUID still work.
     *
     * @return the winner, or null if nothing answered inside the budget.
     */
    private fun race(context: Context, candidates: List<ShardNode>): ShardNode? {
        if (candidates.isEmpty()) return null
        val config = ShardConfigs.probeConfig(candidates, PROBE_BASE_PORT)
        val configFile = ShardConfigs.writeConfig(context, "probe.json", config)
        if (!launch(context, configFile, "$TAG/probe")) return null

        try {
            // xray binds its listeners a moment after exec. Waiting for the first
            // port instead of sleeping a fixed amount keeps a fast device fast.
            var ready = false
            val deadline = System.currentTimeMillis() + 4000
            while (System.currentTimeMillis() < deadline) {
                if (portAccepts(PROBE_BASE_PORT, 300)) {
                    ready = true
                    break
                }
                Thread.sleep(100)
            }
            if (!ready) {
                lastError = "probe listener never came up"
                ConnectionLog.record("$TAG probe listeners did not bind")
                return null
            }

            val winner = java.util.concurrent.atomic.AtomicReference<ShardNode?>(null)
            val winnerLatency = java.util.concurrent.atomic.AtomicInteger(0)
            val latch = java.util.concurrent.CountDownLatch(1)
            val pool = java.util.concurrent.Executors.newFixedThreadPool(
                candidates.size.coerceAtMost(RACE_WIDTH)
            )

            candidates.forEachIndexed { index, node ->
                pool.execute {
                    // Once someone has won, the remaining probes are pointless
                    // work on a metered link — stop rather than finish politely.
                    if (winner.get() != null) return@execute
                    val started = System.currentTimeMillis()
                    val ok = ShardProbe.check(PROBE_BASE_PORT + index, PROBE_TIMEOUT_MS)
                    val elapsed = (System.currentTimeMillis() - started).toInt()
                    if (ok) {
                        ShardHealth.recordSuccess(context, node, elapsed)
                        // compareAndSet, so the genuinely first success wins even
                        // when two finish in the same millisecond.
                        if (winner.compareAndSet(null, node)) {
                            winnerLatency.set(elapsed)
                            latch.countDown()
                        }
                    } else {
                        ShardHealth.recordFailure(context, node)
                    }
                }
            }

            latch.await(RACE_BUDGET_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
            pool.shutdownNow()

            val chosen = winner.get()
            if (chosen == null) {
                lastError = "no node answered"
                ConnectionLog.record("$TAG race found nothing in ${RACE_BUDGET_MS}ms")
            } else {
                ConnectionLog.record("$TAG winner ${LogRedactor.nodeTag(chosen.key)} in ${winnerLatency.get()}ms")
            }
            return chosen
        } catch (e: Exception) {
            lastError = "race failed: ${e.message}"
            ConnectionLog.record("$TAG race error: ${e.message}")
            return null
        } finally {
            // The probe process must die before the tunnel process starts: they
            // would otherwise fight over nothing, but it is 45 idle outbounds worth
            // of memory for no reason.
            stop()
        }
    }
}
