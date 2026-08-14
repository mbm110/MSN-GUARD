package studio.cluvex.aethery

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ServiceInfo
import android.service.quicksettings.TileService
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.util.ArrayDeque
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import ca.psiphon.PsiphonTunnel

/**
 * Protocol sets shared between a rung's config and its winner-detection.
 *
 * Declared top-level (not in the companion) so the ladder property initializer
 * can reference them without depending on companion init order.
 */
private val PROTOCOLS_443 = listOf("TLS-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH", "FRONTED-MEEK-OSSH")
private val PROTOCOLS_FRONTED = listOf("FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH", "FRONTED-MEEK-QUIC-OSSH")
private val PROTOCOLS_INPROXY_BOOTSTRAP = listOf("FRONTED-MEEK-OSSH", "FRONTED-MEEK-QUIC-OSSH", "TLS-OSSH")

/**
 * One rung of the Psiphon escalation ladder.
 *
 * Each rung is a complete, self-contained Psiphon config variant plus the time
 * we are willing to spend on it before moving to the next rung. The ladder is
 * ordered by *expected time to first connection on a hostile carrier*, not by
 * how clever the technique is — the cheapest thing that plausibly works goes
 * first so the common case stays fast.
 */
private class PsiphonStrategy(
    val name: String,
    val label: String,
    val timeoutSeconds: Int,
    /**
     * Protocols this rung asks Psiphon to try first.
     *
     * This is only a *preference*: Psiphon falls back to its full protocol set
     * once InitialLimitTunnelProtocolsCandidateCount candidates are exhausted.
     * So the protocol that ends up carrying the tunnel is often not from this
     * list, which is exactly why winner detection reads the live ActiveTunnel
     * notice instead of assuming the active rung won.
     */
    val preferredProtocols: List<String>,
    val configure: (JSONObject) -> Unit,
)

class MsnGuardVpnService : VpnService(), NativeCore.CoreCallback, PsiphonTunnel.HostService {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val connected = AtomicBoolean(false)
    private val stopRequested = AtomicBoolean(false)
    private val vpnModeActive = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private var lastTrafficSampleMs = 0L
    private var currentTx = 0L
    private var currentRx = 0L
    private var prevTx = 0L
    private var prevRx = 0L
    private var prevSpeedSampleMs = 0L
    private var currentSpeedTx = 0L
    private var currentSpeedRx = 0L
    private var accountedTx = 0L
    private var accountedRx = 0L
    private var storedConfig: String? = null
    private var storedVpnMode = true
    private var currentProtocol = "Tunnel"
    private var currentVpnIp = ""
    private var currentPing = ""
    private var psiphonTunnel: PsiphonTunnel? = null
    private var psiphonConfigJson: String = ""
    private var psiphonVpnMode = false
    private var psiphonVpnActivated = false
    private var activeSocksPort = 0

    // Evidence about how the tunnel was actually established, gathered from
    // Psiphon's own notices rather than inferred from which rung was active.
    private var activeTunnelProtocol = ""
    private var inproxyInUse = false

    // --- Psiphon escalation ladder state ---
    // A hostile carrier (Hamrah-e-Aval) null-routes Psiphon's server IPs, so the
    // first rung of the ladder will time out. Rather than sitting on one config
    // for two minutes and giving up, we walk the ladder automatically: each rung
    // gets its own budget, and a timeout promotes us to the next rung without
    // any user interaction.
    private val ladderScheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private var ladderIndex = 0
    private var ladderAttempts = 0
    private var ladderTimer: ScheduledFuture<*>? = null
    private val ladderActive = AtomicBoolean(false)

    /**
     * The escalation ladder, ordered by expected time-to-connect on a carrier
     * that blocks Psiphon by IP.
     *
     * Rung 1 (B) is first because it costs nothing: same servers, same code
     * path, just a protocol preference. 100% of TLS-OSSH entries and 60% of MEEK
     * entries listen on 443, versus 4% of plain OSSH — so preferring them means
     * we stop wasting the budget dialling ports 53/554 that the carrier drops.
     *
     * Rung 2 (A) adds the DNS escape hatch. FRONTED-MEEK needs working DNS to
     * resolve its CDN front, and in VPN mode our own TUN was swallowing those
     * queries. This rung re-dials with the resolver loop broken.
     *
     * Rung 3 (C) is in-proxy: connect through volunteer peers over WebRTC.
     * Their IPs are residential and not in the carrier's blocklist, so this is
     * the rung that works when every Psiphon server IP is unreachable. It is
     * last because WebRTC negotiation is slow and needs a broker handshake.
     */
    private val psiphonLadder: List<PsiphonStrategy> = listOf(
        PsiphonStrategy(
            name = "B",
            label = "443-only protocols",
            timeoutSeconds = 45,
            preferredProtocols = PROTOCOLS_443,
        ) { config ->
            // Every one of these listens on 443 and looks like ordinary HTTPS on
            // the wire. Psiphon tries these first, then falls back to the full
            // set on its own if the initial limit yields nothing.
            config.put("InitialLimitTunnelProtocols", JSONArray(PROTOCOLS_443))
            config.put("InitialLimitTunnelProtocolsCandidateCount", 40)
            config.put("ConnectionWorkerPoolSize", 12)
        },
        PsiphonStrategy(
            name = "A",
            label = "domain-fronted + public DNS",
            timeoutSeconds = 60,
            preferredProtocols = PROTOCOLS_FRONTED,
        ) { config ->
            // Fronted protocols reach a CDN edge (Amazon/Cloudflare), never a
            // Psiphon-owned IP, so a carrier IP blocklist cannot touch them.
            // They need working DNS to resolve the front, which is why the TUN
            // also lists public resolvers (see the Builder below).
            config.put("InitialLimitTunnelProtocols", JSONArray(PROTOCOLS_FRONTED))
            config.put("InitialLimitTunnelProtocolsCandidateCount", 60)
            config.put("ConnectionWorkerPoolSize", 16)
            // Give slow CDN paths room to complete instead of being cut off as
            // if they were a dead direct dial.
            config.put("NetworkLatencyMultiplier", 2.0)
        },
        PsiphonStrategy(
            name = "C",
            label = "in-proxy (peer relay)",
            timeoutSeconds = 90,
            preferredProtocols = PROTOCOLS_INPROXY_BOOTSTRAP,
        ) { config ->
            // In-proxy routes through other Psiphon users' devices over WebRTC.
            // Their IPs are residential and not in the carrier's blocklist, which
            // is what makes this rung work when every Psiphon server IP is dead.
            //
            // Deliberately NOT setting InitialLimitTunnelProtocols to an
            // INPROXY-* name here: only the 14-char prefix "INPROXY-WEBRTC"
            // exists as a literal in libgojni.so, so the full protocol names are
            // assembled at runtime and we cannot verify the exact spelling. An
            // unrecognised name in that list risks failing config validation and
            // taking the whole rung down. Enabling the in-proxy flags and letting
            // Psiphon choose is equivalent and cannot misfire.
            config.put("InproxyEnabled", true)
            config.put("InproxyAllowClient", true)
            config.put("InproxySkipAwaitFullyConnected", true)
            // Fronted protocols stay available: the broker specs are not shipped
            // in our server_entries.txt, so the broker list has to arrive via a
            // Tactics request, and that request needs a working egress itself.
            config.put("InitialLimitTunnelProtocols", JSONArray(PROTOCOLS_INPROXY_BOOTSTRAP))
            config.put("ConnectionWorkerPoolSize", 16)
            config.put("NetworkLatencyMultiplier", 3.0)
        },
    )

    companion object {
        const val LOG_TAG = "MsnGuardVpnService"
        const val ACTION_CONNECT = "studio.cluvex.aethery.CONNECT"
        const val ACTION_DISCONNECT = "studio.cluvex.aethery.DISCONNECT"
        const val ACTION_RECONNECT = "studio.cluvex.aethery.RECONNECT"
        const val ACTION_NOTIFICATION_HEALTH = "studio.cluvex.aethery.NOTIFICATION_HEALTH"
        const val ACTION_STATUS = "studio.cluvex.aethery.STATUS"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_VPN_MODE = "vpn_mode"
        const val EXTRA_STATUS = "status"
        const val EXTRA_DETAIL = "detail"
        const val EXTRA_TRAFFIC_TX = "traffic_tx"
        const val EXTRA_TRAFFIC_RX = "traffic_rx"
        const val EXTRA_TRAFFIC_SPEED_TX = "traffic_speed_tx"
        const val EXTRA_TRAFFIC_SPEED_RX = "traffic_speed_rx"
        const val EXTRA_TRAFFIC_MONTH_TX = "traffic_month_tx"
        const val EXTRA_TRAFFIC_MONTH_RX = "traffic_month_rx"
        const val EXTRA_NOTIFICATION_IP = "notification_ip"
        const val EXTRA_NOTIFICATION_PING = "notification_ping"
        const val STATUS_CONNECTING = "connecting"
        const val STATUS_STARTING = "starting"
        const val STATUS_SCANNING = "scanning"
        const val STATUS_CONNECTED = "connected"
        const val STATUS_DISCONNECTED = "disconnected"
        const val STATUS_FAILED = "failed"
        const val CHANNEL_ID = "vpn_channel"
        const val NOTIFICATION_ID = 1
        const val TRAFFIC_PREFS = "traffic_stats"
        const val TRAFFIC_MONTH = "month"
        const val TRAFFIC_TX = "tx"
        const val TRAFFIC_RX = "rx"
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun bindToDevice(fd: Long) {
        if (!protect(fd.toInt())) {
            throw PsiphonTunnel.Exception("protect(fd=$fd) failed")
        }
    }

    override fun onListeningSocksProxyPort(port: Int) {
        activeSocksPort = port
        ConnectionLog.record("Psiphon SOCKS proxy listening on port $port")
    }

    override fun onConnecting() {
        ConnectionLog.record("Psiphon connecting")
    }

    override fun onConnected() {
        ConnectionLog.record("Psiphon connected — upstream tunnel ready")
        // A tunnel exists: disarm the watchdog so it cannot tear down a working
        // connection, then work out which rung deserves the credit.
        ladderActive.set(false)
        cancelLadderTimer()
        recordLadderWinner()
        ladderAttempts = 0

        val port = activeSocksPort
        if (port <= 0) {
            sendStatus(STATUS_FAILED, "Psiphon SOCKS port unavailable")
            return
        }
        val socksProxy = "127.0.0.1:$port"

        if (!psiphonVpnMode) {
            // PROXY MODE: just expose the SOCKS port — no TUN needed.
            ConnectionLog.record("Psiphon SOCKS proxy ready at $socksProxy")
            sendStatus(STATUS_CONNECTED)
            return
        }

        // VPN MODE: TUN is already up (created in startTunnel() before Psiphon
        // started). tun2socks keeps running across Psiphon rotations — the SOCKS
        // port is fixed, so a rotation only breaks in-flight upstream sockets and
        // lwIP resets those individual flows while the TUN device stays up.
        if (psiphonVpnActivated && Tun2SocksManager.isRunning) {
            ConnectionLog.record("Psiphon reconnected — tun2socks still routing, nothing to do")
            sendStatus(STATUS_CONNECTED)
            return
        }

        val tunFd = tun
        if (tunFd == null) {
            sendStatus(STATUS_FAILED, "VPN interface missing")
            return
        }

        if (!Tun2SocksManager.start(tunFd, port)) {
            sendStatus(STATUS_FAILED, "Could not start whole-device routing")
            return
        }
        psiphonVpnActivated = true
        ConnectionLog.record("Whole-device routing active via tun2socks → $socksProxy")
        connected.set(true)
        // Replace the placeholder "Connecting..." notification immediately. It used
        // to be overwritten by the first traffic sample from the Rust core; with
        // tun2socks the first sample can be seconds away, so the notification
        // would sit on "Connecting..." while the device was fully tunnelled.
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification(currentTx, currentRx))
        sendStatus(STATUS_CONNECTED)
    }

    override fun onExiting() {
        ConnectionLog.record("Psiphon exiting")
        psiphonTunnel = null
        // Psiphon hit its own EstablishTunnelTimeout and shut the controller down.
        // That is the definitive "this rung is dead" signal, and it arrives before
        // our watchdog's grace period expires — so escalate now instead of leaving
        // the user staring at a stalled spinner for another 8 seconds.
        // Guarded: a user-initiated stop also lands here, and so does a teardown
        // that follows a successful connection.
        if (!stopRequested.get() && !psiphonVpnActivated && ladderActive.get()) {
            escalateLadder()
        }
    }

    override fun onClientAddress(address: String?) {
        if (!address.isNullOrBlank()) {
            ConnectionLog.record("Psiphon exit IP: $address")
            getSharedPreferences("settings", MODE_PRIVATE).edit()
                .putString("last_ip", address).apply()
        }
    }

    override fun onHomepage(homepage: String?) {
        ConnectionLog.record("Psiphon homepage: ${homepage ?: "—"}")
    }

    override fun onClientRegion(region: String?) {
        if (!region.isNullOrBlank()) ConnectionLog.record("Psiphon region: $region")
    }

    override fun onBytesTransferred(sent: Long, received: Long) {
        // In VPN mode there is no Rust core in the data path anymore, so Psiphon's
        // own byte counters are the source of traffic stats. These arrive as
        // deltas, not totals.
        if (!psiphonVpnMode) return
        currentTx += sent
        currentRx += received
        updateTrafficNotification(currentTx, currentRx)
    }

    override fun onDiagnosticMessage(message: String) {
        ConnectionLog.record("Psiphon: $message")
        // Capture the protocol that actually carried the tunnel.
        //
        // InitialLimitTunnelProtocols is a preference, not a constraint: once the
        // candidate budget is spent Psiphon reverts to its full protocol set. Both
        // reported field logs proved this — Hamrah-e-Aval ended on
        // FRONTED-MEEK-OSSH (rung A's protocol) while rung B was active, and
        // SamanTel ended on plain OSSH with an in-proxy broker (rung C's mechanism)
        // while rung B was active. Attributing the win to the active rung was
        // therefore wrong in both cases, and persisting that wrong rung meant the
        // next connect started from a strategy that had not actually worked.
        if (message.startsWith("ActiveTunnel:")) {
            runCatching {
                val protocol = JSONObject(message.substringAfter("ActiveTunnel:").trim())
                    .optString("protocol")
                if (protocol.isNotBlank()) activeTunnelProtocol = protocol
            }
        }
        // An in-proxy broker selection is decisive evidence the peer-relay path is
        // in play, regardless of which OSSH variant rides on top of it.
        if (message.contains("inproxy: selected broker")) {
            inproxyInUse = true
        }
    }

    override fun getContext(): android.content.Context = this

    override fun getPsiphonConfig(): String = psiphonConfigJson

    private fun buildPsiphonConfig(vpnMode: Boolean = true): String {
        val prefs = getSharedPreferences("settings", MODE_PRIVATE)
        // VPN mode: always use fixed port 1819 so TUN can be pre-created.
        // Proxy mode: use user-configured port (default 1819).
        val socksPort = prefs.getInt("default_socks_port", 1819)
        val config = org.json.JSONObject().apply {
            put("PropagationChannelId", "FFFFFFFFFFFFFFFF")
            put("SponsorId", "1111111111111111")
            put("EgressRegion", "")
            put("EstablishTunnelTimeoutSeconds", 120)
            put("DataDirectory", filesDir.absolutePath)
            put("ClientVersion", "1")
            put("TunnelProtocol", "")
            put("RemoteServerListURL", "")
            put("LocalSocksProxyPort", socksPort)
            put("RemoteServerListSignaturePublicKey", "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=")
            put("ServerEntrySignaturePublicKey", "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA=")
            put("ExchangeObfuscationKey", "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU=")
            // Required for onBytesTransferred() to ever fire. Psiphon suppresses
            // the BytesTransferred notice unless this is set, and in VPN mode
            // Psiphon's counters are the ONLY traffic source now that the Rust
            // core is out of the data path — without it the notification stays
            // stuck on "Connecting..." forever and data usage reads 0.
            put("EmitBytesTransferred", true)
            // --- Anti-censorship tuning for restrictive ISPs (e.g. Hamrah-e-Aval) ---
            // Tell Psiphon the user is in Iran so Iran-specific Tactics (protocol
            // selection, padding, server prioritization) are downloaded and applied.
            put("DeviceRegion", "IR")
            // More concurrent connection attempts = higher probability of finding
            // a server/protocol that survives DPI on restrictive networks.
            put("ConnectionWorkerPoolSize", 12)
            // Emit detailed diagnostic notices so we can see exactly which
            // protocols/servers fail on which carriers.
            put("EmitDiagnosticNotices", true)
            // Note: "DisableNetworkManager" was tried here and is a no-op — the
            // key does not exist in libgojni.so (verified with strings). Psiphon's
            // NetworkMonitor still restarts the tunnel when tun0 appears. That is
            // survivable now: tun2socks holds the TUN fd and the SOCKS port is
            // fixed, so a rotation only kills in-flight upstream sockets and lwIP
            // resets those flows individually instead of dropping the interface.
        }

        // Apply the current rung of the escalation ladder. Each rung overrides
        // protocol selection and worker-pool sizing on top of the base config,
        // and owns the establish timeout so a dead rung is abandoned quickly
        // instead of burning the full two minutes.
        val strategy = psiphonLadder.getOrNull(ladderIndex)
        if (strategy != null) {
            strategy.configure(config)
            config.put("EstablishTunnelTimeoutSeconds", strategy.timeoutSeconds)
            ConnectionLog.record(
                "Strategy ${ladderIndex + 1}/${psiphonLadder.size} " +
                    "(${strategy.name}): ${strategy.label} — ${strategy.timeoutSeconds}s budget"
            )
        }
        return config.toString()
    }

    private fun startPsiphonTunnel(vpnMode: Boolean = true) {
        try {
            // Clear evidence from any previous rung: attribution must reflect this
            // attempt only, otherwise a protocol notice from a failed rung would
            // be credited to whichever rung eventually connects.
            activeTunnelProtocol = ""
            inproxyInUse = false
            val tunnel = PsiphonTunnel.newPsiphonTunnel(this)
            // Always SOCKS mode — in VPN mode we bridge TUN→SOCKS ourselves.
            tunnel.setVpnMode(false)
            psiphonTunnel = tunnel
            psiphonConfigJson = buildPsiphonConfig(vpnMode)

            // Load hex-encoded server entries from assets
            val serverEntries = try {
                assets.open("server_entries.txt").bufferedReader().readText().trim()
            } catch (e: Exception) {
                ConnectionLog.record("No server_entries.txt in assets: ${e.message}")
                ""
            }
            // Fire-and-forget: Psiphon connects asynchronously.
            // onListeningSocksProxyPort() saves the port.
            // onConnected() starts the Rust core to bridge TUN → SOCKS.
            tunnel.startTunneling(serverEntries)
            ConnectionLog.record("Psiphon tunnel starting...")
            armLadderTimer()
        } catch (e: Exception) {
            ConnectionLog.record("Psiphon start failed: ${e.message}")
            activeSocksPort = 0
        }
    }

    /**
     * Arm the watchdog for the current rung.
     *
     * Psiphon's own EstablishTunnelTimeout fires inside the Go core and shuts the
     * controller down without telling us which rung failed, so we keep our own
     * timer with a small grace period on top. Whichever fires first, the effect
     * is the same: [escalateLadder] moves to the next rung.
     */
    private fun armLadderTimer() {
        val strategy = psiphonLadder.getOrNull(ladderIndex) ?: return
        cancelLadderTimer()
        ladderActive.set(true)
        // +8s grace so Psiphon's internal timeout and teardown land first; racing
        // it would restart the tunnel while the old controller is still stopping.
        val budget = strategy.timeoutSeconds.toLong() + 8L
        ladderTimer = ladderScheduler.schedule({
            if (ladderActive.get() && !psiphonVpnActivated) escalateLadder()
        }, budget, TimeUnit.SECONDS)
    }

    private fun cancelLadderTimer() {
        ladderTimer?.cancel(false)
        ladderTimer = null
    }

    /**
     * Persist the rung that genuinely produced the tunnel.
     *
     * Attribution is by *evidence*, in order of how conclusive it is:
     *
     *  1. An in-proxy broker was selected -> rung C, whatever protocol rode on
     *     top. SamanTel connected with plain "OSSH" but the log also showed
     *     "inproxy: selected broker", so protocol alone would have mislabelled it.
     *  2. The live ActiveTunnel protocol matches exactly one rung's preferred
     *     list -> that rung. Hamrah-e-Aval ended on FRONTED-MEEK-OSSH, which is
     *     rung A's signature.
     *  3. The protocol appears in several rungs' lists (FRONTED-MEEK-OSSH is in
     *     all three) -> keep the rung that was active, since it is consistent
     *     with the evidence and switching on ambiguity would just add churn.
     *  4. No protocol notice arrived at all -> keep the active rung.
     *
     * Getting this right matters because the stored value decides where the next
     * connect *starts*: a wrong entry costs the user a full rung timeout before
     * the ladder stumbles onto the path that already worked on their carrier.
     */
    private fun recordLadderWinner() {
        val protocol = activeTunnelProtocol
        val inproxyRung = psiphonLadder.indexOfFirst { it.name == "C" }

        val (winnerIndex, reason) = when {
            inproxyInUse && inproxyRung >= 0 ->
                inproxyRung to "in-proxy broker in use"

            protocol.isNotBlank() -> {
                val matches = psiphonLadder.indices.filter { i ->
                    psiphonLadder[i].preferredProtocols.contains(protocol)
                }
                when {
                    matches.size == 1 -> matches[0] to "protocol $protocol is unique to this strategy"
                    matches.contains(ladderIndex) -> ladderIndex to "protocol $protocol consistent with active strategy"
                    matches.isNotEmpty() -> matches[0] to "protocol $protocol best match"
                    else -> ladderIndex to "protocol $protocol not in any preference list; keeping active strategy"
                }
            }

            else -> ladderIndex to "no protocol notice; keeping active strategy"
        }

        val winner = psiphonLadder.getOrNull(winnerIndex) ?: return
        getSharedPreferences("settings", MODE_PRIVATE).edit()
            .putInt("psiphon_winning_strategy", winnerIndex).apply()

        val via = if (protocol.isNotBlank()) " via $protocol" else ""
        ConnectionLog.record(
            "Connected$via — crediting strategy ${winner.name} (${winner.label}): $reason"
        )
        if (winnerIndex != ladderIndex) {
            val active = psiphonLadder.getOrNull(ladderIndex)
            ConnectionLog.record(
                "Note: strategy ${active?.name ?: "?"} was active but ${winner.name} " +
                    "carried the tunnel — next connect will start from ${winner.name}"
            )
        }
    }

    /**
     * Move to the next rung and re-dial, or give up if the ladder is exhausted.
     *
     * The TUN interface is deliberately left up across rungs: it was created
     * before Psiphon started, tun2socks is not running yet (no tunnel ever came
     * up), and rebuilding it would drop the VPN permission dialog state. Only
     * the Psiphon controller is torn down and restarted with the next config.
     */
    private fun escalateLadder() {
        if (stopRequested.get()) return
        if (!ladderActive.compareAndSet(true, false)) return
        cancelLadderTimer()

        val failed = psiphonLadder.getOrNull(ladderIndex)
        ladderAttempts += 1

        // Wrap around instead of walking off the end. Because a successful rung is
        // remembered and reused first, the ladder can start anywhere — so "done"
        // means every rung has had a turn, not that the index hit the last slot.
        if (ladderAttempts >= psiphonLadder.size) {
            ConnectionLog.record(
                "All ${psiphonLadder.size} strategies exhausted — carrier is blocking every available path"
            )
            sendStatus(STATUS_FAILED, "Could not connect on this carrier. Try Wi-Fi or another SIM.")
            ladderIndex = 0
            ladderAttempts = 0
            return
        }

        ladderIndex = (ladderIndex + 1) % psiphonLadder.size
        val next = psiphonLadder[ladderIndex]
        ConnectionLog.record(
            "Strategy ${failed?.name ?: "?"} timed out — escalating to ${next.name}: ${next.label}"
        )
        sendStatus(STATUS_CONNECTING, "Trying ${next.label}...")

        worker.execute {
            if (stopRequested.get()) return@execute
            // Tear down only the Psiphon controller. The TUN stays up.
            try { psiphonTunnel?.stop() } catch (_: Exception) {}
            psiphonTunnel = null
            activeSocksPort = getSharedPreferences("settings", MODE_PRIVATE)
                .getInt("default_socks_port", 1819)
            try { Thread.sleep(1200) } catch (_: InterruptedException) {}
            if (stopRequested.get()) return@execute
            startPsiphonTunnel(psiphonVpnMode)
        }
    }

    private fun stopPsiphonTunnel() {
        try { psiphonTunnel?.stop() } catch (_: Exception) {}
        psiphonTunnel = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> intent.getStringExtra(EXTRA_CONFIG)?.let { config ->
                startTunnel(config, intent.getBooleanExtra(EXTRA_VPN_MODE, true))
            }
            ACTION_DISCONNECT -> stopTunnel()
            ACTION_RECONNECT -> {
                val config = storedConfig
                if (config != null && connected.get()) {
                    ConnectionLog.record("Quick reconnect requested")
                    stopTunnel(notify = false, teardownService = false)
                    worker.execute {
                        try { Thread.sleep(500) } catch (_: InterruptedException) {}
                        startTunnel(config, storedVpnMode)
                    }
                }
            }
            ACTION_NOTIFICATION_HEALTH -> {
                intent.getStringExtra(EXTRA_NOTIFICATION_IP)?.let { currentVpnIp = it }
                intent.getStringExtra(EXTRA_NOTIFICATION_PING)?.let { currentPing = it }
                getSystemService(NotificationManager::class.java)
                    .notify(NOTIFICATION_ID, notification(currentTx, currentRx))
            }
        }
        return Service.START_REDELIVER_INTENT
    }

    override fun onDestroy() {
        stopTunnel(notify = false)
        cancelLadderTimer()
        ladderScheduler.shutdownNow()
        worker.shutdownNow()
        super.onDestroy()
    }

    fun protectSocket(fd: Int): Boolean = !vpnModeActive.get() || protect(fd)

    override fun onEvent(json: String) {
        try {
            val event = JSONObject(json)
            when (event.getString("type")) {
                "status" -> {
                    val status = event.getString("status")
                    val detail = if (event.isNull("detail")) null else event.getString("detail")
                    sendStatus(status, detail)
                }
                "traffic" -> {
                    val tx = event.getLong("tx")
                    val rx = event.getLong("rx")
                    currentTx = tx
                    currentRx = rx
                    updateTrafficNotification(tx, rx)
                }
                "log" -> {
                    val message = event.getString("message")
                    ConnectionLog.record(message)
                }
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Failed to parse event: $json", e)
        }
    }

    private fun startTunnel(config: String, vpnMode: Boolean) {
        if (!connected.compareAndSet(false, true)) return
        storedConfig = config
        storedVpnMode = vpnMode
        currentProtocol = config.substringAfter("\"protocol\":\"").substringBefore('"').uppercase()
        currentVpnIp = ""
        currentPing = ""
        stopRequested.set(false)
        vpnModeActive.set(vpnMode)
        startAsForeground()

        // PSIPHON: callback-driven lifecycle — MUST NOT enter try/finally.
        // The finally block calls stopSelf() which destroys the service and kills Psiphon.
        if (currentProtocol.contains("PSIPHON")) {
            psiphonVpnMode = vpnMode  // Save for onConnected() callback
            psiphonVpnActivated = false
            // Start from the rung that last worked on this device. On the first
            // ever connect, or after a full ladder failure, this is rung 0.
            ladderIndex = getSharedPreferences("settings", MODE_PRIVATE)
                .getInt("psiphon_winning_strategy", 0)
                .coerceIn(0, psiphonLadder.size - 1)
            ladderAttempts = 0
            worker.execute {
                try {
                    ConnectionLog.record("Preparing PSIPHON identity (${if (vpnMode) "VPN" else "Proxy"} mode)")
                    if (vpnMode) {
                        // VPN MODE: Create TUN FIRST, then start Psiphon.
                        // This prevents Psiphon's NetworkMonitor from seeing a "change"
                        // when tun0 appears — the 13-second restart loop is eliminated.
                        val socksPort = getSharedPreferences("settings", MODE_PRIVATE)
                            .getInt("default_socks_port", 1819)

                        // Address plan comes from tun2socks: the interface gets
                        // .ipAddress while lwIP answers on .router, which is also
                        // the DNS resolver the system will use. These must not be
                        // swapped or lwIP drops every packet.
                        val address = Tun2SocksManager.selectPrivateAddress()

                        ConnectionLog.record("Creating TUN interface BEFORE Psiphon starts")
                        tun = Builder()
                            .setSession("MSN-VPN")
                            .setMtu(Tun2SocksManager.VPN_INTERFACE_MTU)
                            .addAddress(address.ipAddress, address.prefixLength)
                            .addRoute("0.0.0.0", 0)
                            .addRoute(address.subnet, address.prefixLength)
                            .addDnsServer(address.router)
                            // --- Strategy A: break the DNS bootstrap deadlock ---
                            // With only address.router as a resolver, every DNS
                            // query goes lwIP → udpgw → Psiphon. Before a tunnel
                            // exists there is nothing on the far end, so DNS is
                            // dead exactly when Psiphon needs it to resolve the
                            // CDN hostnames that FRONTED-MEEK depends on. The log
                            // showed this as "resp 0/0" with 20-second RTTs and
                            // four consecutive "resolve canceled" tactics failures.
                            //
                            // Listing public resolvers as additional DNS servers
                            // gives the resolver somewhere to go. Combined with
                            // addDisallowedApplication(packageName) below — which
                            // keeps our own process off the TUN entirely — Psiphon's
                            // queries leave over the carrier link and resolve
                            // normally, so the fronted protocols become usable.
                            .addDnsServer("1.1.1.1")
                            .addDnsServer("8.8.8.8")
                            .addDisallowedApplication(packageName)
                            .establish() ?: error("Android could not establish the VPN interface")
                        vpnModeActive.set(true)
                        ConnectionLog.record("TUN ready — now starting Psiphon on port $socksPort")
                        // Pre-save the SOCKS port so onConnected() can start tun2socks immediately.
                        activeSocksPort = socksPort
                        startPsiphonTunnel(vpnMode)
                        sendStatus(STATUS_CONNECTING, "Psiphon starting...")
                    } else {
                        // PROXY MODE: just start Psiphon, no TUN needed.
                        startPsiphonTunnel(vpnMode)
                        sendStatus(STATUS_CONNECTING, "Psiphon starting...")
                    }
                } catch (e: Exception) {
                    ConnectionLog.record("Psiphon start failed: ${e.message}")
                    sendStatus(STATUS_FAILED, e.message)
                    connected.set(false)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
            return
        }

        worker.execute {
            try {
                ConnectionLog.record("Preparing $currentProtocol identity")
                NativeCore.attach(this)
                val result = if (vpnMode) {
                    val addresses = NativeCore.prepare(config)
                    ConnectionLog.record("Creating Android VPN interface")
                    tun = Builder()
                        .setSession("MSN-VPN")
                        .setMtu(1280)
                        .addAddress(addresses.ipv4, 32)
                        .addAddress(addresses.ipv6, 128)
                        .addRoute("0.0.0.0", 0)
                        .addRoute("::", 0)
                        .applyDns(config)
                        .applyLanAccess()
                        .applySplitTunneling()
                        // applySplitTunneling() handles app exclusion per mode.
                        .establish() ?: error("Android could not establish the VPN interface")
                    ConnectionLog.record("Scanning gateways for VPN")
                    NativeCore.start(config, tun!!.fd)
                } else {
                    ConnectionLog.record("Starting local SOCKS5 proxy")
                    NativeCore.startProxy(config)
                }

                if (result != 0 && !stopRequested.get()) {
                    val detail = NativeCore.lastError().ifBlank { "Tunnel exited with code $result" }
                    ConnectionLog.record("Native tunnel exited: $detail")
                    sendStatus(STATUS_FAILED, detail)
                } else if (stopRequested.get()) {
                    sendStatus(STATUS_DISCONNECTED)
                } else {
                    ConnectionLog.record("Native tunnel stopped unexpectedly")
                    sendStatus(STATUS_FAILED, "Tunnel stopped unexpectedly")
                }
            } catch (error: Exception) {
                val detail = NativeCore.lastError().ifBlank { error.message ?: "Tunnel setup failed" }
                Log.e(LOG_TAG, "Tunnel failed: $detail", error)
                sendStatus(STATUS_FAILED, detail)
            } finally {
                NativeCore.detach()
                vpnModeActive.set(false)
                val killSwitch = getSharedPreferences("settings", MODE_PRIVATE).getBoolean("kill_switch", false)
                tun?.close()
                tun = null
                connected.set(false)
                if (killSwitch && !stopRequested.get()) {
                    ConnectionLog.record("Kill switch active; blocking all traffic")
                    sendStatus(STATUS_FAILED, "Kill switch active — tunnel dropped")
                    rebuildKillSwitchVpn()
                } else {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }


    private fun stopTunnel(notify: Boolean = true, teardownService: Boolean = true) {
        stopRequested.set(true)
        // Disarm the escalation ladder before anything else: a pending timer that
        // fires after teardown would resurrect Psiphon on a dead TUN.
        ladderActive.set(false)
        cancelLadderTimer()
        // Order matters: stop routing first so no more packets enter a tunnel
        // that is being torn down, then stop Psiphon itself.
        Tun2SocksManager.stop()
        stopPsiphonTunnel()
        NativeCore.stop()

        if (psiphonVpnMode) {
            // In VPN mode nothing else owns the service lifecycle now that the
            // Rust core is out of the data path, so tear down here.
            NativeCore.detach()
            vpnModeActive.set(false)
            psiphonVpnActivated = false
            tun?.close()
            tun = null
            connected.set(false)
            if (notify) sendStatus(STATUS_DISCONNECTED)
            // A reconnect re-enters startTunnel() on the worker thread, so the
            // service must survive; only a real disconnect stops it.
            if (teardownService) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            return
        }

        if (notify && !connected.get()) sendStatus(STATUS_DISCONNECTED)
    }

    private fun rebuildKillSwitchVpn() {
        try {
            tun?.close()
            tun = Builder()
                .setSession("MSN-VPN — Kill Switch")
                .setMtu(1280)
                .addAddress("100.64.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .establish()
            ConnectionLog.record("Kill switch VPN active; all traffic blocked")
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Kill switch rebuild failed: ${e.message}")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun sendStatus(status: String, detail: String? = null) {
        Log.i(LOG_TAG, "status=$status${detail?.let { " detail=$it" } ?: ""}")
        sendBroadcast(Intent(ACTION_STATUS)
            .setPackage(packageName)
            .putExtra(EXTRA_STATUS, status)
            .apply { detail?.let { putExtra(EXTRA_DETAIL, it) } })
        TileService.requestListeningState(
            this,
            ComponentName(this, MsnGuardTileService::class.java),
        )
    }

    private fun updateTrafficNotification(tx: Long, rx: Long) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastTrafficSampleMs < 900) return

        val elapsed = now - prevSpeedSampleMs
        if (elapsed > 0 && prevSpeedSampleMs > 0) {
            currentSpeedTx = ((tx - prevTx) * 1000) / elapsed
            currentSpeedRx = ((rx - prevRx) * 1000) / elapsed
        }
        prevTx = tx
        prevRx = rx
        prevSpeedSampleMs = now

        val (monthTx, monthRx) = recordMonthlyTraffic(
            (tx - accountedTx).coerceAtLeast(0),
            (rx - accountedRx).coerceAtLeast(0),
        )
        accountedTx = tx
        accountedRx = rx
        sendTraffic(tx, rx, monthTx, monthRx)

        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification(tx, rx))
        lastTrafficSampleMs = now
    }

    private fun recordMonthlyTraffic(tx: Long, rx: Long): Pair<Long, Long> {
        val month = java.text.SimpleDateFormat("yyyy-MM", java.util.Locale.US).format(java.util.Date())
        val prefs = getSharedPreferences(TRAFFIC_PREFS, MODE_PRIVATE)
        val sameMonth = prefs.getString(TRAFFIC_MONTH, null) == month
        val monthTx = (if (sameMonth) prefs.getLong(TRAFFIC_TX, 0) else 0) + tx
        val monthRx = (if (sameMonth) prefs.getLong(TRAFFIC_RX, 0) else 0) + rx
        prefs.edit()
            .putString(TRAFFIC_MONTH, month)
            .putLong(TRAFFIC_TX, monthTx)
            .putLong(TRAFFIC_RX, monthRx)
            .apply()
        return monthTx to monthRx
    }

    private fun sendTraffic(tx: Long, rx: Long, monthTx: Long, monthRx: Long) {
        sendBroadcast(Intent(ACTION_STATUS)
            .setPackage(packageName)
            .putExtra(EXTRA_TRAFFIC_TX, tx)
            .putExtra(EXTRA_TRAFFIC_RX, rx)
            .putExtra(EXTRA_TRAFFIC_SPEED_TX, currentSpeedTx)
            .putExtra(EXTRA_TRAFFIC_SPEED_RX, currentSpeedRx)
            .putExtra(EXTRA_TRAFFIC_MONTH_TX, monthTx)
            .putExtra(EXTRA_TRAFFIC_MONTH_RX, monthRx))
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1_024 -> "$bytes B"
        bytes < 1_048_576 -> "${bytes / 1_024} KB"
        bytes < 1_073_741_824 -> "${bytes / 1_048_576} MB"
        else -> String.format(java.util.Locale.US, "%.2f GB", bytes / 1_073_741_824.toDouble())
    }

    private fun formatSpeed(bytesPerSec: Long): String = when {
        bytesPerSec < 1_024 -> "$bytesPerSec B/s"
        bytesPerSec < 1_048_576 -> "${bytesPerSec / 1_024} KB/s"
        else -> String.format(java.util.Locale.US, "%.1f MB/s", bytesPerSec / 1_048_576.0)
    }

    private fun startAsForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(
            CHANNEL_ID,
            "VPN Service",
            NotificationManager.IMPORTANCE_LOW
        ))
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("MSN-GUARD")
            .setContentText("Connecting...")
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun notification(tx: Long, rx: Long): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = Intent(this, MsnGuardVpnService::class.java).apply {
            action = ACTION_DISCONNECT
            putExtra(EXTRA_CONFIG, storedConfig ?: "")
            putExtra(EXTRA_VPN_MODE, storedVpnMode)
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this, 1, disconnectIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val reconnectIntent = Intent(this, MsnGuardVpnService::class.java).apply {
            action = ACTION_RECONNECT
        }
        val reconnectPendingIntent = PendingIntent.getService(
            this, 2, reconnectIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("MSN-GUARD")
            .setContentText("VPN: $currentProtocol • ${formatBytes(tx)}↑ ${formatBytes(rx)}↓ • ${formatSpeed(currentSpeedTx)}↑ ${formatSpeed(currentSpeedRx)}↓")
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectPendingIntent)
            .addAction(android.R.drawable.ic_menu_revert, "Reconnect", reconnectPendingIntent)
            .build()
    }

    private fun Builder.applySplitTunneling(): Builder {
        val settings = SplitTunnelSettings(this@MsnGuardVpnService)
        val mode = settings.mode()
        val packages = settings.packages()

        if (mode == SplitTunnelSettings.Mode.ALL) {
            // GLOBAL: all apps through VPN, but MUST exclude ourselves to prevent routing loop.
            addDisallowedApplication(packageName)
            return this
        }
        if (mode == SplitTunnelSettings.Mode.INCLUDE) {
            // INCLUDE (whitelist): only listed apps go through VPN.
            // Do NOT add our own packageName — it's excluded by default.
            // Do NOT use addDisallowedApplication here (mixing with addAllowedApplication crashes).
        }
        if (packages.isEmpty()) {
            check(mode != SplitTunnelSettings.Mode.INCLUDE) {
                "No apps selected for tunnel. Connection aborted for safety."
            }
            // EXCLUDE with empty list: nothing to exclude beyond ourselves.
            addDisallowedApplication(packageName)
            return this
        }

        var addedCount = 0
        packages.forEach { pkg ->
            try {
                when (mode) {
                    SplitTunnelSettings.Mode.INCLUDE -> {
                        addAllowedApplication(pkg)
                        addedCount++
                    }
                    SplitTunnelSettings.Mode.EXCLUDE -> {
                        if (pkg != packageName) {
                            addDisallowedApplication(pkg)
                            addedCount++
                        }
                    }
                }
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                Log.w(LOG_TAG, "Split tunnel skipped missing app: $pkg")
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Failed to add $pkg to split tunnel: ${e.message}")
            }
        }

        if (mode == SplitTunnelSettings.Mode.INCLUDE && addedCount == 0) {
            error("Selected apps are no longer installed. Connection aborted.")
        }

        // EXCLUDE mode: also disallow our own app to prevent routing loop.
        if (mode == SplitTunnelSettings.Mode.EXCLUDE) {
            addDisallowedApplication(packageName)
        }

        ConnectionLog.record("Split tunnel ${mode.label.lowercase()}: $addedCount app(s)")
        return this
    }

    private fun Builder.applyLanAccess(): Builder {
        if (!getSharedPreferences("settings", MODE_PRIVATE).getBoolean("lan_sharing", false)) return this
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            ConnectionLog.record("LAN access uses system local routes on Android 12 and older")
            return this
        }
        listOf(
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",
            "fe80::/10",
        ).forEach { cidr ->
            val (address, prefix) = cidr.split('/')
            excludeRoute(IpPrefix(InetAddress.getByName(address), prefix.toInt()))
        }
        ConnectionLog.record("LAN routes bypass the VPN")
        return this
    }

    private fun Builder.applyDns(config: String): Builder {
        // Always force known-good public DNS to prevent carrier DNS leaks.
        // Carrier DNS (10.x.x.x) is rejected by Psiphon SOCKS5 (reply 5).
        val forcedDns = listOf("1.1.1.1", "8.8.8.8")
        forcedDns.forEach { addDnsServer(InetAddress.getByName(it)) }

        // Also add any DNS servers from config (for non-Psiphon protocols).
        val configured = JSONObject(config).optString("dns_servers")
        configured.split(',', ';', ' ', '\n')
            .map(String::trim)
            .filter(String::isNotEmpty)
            .mapNotNull { entry ->
                val address = when {
                    entry.startsWith('[') -> entry.substringAfter('[').substringBefore(']')
                    entry.count { it == ':' } == 1 -> entry.substringBefore(':')
                    else -> entry
                }
                runCatching { InetAddress.getByName(address) }.getOrNull()
            }
            .distinct()
            .filter { it.hostAddress !in forcedDns }
            .forEach { addDnsServer(it) }

        ConnectionLog.record("DNS forced to public resolvers, carrier DNS excluded")
        return this
    }
}

// ── ConnectionLog ──

object ConnectionLog {
    private const val MAX_ENTRIES = 100
    private val entries = ArrayDeque<String>()

    @Synchronized
    fun record(message: String) {
        if (entries.size == MAX_ENTRIES) entries.removeFirst()
        entries.addLast("${java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())}  $message")
    }

    @Synchronized
    fun snapshot(): List<String> = entries.toList()
}