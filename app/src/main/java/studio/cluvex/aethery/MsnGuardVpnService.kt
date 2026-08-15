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
import android.net.ProxyInfo
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
 *
 * Every name here was verified to exist as a substring in libgojni.so. The
 * INPROXY-* names are deliberately absent: they are assembled at runtime and do
 * not appear as literals, so passing one risks failing config validation.
 */
private val PROTOCOLS_FRONTED = listOf(
    "FRONTED-MEEK-OSSH",
    "FRONTED-MEEK-HTTP-OSSH",
    "FRONTED-MEEK-QUIC-OSSH",
)

/**
 * Direct-dial protocols, i.e. everything that connects straight to a Psiphon
 * server IP. Used only for winner detection — the direct rung passes no
 * protocol limit at all and lets Psiphon pick.
 */
private val PROTOCOLS_DIRECT = listOf(
    "QUIC-OSSH",
    "TLS-OSSH",
    "UNFRONTED-MEEK-HTTPS-OSSH",
    "UNFRONTED-MEEK-OSSH",
    "SHADOWSOCKS-OSSH",
    "CONJURE-OSSH",
    "OSSH",
    "SSH",
)

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
    private val attributionPending = AtomicBoolean(false)

    /**
     * The escalation ladder, ordered by *measured* time-to-connect on a hostile
     * carrier, using the Build #65 field logs from Hamrah-e-Aval and SamanTel.
     *
     * What those logs proved:
     *
     *  - On Hamrah-e-Aval every direct dial fails at the TCP layer:
     *    TLS-OSSH, UNFRONTED-MEEK-HTTPS-OSSH, OSSH and SSH candidates all end in
     *    "connect: connection timed out" / "i/o timeout" from tcpDial#308. Not
     *    resets, not TLS errors — the packets never arrive. The carrier
     *    null-routes Psiphon server IPs.
     *  - Only FRONTED-MEEK works there, because it dials a CDN edge instead of a
     *    Psiphon-owned IP. It connected on FRONTED-MEEK-HTTP-OSSH in 33s.
     *  - The old first rung ("443-only protocols") therefore burned its entire
     *    45s budget for nothing before the fronted rung even started, which is
     *    the whole reason connecting felt slow.
     *  - On SamanTel a plain direct QUIC-OSSH dial won in seconds, so direct
     *    protocols must stay reachable early for carriers that do not block.
     *
     * Hence the order: fronted first (the only path that works on the hostile
     * carrier), then wide-open direct (fast where nothing is blocked), then
     * in-proxy (slowest, needs a broker plus WebRTC/ICE negotiation).
     *
     * The rung that actually carries the tunnel is remembered per device, so
     * after one successful connect each SIM starts on its own best rung and the
     * ordering here only matters for the very first attempt.
     */
    private val psiphonLadder: List<PsiphonStrategy> = listOf(
        PsiphonStrategy(
            name = "A",
            label = "domain-fronted (CDN)",
            timeoutSeconds = 60,
            preferredProtocols = PROTOCOLS_FRONTED,
        ) { config ->
            // Fronted protocols terminate on an Amazon/Cloudflare edge address,
            // never on a Psiphon-owned IP, so a carrier IP blocklist cannot see
            // or drop them. They do need working DNS to resolve the front, which
            // is what the public resolvers on the TUN provide.
            //
            // Only 5 of the 430 bundled server entries advertise FRONTED-MEEK
            // (4x US, 1x GB) — that is why a fronted connection always lands in
            // the US. A low candidate count keeps Psiphon cycling those few
            // entries with fresh dial parameters instead of opening up to the
            // 425 direct entries that are known-dead on this carrier.
            config.put("InitialLimitTunnelProtocols", JSONArray(PROTOCOLS_FRONTED))
            config.put("InitialLimitTunnelProtocolsCandidateCount", 30)
            config.put("ConnectionWorkerPoolSize", 12)
            // CDN paths are legitimately slower than a direct dial; without this
            // Psiphon abandons them as if they were dead.
            config.put("NetworkLatencyMultiplier", 2.0)
        },
        PsiphonStrategy(
            name = "D",
            label = "all protocols (direct)",
            timeoutSeconds = 45,
            preferredProtocols = PROTOCOLS_DIRECT,
        ) { config ->
            // No InitialLimitTunnelProtocols at all: Psiphon uses its own full
            // protocol set and its own replay/tactics ordering. This is the rung
            // that wins on a carrier which is not blocking anything — SamanTel
            // connected this way on QUIC-OSSH — and it is also the safety net if
            // the CDN fronts themselves ever get blocked.
            config.put("ConnectionWorkerPoolSize", 16)
        },
        PsiphonStrategy(
            name = "C",
            label = "in-proxy (peer relay)",
            timeoutSeconds = 75,
            preferredProtocols = emptyList(),
        ) { config ->
            // In-proxy routes through other Psiphon users' devices over WebRTC.
            // Their addresses are residential and not in any carrier blocklist,
            // which is what makes this rung the last resort that can still work
            // when every server IP and every CDN front is unreachable.
            //
            // Deliberately NOT setting InitialLimitTunnelProtocols here: the
            // INPROXY-* protocol names do not exist as literals in libgojni.so
            // (verified with strings — they are assembled at runtime), so passing
            // one risks failing config validation and killing the whole rung.
            // The flags below are enough; the log confirms Psiphon then reports
            // "in-proxy protocol preferred" and dials INPROXY-WEBRTC-OSSH itself.
            config.put("InproxyEnabled", true)
            config.put("InproxyAllowClient", true)
            config.put("InproxySkipAwaitFullyConnected", true)
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

        /**
         * elapsedRealtime at the moment the tunnel last reached CONNECTED, or 0
         * when it is down. The activity reads this so a session timer survives
         * the UI being destroyed and recreated (rotation, screen off, returning
         * from Recents) instead of restarting from zero on every rebind.
         *
         * Volatile and static because the service and the activity are different
         * lifecycles in the same process; it is a plain timestamp, so a stale
         * read is harmless.
         */
        @Volatile
        private var connectedSince = 0L

        fun connectedSinceElapsed(): Long = connectedSince
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
        // connection.
        ladderActive.set(false)
        cancelLadderTimer()
        ladderAttempts = 0
        // Attribution is NOT done here. The ActiveTunnel notice that names the
        // protocol arrives *after* this callback — both field logs show it one
        // line below "Psiphon connected" — so at this point activeTunnelProtocol
        // is still empty and any decision would be a guess. See
        // scheduleLadderAttribution() for the deferred, evidence-based version.
        scheduleLadderAttribution()

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

    private fun buildPsiphonConfig(): String {
        // Fixed port so the TUN can be pre-created before Psiphon starts.
        val socksPort = CoreConfig.SOCKS_PORT
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

    private fun startPsiphonTunnel() {
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
            psiphonConfigJson = buildPsiphonConfig()

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
     * Defer winner attribution until Psiphon has reported the live protocol.
     *
     * Ordering in the real logs, both carriers, is always:
     *
     *     Psiphon connected — upstream tunnel ready   <- onConnected()
     *     Tunnels: {"count":1}
     *     ActiveTunnel: {"protocol":"FRONTED-MEEK-HTTP-OSSH"}   <- the evidence
     *
     * so reading the protocol inside onConnected() always saw an empty string
     * and fell through to "keep the active rung". That is precisely the wrong
     * answer in the interesting cases: Hamrah-e-Aval was credited to A while
     * rung A was active only by luck, and SamanTel was credited to C purely on a
     * background broker notice while the tunnel was direct QUIC-OSSH.
     *
     * A short delay is enough — the notice follows within milliseconds — and the
     * whole thing is best-effort: if nothing arrives we keep the active rung,
     * which is the old behaviour.
     */
    private fun scheduleLadderAttribution() {
        if (!attributionPending.compareAndSet(false, true)) return
        val rungAtConnect = ladderIndex
        ladderScheduler.schedule({
            attributionPending.set(false)
            if (!stopRequested.get()) recordLadderWinner(rungAtConnect)
        }, 2, TimeUnit.SECONDS)
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
    private fun recordLadderWinner(rungAtConnect: Int) {
        val protocol = activeTunnelProtocol
        val inproxyRung = psiphonLadder.indexOfFirst { it.name == "C" }

        val (winnerIndex, reason) = when {
            // The protocol name is the strongest signal available. An INPROXY-*
            // tunnel is unambiguously the peer-relay rung.
            protocol.startsWith("INPROXY") && inproxyRung >= 0 ->
                inproxyRung to "in-proxy protocol $protocol"

            protocol.isNotBlank() -> {
                val matches = psiphonLadder.indices.filter { i ->
                    psiphonLadder[i].preferredProtocols.contains(protocol)
                }
                when {
                    matches.size == 1 -> matches[0] to "protocol $protocol is unique to this strategy"
                    matches.contains(rungAtConnect) -> rungAtConnect to "protocol $protocol consistent with active strategy"
                    matches.isNotEmpty() -> matches[0] to "protocol $protocol best match"
                    else -> rungAtConnect to "protocol $protocol not in any preference list; keeping active strategy"
                }
            }

            // Only fall back to broker evidence when no protocol was reported.
            // "inproxy: selected broker" is NOT proof the tunnel used a peer
            // relay: the SamanTel log shows that notice arriving while the
            // established tunnel was plain direct QUIC-OSSH, because the
            // in-proxy machinery keeps negotiating in the background. Crediting
            // rung C there would have pinned that SIM to the slowest rung (75s)
            // when the direct rung connects in seconds.
            inproxyInUse && inproxyRung >= 0 ->
                inproxyRung to "in-proxy broker in use, no protocol notice"

            else -> rungAtConnect to "no protocol notice; keeping active strategy"
        }

        val winner = psiphonLadder.getOrNull(winnerIndex) ?: return
        getSharedPreferences("settings", MODE_PRIVATE).edit()
            .putInt("psiphon_winning_strategy", winnerIndex).apply()

        val via = if (protocol.isNotBlank()) " via $protocol" else ""
        ConnectionLog.record(
            "Connected$via — crediting strategy ${winner.name} (${winner.label}): $reason"
        )
        if (winnerIndex != rungAtConnect) {
            val active = psiphonLadder.getOrNull(rungAtConnect)
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
            activeSocksPort = CoreConfig.SOCKS_PORT
            try { Thread.sleep(1200) } catch (_: InterruptedException) {}
            if (stopRequested.get()) return@execute
            startPsiphonTunnel()
        }
    }

    private fun stopPsiphonTunnel() {
        // PsiphonTunnel.stop() blocks until the Go controller has fully unwound,
        // which during establishing means waiting on in-flight dials. stopTunnel()
        // is reached from onStartCommand() on the main thread, so doing that here
        // synchronously froze the UI — which is what made a mid-connect cancel
        // look like it did nothing. Detach the reference synchronously (so
        // nothing else can use it) and let the blocking stop happen off-thread.
        val tunnel = psiphonTunnel ?: return
        psiphonTunnel = null
        Thread({
            try { tunnel.stop() } catch (_: Exception) {}
        }, "psiphon-stop").start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> intent.getStringExtra(EXTRA_CONFIG)?.let { config ->
                startTunnel(config)
            }
            ACTION_DISCONNECT -> stopTunnel()
            ACTION_RECONNECT -> {
                val config = storedConfig
                if (config != null && connected.get()) {
                    ConnectionLog.record("Quick reconnect requested")
                    stopTunnel(notify = false, teardownService = false)
                    worker.execute {
                        try { Thread.sleep(500) } catch (_: InterruptedException) {}
                        startTunnel(config)
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

    /**
     * Start a tunnel. Always whole-device VPN mode — proxy mode was removed, so
     * there is no longer a `vpnMode` parameter to branch on.
     */
    private fun startTunnel(config: String) {
        if (!connected.compareAndSet(false, true)) return
        storedConfig = config
        currentProtocol = config.substringAfter("\"protocol\":\"").substringBefore('"').uppercase()
        currentVpnIp = ""
        currentPing = ""
        stopRequested.set(false)
        vpnModeActive.set(true)
        startAsForeground()

        // PSIPHON: callback-driven lifecycle — MUST NOT enter try/finally.
        // The finally block calls stopSelf() which destroys the service and kills Psiphon.
        if (currentProtocol.contains("PSIPHON")) {
            psiphonVpnMode = true  // Read by onConnected() to start tun2socks
            psiphonVpnActivated = false
            // Start from the rung that last worked on this device. On the first
            // ever connect, or after a full ladder failure, this is rung 0.
            ladderIndex = getSharedPreferences("settings", MODE_PRIVATE)
                .getInt("psiphon_winning_strategy", 0)
                .coerceIn(0, psiphonLadder.size - 1)
            ladderAttempts = 0
            worker.execute {
                try {
                    ConnectionLog.record("Preparing PSIPHON identity")
                    // Create the TUN first, then start Psiphon: this stops Psiphon's
                    // NetworkMonitor seeing tun0 appear as a network change, which
                    // used to cause a 13-second restart loop.
                    val socksPort = CoreConfig.SOCKS_PORT

                    // Address plan comes from tun2socks: the interface gets
                    // .ipAddress while lwIP answers on .router, which is also
                    // the DNS resolver the system will use. These must not be
                    // swapped or lwIP drops every packet.
                    val address = Tun2SocksManager.selectPrivateAddress()

                    ConnectionLog.record("Creating TUN interface BEFORE Psiphon starts")
                    tun = Builder()
                        .setSession("MSN-GUARD")
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
                    startPsiphonTunnel()
                    sendStatus(STATUS_CONNECTING, "Psiphon starting...")
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
                // VPN mode is the only mode, so the Rust core always binds the
                // Android TUN directly — there is no proxy branch any more.
                val addresses = NativeCore.prepare(config)
                if (addresses.organization.isNotBlank()) {
                    ConnectionLog.record("Zero Trust organization ${addresses.organization}")
                }
                ConnectionLog.record("Creating Android VPN interface")
                tun = Builder()
                    .setSession("MSN-GUARD")
                    .setMtu(1280)
                    // applyTunnelAddresses replaces the hardcoded /32 + /128
                    // pair: v0.8.0 identities can carry a real prefix length,
                    // and a WARP identity without a v6 address must not get a
                    // v6 default route.
                    .applyTunnelAddresses(addresses)
                    .applyDns(config, addresses)
                    .applyGatewayProxy(config, addresses)
                    .applyLanAccess(addresses)
                    .applySplitTunneling()
                    // applySplitTunneling() handles app exclusion per mode.
                    .establish() ?: error("Android could not establish the VPN interface")
                ConnectionLog.record("Scanning gateways for VPN")
                // The Rust core is about to bind this TUN fd directly, which
                // means no local SOCKS listener will exist for this session.
                // The UI health check must go direct, not via 127.0.0.1.
                TunnelStatus.isNativeTunMode = true
                val result = NativeCore.start(config, tun!!.fd)

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
                TunnelStatus.isNativeTunMode = false
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
        // Clear the session stamp here, not in sendStatus: the reconnect path and
        // onDestroy both call stopTunnel(notify = false), so relying on the
        // DISCONNECTED broadcast left connectedSince set and the next session's
        // timer resumed the old elapsed time instead of restarting at zero.
        connectedSince = 0L
        // Disarm the escalation ladder before anything else: a pending timer that
        // fires after teardown would resurrect Psiphon on a dead TUN.
        ladderActive.set(false)
        cancelLadderTimer()
        // Order matters: stop routing first so no more packets enter a tunnel
        // that is being torn down, then stop Psiphon itself.
        Tun2SocksManager.stop()
        stopPsiphonTunnel()
        NativeCore.stop()
        TunnelStatus.isNativeTunMode = false

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
                .setSession("MSN-GUARD — Kill Switch")
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
        // Stamp the connect moment here rather than at each call site: there are
        // several paths to CONNECTED (native tunnel ready, Psiphon proxy ready,
        // tun2socks up, reconnect) and every one funnels through sendStatus.
        when (status) {
            STATUS_CONNECTED -> if (connectedSince == 0L) connectedSince = SystemClock.elapsedRealtime()
            STATUS_DISCONNECTED, STATUS_FAILED -> connectedSince = 0L
        }
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

    private fun Builder.applyLanAccess(addresses: NativeCore.TunnelAddresses): Builder {
        if (!lanBypassEnabled()) return this
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            ConnectionLog.record("LAN access uses system local routes on Android 12 and older")
            return this
        }
        val ranges = mutableListOf(
            "10.0.0.0/8",
            "192.168.0.0/16",
            "fc00::/7",
            "fe80::/10",
        )
        // Upstream v0.8.0: WARP/Zero Trust device and gateway addresses live in
        // 172.16.0.0/12. Excluding that range would leak org DNS/gateway onto the
        // LAN, so it is only bypassed when we are not on a WARP CGNAT identity.
        if (!isWarpCgnat(addresses)) {
            ranges.add(1, "172.16.0.0/12")
        }
        ranges.forEach { cidr ->
            val (address, prefix) = cidr.split('/')
            excludeRoute(IpPrefix(InetAddress.getByName(address), prefix.toInt()))
        }
        ConnectionLog.record("LAN routes bypass the VPN")
        return this
    }

    /**
     * Upstream v0.8.0 renamed the LAN preference from `lan_sharing` to
     * `lan_bypass` and migrates the old value on first read. Kept verbatim so the
     * service and the merged MainActivity agree on which key is authoritative.
     */
    private fun lanBypassEnabled(): Boolean {
        val prefs = getSharedPreferences("settings", MODE_PRIVATE)
        if (!prefs.contains("lan_bypass") && prefs.getBoolean("lan_sharing", false)) {
            prefs.edit().putBoolean("lan_bypass", true).apply()
            return true
        }
        return prefs.getBoolean("lan_bypass", false)
    }

    private fun Builder.applyTunnelAddresses(addresses: NativeCore.TunnelAddresses): Builder {
        val v4 = parseTunnelAddress(addresses.ipv4, 32)
            ?: error("Zero Trust identity has no usable IPv4 address")
        addAddress(v4.first, v4.second)
        addRoute("0.0.0.0", 0)
        val v6 = parseTunnelAddress(addresses.ipv6, 128)
        if (v6 != null) {
            addAddress(v6.first, v6.second)
            addRoute("::", 0)
        }
        return this
    }

    private fun Builder.applyGatewayProxy(
        config: String,
        addresses: NativeCore.TunnelAddresses,
    ): Builder {
        if (!JSONObject(config).optBoolean("gateway", false)) return this
        val parsed = parseSocketAddress(addresses.gatewayProxy) ?: return this
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            setHttpProxy(ProxyInfo.buildDirectProxy(parsed.first, parsed.second))
            ConnectionLog.record("Zero Trust gateway ${parsed.first}:${parsed.second}")
        } else {
            ConnectionLog.record("Gateway filtering in VPN mode needs Android 10 or newer")
        }
        return this
    }

    private fun parseTunnelAddress(raw: String, defaultPrefix: Int): Pair<InetAddress, Int>? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        val host = trimmed.substringBefore('/')
        val prefix = trimmed.substringAfter('/', missingDelimiterValue = "")
            .toIntOrNull() ?: defaultPrefix
        val address = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return null
        val maxPrefix = if (address.address.size == 4) 32 else 128
        return address to prefix.coerceIn(0, maxPrefix)
    }

    private fun parseSocketAddress(raw: String): Pair<String, Int>? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        return if (trimmed.startsWith('[')) {
            val host = trimmed.substringAfter('[').substringBefore(']')
            val port = trimmed.substringAfter("]:", "").toIntOrNull() ?: return null
            host to port
        } else {
            val separator = trimmed.lastIndexOf(':')
            if (separator <= 0) return null
            val host = trimmed.substring(0, separator)
            val port = trimmed.substring(separator + 1).toIntOrNull() ?: return null
            host to port
        }
    }

    private fun isWarpCgnat(addresses: NativeCore.TunnelAddresses): Boolean {
        val host = addresses.ipv4.substringBefore('/').trim()
        val octets = host.split('.')
        if (octets.size == 4) {
            val first = octets[0].toIntOrNull()
            val second = octets[1].toIntOrNull()
            if (first == 172 && second != null && second in 16..31) return true
        }
        return addresses.gatewayProxy.contains("172.16.") ||
            addresses.gatewayProxy.contains("172.17.") ||
            addresses.gatewayProxy.contains("172.18.")
    }

    private fun Builder.applyDns(config: String, addresses: NativeCore.TunnelAddresses): Builder {
        // OURS, kept over upstream's version — this is load-bearing for Psiphon.
        //
        // Carrier DNS on Iranian mobile networks is both censored and rejected by
        // Psiphon's SOCKS5 (reply 5), so public resolvers are forced first and any
        // carrier-supplied server is filtered out rather than merely appended
        // after. Upstream instead uses 1.1.1.1/1.0.0.1 only as a *fallback* when
        // the config lists nothing, which would let carrier DNS through.
        val forcedDns = listOf("1.1.1.1", "8.8.8.8")
        forcedDns.forEach { addDnsServer(InetAddress.getByName(it)) }

        // From upstream v0.8.0: advertise a v6 resolver when the identity has a
        // v6 address, otherwise v6-only lookups have nowhere to go.
        if (addresses.ipv6.isNotBlank()) {
            runCatching { addDnsServer(InetAddress.getByName("2606:4700:4700::1111")) }
        }

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
    private const val MAX_FILE_BYTES = 256 * 1024L
    private val entries = ArrayDeque<String>()
    private var sink: java.io.File? = null

    /**
     * Ported from upstream v0.8.0: mirror the ring buffer to a file so logs
     * survive the process being killed. Required — the merged MainActivity calls
     * this on startup. Capped and self-truncating so it cannot grow unbounded.
     */
    @Synchronized
    fun bind(file: java.io.File) {
        sink = file
        if (file.exists() && file.length() > MAX_FILE_BYTES) {
            file.delete()
        }
    }

    @Synchronized
    fun record(message: String) {
        val line = "${java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())}  $message"
        if (entries.size == MAX_ENTRIES) entries.removeFirst()
        entries.addLast(line)
        runCatching { sink?.appendText(line + "\n") }
    }

    @Synchronized
    fun snapshot(): List<String> = entries.toList()
}