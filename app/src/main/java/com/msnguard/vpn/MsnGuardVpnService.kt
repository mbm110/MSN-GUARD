package com.msnguard.vpn

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
 * Every protocol that can cross a SOCKS5 upstream proxy — i.e. TCP only.
 *
 * Used as a HARD limit (`LimitTunnelProtocols`, not the `InitialLimit…`
 * preference) whenever Psiphon runs over WARP. Two separate reasons it has to be
 * a hard limit:
 *
 *  - `InitialLimitTunnelProtocols` is only a preference: once the candidate
 *    budget is spent Psiphon reverts to its full set, which includes the
 *    `INPROXY-WEBRTC-*` entries the bundled server list advertises.
 *  - in-proxy is WebRTC, so it needs raw UDP sockets. A SOCKS5 upstream cannot
 *    carry those, and the field log proves what happens: STUN goes out over the
 *    carrier instead of the tunnel ("Failed get server reflexive address udp4
 *    stun:… timeout while waiting for XORMappedAddr"), ICE gathering takes 34s
 *    instead of ~130ms, and the broker round trip resolves DNS *untunneled*
 *    (`UntunneledResolveIP` → `context deadline exceeded`) on exactly the link
 *    Hamrah-e-Aval null-routes.
 *
 * QUIC-OSSH is absent for the same reason — it is UDP. Psiphon already declines
 * to dial it when an upstream proxy is set (measured: 0 attempts across a full
 * run, against 3 when dialling directly), so naming it here would be a
 * contradiction rather than an option.
 */
private val PROTOCOLS_CHAINABLE = listOf(
    "FRONTED-MEEK-OSSH",
    "FRONTED-MEEK-HTTP-OSSH",
    "TLS-OSSH",
    "UNFRONTED-MEEK-HTTPS-OSSH",
    "UNFRONTED-MEEK-OSSH",
    "SHADOWSOCKS-OSSH",
    "OSSH",
    "SSH",
)

/**
 * Public DNS resolvers on NON-standard ports, for Psiphon's own resolver.
 *
 * Why this exists, from a field log where Psiphon could not connect at all:
 * every dial died on the same line —
 * `checkDNSAnswerIP#1767: IP is bogon`. The resolver got an *answer*, and the
 * answer was a private-range address, i.e. the operator's DNS hijack. Psiphon
 * correctly refused it, so tactics never loaded and not one of the five bundled
 * FRONTED-MEEK entries could be resolved. `Tunnels: {"count":0}`.
 *
 * The resolvers we put on the TUN (`applyDns`, 1.1.1.1 / 8.8.8.8) do NOT help
 * here. Psiphon's resolver builds its own UDP socket and calls `bindToDevice` on
 * it (upstream `resolver.go`), so it leaves *outside* the TUN, straight onto the
 * operator link where UDP/53 is hijacked no matter which address is targeted.
 *
 * The port is the whole point. The hijack observed intercepts UDP/53; the same
 * providers answering on another port were reached cleanly from an uncensored
 * host. So these are ordinary public resolvers reached where the interception
 * does not sit:
 *
 *  - 208.67.222.222:5353 / 208.67.220.220:5353 — OpenDNS's alternate port
 *  - 9.9.9.9:9953 — Quad9's alternate port
 *
 * Scope, so nobody expects too much of this: it fixes name resolution only. On a
 * network that also blocks the transport itself there is nothing to resolve to,
 * and a chained run never even reaches this code — the outer WARP leg has to be
 * up first, and if it is up then DNS was never the problem. Plain Psiphon is
 * where this pays off.
 */
private val PSIPHON_ALTERNATE_DNS = listOf(
    "208.67.222.222:5353",
    "9.9.9.9:9953",
    "208.67.220.220:5353",
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
    /**
     * Monthly totals held in memory, flushed to disk on a timer.
     *
     * These used to be written through to SharedPreferences on every traffic
     * sample, i.e. roughly once a second for the whole life of a tunnel. That is
     * thousands of `apply()` calls an hour, each one a disk write behind the
     * scenes — expensive on flash and on battery, to persist a counter nobody
     * reads until the traffic screen is opened.
     *
     * Now the counters live here and reach disk every [TRAFFIC_FLUSH_MS] and on
     * teardown. Worst case a hard process kill loses the last few seconds of
     * accounting, which is not a number anything depends on being exact.
     */
    private var monthKey: String? = null
    private var monthTxTotal = 0L
    private var monthRxTotal = 0L
    private var lastTrafficFlushMs = 0L

    /**
     * Whether this session has already recorded its transport as working.
     *
     * A latch, not a state: the recording is idempotent and only the first crossing
     * of the byte threshold matters, so once set every later traffic sample costs a
     * single boolean test instead of a preferences write. Reset per tunnel in
     * [resetSessionTraffic].
     */
    private var plainTransportRecorded = false
    private var storedConfig: String? = null
    private var currentProtocol = "Tunnel"
    private var currentVpnIp = ""
    private var currentPing = ""

    /**
     * Country shown on the notification's second line, e.g. "Germany".
     *
     * Empty until something authoritative supplies it. The notification simply
     * omits the segment while it is empty rather than printing a placeholder —
     * an unknown exit country is not worth a line of its own.
     */
    private var currentCountry = ""

    /** Last progress value published, so a repost can reuse it. */
    @Volatile
    private var connectProgress = -1

    /** Polls [TorManager.progress] while Tor bootstraps. */
    private var torProgressTask: java.util.concurrent.ScheduledFuture<*>? = null

    /**
     * Liveness watchdog for an established tunnel. See [startWatchdog].
     */
    private var watchdogTask: java.util.concurrent.ScheduledFuture<*>? = null

    /**
     * True only when the *user* asked to disconnect (dial tap, notification
     * action, kill switch, revoke).
     *
     * The distinction is the whole point of auto-reconnect: a tunnel that dies
     * on its own must come back, and one the user switched off must stay off.
     * [stopRequested] cannot answer this — it is set by every teardown path,
     * including the ones auto-reconnect itself drives.
     */
    private val userInitiatedStop = AtomicBoolean(false)

    /** Consecutive auto-reconnect attempts since the last verified connect. */
    private var reconnectAttempts = 0

    /** The pending auto-reconnect, so a user action can cancel it. */
    private var reconnectTask: java.util.concurrent.ScheduledFuture<*>? = null

    /**
     * Set by the Rust-core path when its tunnel ended without the user asking.
     *
     * The core's lifecycle is a blocking call inside a `try/finally`, so unlike
     * the Psiphon and Tor paths the decision "was this a drop or a disconnect"
     * has to be carried from the body of the try into the finally block.
     */
    private var nativeExitWasUnexpected = false

    /** Composited launcher artwork for the notification. Built once. */
    private var cachedBadge: android.graphics.drawable.Icon? = null
    private var psiphonTunnel: PsiphonTunnel? = null
    private var psiphonConfigJson: String = ""
    private var psiphonVpnMode = false
    private var psiphonVpnActivated = false
    private var activeSocksPort = 0

    /**
     * True while running Psiphon-over-WARP: the Rust core holds a WARP tunnel and
     * publishes a local SOCKS5 listener, and Psiphon dials out through it.
     *
     * Why this mode exists at all — measured on this VPS, not assumed. Chaining
     * costs latency (0.23s direct vs 0.32s chained on the same protocol) and buys
     * no throughput, so it is NOT a speed feature and must never be the default.
     * What it does buy is an exit IP that belongs to neither layer alone: sites
     * that refuse Cloudflare WARP addresses see a Psiphon egress, and carriers
     * that block every Psiphon dial see only a WARP flow. That is the case this
     * mode is for.
     *
     * One measured consequence shapes the config: with an upstream proxy set,
     * Psiphon never dials QUIC-OSSH (0 attempts across a full run, against 3 when
     * dialling directly). Every protocol it does use is TCP, which the core's
     * SOCKS listener carries — CMD_CONNECT only, and it was never asked for a UDP
     * associate in testing.
     */
    private var chainMode = false

    /**
     * True once an outer transport has been accepted and Psiphon started on it.
     *
     * Distinguishes "this rung failed, try the next" from "the transport carrying a
     * live session just died". Before it is set, an outer leg ending is normal —
     * [raiseOuterLeg] is walking the ladder. After it is set, the same event means
     * the chain has lost its foundation and the UI must be told.
     */
    @Volatile
    private var chainOuterCommitted = false

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

    /**
     * Polls [TorSocksFront]'s byte counters while a Tor session is up.
     *
     * Needed because Tor mode is the only path with no push source for traffic:
     * the Rust core emits a `traffic` event and Psiphon calls
     * `onBytesTransferred`, but a Tor session has neither. Without this the UI
     * would sit at 0 B on a working tunnel and the RX verification gate would
     * never arm.
     *
     * One task per second, cancelled on teardown, and it does nothing but read
     * two atomics — the same cost as the existing notification refresh, so this
     * does not add a wakeup source beyond what a connected session already has.
     */
    private var torTrafficTask: java.util.concurrent.ScheduledFuture<*>? = null
    private var ladderIndex = 0
    private var ladderAttempts = 0
    private var ladderTimer: ScheduledFuture<*>? = null
    private val ladderActive = AtomicBoolean(false)
    private val attributionPending = AtomicBoolean(false)

    /**
     * Whether this attempt is the short "preferred country" attempt that runs in
     * front of the ladder.
     *
     * The user's country choice is a preference, and Psiphon has no way to express
     * one: `EgressRegion` is a hard filter, so a pinned country removes every
     * server outside it from the candidate pool. On the worst domestic operator
     * that is fatal — only 5 of the 430 embedded server entries advertise
     * FRONTED-MEEK and every one of them is US/GB, so a pin on any other country
     * deletes the only protocol family that works there.
     *
     * So the country gets one bounded attempt, on the rung that last carried a
     * tunnel on this device, and then the flag clears and the normal ladder runs
     * with no region filter at all. Cost of a wrong country is
     * [REGION_PHASE_TIMEOUT_SECONDS], not a failed connection.
     */
    private var regionPhase = false

    /** The country this session already tried, so it is attempted exactly once. */
    private var regionPhaseTried = ""


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
            // A HARD limit as well as the initial preference, so the rung's whole
            // budget is spent on fronted candidates instead of lapsing back to the
            // 425 direct entries that are null-routed on this carrier. Rung D is
            // where direct protocols get their turn.
            config.put("LimitTunnelProtocols", JSONArray(PROTOCOLS_FRONTED))
            config.put("ConnectionWorkerPoolSize", 12)
            // CDN paths are legitimately slower than a direct dial; without this
            // Psiphon abandons them as if they were dead.
            config.put("NetworkLatencyMultiplier", 2.0)
            applyTacticsOverride(config)
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
            // Direct dials do not need tactics either, and with tactics on this
            // rung was also being forced onto in-proxy — see applyTacticsOverride.
            applyTacticsOverride(config)
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

    /**
     * The ladder actually in use for this session.
     *
     * Chained runs drop rung C. It is WebRTC, a SOCKS5 upstream cannot carry UDP,
     * and the field log shows the failure precisely: STUN leaving over the carrier
     * instead of the tunnel, 34-second ICE gathering, and an untunneled broker DNS
     * lookup timing out on the link Hamrah-e-Aval null-routes. Keeping it in the
     * list did not merely waste its 75s budget — the *starting* rung is read from
     * `psiphon_winning_strategy`, which plain Psiphon had already set to C after a
     * successful unchained connect, so the very first chained attempt began on the
     * one rung that cannot work and the chainable rungs never got a fair turn.
     *
     * Indices differ between the two lists, which is exactly why the remembered
     * rung is stored under a separate key per mode — see [winningStrategyKey].
     */
    private val activeLadder: List<PsiphonStrategy>
        get() = if (chainMode) psiphonLadder.filter { it.name != "C" } else psiphonLadder

    /**
     * Where the last-working rung is remembered, per mode.
     *
     * Chained and unchained runs have different ladders, so an index means
     * different things in each. Sharing one key is what put the chain on rung C to
     * begin with.
     */
    private fun winningStrategyKey(): String =
        if (chainMode) "psiphon_winning_strategy_chained" else "psiphon_winning_strategy"

    /** Where the ladder composition that produced the remembered index is stored. */
    private fun ladderShapeKey(): String = winningStrategyKey() + "_shape"

    /**
     * The rung composition currently in use, e.g. "A,D,C".
     *
     * The remembered rung is persisted as a plain index into [activeLadder], so it
     * is only meaningful for the exact ladder that wrote it. Every past change to
     * the rung list silently repointed it: the ladder once had a rung B, and an
     * index of 1 meant "443-only protocols" then and "all protocols (direct)" now.
     */
    private fun ladderSignature(): String = activeLadder.joinToString(",") { it.name }

    /**
     * The rung this connect should start on.
     *
     * Reads the remembered index only when the ladder still has the shape it had
     * when that index was written. After an app update that adds, removes or
     * reorders rungs the stored number points somewhere else, and the cost is a
     * full rung timeout on the first connect after every update — on precisely the
     * carrier where the user already found a working path. Falling back to rung 0
     * is honest: the ladder's own ordering is the best guess when there is no
     * valid memory, and the next successful connect rewrites it.
     */
    private fun rememberedRungIndex(): Int {
        val prefs = getSharedPreferences("settings", MODE_PRIVATE)
        val shape = ladderSignature()
        val storedShape = prefs.getString(ladderShapeKey(), null)
        if (storedShape != shape) {
            // Drop the stale index and record the new shape, so this happens once
            // per update rather than on every connect.
            prefs.edit()
                .remove(winningStrategyKey())
                .putString(ladderShapeKey(), shape)
                .apply()
            if (storedShape != null) {
                ConnectionLog.record(
                    "Strategy list changed ($storedShape -> $shape) — " +
                        "discarding the remembered strategy and starting from the top"
                )
            }
            return 0
        }
        return prefs.getInt(winningStrategyKey(), 0)
            .coerceIn(0, activeLadder.size - 1)
    }

    companion object {
        const val LOG_TAG = "MsnGuardVpnService"
        const val ACTION_CONNECT = "com.msnguard.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.msnguard.vpn.DISCONNECT"
        const val ACTION_RECONNECT = "com.msnguard.vpn.RECONNECT"
        const val ACTION_NOTIFICATION_HEALTH = "com.msnguard.vpn.NOTIFICATION_HEALTH"
        const val ACTION_STATUS = "com.msnguard.vpn.STATUS"
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

        /**
         * Country the tunnel exits in, for the notification's second line.
         *
         * Sent by the activity once its geolocation lookup lands, because that
         * lookup is a property of the address rather than of the route and the
         * service has no reason to duplicate it. Psiphon also fills this in
         * directly from `onConnectedServerRegion`, which is authoritative and
         * arrives earlier.
         */
        const val EXTRA_NOTIFICATION_COUNTRY = "notification_country"

        /**
         * 0..100 while connecting, or -1 when this status carries no measurable
         * progress.
         *
         * Deliberately not a fabricated animation: every value published here is
         * a real milestone the service has actually reached (see
         * [publishProgress]), and for Tor it is the bootstrap percentage Tor
         * itself reports. A progress bar that moves on a timer while nothing
         * happens is worse than no progress bar.
         */
        const val EXTRA_PROGRESS = "progress"

        /**
         * Accent used for the notification's icon tint and header text.
         *
         * Sampled from the launcher artwork's neon ring (#70E0B0 region), so the
         * shade row and the app icon read as the same brand.
         */
        private const val NOTIFICATION_ACCENT = 0xFF70E0B0.toInt()

        /** Preference key for the auto-reconnect toggle. */
        const val AUTO_RECONNECT_PREF = "auto_reconnect"

        /**
         * Auto-reconnect is ON by default.
         *
         * The standing requirement for this app is one-click connect on a hostile
         * network. A tunnel that dies at 3am and stays dead until the user notices
         * their apps are offline is the same failure as not connecting at all, so
         * recovery is not an opt-in feature. An explicit "off" from the user is
         * still honoured — the key is written on every toggle.
         */
        const val AUTO_RECONNECT_DEFAULT = true

        /** How often the liveness watchdog checks an established tunnel. */
        private const val WATCHDOG_INTERVAL_S = 30L

        /** Auto-reconnect backoff in seconds; the last entry repeats forever. */
        private val RECONNECT_BACKOFF_S = longArrayOf(5, 15, 30, 60, 120)
        /** Exit address measured by the core from inside the tunnel. */
        const val EXTRA_EXIT_IP = "exit_ip"
        const val STATUS_CONNECTING = "connecting"
        const val STATUS_STARTING = "starting"
        const val STATUS_SCANNING = "scanning"
        const val STATUS_CONNECTED = "connected"
        const val STATUS_DISCONNECTED = "disconnected"
        const val STATUS_FAILED = "failed"
        /**
         * Deliberately a new id, not a rename.
         *
         * A channel's lock-screen visibility is fixed at creation: after the first
         * `createNotificationChannel` call Android ignores every later change to
         * that field, so patching the old channel in place would have shipped a
         * build where the code says PUBLIC and the device still behaves as before
         * for everyone who already had the app installed. A fresh id is created
         * fresh, with the new visibility, and [CHANNEL_ID_LEGACY] is deleted so the
         * user is not left with two VPN rows in notification settings.
         */
        const val CHANNEL_ID = "vpn_channel_v2"

        /** The pre-1.4.0 channel, deleted on first foreground start. */
        private const val CHANNEL_ID_LEGACY = "vpn_channel"

        /**
         * Marks a config as Psiphon-over-WARP.
         *
         * Deliberately not a `protocol` value the core knows: the core never sees
         * this string. `startTunnel` reads it, runs the two legs itself (core in
         * SOCKS mode + the Psiphon Go library on top), and hands each leg the
         * protocol name it actually understands.
         */
        const val CHAIN_PROTOCOL_MARKER = "PSIPHON-OVER-WARP"

        /**
         * How long to wait for a rejected outer leg to actually stop.
         *
         * `aether_stop` only raises a flag; the core's RUNNING guard clears when the
         * tunnel task unwinds. Starting the next rung before then gets "Aether tunnel
         * already running" and fails it for the wrong reason.
         */
        private const val OUTER_STOP_GRACE_MS = 6_000L

        /**
         * How long a freshly started outer rung has to raise the core's RUNNING flag.
         *
         * `startProxy` is spawned on its own thread, so for a moment after the call
         * the core is legitimately not running yet. Without this grace the readiness
         * loop would read that gap as "the rung died" and reject every transport
         * instantly.
         */
        private const val OUTER_START_GRACE_MS = 3_000L

        /**
         * Budget for the preferred-country attempt that runs in front of the ladder.
         *
         * Deliberately short. `EgressRegion` is a hard filter, so this attempt runs
         * against one country's servers only — if that country is reachable it
         * answers quickly, and if it is not, every extra second is time stolen from
         * the ladder that will actually connect. 25s covers a fronted CDN handshake
         * (measured at 33s on the worst operator *without* a filter, where the win
         * came from a rung with a 60s budget) while keeping the worst case for a
         * wrong country to roughly half a minute.
         */
        private const val REGION_PHASE_TIMEOUT_SECONDS = 25

        const val NOTIFICATION_ID = 1
        const val TRAFFIC_PREFS = "traffic_stats"
        const val TRAFFIC_MONTH = "month"
        const val TRAFFIC_TX = "tx"
        const val TRAFFIC_RX = "rx"

        /**
         * Schema version of [TRAFFIC_PREFS], bumped when stored totals become
         * untrustworthy and have to be discarded rather than migrated.
         *
         * 1 = totals written before the monthly-inflation fix.
         */
        const val TRAFFIC_SCHEMA = "schema"
        const val TRAFFIC_SCHEMA_VERSION = 1

        /**
         * How often the monthly traffic counters are written to disk while a
         * tunnel is up. Teardown always flushes, so this only bounds what a hard
         * process kill can lose.
         */
        private const val TRAFFIC_FLUSH_MS = 60_000L

        /**
         * In-tunnel RX bytes that count as "this transport really works".
         *
         * Mirrors `MainActivity.VERIFY_MIN_RX_BYTES` on purpose — the two answer the
         * same question ("did real payload arrive?") and drifting apart would let one
         * of them accept a tunnel the other rejects. Not shared as one constant
         * because the activity's copy also documents the verification gate's own
         * retry loop; if either changes, change both.
         */
        private const val VERIFIED_RX_BYTES = 4_096L


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

        /**
         * The exit address the core last measured from inside the tunnel, or "".
         *
         * Static for the same reason as [connectedSince], but it fixes a sharper
         * bug. The core measures the exit exactly once per tunnel, about a second
         * after the first byte crosses (`ExitProbe` in tun.rs goes to `Done` and
         * stops ticking — deliberately, since waking the loop forever costs
         * battery). That measurement is announced with a single broadcast.
         *
         * Connect from the Quick Settings tile and there is no activity alive at
         * that moment, and the receiver is registered in `onStart` rather than in
         * the manifest — so the broadcast reaches nobody and the only measurement
         * of the session is lost. Opening the app afterwards then finds its own
         * `coreExitIp` empty and, correctly refusing to ask over the carrier link
         * (we are excluded from our own TUN, so the answer would be the carrier's
         * address), sits on "measuring…" for the rest of the session.
         *
         * The service outlives the UI, so it keeps the answer here and the
         * activity reads it on start. The notification already showed this value
         * while the card claimed to be measuring; now both read the same source.
         */
        @Volatile
        private var lastExitIp = ""

        fun lastMeasuredExitIp(): String = lastExitIp
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
        if (CoreConfig.lanSharingEnabled(this)) {
            val host = CoreConfig.localNetworkAddress(this)
            if (host != null) {
                ConnectionLog.record("LAN sharing: SOCKS5 at $host:$port")
            } else {
                ConnectionLog.record(
                    "LAN sharing is on but this device has no local network address — " +
                        "turn on the hotspot or join a Wi-Fi network"
                )
                // The inputs, not just the verdict. Two builds in a row got this
                // answer wrong and the only evidence was a screenshot of the row.
                ConnectionLog.record("LAN survey: " + CoreConfig.describeLocalNetworks(this))
            }
        }
    }

    /**
     * Only fires when LAN sharing wrote LocalHttpProxyPort — see buildPsiphonConfig.
     * Logged with the address because that is what the user has to type on the other
     * device, and an "it's on" message they cannot act on is worthless.
     */
    override fun onListeningHttpProxyPort(port: Int) {
        val host = CoreConfig.localNetworkAddress(this)
        if (host != null) {
            ConnectionLog.record("LAN sharing: HTTP proxy at $host:$port")
        } else {
            ConnectionLog.record("LAN sharing: HTTP proxy listening on port $port")
        }
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
        // The preferred-country attempt succeeded, or we were already past it.
        // Either way the phase is over: Psiphon's NetworkMonitor can restart the
        // controller on its own, and leaving the flag set would re-arm a filtered
        // candidate pool on a tunnel that is already working.
        if (regionPhase) {
            regionPhase = false
            ConnectionLog.record(
                "Connected in preferred country ${PsiphonRegions.name(regionPhaseTried)}"
            )
        }

        // Attribution is NOT done here. The ActiveTunnel notice that names the
        // protocol arrives *after* this callback — both field logs show it one
        // line below "Psiphon connected" — so at this point activeTunnelProtocol
        // is still empty and any decision would be a guess. See
        // scheduleLadderAttribution() for the deferred, evidence-based version.
        scheduleLadderAttribution()

        val port = activeSocksPort
        if (port <= 0) {
            failAndStop("Psiphon SOCKS port unavailable")
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
            failAndStop("VPN interface missing")
            return
        }

        if (!Tun2SocksManager.start(tunFd, port)) {
            failAndStop("Could not start whole-device routing")
            return
        }
        psiphonVpnActivated = true
        ConnectionLog.record("Whole-device routing active via tun2socks → $socksProxy")
        connected.set(true)
        // Replace the placeholder "Connecting..." notification immediately. It used
        // to be overwritten by the first traffic sample from the Rust core; with
        // tun2socks the first sample can be seconds away, so the notification
        // would sit on "Connecting..." while the device was fully tunnelled.
        repostNotification()
        sendStatus(STATUS_CONNECTED)
        startWatchdog()
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
        // The controller exiting *after* a session was established is the silent
        // death the field report describes: Psiphon is gone, tun2socks keeps
        // routing into nothing, and without this the app would sit there claiming
        // to be connected. Handled here rather than waiting up to 30s for the
        // watchdog tick, because this callback is the definitive signal.
        if (!stopRequested.get() && !userInitiatedStop.get() &&
            psiphonVpnActivated && connected.get()
        ) {
            onTunnelLost("the Psiphon tunnel stopped")
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

    /**
     * Psiphon's live list of countries it can currently egress from.
     *
     * Cached because it is the only authoritative source: the 430 embedded server
     * entries age, and the picker must not offer a country the network cannot
     * actually reach. Arrives on every handshake, tunnel or not.
     */
    override fun onAvailableEgressRegions(regions: MutableList<String>?) {
        val list = regions?.filterNotNull().orEmpty()
        if (list.isEmpty()) return
        PsiphonRegions.remember(this, list)
        ConnectionLog.record("Psiphon egress countries available: ${list.size}")
    }

    /**
     * Which country the established tunnel actually exits in.
     *
     * Logged next to the preference so a mismatch is visible: with the country
     * treated as a preference rather than a pin, exiting somewhere else is the
     * expected outcome of a failed region phase, not a bug.
     */
    override fun onConnectedServerRegion(region: String?) {
        if (region.isNullOrBlank()) return
        val wanted = CoreConfig.egressRegion(this)
        val exitedIn = PsiphonRegions.name(region)
        ConnectionLog.record(
            if (wanted == null || wanted == region.uppercase()) {
                "Exit country: $exitedIn ($region)"
            } else {
                "Exit country: $exitedIn ($region) — ${PsiphonRegions.name(wanted)} was preferred but unavailable"
            }
        )
        getSharedPreferences("settings", MODE_PRIVATE).edit()
            .putString("last_exit_region", region.uppercase()).apply()
        // Psiphon knows its own egress country, which is both earlier and more
        // reliable than the activity's geolocation lookup. One repost, on a
        // change the user can see.
        if (currentCountry != exitedIn) {
            currentCountry = exitedIn
            repostNotification()
        }
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
            // --- LAN sharing, opt-in ---
            //
            // "any" is psiphon-tunnel-core's own spelling for 0.0.0.0 (config.go:
            // "If 'any' is provided then use 0.0.0.0"), so no socket surgery is
            // needed on our side. The HTTP proxy is only bound when sharing is on:
            // Windows takes an HTTP proxy system-wide while SOCKS has to be set per
            // application, so a shared tunnel needs both, but an unshared one has no
            // use for a second listener and should not open one.
            //
            // With sharing off, neither key is written at all — the Go default is
            // 127.0.0.1 and no HTTP proxy, which is exactly the previous behaviour.
            if (CoreConfig.lanSharingEnabled(this@MsnGuardVpnService)) {
                put("ListenInterface", "any")
                put("LocalHttpProxyPort", CoreConfig.HTTP_PROXY_PORT)
            }
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
            // --- Give Psiphon a resolver the operator does not intercept ---
            //
            // See [PSIPHON_ALTERNATE_DNS] for the field evidence. Three keys, and
            // each one is load-bearing:
            //
            //  * PreferredAlternateServers, not AlternateServers: upstream only
            //    consults the plain Alternate list when the system server list is
            //    EMPTY, and on Android it never is — GetDNSServers returns the
            //    resolvers we set on the TUN. Only the Preferred list is allowed
            //    to go first while system servers exist.
            //  * Probability 1.0, because the default is 0.0. The Preferred list
            //    is selected by a weighted coin flip, so without this the list is
            //    configured and then almost never used.
            //  * AttemptsPerPreferredServer 2 (default 1): one lost UDP packet on
            //    a mobile link would otherwise drop us straight back to the
            //    hijacked system resolver.
            //
            // Not a hard override: the system resolvers stay in the list behind
            // these, so a network with honest DNS still resolves normally if the
            // alternate ports are the ones being blocked.
            put("DNSResolverPreferredAlternateServers", JSONArray(PSIPHON_ALTERNATE_DNS))
            put("DNSResolverPreferAlternateServerProbability", 1.0)
            put("DNSResolverAttemptsPerPreferredServer", 2)
            // Psiphon-over-WARP: dial out through the core's SOCKS listener, so
            // every Psiphon connection leaves inside the WARP tunnel.
            //
            // Measured consequence, worth knowing before reading a chained log:
            // with this set Psiphon stops attempting QUIC-OSSH entirely (0
            // attempts over a full run, against 3 when dialling directly) and
            // uses TCP protocols only. That is Psiphon's own rule — a SOCKS5
            // upstream cannot carry its UDP dials — and it is why the ladder's
            // fronted and direct rungs still work here while nothing needs a
            // UDP associate from the outer listener.
            if (chainMode) {
                put(
                    "UpstreamProxyURL",
                    "socks5://127.0.0.1:${CoreConfig.CHAIN_SOCKS_PORT}",
                )
            }
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
        val strategy = activeLadder.getOrNull(ladderIndex)
        if (strategy != null) {
            strategy.configure(config)
            config.put("EstablishTunnelTimeoutSeconds", strategy.timeoutSeconds)
            ConnectionLog.record(
                "Strategy ${ladderIndex + 1}/${activeLadder.size} " +
                    "(${strategy.name}): ${strategy.label} — ${strategy.timeoutSeconds}s budget"
            )
        }

        // The preferred-country attempt, in front of the ladder and only once.
        //
        // Applied AFTER the rung so it owns the establish timeout: the rung's own
        // budget (up to 75s) is sized for searching a hostile carrier, and spending
        // that on a country preference would make a wrong choice cost more than the
        // whole ladder. A short budget is also the honest one — if the preferred
        // country is reachable at all it answers quickly, because the filter has
        // already removed everything else.
        val preferredRegion = if (regionPhase) CoreConfig.egressRegion(this) else null
        if (preferredRegion != null) {
            config.put("EgressRegion", preferredRegion)
            config.put("EstablishTunnelTimeoutSeconds", REGION_PHASE_TIMEOUT_SECONDS)
            // Drop the rung's protocol ordering for this one attempt.
            //
            // Not a detail — it is what makes the feature usable. Rung A prefers
            // FRONTED-MEEK, and only 5 of the 430 embedded entries advertise it, all
            // of them US/GB. Since the remembered rung is A on any operator where
            // fronting is the only thing that works, keeping its preference would
            // pair "only fronted servers" with "only German servers" and match
            // nothing at all — so a German preference would fail its 25s every
            // single time, on exactly the operators where the user is most likely
            // to have set one. Widening to Psiphon's full set asks the honest
            // question instead: is *anything* in this country reachable?
            //
            // The chained branch below still narrows to TCP-only afterwards, which
            // is a hard requirement of a SOCKS5 upstream rather than a preference.
            config.remove("InitialLimitTunnelProtocols")
            config.remove("InitialLimitTunnelProtocolsCandidateCount")
            // Rung A now also pins a HARD fronted-only limit, and that would
            // survive the two removals above — pairing "only fronted servers"
            // with "only this country's servers" and matching nothing, which is
            // the exact failure this widening exists to prevent.
            config.remove("LimitTunnelProtocols")
            ConnectionLog.record(
                "Preferred country ${PsiphonRegions.name(preferredRegion)} " +
                    "($preferredRegion), all protocols — ${REGION_PHASE_TIMEOUT_SECONDS}s before the ladder"
            )
        }


        // Applied AFTER the rung, so no rung can widen it back. This is a hard
        // limit, unlike the rungs' InitialLimitTunnelProtocols preference, because
        // a preference lapses once the candidate budget is spent and Psiphon then
        // reverts to its full set — including the UDP protocols a SOCKS5 upstream
        // cannot carry.
        if (chainMode) {
            config.put("LimitTunnelProtocols", JSONArray(PROTOCOLS_CHAINABLE))

            // The rung's ORDERING is kept, just narrowed to what can cross the
            // proxy. Dropping it entirely would collapse rung A into rung D, and
            // rung A's "fronted first" is the behaviour that works on
            // Hamrah-e-Aval, where every direct dial is null-routed.
            val preference = config.optJSONArray("InitialLimitTunnelProtocols")
            if (preference != null) {
                val chainable = (0 until preference.length())
                    .map(preference::getString)
                    .filter(PROTOCOLS_CHAINABLE::contains)
                if (chainable.isEmpty()) {
                    config.remove("InitialLimitTunnelProtocols")
                    config.remove("InitialLimitTunnelProtocolsCandidateCount")
                } else {
                    config.put("InitialLimitTunnelProtocols", JSONArray(chainable))
                }
            }

            // In-proxy off explicitly: rung C is already filtered out of
            // activeLadder, but the base config must not leave the door open.
            config.put("InproxyEnabled", false)
            config.put("InproxyAllowClient", false)
            ConnectionLog.record("Chain: TCP-only protocols (a SOCKS proxy cannot carry UDP)")
        }
        // Stated once per attempt so a support log proves the resolver was in
        // play. Without it, a future "IP is bogon" log would be impossible to
        // tell apart from a build that predates this.
        ConnectionLog.record(
            "Psiphon DNS: ${PSIPHON_ALTERNATE_DNS.size} public resolvers on " +
                "non-standard ports preferred over the operator's"
        )
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
            // Nothing is armed at this point — the exception happened before
            // armLadderTimer(), so no watchdog and no onExiting() will ever fire.
            // Without stopping here the service sits on "Connecting…" forever with
            // a live TUN and no tunnel behind it.
            failAndStop(e.message ?: "Psiphon could not start")
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
        val strategy = activeLadder.getOrNull(ladderIndex) ?: return
        cancelLadderTimer()
        ladderActive.set(true)
        // +8s grace so Psiphon's internal timeout and teardown land first; racing
        // it would restart the tunnel while the old controller is still stopping.
        //
        // During the preferred-country attempt the budget is the region phase's,
        // not the rung's: buildPsiphonConfig() overrode EstablishTunnelTimeout for
        // that attempt, so watching the rung's longer budget would leave the user
        // on a filtered candidate pool long after Psiphon had already given up.
        val seconds = if (regionPhase && CoreConfig.egressRegion(this) != null) {
            REGION_PHASE_TIMEOUT_SECONDS
        } else {
            strategy.timeoutSeconds
        }
        val budget = seconds.toLong() + 8L
        ladderTimer = ladderScheduler.schedule({
            if (ladderActive.get() && !psiphonVpnActivated) escalateLadder()
        }, budget, TimeUnit.SECONDS)
    }


    /**
     * Decide whether this connect starts with the preferred-country attempt.
     *
     * Called once per connect, before the first [startPsiphonTunnel].
     *
     * Chained runs only. A plain Psiphon connect always lets Psiphon pick whichever
     * server answers first, which is both the fastest path and the behaviour that
     * predates this feature — so the country preference must not leak into it. The
     * flag is written unconditionally (not just when chained) precisely so that a
     * plain connect following a chained one cannot inherit a stale `true` and start
     * against a filtered candidate pool.
     */
    private fun armRegionPhase() {
        val region = if (chainMode) CoreConfig.egressRegion(this) else null
        regionPhase = region != null
        regionPhaseTried = region.orEmpty()
        if (region != null) {
            ConnectionLog.record(
                "Preferred country: ${PsiphonRegions.name(region)} ($region), " +
                    "then all countries if it does not connect"
            )
        }
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
        // Indices are into activeLadder, which is the list ladderIndex walks and
        // the list the stored value is read back against. In chained mode rung C
        // is not in it, so `inproxyRung` is -1 there and every in-proxy branch
        // below is correctly unreachable.
        val ladder = activeLadder
        val inproxyRung = ladder.indexOfFirst { it.name == "C" }

        val (winnerIndex, reason) = when {
            // The protocol name is the strongest signal available. An INPROXY-*
            // tunnel is unambiguously the peer-relay rung.
            protocol.startsWith("INPROXY") && inproxyRung >= 0 ->
                inproxyRung to "in-proxy protocol $protocol"

            protocol.isNotBlank() -> {
                val matches = ladder.indices.filter { i ->
                    ladder[i].preferredProtocols.contains(protocol)
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

        val winner = ladder.getOrNull(winnerIndex) ?: return
        getSharedPreferences("settings", MODE_PRIVATE).edit()
            .putInt(winningStrategyKey(), winnerIndex)
            // Written together with the index, never separately: the index is only
            // meaningful for the ladder shape that produced it, and
            // rememberedRungIndex() discards it if the two disagree.
            .putString(ladderShapeKey(), ladderSignature())
            .apply()

        val via = if (protocol.isNotBlank()) " via $protocol" else ""
        ConnectionLog.record(
            "Connected$via — crediting strategy ${winner.name} (${winner.label}): $reason"
        )
        if (winnerIndex != rungAtConnect) {
            val active = ladder.getOrNull(rungAtConnect)
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

        val ladder = activeLadder

        // The preferred country failed. Drop the region filter and hand over to the
        // ladder *at the same rung*, without counting an attempt: the rung was never
        // given a fair try, it ran against one country's servers only. Counting it
        // would silently shorten the ladder by one every time a country is pinned.
        if (regionPhase) {
            regionPhase = false
            val region = regionPhaseTried
            ConnectionLog.record(
                "Preferred country ${PsiphonRegions.name(region)} did not connect — " +
                    "continuing with all countries from strategy ${ladder.getOrNull(ladderIndex)?.name ?: "?"}"
            )
            sendStatus(STATUS_CONNECTING, "Trying all countries…")
            worker.execute {
                if (stopRequested.get()) return@execute
                try { psiphonTunnel?.stop() } catch (_: Exception) {}
                psiphonTunnel = null
                activeSocksPort = CoreConfig.SOCKS_PORT
                try { Thread.sleep(1200) } catch (_: InterruptedException) {}
                if (stopRequested.get()) return@execute
                startPsiphonTunnel()
            }
            return
        }

        val failed = ladder.getOrNull(ladderIndex)
        ladderAttempts += 1


        // Wrap around instead of walking off the end. Because a successful rung is
        // remembered and reused first, the ladder can start anywhere — so "done"
        // means every rung has had a turn, not that the index hit the last slot.
        if (ladderAttempts >= ladder.size) {
            ConnectionLog.record(
                "All ${ladder.size} strategies exhausted — carrier is blocking every available path"
            )
            ladderIndex = 0
            ladderAttempts = 0
            regionPhase = false
            // Deliberately the same generic failure whether chained or not: the
            // user asked for one message, and a chained-specific string would only
            // suggest the chain itself was at fault when the carrier is.
            failAndStop("Could not connect on this carrier. Try Wi-Fi or another SIM.")
            return
        }

        ladderIndex = (ladderIndex + 1) % ladder.size
        val next = ladder[ladderIndex]
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

    /**
     * Take protocol selection back from Psiphon's remote tactics.
     *
     * The field log from Iran proved the rung's protocol list was being ignored:
     * rung A asked for the three FRONTED-MEEK protocols, and Psiphon's own
     * `CandidateServers` notice reported
     * `initialLimitTunnelProtocols: [INPROXY-WEBRTC-*]` instead, followed by
     * `in-proxy protocol selection forced` and 228 WebRTC dials that had no hope
     * on a network where UDP is dead.
     *
     * That is not a bug in our config — it is precedence. `Config.SetParameters`
     * passes `[configParameters, tacticsParameters]` to `Parameters.Set`, and
     * `getAppliedValue` walks that list **backwards**, so the remotely delivered
     * tactics value wins over anything the app set. Psiphon changed its Iran
     * tactics to force in-proxy, and every rung of our ladder silently became the
     * same in-proxy rung. It is also why the ladder felt useless: three rungs, one
     * effective behaviour.
     *
     * `DisableTactics` is the only lever that restores our own ordering, because
     * it stops the tactics request and the stored-tactics load entirely. It is
     * applied per rung, not globally:
     *
     *  - rung A (fronted) sets it — the fronting domains live in the embedded
     *    server entries, so this rung needs nothing from tactics.
     *  - rung C (in-proxy) must NOT set it — broker specs arrive via tactics, and
     *    without them the peer-relay rung cannot dial at all.
     *
     * Cost: rung A loses remote tuning it was not benefiting from anyway. Benefit:
     * the 5 fronted server entries actually get dialled, which is the only path
     * that has ever worked on Hamrah-e-Aval.
     */
    private fun applyTacticsOverride(config: JSONObject) {
        // Chained runs are left exactly as they were. Psiphon rides inside WARP
        // there, its tactics request goes out over a working tunnel, and the user
        // reports the chain connecting on the first try — so there is nothing to
        // fix and no reason to change a path that works. Rung C is filtered out of
        // the chained ladder anyway, so forced in-proxy cannot strand it either.
        if (chainMode) return
        config.put("DisableTactics", true)
        // With tactics off there are no broker specs, so in-proxy is dead weight
        // here: it would still consume worker slots on WebRTC/ICE that cannot
        // complete. Rung C is where the peer relay gets its turn, with tactics on.
        config.put("InproxyEnabled", false)
        config.put("InproxyAllowClient", false)
        ConnectionLog.record(
            "Tactics disabled for this rung — using the app's own protocol order"
        )
    }

    /**
     * Report a terminal failure and actually stop.
     *
     * Every path that reaches this used to call `sendStatus(STATUS_FAILED, …)` and
     * return, which told the UI the truth but left the service running with a
     * live TUN and the placeholder "Connecting…" notification. On a Psiphon run
     * the TUN is created *before* Psiphon starts, so that state is not merely
     * cosmetic: the device has a default route into a tunnel with nothing on the
     * other end, i.e. no internet, and no visible sign the app has given up. That
     * is exactly what was reported from the field.
     *
     * The kill switch is deliberately not consulted here. These are failures to
     * ever establish, not a tunnel dropping under a user who asked to stay
     * protected — blocking all traffic after a failed connect would leave the
     * device offline with no explanation.
     */
    private fun failAndStop(detail: String) {
        sendStatus(STATUS_FAILED, detail)
        connected.set(false)
        stopTunnel(notify = false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
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
                // A fresh user-initiated connect clears both the "user switched it
                // off" latch and the backoff counter, so a manual retry always
                // starts from the first, shortest delay.
                userInitiatedStop.set(false)
                reconnectAttempts = 0
                startTunnel(config)
            }
            ACTION_DISCONNECT -> {
                // The one place that means "the user wants this off". Auto-reconnect
                // reads this latch and stays out of the way.
                userInitiatedStop.set(true)
                cancelAutoReconnect()
                stopTunnel()
            }
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
                // The activity's geolocation lookup is a fallback for transports
                // that cannot name their own exit country (everything except
                // Psiphon, which reports it via onConnectedServerRegion). It must
                // not overwrite a country Psiphon already gave us.
                intent.getStringExtra(EXTRA_NOTIFICATION_COUNTRY)?.takeIf { it.isNotBlank() }
                    ?.let { if (currentCountry.isBlank()) currentCountry = it }
                repostNotification()
            }
        }
        return Service.START_REDELIVER_INTENT
    }

    override fun onDestroy() {
        cancelAutoReconnect()
        stopTorProgressPolling()
        stopTunnel(notify = false)
        cancelLadderTimer()
        ladderScheduler.shutdownNow()
        worker.shutdownNow()
        super.onDestroy()
    }

    /**
     * Android revoked our VPN permission — another VPN app was started, or the
     * user hit "disconnect" in system settings.
     *
     * Reconnecting here would be wrong twice over: the permission is gone, so a
     * retry cannot succeed, and fighting another VPN app for the tunnel is not
     * this app's decision to make. Treated exactly like a user disconnect.
     */
    override fun onRevoke() {
        ConnectionLog.record("VPN permission revoked by the system")
        userInitiatedStop.set(true)
        cancelAutoReconnect()
        stopTunnel()
        super.onRevoke()
    }

    fun protectSocket(fd: Int): Boolean = !vpnModeActive.get() || protect(fd)

    override fun onEvent(json: String) {
        try {
            val event = JSONObject(json)
            when (event.getString("type")) {
                "status" -> {
                    val status = event.getString("status")
                    val detail = if (event.isNull("detail")) null else event.getString("detail")
                    // In chained mode these events describe the OUTER leg only.
                    //
                    // The core fires mark_ready() the moment WARP is up, which is
                    // long before Psiphon has a tunnel. Forwarding that as
                    // CONNECTED made the UI start its verification gate against
                    // Psiphon's SOCKS port while Psiphon was still establishing:
                    // the field log shows "no active tunnels" at 18:01:49 and the
                    // probe only passing at 18:02:06, i.e. ten attempts and seven
                    // seconds stuck on "Connecting" — and in the second log the
                    // same race hit the probe ceiling and reported Connection
                    // Failed over a perfectly healthy outer tunnel.
                    //
                    // So in chained mode the outer leg never reports CONNECTED.
                    // The chain's CONNECTED comes from onConnected(), once Psiphon
                    // has a tunnel and tun2socks is routing.
                    //
                    // "starting" is swallowed for the same reason: the ladder emits
                    // one per rung it tries, and each would reset the UI to
                    // "Starting" mid-attempt, hiding which transport is being
                    // attempted. raiseOuterLeg() narrates the ladder itself.
                    if (chainMode && (status == STATUS_CONNECTED || status == STATUS_STARTING)) {
                        // Only meaningful once a rung has been accepted. While the
                        // ladder is still walking, several rungs can each announce
                        // themselves ready before being rejected.
                        if (chainOuterCommitted && status == STATUS_CONNECTED) {
                            // Name the inner leg: this same branch now serves Tor
                            // over WARP, where "waiting for Psiphon" would be wrong.
                            val inner = if (currentProtocol.contains("TOR")) "Tor" else "Psiphon"
                            ConnectionLog.record("Chain: outer leg is up; waiting for $inner")
                            sendStatus(STATUS_CONNECTING, "Connecting $inner through WARP…")
                        }
                        return
                    }
                    // A rejected rung's teardown emits DISCONNECTED/FAILED. Before a
                    // rung is accepted that is the ladder working as intended, not
                    // the chain failing, and forwarding it would paint the dial red
                    // between attempts.
                    if (chainMode && !chainOuterCommitted &&
                        (status == STATUS_DISCONNECTED || status == STATUS_FAILED)
                    ) {
                        return
                    }
                    sendStatus(status, detail)
                }
                "traffic" -> {
                    val tx = event.getLong("tx")
                    val rx = event.getLong("rx")
                    // Chained mode has two sets of counters for the same bytes: the
                    // core's (outer, absolute totals) and Psiphon's (inner, deltas
                    // via onBytesTransferred). Letting both write here made them
                    // fight — Psiphon accumulating while the core overwrote. The
                    // inner leg is the one carrying the user's data, and it is what
                    // plain Psiphon mode already reports, so the outer leg's
                    // counters are dropped for consistency.
                    if (chainMode) return
                    currentTx = tx
                    currentRx = rx
                    updateTrafficNotification(tx, rx)
                }
                // The core measured the exit address from inside the tunnel. This
                // is the authoritative source: the app's own HTTP lookup leaves
                // over the carrier link (we are excluded from our own TUN) and so
                // reports the carrier's IP, not the tunnel's.
                "exit_ip" -> {
                    val ip = event.getString("ip")
                    // In chained mode this is the OUTER leg's exit — a Cloudflare
                    // WARP address — and it is NOT where the device's traffic
                    // leaves. Psiphon's egress is, and the field report caught the
                    // contradiction: the card read Germany (Psiphon's server, per
                    // `ConnectedServerRegion: DE`) while the WARP address behind it
                    // was American. Publishing the outer address would make the
                    // card and the traffic disagree, so it is logged and dropped.
                    //
                    // Belt and braces: the outer leg runs the userspace netstack,
                    // which has no exit probe (only tun::bridge does), so today it
                    // never emits this at all. The guard is here so that adding one
                    // later cannot silently start overwriting the card.
                    if (chainMode) {
                        if (ip.isNotBlank()) {
                            ConnectionLog.record("Chain: outer WARP leg exits at $ip (not the app's exit)")
                        }
                        return
                    }
                    if (ip.isNotBlank()) {
                        currentVpnIp = ip
                        // Survives the UI: the tile can connect with no activity
                        // alive, and this is the session's only measurement.
                        lastExitIp = ip
                        ConnectionLog.record("Tunnel exit $ip")
                        // The country is resolved by the UI from this address; the
                        // core cannot tell one from inside the tunnel.
                        sendExitIp(ip)
                        repostNotification()
                    }
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
     * Bring up Psiphon-over-WARP: WARP carries the traffic, Psiphon rides inside it.
     *
     * Order is forced by three separate constraints, none of them cosmetic:
     *
     *  1. TUN first, before either tunnel. Psiphon's NetworkMonitor treats tun0
     *     appearing as a network change and restarts the controller, which is the
     *     13-second restart loop the plain Psiphon path already works around.
     *  2. The outer WARP leg next, and we must WAIT for it. Psiphon validates
     *     UpstreamProxyURL by dialling it, so starting Psiphon against a proxy whose
     *     tunnel is not up yet fails the whole rung.
     *  3. tun2socks last, on Psiphon's port, from onConnected() — the same as the
     *     plain path. Only then does device traffic have somewhere to go.
     *
     * The core runs WITHOUT a tun_fd here (NativeCore.startProxy), so it publishes
     * SOCKS on CHAIN_SOCKS_PORT instead of taking the device TUN. Its own sockets
     * are protected via the JNI protector, so the WARP leg leaves over the carrier
     * link rather than looping back into our own TUN.
     *
     * The outer leg walks [CoreConfig.CHAIN_OUTER_LADDER] — MASQUE, then WireGuard,
     * then WoW — until one comes up, because which of them a carrier allows varies:
     * Hamrah-e-Aval has never carried WireGuard, while other SIMs connect on it
     * instantly. The winning rung is remembered per device, so the cost of finding
     * it is paid once rather than on every connect.
     */
    private fun startChainTunnel() {
        chainMode = true
        chainOuterCommitted = false
        psiphonVpnMode = true
        psiphonVpnActivated = false
        // chainMode is set first, so this reads the chained ladder and the chained
        // remembered rung. Reading the unchained key here is what started the very
        // first chained attempt on rung C — the one rung a SOCKS upstream cannot
        // carry — and burned its 75s budget before anything chainable was tried.
        ladderIndex = rememberedRungIndex()
        ladderAttempts = 0
        armRegionPhase()

        worker.execute {
            try {
                val address = Tun2SocksManager.selectPrivateAddress()
                ConnectionLog.record("Chain: creating TUN before either tunnel starts")
                tun = Builder()
                    .setSession("MSN-GUARD")
                    .setMtu(Tun2SocksManager.VPN_INTERFACE_MTU)
                    .addAddress(address.ipAddress, address.prefixLength)
                    .addRoute("0.0.0.0", 0)
                    .addRoute(address.subnet, address.prefixLength)
                    .addDnsServer(address.router)
                    // Same reasoning as the plain Psiphon path: public resolvers
                    // plus our own exclusion, so both legs can resolve names
                    // over the carrier link before any tunnel exists.
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.8.8")
                    // Same reason as the plain Psiphon path: the Split screen's
                    // choice has to apply to chained runs too, and our own package
                    // stays off the TUN in every mode.
                    .applySplitTunneling()
                    .establish() ?: error("Android could not establish the VPN interface")
                vpnModeActive.set(true)

                NativeCore.attach(this)
                val outer = raiseOuterLeg() ?: error(
                    if (CoreConfig.chainOuterIsAuto(this)) {
                        "No WARP transport could carry Psiphon on this network"
                    } else {
                        // Naming the pinned transport is the actionable part: the fix
                        // is to change the pin, not to retry.
                        val pinned = CoreConfig.chainOuterLabel(
                            CoreConfig.chainOuterCandidates(this).first()
                        )
                        "$pinned could not carry Psiphon; try Auto in settings"
                    }
                )
                ConnectionLog.record("Chain: outer leg ready — starting Psiphon through it")

                // --- Inner leg: Psiphon, dialling out through the outer SOCKS ---
                activeSocksPort = CoreConfig.SOCKS_PORT
                startPsiphonTunnel()
                sendStatus(STATUS_CONNECTING, "Connecting Psiphon through $outer…")
            } catch (e: Exception) {
                ConnectionLog.record("Chain start failed: ${e.message}")
                chainMode = false
                failAndStop(e.message ?: "Chain start failed")
            }
        }
    }

    /**
     * Bring up a Tor session: TUN → tun2socks → TorSocksFront → Tor → circuit.
     *
     * Deliberately shaped like the plain Psiphon path rather than the Rust-core
     * one, because the sequencing constraint is the same: the TUN must exist
     * before the tunnel process starts, or Android's new-network callback makes
     * the tunnel treat tun0 as a network change and restart.
     *
     * Unlike Psiphon this path is **synchronous** — there is no connect callback
     * to wait on. [TorManager.start] blocks on its worker thread until bootstrap
     * reaches 100% or every mode has failed, so tun2socks is started right here
     * once it returns true.
     *
     * ## Tor over WARP
     *
     * When [TorManager.chainArmed] agrees, a WARP leg is raised first and Tor is
     * pointed at its SOCKS listener, exactly as Psiphon-over-WARP does — the same
     * [raiseOuterLeg] ladder (MASQUE → WireGuard → WoW) and the same per-device
     * memory of which rung worked, untouched. Only Tor's own ladder narrows:
     * Direct then Meek, because those are the two that were measured working
     * through a proxy (see [TorManager] `chainedLadder`).
     *
     * [chainMode] is set for a chained Tor run as well, and it is load-bearing for
     * three behaviours in [onEvent] that are about the outer leg rather than about
     * Psiphon: the premature CONNECTED is swallowed, the outer traffic counters are
     * dropped in favour of the inner leg's, and the outer exit IP is not published
     * as the session's exit. All three are exactly what a chained Tor run needs.
     * The Psiphon-specific reads of [chainMode] are unreachable here: no
     * `psiphonLadder`, no `armRegionPhase`, no Psiphon config is built on this path.
     *
     * Note what is still NOT done here: no ladder, no `armRegionPhase`, no
     * `recordWorkingPlainTransport`. Those all belong to the Psiphon/WARP
     * transports. Tor keeps its own mode memory inside [TorManager].
     */
    private fun startTorTunnel() {
        val chained = TorManager.chainArmed(this)
        chainMode = chained
        chainOuterCommitted = false

        worker.execute {
            try {
                val address = Tun2SocksManager.selectPrivateAddress()
                ConnectionLog.record("Tor: creating TUN before Tor starts")
                tun = Builder()
                    .setSession("MSN-GUARD")
                    .setMtu(Tun2SocksManager.VPN_INTERFACE_MTU)
                    .addAddress(address.ipAddress, address.prefixLength)
                    .addRoute("0.0.0.0", 0)
                    .addRoute(address.subnet, address.prefixLength)
                    // The ONLY resolver, on purpose — and the opposite of the
                    // Psiphon path, which also lists 1.1.1.1 and 8.8.8.8.
                    //
                    // There, the public resolvers exist to break a bootstrap
                    // deadlock: Psiphon must resolve CDN hostnames before its
                    // tunnel is up. Tor has no such need — every bridge here is
                    // reached by IP, or by a URL the transport resolves itself
                    // over the carrier link (our own package is off the TUN).
                    //
                    // Listing a public resolver on this path would be an actual
                    // anonymity leak: apps' DNS would go to Cloudflare in the
                    // clear, outside the circuit, revealing exactly what a Tor
                    // user is browsing. Tor's DNSPort is the only resolver.
                    //
                    // This holds for the chained run too. The outer WARP leg
                    // resolves its own gateway names in the core, off the TUN, so
                    // it needs nothing added here either.
                    .addDnsServer(address.router)
                    .applySplitTunneling()
                    .establish() ?: error("Android could not establish the VPN interface")
                vpnModeActive.set(true)

                // --- Outer leg, when armed: WARP first, then Tor inside it ---
                var outer: String? = null
                if (chained) {
                    NativeCore.attach(this)
                    outer = raiseOuterLeg(inner = "Tor") ?: error(
                        if (CoreConfig.chainOuterIsAuto(this, forTor = true)) {
                            "No WARP transport could carry Tor on this network"
                        } else {
                            val pinned = CoreConfig.chainOuterLabel(
                                CoreConfig.chainOuterCandidates(this, forTor = true).first()
                            )
                            "$pinned could not carry Tor; try Auto in settings"
                        }
                    )
                    // Only now, once a rung is committed and its listener accepts:
                    // arming the proxy earlier would have Tor write Socks5Proxy
                    // pointing at a port with nothing behind it.
                    TorManager.useUpstreamProxy("127.0.0.1:${CoreConfig.CHAIN_SOCKS_PORT}")
                    ConnectionLog.record("Chain: outer leg ready — bootstrapping Tor through $outer")
                } else {
                    TorManager.useUpstreamProxy(null)
                }

                sendStatus(
                    STATUS_CONNECTING,
                    if (outer != null) "Starting Tor through $outer…" else "Starting Tor…",
                    5,
                )
                ConnectionLog.record("Tor: TUN ready — bootstrapping")
                // Tor is the one transport that reports genuine progress, so the
                // percentage under "Connecting" is its own bootstrap figure.
                startTorProgressPolling()

                if (!TorManager.start(this)) {
                    error(
                        when {
                            // Inside the chain only Direct and Meek are tried, so
                            // "any method" would overstate what was attempted and
                            // send the user looking for a network fault. Disarming
                            // the chain is the actionable next step, since obfs4
                            // and Snowflake are available unchained.
                            outer != null -> "Tor could not connect through $outer; " +
                                "turn Tor over WARP off to try obfs4 and Snowflake"
                            TorManager.selectedMode(this) == TorManager.TorMode.AUTO ->
                                "Tor could not connect with any method on this network"
                            // Name the pinned mode: the fix is to change it or
                            // switch to Auto, not to retry the same thing.
                            else -> "Tor could not connect over " +
                                "${TorManager.selectedMode(this).label}; try Auto"
                        }
                    )
                }
                stopTorProgressPolling()

                val mode = TorManager.activeMode?.label ?: "Tor"
                activeSocksPort = TorManager.FRONT_SOCKS_PORT
                // dnsOnlyUdpgw: Tor is TCP-only, so TorSocksFront answers DNS and
                // discards every other UDP flow. Feeding those flows to udpgw
                // anyway burned one of its 256 never-expiring conids each, and
                // once the table saturated (a few minutes of QUIC-heavy traffic,
                // e.g. speed tests) DNS replies came back on rebinded conids and
                // were rejected as "wrong remote address" — name resolution died
                // mid-session while the tunnel itself was still healthy.
                if (!Tun2SocksManager.start(tun!!, TorManager.FRONT_SOCKS_PORT, dnsOnlyUdpgw = true)) {
                    error("Could not start device routing")
                }

                currentVpnIp = ""
                val via = if (outer != null) "$mode over $outer" else mode
                sendStatus(STATUS_CONNECTED, "Tor connected via $via")
                ConnectionLog.record("Tor: connected via $via")
                // The mode is only known now, and it is part of the notification's
                // subtitle ("Tor (Meek)").
                repostNotification()
                startTrafficPolling()
                startWatchdog()
            } catch (e: Exception) {
                stopTorProgressPolling()
                ConnectionLog.record("Tor start failed: ${e.message}")
                TorManager.stop()
                // The outer leg is the service's to stop; TorManager only owns tor
                // and its PT. Left running it would hold the core and make the next
                // connect fail with "already running".
                if (chained) stopOuterLeg()
                chainMode = false
                failAndStop(e.message ?: "Tor start failed")
            }
        }
    }

    /**
     * Feeds [TorSocksFront]'s counters into the same traffic pipeline the other
     * transports use.
     *
     * [updateTrafficNotification] already owns everything downstream — speed
     * deltas, monthly totals with the rebase guard, notification throttling — so
     * this poll only has to present the numbers once a second; nothing about the
     * accounting is duplicated here.
     *
     * Runs on [ladderScheduler], which is idle for the whole life of a connected
     * Tor session: its other job, the Psiphon escalation timer, is cancelled
     * before any of this starts.
     */
    private fun startTrafficPolling() {
        torTrafficTask?.cancel(false)
        torTrafficTask = ladderScheduler.scheduleAtFixedRate({
            try {
                if (!TorSocksFront.isRunning) return@scheduleAtFixedRate
                updateTrafficNotification(TorSocksFront.sessionTx, TorSocksFront.sessionRx)
            } catch (_: Exception) {
            }
        }, 1L, 1L, TimeUnit.SECONDS)
    }

    private fun stopTrafficPolling() {
        torTrafficTask?.cancel(false)
        torTrafficTask = null
    }

    // ------------------------------------------------------ auto-reconnect

    /**
     * Watch an established tunnel and bring it back when it dies on its own.
     *
     * ## The bug this fixes
     *
     * Reported from the field: after some hours the notification still said
     * connected, but nothing had internet. Opening the app showed the tunnel
     * already disconnected, and tapping connect fixed it. Two separate faults
     * produced that:
     *
     *  1. **Nothing noticed.** On the Psiphon and Tor paths the data plane is
     *     `tun2socks` + a tunnel process. If those die without the service being
     *     told — a Psiphon controller exit after a long doze, tun2socks unwinding
     *     on a network change, Tor's process being killed by the OEM's memory
     *     manager — no callback fires. `connected` stays true and the
     *     notification keeps its last text forever. (The Rust-core path is
     *     different: its `finally` block runs and reports FAILED.)
     *  2. **Nothing recovered.** Even where the failure *was* reported, the only
     *     response was to paint the UI red and wait for a human.
     *
     * ## Shape
     *
     * A 30-second poll — the cheapest thing that can detect case 1 at all, and
     * ~2,900 wakeups over 24 hours of connection, which is inside the budget for
     * a foreground VPN service that is already holding a TUN. It only asks
     * questions that are free (are these threads/processes alive) and never
     * touches the network, so a doze-suppressed tick costs nothing.
     *
     * Deliberately **not** an HTTP health check: our own package is off the TUN
     * (`addDisallowedApplication`), so a probe from here rides the carrier link
     * and proves nothing about the tunnel — the same trap documented in
     * `openTunnelConnection`. Process liveness is the honest signal available in
     * the service.
     */
    private fun startWatchdog() {
        watchdogTask?.cancel(false)
        reconnectAttempts = 0
        watchdogTask = ladderScheduler.scheduleWithFixedDelay({
            try {
                if (stopRequested.get() || userInitiatedStop.get()) return@scheduleWithFixedDelay
                if (!connected.get()) return@scheduleWithFixedDelay
                val dead = tunnelIsDead() ?: return@scheduleWithFixedDelay
                ConnectionLog.record("Watchdog: $dead — reconnecting")
                onTunnelLost(dead)
            } catch (_: Exception) {
            }
        }, WATCHDOG_INTERVAL_S, WATCHDOG_INTERVAL_S, TimeUnit.SECONDS)
    }

    private fun stopWatchdog() {
        watchdogTask?.cancel(false)
        watchdogTask = null
    }

    /**
     * Reason the current data path is broken, or null when it looks healthy.
     *
     * Per-transport because each has a different thing that can die silently.
     * Everything checked here is a local liveness flag; nothing blocks.
     */
    private fun tunnelIsDead(): String? {
        // Whole-device routing is common to Psiphon, the chain and Tor. Without
        // it, packets from the TUN reach nothing regardless of tunnel state.
        val needsRouting = psiphonVpnMode || currentProtocol.contains("TOR")
        if (needsRouting && !Tun2SocksManager.isRunning) return "device routing stopped"

        if (currentProtocol.contains("TOR")) {
            if (!TorManager.isRunning) return "the Tor process exited"
            if (!TorSocksFront.isRunning) return "the Tor front-end stopped"
            // Tor over WARP: tor stays alive when the outer leg dies, but every
            // circuit it holds is dead, so tor's own liveness is not enough here.
            // Checked last so a plainer cause is reported in preference to this.
            if (chainMode && !NativeCore.isRunning()) return "the WARP leg carrying Tor stopped"
            return null
        }
        if (psiphonVpnMode && psiphonTunnel == null) return "the Psiphon tunnel is gone"
        return null
    }

    /**
     * Tear the dead session down and schedule its replacement.
     *
     * Runs on [ladderScheduler]; [stopTunnel] and [startTunnel] are both safe off
     * the main thread, and `teardownService = false` keeps the foreground service
     * (and therefore the notification and the VPN permission) alive across the
     * gap so the reconnect does not have to re-prompt the user.
     */
    private fun onTunnelLost(reason: String) {
        if (!autoReconnectEnabled()) {
            ConnectionLog.record("Auto reconnect is off — leaving the tunnel down")
            sendStatus(STATUS_FAILED, reason)
            connected.set(false)
            stopTunnel(notify = false)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        stopWatchdog()
        connected.set(false)
        stopTunnel(notify = false, teardownService = false)
        scheduleAutoReconnect(reason)
    }

    /**
     * Re-dial after a backoff, until it works or the user intervenes.
     *
     * Backoff is 5s, 15s, 30s, 60s, then 120s forever. Capped rather than
     * abandoned: the overnight case this exists for is a phone that lost its
     * data connection entirely, and the correct behaviour when service returns
     * three hours later is still to reconnect. A 2-minute ceiling costs one
     * wakeup per two minutes while offline, which is less than the OS already
     * spends retrying its own connectivity checks.
     */
    private fun scheduleAutoReconnect(reason: String) {
        if (userInitiatedStop.get()) return
        val config = storedConfig
        if (config == null) {
            ConnectionLog.record("Auto reconnect: no stored config; giving up")
            return
        }
        val delay = RECONNECT_BACKOFF_S[
            reconnectAttempts.coerceAtMost(RECONNECT_BACKOFF_S.size - 1)
        ]
        reconnectAttempts++
        // The UI is told CONNECTING, not FAILED: from the user's point of view the
        // app is working on it, and painting the dial red for a recovery that is
        // about to happen on its own is the wrong report.
        sendStatus(STATUS_CONNECTING, "Reconnecting after $reason…")
        ConnectionLog.record("Auto reconnect #$reconnectAttempts in ${delay}s")
        reconnectTask?.cancel(false)
        reconnectTask = ladderScheduler.schedule({
            try {
                if (userInitiatedStop.get() || connected.get()) return@schedule
                startTunnel(config)
            } catch (e: Exception) {
                ConnectionLog.record("Auto reconnect failed to start: ${e.message}")
                scheduleAutoReconnect("start failure")
            }
        }, delay, TimeUnit.SECONDS)
    }

    private fun cancelAutoReconnect() {
        reconnectTask?.cancel(false)
        reconnectTask = null
        stopWatchdog()
        reconnectAttempts = 0
    }

    private fun autoReconnectEnabled(): Boolean =
        getSharedPreferences("settings", MODE_PRIVATE)
            .getBoolean(AUTO_RECONNECT_PREF, AUTO_RECONNECT_DEFAULT)

    /**
     * Whether a dropped tunnel will be picked back up automatically.
     *
     * Both conditions matter: the feature must be on, and the user must not have
     * asked for the disconnect. Used to decide whether a drop is reported as a
     * failure (red dial, session over) or as a reconnect in progress.
     */
    private fun willAutoReconnect(): Boolean =
        autoReconnectEnabled() && !userInitiatedStop.get() && storedConfig != null

    /**
     * Records that the current PLAIN transport reached the internet on this network.
     *
     * Only meaningful for the three transports the chain can use as its outer leg,
     * and only for an unchained run — inside the chain the byte counters belong to
     * Psiphon, and [raiseOuterLeg] already records that case directly and more
     * precisely.
     *
     * The threshold is deliberately the same 4 KiB the app's own verification gate
     * uses ([VERIFIED_RX_BYTES], mirroring MainActivity.VERIFY_MIN_RX_BYTES), and it
     * is on **RX only**:
     *
     *  - TX proves nothing. A dead or size-blind tunnel still sends: retransmits
     *    leave, the WireGuard health probe leaves, and none of it comes back. Every
     *    fake-connected bug in this project's history looked healthy on TX.
     *  - The floor must clear the core's own keepalive drip. The 3-second WireGuard
     *    data-plane probe pushes a few hundred bytes through a completely dead
     *    tunnel, so `rx > 0` would happily record a transport that carries nothing.
     *
     * Latches per session via [plainTransportRecorded] so this is one boolean test
     * per traffic sample once it has fired, not a SharedPreferences write per second.
     */
    private fun recordWorkingPlainTransport(rx: Long) {
        if (plainTransportRecorded) return
        if (chainMode || psiphonVpnMode) return
        if (rx < VERIFIED_RX_BYTES) return
        val transport = currentProtocol.lowercase()
        if (transport !in CoreConfig.CHAIN_OUTER_LADDER) return
        plainTransportRecorded = true
        getSharedPreferences("settings", MODE_PRIVATE).edit()
            .putString(CoreConfig.PLAIN_WORKING_TRANSPORT_PREF, transport)
            .apply()
        ConnectionLog.record(
            "$currentProtocol carried real traffic on this network — " +
                "Psiphon-over-WARP will try it first"
        )
    }

    /**
     * Try each WARP transport in turn until one is carrying traffic.
     *
     * Returns the label of the transport that came up, or null when none did.
     *
     * Starts from the rung with the best evidence for this network, then wraps, so
     * every rung still gets a turn but the likeliest one goes first. That matters
     * more here than in the Psiphon ladder: a rung the carrier blocks outright does
     * not fail fast — MASQUE keeps scanning gateways until its budget expires — so a
     * wrong starting rung costs the user most of a minute.
     *
     * Evidence is ranked, strongest first:
     *
     *  1. [CoreConfig.CHAIN_OUTER_PREF] — a transport that has carried Psiphon
     *     inside it before. Direct evidence about the exact job at hand.
     *  2. [CoreConfig.PLAIN_WORKING_TRANSPORT_PREF] — a transport that reached the
     *     internet unchained on this carrier. Weaker (carrying Psiphon is harder
     *     than carrying ordinary traffic, so this can still fail) but far better
     *     than a static order, and it is the common case for a user who used the
     *     app normally before arming the chain.
     *  3. Ladder order — a fresh install with no history at all starts at MASQUE and
     *     walks the usual sequence.
     *
     * Each rung gets its own budget (see [chainOuterBudgetMs]) and the core is fully
     * stopped between attempts: `aether_start_json` refuses to run twice
     * concurrently (its RUNNING compare_exchange returns "already running"), so the
     * next rung would fail instantly if the previous one were still unwinding.
     */
    private fun raiseOuterLeg(inner: String = "Psiphon"): String? {
        // Auto gives the whole ladder; a pinned transport gives just that one, with
        // no fallback — a pin exists to stop the app spending a minute on transports
        // the user already knows their carrier blocks.
        //
        // Tor and Psiphon read separate pins: the same outer leg suits them
        // differently, and the settings screen offers each its own row.
        val forTor = inner == "Tor"
        val ladder = CoreConfig.chainOuterCandidates(this, forTor)
        val auto = ladder.size > 1
        val prefs = getSharedPreferences("settings", MODE_PRIVATE)
        // -1, not 0: absent must be distinguishable from "rung 0 worked", or a fresh
        // install would look like it had already proven MASQUE and the plain-history
        // hint below would never be consulted.
        val chainMemory = prefs.getInt(CoreConfig.CHAIN_OUTER_PREF, -1)
        val plainHint = prefs.getString(CoreConfig.PLAIN_WORKING_TRANSPORT_PREF, null)
            ?.let { ladder.indexOf(it) }
            ?.takeIf { it >= 0 }
        // The remembered index is into the full ladder, so it only means anything
        // when the full ladder is what we are walking.
        val start = when {
            !auto -> 0
            chainMemory in ladder.indices -> chainMemory
            plainHint != null -> plainHint
            else -> 0
        }

        if (!auto) {
            ConnectionLog.record(
                "Chain: outer transport pinned to ${CoreConfig.chainOuterLabel(ladder[0])}"
            )
        } else if (chainMemory !in ladder.indices && plainHint != null) {
            // Say which evidence was used. Without this the reordering is invisible
            // and a support log cannot distinguish it from the static order.
            ConnectionLog.record(
                "Chain: no chained history yet — starting with " +
                    "${CoreConfig.chainOuterLabel(ladder[plainHint])}, which last carried " +
                    "real traffic on its own"
            )
        }

        for (offset in ladder.indices) {
            if (stopRequested.get()) return null
            val index = (start + offset) % ladder.size
            val protocol = ladder[index]
            val label = CoreConfig.chainOuterLabel(protocol)
            val budget = chainOuterBudgetMs(protocol)

            // The core must be fully idle before this rung starts. If a previous
            // rung is still unwinding, `startProxy` returns "already running"
            // immediately while `isRunning`/`isReady` still describe the OLD tunnel
            // — so awaitOuterProxy would accept a rung that never started. Refusing
            // to continue is the only safe answer; the alternative is handing the
            // inner leg a proxy backed by a tunnel that is being torn down.
            if (NativeCore.isRunning()) {
                ConnectionLog.record("Chain: core still busy; cannot start the $label leg")
                return null
            }

            ConnectionLog.record(
                "Chain leg 1/2 attempt ${offset + 1}/${ladder.size}: " +
                    "$label → SOCKS ${CoreConfig.CHAIN_SOCKS_PORT} (${budget / 1000}s budget)"
            )
            sendStatus(STATUS_CONNECTING, "Connecting $label…")

            val config = CoreConfig.chainOuterJson(this, protocol)
            val started = runCatching {
                // Provisions or loads this protocol's identity. MASQUE and WireGuard
                // keep separate ones, and a failure here (a refused registration, no
                // network) is this rung's failure, not the chain's.
                NativeCore.prepare(config)
                Thread({
                    // Guarded for the same reason as the Tor front proxy's relay
                    // threads: this is a bare thread, so anything escaping it goes
                    // to the default handler and takes the process down instead of
                    // failing this one rung.
                    try {
                        val result = NativeCore.startProxy(config)
                        if (result != 0 && !stopRequested.get()) {
                            val detail = NativeCore.lastError()
                                .ifBlank { "exited with code $result" }
                            ConnectionLog.record("Chain: $label leg ended: $detail")
                            // Only a failure once this rung was the accepted one is the
                            // chain's failure. Before that, ending is how a rung is
                            // rejected and raiseOuterLeg moves on — reporting FAILED
                            // there would abort the ladder on its first miss.
                            if (chainOuterCommitted) {
                                failAndStop("The $label tunnel carrying $inner dropped")
                            }
                        }
                    } catch (t: Throwable) {
                        ConnectionLog.record("Chain: $label leg threw: ${t.message}")
                        if (chainOuterCommitted && !stopRequested.get()) {
                            failAndStop("The $label tunnel carrying $inner dropped")
                        }
                    }
                }, "chain-outer-$protocol").start()
            }.isSuccess

            if (!started) {
                ConnectionLog.record("Chain: $label could not be prepared: ${NativeCore.lastError()}")
                stopOuterLeg()
                continue
            }

            if (awaitOuterProxy(budget)) {
                // Remember what worked, so the next automatic connect starts here.
                // Only meaningful for the full ladder: with a pin there is one entry
                // and the index would refer to the wrong transport later.
                if (auto) {
                    getSharedPreferences("settings", MODE_PRIVATE).edit()
                        .putInt(CoreConfig.CHAIN_OUTER_PREF, index).apply()
                }
                chainOuterCommitted = true
                ConnectionLog.record("Chain: $label is carrying the outer leg")
                return label
            }

            if (stopRequested.get()) return null
            if (auto) {
                ConnectionLog.record(
                    "Chain: $label did not come up in ${budget / 1000}s; trying the next transport"
                )
            } else {
                // A pin has nothing to fall back to, by design.
                ConnectionLog.record(
                    "Chain: $label did not come up in ${budget / 1000}s and it is pinned; " +
                        "switch the outer transport to Auto in settings to try the others"
                )
            }
            stopOuterLeg()
        }
        return null
    }

    /**
     * How long a given outer transport gets before the chain moves on.
     *
     * Not uniform, because their failure modes are not. MASQUE does not fail fast
     * when blocked — it keeps scanning gateways until its own budget runs out — so
     * its number is a cap on that scan rather than a timeout on a dial. WireGuard
     * either handshakes quickly or is being dropped. WoW has to raise two tunnels
     * in sequence, so it needs the most.
     *
     * The totals matter: worst case is the sum, spent only on the first connect
     * from a SIM whose usual transport is blocked, since the winner is remembered.
     */
    private fun chainOuterBudgetMs(protocol: String): Long = when (protocol) {
        "masque" -> 50_000L
        "wireguard" -> 40_000L
        else -> 60_000L
    }

    /**
     * Stop the outer leg and wait for the core to actually let go.
     *
     * `aether_stop` only sets a flag; RUNNING stays true until the tunnel task
     * unwinds and drops its guard. Starting the next rung before that returns
     * "Aether tunnel already running" and the rung fails for the wrong reason.
     */
    private fun stopOuterLeg() {
        NativeCore.stop()
        val deadline = SystemClock.elapsedRealtime() + OUTER_STOP_GRACE_MS
        while (NativeCore.isRunning() && SystemClock.elapsedRealtime() < deadline) {
            try {
                Thread.sleep(200)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
        }
        if (NativeCore.isRunning()) {
            ConnectionLog.record("Chain: previous outer leg is still shutting down")
        }
    }

    /**
     * Wait until the outer leg is genuinely ready to carry Psiphon.
     *
     * Gated on `aether_is_ready()`, NOT on the SOCKS port accepting a connection.
     * That distinction is the whole point: `socks::serve` binds its listener as soon
     * as the userspace netstack exists, before the tunnel behind it is validated, so
     * a port probe returns true almost immediately and would hand Psiphon a proxy
     * with nothing behind it. READY is set by `mark_ready()`, which the core only
     * calls once its data path is up — for MASQUE after data-plane validation, for
     * WoW after both legs are established.
     *
     * The port is then checked as well, since a ready tunnel with an unbound
     * listener would still fail Psiphon's UpstreamProxyURL validation.
     */
    private fun awaitOuterProxy(budgetMs: Long): Boolean {
        val startedAt = SystemClock.elapsedRealtime()
        val deadline = startedAt + budgetMs
        while (SystemClock.elapsedRealtime() < deadline) {
            if (stopRequested.get()) return false
            // A dead rung stops the core outright, so there is nothing left to wait
            // for — but only after it has had time to set RUNNING at all. The caller
            // has just spawned startProxy on another thread, and treating that gap as
            // "the rung died" would reject every rung the instant it was started.
            val elapsed = SystemClock.elapsedRealtime() - startedAt
            if (elapsed > OUTER_START_GRACE_MS && !NativeCore.isRunning()) return false
            if (NativeCore.isReady() && outerProxyAccepts()) return true
            try {
                Thread.sleep(300)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
        }
        return false
    }

    /** Whether the core's chained SOCKS listener is accepting connections. */
    private fun outerProxyAccepts(): Boolean = runCatching {
        java.net.Socket().use { probe ->
            probe.connect(
                java.net.InetSocketAddress("127.0.0.1", CoreConfig.CHAIN_SOCKS_PORT),
                1_000,
            )
        }
    }.isSuccess

    /**
     * Start a tunnel. Always whole-device VPN mode — proxy mode was removed, so
     * there is no longer a `vpnMode` parameter to branch on.
     */
    private fun startTunnel(config: String) {
        if (!connected.compareAndSet(false, true)) return
        // A start supersedes any pending retry, whoever asked for it.
        reconnectTask?.cancel(false)
        reconnectTask = null
        nativeExitWasUnexpected = false
        storedConfig = config
        currentProtocol = config.substringAfter("\"protocol\":\"").substringBefore('"').uppercase()
        currentVpnIp = ""
        // The country belongs to the session that just ended. Left set, the
        // notification would label a fresh tunnel with the previous exit's
        // country until something overwrote it.
        currentCountry = ""
        // The previous tunnel's exit belongs to the previous tunnel. Cleared here
        // as well as in stopTunnel because a reconnect goes straight from one
        // startTunnel to the next, and a stale address would otherwise be handed
        // to the UI as this session's measurement.
        lastExitIp = ""
        currentPing = ""
        // Every new tunnel makes the core start counting bytes from zero again
        // (rx_total/tx_total are locals inside tun::bridge). Anything here that
        // still holds the previous session's totals would then be compared
        // against a counter that just went backwards, so it all has to be reset
        // together, before the first sample of the new session arrives.
        resetSessionTraffic()
        stopRequested.set(false)
        vpnModeActive.set(true)
        // Belt and braces with the clear in stopTunnel(): a reconnect goes straight
        // from one startTunnel to the next without necessarily passing through the
        // teardown path, and these two flags decide whether this session counts as
        // "plain" for recordWorkingPlainTransport(). The branches below set them
        // again for the Psiphon and chained paths.
        chainMode = false
        psiphonVpnMode = false
        startAsForeground()

        // PSIPHON-OVER-WARP must be tested before the plain PSIPHON branch: its
        // protocol name contains "PSIPHON" too, so the order of these checks is
        // what keeps the chain from being started as an ordinary Psiphon tunnel.
        if (currentProtocol.contains(CHAIN_PROTOCOL_MARKER)) {
            startChainTunnel()
            return
        }

        // TOR is checked before PSIPHON only for symmetry with the chain marker
        // above; "TOR" and "PSIPHON" do not overlap as substrings, so the order
        // between these two is not load-bearing.
        if (currentProtocol.contains("TOR")) {
            startTorTunnel()
            return
        }

        // PSIPHON: callback-driven lifecycle — MUST NOT enter try/finally.
        // The finally block calls stopSelf() which destroys the service and kills Psiphon.
        if (currentProtocol.contains("PSIPHON")) {
            psiphonVpnMode = true  // Read by onConnected() to start tun2socks
            psiphonVpnActivated = false
            // Start from the rung that last worked on this device. On the first
            // ever connect, or after a full ladder failure, this is rung 0.
            // chainMode is false on this path, so both the ladder and the key are
            // the unchained ones.
            ladderIndex = rememberedRungIndex()
            ladderAttempts = 0
            armRegionPhase()
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
                        // Split tunnelling was ignored on this path: it only ever
                        // excluded our own package, so a user who picked apps in the
                        // Split screen and then connected with Psiphon silently got
                        // every app tunnelled. applySplitTunneling() honours the
                        // choice and still keeps our own process off the TUN in every
                        // mode — which the DNS bootstrap above depends on.
                        .applySplitTunneling()
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

                // Did the tunnel end on its own, i.e. without the user asking?
                // That is the case auto-reconnect exists for, and it has to be
                // decided here where the exit reason is still known.
                val diedOnItsOwn = !stopRequested.get()
                if (result != 0 && !stopRequested.get()) {
                    val detail = NativeCore.lastError().ifBlank { "Tunnel exited with code $result" }
                    ConnectionLog.record("Native tunnel exited: $detail")
                    if (!willAutoReconnect()) sendStatus(STATUS_FAILED, detail)
                } else if (stopRequested.get()) {
                    sendStatus(STATUS_DISCONNECTED)
                } else {
                    ConnectionLog.record("Native tunnel stopped unexpectedly")
                    if (!willAutoReconnect()) sendStatus(STATUS_FAILED, "Tunnel stopped unexpectedly")
                }
                nativeExitWasUnexpected = diedOnItsOwn
            } catch (error: Exception) {
                val detail = NativeCore.lastError().ifBlank { error.message ?: "Tunnel setup failed" }
                Log.e(LOG_TAG, "Tunnel failed: $detail", error)
                sendStatus(STATUS_FAILED, detail)
                // A setup failure is not a dropped tunnel: there is nothing to
                // restore, and retrying a config Android or the core rejected
                // would loop. Reported and left to the user.
                nativeExitWasUnexpected = false
            } finally {
                NativeCore.detach()
                vpnModeActive.set(false)
                TunnelStatus.isNativeTunMode = false
                // The native tunnel can end without stopTunnel() ever running —
                // the core exiting on its own, or the kill-switch branch below,
                // both land here instead. stopTunnel() is where the monthly
                // counters are normally persisted, so without this the traffic
                // since the last 60-second flush was lost on exactly the paths
                // that end a session unexpectedly.
                flushMonthlyTraffic()
                val killSwitch = getSharedPreferences("settings", MODE_PRIVATE).getBoolean("kill_switch", false)
                tun?.close()
                tun = null
                connected.set(false)
                if (killSwitch && !stopRequested.get()) {
                    ConnectionLog.record("Kill switch active; blocking all traffic")
                    sendStatus(STATUS_FAILED, "Kill switch active — tunnel dropped")
                    rebuildKillSwitchVpn()
                } else if (nativeExitWasUnexpected && willAutoReconnect()) {
                    // The core died on its own and the user still wants to be
                    // connected. Keep the foreground service alive so the retry
                    // does not need a fresh VPN consent dialog.
                    nativeExitWasUnexpected = false
                    scheduleAutoReconnect("the tunnel dropped")
                } else {
                    nativeExitWasUnexpected = false
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }


    private fun stopTunnel(notify: Boolean = true, teardownService: Boolean = true) {
        stopRequested.set(true)
        // The watchdog must go first: it is what turns a teardown into a
        // reconnect, and leaving it armed while we dismantle the data path would
        // make it fire on the wreckage of a session that is deliberately ending.
        stopWatchdog()
        stopTorProgressPolling()
        // The traffic counters are only flushed to disk on a slow timer while
        // running, so an ordinary disconnect must persist the remainder here or
        // the last minute of the session would be lost from the monthly total.
        flushMonthlyTraffic()
        // Clear the session stamp here, not in sendStatus: the reconnect path and
        // onDestroy both call stopTunnel(notify = false), so relying on the
        // DISCONNECTED broadcast left connectedSince set and the next session's
        // timer resumed the old elapsed time instead of restarting at zero.
        connectedSince = 0L
        // No tunnel, no exit address. Leaving it set would let the next UI start
        // paint a dead tunnel's exit as if it were live.
        lastExitIp = ""
        // Disarm the escalation ladder before anything else: a pending timer that
        // fires after teardown would resurrect Psiphon on a dead TUN.
        ladderActive.set(false)
        cancelLadderTimer()
        // A stale region phase would apply the country filter to the *next*
        // connect's first attempt even after the user set the picker back to Auto.
        regionPhase = false
        // Order matters: stop routing first so no more packets enter a tunnel
        // that is being torn down, then stop Psiphon itself.
        Tun2SocksManager.stop()
        stopTrafficPolling()
        TorManager.stop()
        stopPsiphonTunnel()
        NativeCore.stop()
        TunnelStatus.isNativeTunMode = false

        if (psiphonVpnMode) {
            // In VPN mode nothing else owns the service lifecycle now that the
            // Rust core is out of the data path, so tear down here.
            //
            // This also covers Psiphon-over-WARP: NativeCore.stop() above ends the
            // outer WARP leg, and chainMode must be cleared here so the next
            // buildPsiphonConfig() does not attach an UpstreamProxyURL pointing at
            // a listener that no longer exists.
            NativeCore.detach()
            chainMode = false
            chainOuterCommitted = false
            vpnModeActive.set(false)
            // Cleared with the rest of the per-session Psiphon state. It used to be
            // left set, which was harmless only because nothing read it after
            // teardown — recordWorkingPlainTransport() now does, and a stale `true`
            // would make every later plain MASQUE/WireGuard session look like a
            // Psiphon one and never record the transport that actually worked.
            psiphonVpnMode = false
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

        if (currentProtocol.contains("TOR")) {
            // Tor owns its own lifecycle the same way: everything to unwind lives in
            // TorManager/Tun2SocksManager, both already stopped above. All that is
            // left is the outer leg's bookkeeping, the TUN and the service.
            if (chainMode) {
                // Tor over WARP did attach the core, so it must detach — unlike the
                // unchained Tor path, where attach/detach never ran. NativeCore.stop()
                // above already ended the outer leg; without the detach the next
                // connect starts with a core still bound to a dead service.
                NativeCore.detach()
                chainMode = false
                chainOuterCommitted = false
            }
            vpnModeActive.set(false)
            tun?.close()
            tun = null
            connected.set(false)
            if (notify) sendStatus(STATUS_DISCONNECTED)
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

    /**
     * Post the current notification content once.
     *
     * Every caller is a real state change (connected, protocol resolved, country
     * learned) — never a timer. See [updateTrafficNotification] for why nothing
     * periodic is allowed to call this.
     */
    private fun repostNotification() {
        try {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION_ID, notification())
        } catch (_: Exception) {
        }
    }

    private fun sendStatus(status: String, detail: String? = null, progress: Int = -1) {
        Log.i(LOG_TAG, "status=$status${detail?.let { " detail=$it" } ?: ""}")
        // Stamp the connect moment here rather than at each call site: there are
        // several paths to CONNECTED (native tunnel ready, Psiphon proxy ready,
        // tun2socks up, reconnect) and every one funnels through sendStatus.
        when (status) {
            STATUS_CONNECTED -> if (connectedSince == 0L) connectedSince = SystemClock.elapsedRealtime()
            STATUS_DISCONNECTED, STATUS_FAILED -> connectedSince = 0L
        }
        // Keep the last known figure across the many CONNECTING broadcasts that
        // carry no progress of their own, so a "Starting Tor…" message arriving
        // after "40%" does not visibly reset the percentage to nothing.
        if (progress >= 0) connectProgress = progress
        if (status == STATUS_CONNECTED || status == STATUS_DISCONNECTED || status == STATUS_FAILED) {
            connectProgress = -1
        }
        sendBroadcast(Intent(ACTION_STATUS)
            .setPackage(packageName)
            .putExtra(EXTRA_STATUS, status)
            .putExtra(EXTRA_PROGRESS, connectProgress)
            .apply { detail?.let { putExtra(EXTRA_DETAIL, it) } })
        TileService.requestListeningState(
            this,
            ComponentName(this, MsnGuardTileService::class.java),
        )
    }

    /**
     * Republish the current CONNECTING state with a new percentage.
     *
     * Used by the Tor bootstrap poller, which has a number but nothing new to
     * say in words. The detail text is left untouched by passing null, so the
     * line the user is reading ("trying Meek…") survives the update.
     */
    private fun publishProgress(percent: Int) {
        if (percent == connectProgress) return
        sendStatus(STATUS_CONNECTING, null, percent)
    }

    /**
     * Mirror Tor's own bootstrap percentage into the UI while it climbs.
     *
     * Tor reports 15 bootstrap notices per attempt and [TorManager] already
     * parses them into [TorManager.progress]; polling that field is cheaper than
     * threading a callback through the process reader, and one wakeup a second
     * on a screen the user is actively watching is not a battery concern — the
     * poller is cancelled the moment the connect resolves either way.
     */
    private fun startTorProgressPolling() {
        torProgressTask?.cancel(false)
        torProgressTask = ladderScheduler.scheduleAtFixedRate({
            try {
                if (stopRequested.get()) return@scheduleAtFixedRate
                val percent = TorManager.progress
                if (percent in 1..99) publishProgress(percent)
            } catch (_: Exception) {
            }
        }, 1L, 1L, TimeUnit.SECONDS)
    }

    private fun stopTorProgressPolling() {
        torProgressTask?.cancel(false)
        torProgressTask = null
    }

    private fun updateTrafficNotification(tx: Long, rx: Long) {
        val now = SystemClock.elapsedRealtime()
        // Throttle FIRST, before the rebase guard below.
        //
        // The order used to be the other way round, and that was the monthly-total
        // inflation bug. The guard zeroes `accountedTx/Rx`; the throttle then
        // returned without recording anything. So any backwards sample that landed
        // inside the 900 ms window left the accounting baseline at zero, and the
        // next sample re-added the session's entire cumulative byte count to the
        // month. One dip every 30 s over an hour of browsing turned 0.17 GB of real
        // traffic into 10.4 GB — a 60x overstatement, which is what produced the
        // reported 230 GB month.
        //
        // Returning before touching any state is the fix: a throttled callback must
        // be a pure no-op. Backwards samples are still caught, just on a callback
        // that goes on to consume them.
        if (now - lastTrafficSampleMs < 900) return

        // The core's counters are per-tunnel locals, and the core reconnects on
        // its own (the MASQUE and WireGuard reconnect loops both re-enter
        // `tun::bridge`) without the service being told. When that happens the
        // numbers arriving here go backwards, and every derived figure below —
        // the speed delta and the monthly delta — would compute a large negative
        // or absurd value from a mismatched baseline. Rebase instead of trying to
        // subtract across the discontinuity.
        if (tx < prevTx || rx < prevRx || tx < accountedTx || rx < accountedRx) {
            prevTx = 0
            prevRx = 0
            accountedTx = 0
            accountedRx = 0
            prevSpeedSampleMs = 0
            currentSpeedTx = 0
            currentSpeedRx = 0
        }

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
        // A plain tunnel that has moved real bytes is evidence about this carrier
        // that the chain can reuse later. Cheap: a single boolean check on the
        // common path.
        recordWorkingPlainTransport(rx)
        sendTraffic(tx, rx, monthTx, monthRx)

        if (now - lastTrafficFlushMs >= TRAFFIC_FLUSH_MS) {
            flushMonthlyTraffic()
            lastTrafficFlushMs = now
        }

        // The notification is NOT reposted here any more.
        //
        // It used to be, every 5 seconds, because it carried live byte counters
        // and speeds. That was the lock-screen alarm the user reported: the row
        // is IMPORTANCE_DEFAULT (required, or MIUI's lock screen drops it as
        // "silent"), and on MIUI every *post* of a DEFAULT row pokes the ambient
        // display even with setOnlyAlertOnce and no sound or vibration on the
        // channel. A tunnel left connected overnight therefore woke the screen
        // 720 times an hour.
        //
        // With the counters gone from the text there is nothing left in it that
        // changes second to second: the elapsed time is drawn by SystemUI's own
        // chronometer (see [notification]), and protocol and country only change
        // when something real happens — each of which reposts once, from its own
        // call site. So the steady state is exactly zero posts.
        lastTrafficSampleMs = now
    }

    /**
     * Adds this sample to the monthly totals, in memory.
     *
     * The disk write is deliberately not here — see [flushMonthlyTraffic] and the
     * fields it persists. The date is also only formatted when the month is not
     * already known, because building a SimpleDateFormat once a second to
     * re-derive the same string is waste in its own right.
     */
    private fun recordMonthlyTraffic(tx: Long, rx: Long): Pair<Long, Long> {
        // First sample of this process, or the month rolled over mid-session.
        loadMonthlyTotals()
        monthTxTotal += tx
        monthRxTotal += rx
        return monthTxTotal to monthRxTotal
    }

    private fun currentMonthKey(): String =
        java.text.SimpleDateFormat("yyyy-MM", java.util.Locale.US).format(java.util.Date())

    /** Loads the persisted monthly totals into memory, once per month key. */
    private fun loadMonthlyTotals() {
        val month = currentMonthKey()
        if (monthKey == month) return
        // The month just rolled over mid-session: persist what the old month
        // accumulated before its key is replaced. Without this, everything since
        // the last 60-second flush was silently dropped from the month that ended,
        // because `monthKey` is what flushMonthlyTraffic() writes under.
        if (monthKey != null) flushMonthlyTraffic()
        val prefs = getSharedPreferences(TRAFFIC_PREFS, MODE_PRIVATE)
        // Discard totals written by a build that had the inflation bug.
        //
        // Fixing the accounting does not fix the number already on disk: it was
        // overstated by roughly the number of throttled backwards samples, which
        // varies per device, so there is no honest factor to divide by. Zeroing
        // once is the only truthful option — the month restarts from a correct
        // baseline instead of carrying a figure nobody can interpret.
        //
        // Gated on a stored schema version, not on the app version, so it happens
        // exactly once ever rather than on every update from here on.
        if (prefs.getInt(TRAFFIC_SCHEMA, 0) < TRAFFIC_SCHEMA_VERSION) {
            // Was there actually anything to throw away? On a fresh install there
            // is not, and announcing "your total was miscounted" to someone who
            // has never had a total is both false and alarming — the line showed
            // up on the first line of every field log for that reason.
            val hadTotals = prefs.contains(TRAFFIC_TX) || prefs.contains(TRAFFIC_RX)
            prefs.edit()
                .putInt(TRAFFIC_SCHEMA, TRAFFIC_SCHEMA_VERSION)
                .remove(TRAFFIC_MONTH)
                .remove(TRAFFIC_TX)
                .remove(TRAFFIC_RX)
                // commit(), not apply(): this must be on disk before anything
                // else, because if the write is lost the discard runs again on the
                // next launch and the month restarts from zero a second time.
                .commit()
            monthTxTotal = 0
            monthRxTotal = 0
            monthKey = month
            if (hadTotals) {
                ConnectionLog.record("Monthly traffic counter reset — previous total was miscounted")
            }
            return
        }
        val stored = prefs.getString(TRAFFIC_MONTH, null)
        monthTxTotal = if (stored == month) prefs.getLong(TRAFFIC_TX, 0) else 0
        monthRxTotal = if (stored == month) prefs.getLong(TRAFFIC_RX, 0) else 0
        monthKey = month
    }

    /**
     * Clears everything that describes the *current session's* traffic.
     *
     * Called at the start of every tunnel. The core's counters are locals inside
     * `tun::bridge`, so each new tunnel restarts them at zero; every mirror of
     * them here has to restart too.
     *
     * This is what the connect/disconnect/connect failure came down to. The
     * activity's verification gate takes `rxAtStart = trafficRx` when the
     * transport reports CONNECTED and then waits for `trafficRx` to reach
     * `rxAtStart + VERIFY_MIN_RX_BYTES`. `trafficRx` is fed straight from
     * `currentRx` here, and neither was ever reset, so on the second connect of
     * a process the gate demanded that a counter starting from zero exceed the
     * *previous* session's final total. It never could, so verification always
     * timed out after 18s and the UI reported "handshake succeeded but nothing
     * passes" for a tunnel that was working. Force-stopping the app made the
     * first connect succeed again because fresh fields start at zero — which is
     * exactly the workaround that was being used.
     *
     * The monthly totals are deliberately NOT cleared: they are cumulative
     * across sessions. Only the per-session deltas reset, and `accountedTx/Rx`
     * going to zero is what keeps the monthly accounting correct — the next
     * sample's delta is measured from zero, matching the core's fresh counter.
     */
    private fun resetSessionTraffic() {
        // The month totals are read lazily on the first sample; make sure they are
        // loaded before broadcasting, or a reset before any traffic would tell the
        // UI the month total is zero and the traffic screen would blank out.
        loadMonthlyTotals()
        currentTx = 0
        currentRx = 0
        prevTx = 0
        prevRx = 0
        currentSpeedTx = 0
        currentSpeedRx = 0
        accountedTx = 0
        accountedRx = 0
        // Zeroed, not set to `now`: these are throttle stamps, and a fresh
        // session should publish its first sample immediately rather than wait
        // out a window inherited from the tunnel that just died.
        prevSpeedSampleMs = 0
        lastTrafficSampleMs = 0
        // Per-session latch: each tunnel gets one chance to prove its transport
        // works. Without this reset the flag would stay set for the life of the
        // process, so a later session on a different transport (or a different
        // network) would never record what actually worked.
        plainTransportRecorded = false
        // The UI keeps its own mirrors, and it cannot know the core restarted
        // counting unless it is told. Without this broadcast the activity would
        // hold the old totals until the first traffic sample of the new session,
        // and the verification baseline is taken before that arrives.
        sendTraffic(0, 0, monthTxTotal, monthRxTotal)
    }

    /**
     * Writes the in-memory monthly totals to disk.
     *
     * Called on a slow timer from the traffic path and unconditionally on
     * teardown, so an ordinary disconnect always persists an exact figure.
     */
    private fun flushMonthlyTraffic() {
        val month = monthKey ?: return
        getSharedPreferences(TRAFFIC_PREFS, MODE_PRIVATE).edit()
            .putString(TRAFFIC_MONTH, month)
            .putLong(TRAFFIC_TX, monthTxTotal)
            .putLong(TRAFFIC_RX, monthRxTotal)
            .apply()
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

    /**
     * Broadcasts the core-measured exit address to the UI.
     *
     * Address only. The country is a geolocation question, which the UI answers
     * over whatever link it has — the answer for a given address is the same
     * either way, so it does not need to be asked from inside the tunnel.
     */
    private fun sendExitIp(ip: String) {
        sendBroadcast(Intent(ACTION_STATUS)
            .setPackage(packageName)
            .putExtra(EXTRA_EXIT_IP, ip))
    }

    private fun startAsForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        ensureNotificationChannel(manager)
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Connecting…")
            .setContentText(prettyProtocol())
            .setSmallIcon(R.drawable.ic_notification)
            .setLargeIcon(appBadge())
            .setColor(NOTIFICATION_ACCENT)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setOnlyAlertOnce(true)
            // No elapsed time yet, and a "0 seconds ago" stamp on a connect
            // attempt is noise.
            .setShowWhen(false)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    /**
     * Create the notification channel so the row survives on the lock screen.
     *
     * Why the old channel did not: it was `IMPORTANCE_LOW`, which Android files as
     * a *silent* notification, and the lock screen's own filter ("Show sensitive /
     * Don't show silent notifications", plus the equivalent on MIUI/EMUI/One UI)
     * drops silent rows entirely on many devices. That is the difference the user
     * sees against other VPN apps: it is the importance class, not the content.
     *
     * So the channel is `IMPORTANCE_DEFAULT` — the alerting class, which the lock
     * screen keeps — with sound and vibration explicitly removed. Alerting without
     * noise is the combination a VPN status row wants; raising importance alone
     * would have made it beep.
     *
     * `lockscreenVisibility = PUBLIC` is the second half: with `PRIVATE` (the
     * default) a device set to hide sensitive content shows "Contents hidden"
     * instead of the status. Nothing here is sensitive — app name, protocol,
     * byte counters — and hiding it defeats the purpose of the request.
     *
     * Battery cost of all this: zero. It changes how an already-posted
     * notification is classified, not how often it is posted.
     */
    private fun ensureNotificationChannel(manager: NotificationManager) {
        // Visibility and importance are frozen at creation time, so the old
        // channel can never be upgraded in place — it is removed instead. Harmless
        // when it was never created (fresh install).
        try { manager.deleteNotificationChannel(CHANNEL_ID_LEGACY) } catch (_: Exception) {}
        val channel = NotificationChannel(
            CHANNEL_ID,
            "VPN Service",
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setSound(null, null)
            enableVibration(false)
            enableLights(false)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    /**
     * The ongoing status notification.
     *
     * Takes no traffic figures: byte counters and speeds were removed from the
     * text (see [updateTrafficNotification]), which is what allows the row to be
     * posted only on real state changes instead of every few seconds.
     */
    private fun notification(): Notification {
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

        // Second line: what is carrying the traffic and where it comes out.
        // Byte counters and speed are deliberately gone from here — see
        // [updateTrafficNotification] for why they were the cause of the
        // lock-screen wakeups, not just clutter.
        val method = prettyProtocol()
        val subtitle = if (currentCountry.isNotBlank()) "$method • $currentCountry" else method

        val builder = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("VPN connected")
            .setContentText(subtitle)
            .setSmallIcon(R.drawable.ic_notification)
            .setLargeIcon(appBadge())
            // Tints the small icon and the header text in the app's own accent,
            // which is what makes the row read as MSN-GUARD's at a glance.
            .setColor(NOTIFICATION_ACCENT)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            // Same reasoning as the channel: nothing here is sensitive, and PRIVATE
            // would render "Contents hidden" on a device that hides sensitive
            // content — the exact case the user is complaining about.
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setOnlyAlertOnce(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectPendingIntent)
            .addAction(android.R.drawable.ic_menu_revert, "Reconnect", reconnectPendingIntent)

        // The session timer, ticked by the system rather than by us.
        //
        // This is the whole fix for the lock-screen buzzing. Putting an elapsed
        // time in the text would mean re-posting the notification every second,
        // and on MIUI/EMUI every post of an IMPORTANCE_DEFAULT row wakes the
        // ambient display even with setOnlyAlertOnce — which is exactly what the
        // user saw. setUsesChronometer hands the clock to SystemUI: it counts up
        // on its own from `when`, forever, with zero further posts from us.
        //
        // `when` is derived by mapping the elapsedRealtime stamp we already keep
        // onto wall-clock time; using System.currentTimeMillis() directly would
        // restart the displayed timer on every repost.
        if (connectedSince > 0L) {
            val elapsed = SystemClock.elapsedRealtime() - connectedSince
            builder.setWhen(System.currentTimeMillis() - elapsed)
                .setUsesChronometer(true)
                .setShowWhen(true)
        } else {
            builder.setShowWhen(false)
        }

        return builder.build()
    }

    /**
     * Human-readable transport name for the notification.
     *
     * [currentProtocol] is upper-cased raw config text ("PSIPHON-OVER-WARP",
     * "TOR", "MASQUE"), which is right for substring matching and wrong for a
     * user-facing line. For Tor it also names the transport that actually
     * carried the circuit, because "Tor" alone hides the difference between a
     * direct connection and one riding a Snowflake proxy.
     *
     * Tor over WARP has no marker in [currentProtocol] — the chain is decided from
     * the preference, not the config string — so [chainMode] is what distinguishes
     * it here.
     */
    private fun prettyProtocol(): String = when {
        currentProtocol.contains(CHAIN_PROTOCOL_MARKER) -> "Psiphon over WARP"
        currentProtocol.contains("TOR") -> {
            val mode = TorManager.activeMode?.let { " (${it.label})" } ?: ""
            if (chainMode) "Tor$mode over WARP" else "Tor$mode"
        }
        currentProtocol.contains("PSIPHON") -> "Psiphon"
        currentProtocol.contains("MASQUE") -> "MASQUE"
        currentProtocol.contains("WIREGUARD") -> "WireGuard"
        currentProtocol.contains("GOOL") -> "WARP-on-WARP"
        currentProtocol.isBlank() -> "Tunnel"
        else -> currentProtocol.lowercase().replaceFirstChar { it.uppercase() }
    }

    /**
     * The app's launcher artwork as a round, full-colour notification badge.
     *
     * Rendered here rather than handed to the system as
     * `Icon.createWithResource(R.mipmap.ic_launcher)` because that resource is an
     * adaptive icon: launchers apply a mask to it, but `setLargeIcon` does not,
     * so on several OEM shells it lands as an unmasked square with the
     * background plate showing at the corners. Compositing background+foreground
     * into a circular bitmap ourselves gives the same round badge on every
     * device.
     *
     * Cached: this is a 128 px bitmap draw, and rebuilding it on every repost
     * would be pure waste on a row that is posted for hours.
     */
    private fun appBadge(): android.graphics.drawable.Icon {
        cachedBadge?.let { return it }
        val size = (resources.displayMetrics.density * 48f).toInt().coerceAtLeast(96)
        val bitmap = android.graphics.Bitmap.createBitmap(
            size, size, android.graphics.Bitmap.Config.ARGB_8888
        )
        val canvas = android.graphics.Canvas(bitmap)

        // Circular clip first, so both layers are trimmed identically.
        val clip = android.graphics.Path().apply {
            addCircle(size / 2f, size / 2f, size / 2f, android.graphics.Path.Direction.CW)
        }
        canvas.clipPath(clip)

        // Adaptive-icon geometry: the artwork is authored on a 108dp canvas of
        // which the inner 72dp is the guaranteed-visible area, i.e. the layers
        // are drawn 1.5x oversized and centred. Reproducing that scale is what
        // keeps the neon ring from being cropped.
        val inset = (-size * 0.25f).toInt()
        val bounds = android.graphics.Rect(inset, inset, size - inset, size - inset)
        listOf(R.drawable.msnguard_icon_bg, R.drawable.msnguard_icon_fg).forEach { id ->
            getDrawable(id)?.apply {
                setBounds(bounds)
                draw(canvas)
            }
        }
        return android.graphics.drawable.Icon.createWithBitmap(bitmap)
            .also { cachedBadge = it }
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
     * One formatter, reused.
     *
     * SimpleDateFormat is not thread-safe, which is why the usual advice is to make
     * a new one per call — but every write here is already inside a @Synchronized
     * block, so one instance is safe and saves an object plus its parsed pattern on
     * every line. That matters because a single Psiphon connect produces several
     * hundred lines in under two seconds.
     */
    private val stamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)

    /**
     * Psiphon notices that are pure bookkeeping.
     *
     * These are not merely noise to read past — they were actively destructive. A
     * single connect emits one `updated server <id>` line per server entry (430 of
     * them in the field log, plus a second wave after the tunnel comes up), and the
     * ring buffer holds 100 entries. Every genuinely useful line — which strategy
     * ran, which country was preferred, why a rung failed — was evicted before the
     * user could ever see it, and each line also cost a JNI hop and a separate file
     * append.
     *
     * Dropped by prefix rather than by log level so the interesting warnings and
     * errors from the same subsystem still arrive.
     */
    private val NOISE = listOf(
        "\"message\":\"updated server ",
        "\"message\":\"Memory metrics at ",
        "\"message\":\"Datastore metrics at ",
        "\"message\":\"DNS metrics at ",
        "\"message\":\"ServerEntryIterator.reset:",
        "\"message\":\"Awaited ScanServerEntries:",
        "\"message\":\"Set dial parameters for ",
        "\"message\":\"port forward failures for ",
    )

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
        if (NOISE.any(message::contains)) return
        val line = "${stamp.format(java.util.Date())}  $message"
        if (entries.size == MAX_ENTRIES) entries.removeFirst()
        entries.addLast(line)
        runCatching { sink?.appendText(line + "\n") }
    }

    @Synchronized
    fun snapshot(): List<String> = entries.toList()
}