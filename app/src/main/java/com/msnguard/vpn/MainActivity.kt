package com.msnguard.vpn

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Dialog
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.widget.ImageView.ScaleType
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings as AndroidSettings
import android.text.InputType
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowInsetsController
import android.view.WindowManager
import android.window.OnBackInvokedCallback
import android.window.OnBackInvokedDispatcher
import android.view.animation.DecelerateInterpolator
import android.view.animation.PathInterpolator
import android.widget.FrameLayout
import android.widget.EditText
import android.widget.CheckBox
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import android.graphics.Typeface
import androidx.core.content.res.ResourcesCompat
import android.widget.LinearLayout.LayoutParams
import androidx.core.content.FileProvider
import java.io.File
import java.util.Locale
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import kotlin.math.min
import kotlin.math.roundToInt
import com.msnguard.vpn.profiled

class MainActivity : Activity() {
    private lateinit var orbitDial: OrbitDialView
    private lateinit var connectionTitle: TextView
    private lateinit var connectionDetail: TextView
    private lateinit var chipLatency: TextView
    private lateinit var chipProtocol: TextView
    private lateinit var tileDown: MetricTile
    private lateinit var tileUp: MetricTile
    private lateinit var tileSpeed: MetricTile
    private lateinit var exitNodeCard: ExitNodeCard
    private lateinit var chainCard: ChainModeCard

    /**
     * The MASQUE twin of [chainCard], in the same slot: masque-over-masque
     * chains a second MASQUE hop inside the first, exactly as the chain card
     * wraps Psiphon/Tor in WARP. Only ever visible with MASQUE selected.
     */
    private lateinit var mimCard: MimCard
    /**
     * The SHARD twin of [chainCard], in the same slot.
     *
     * Only one of the two is ever applicable — the chain wraps Psiphon/Tor, this
     * splits SHARD — so they share the row and the layout never grows.
     */
    private lateinit var smartSplitCard: SmartSplitCard
    /**
     * Whether the transport controls accept input, i.e. no tunnel is up.
     *
     * Mirrored here because [renderChainCard] needs it alongside the selected
     * protocol, and reading it back off the rail's `isEnabled` would couple the two
     * controls for no reason.
     */
    private var modeControlsEnabled = true
    private lateinit var transportRail: TransportRail

    /** Measured once from the rail's own row count; see where it is assigned. */
    private var transportRailHeight = 0
    private lateinit var footerWave: OrbitFooterWave
    private lateinit var statusLed: View
    private lateinit var mainRoot: FrameLayout
    private lateinit var pageHost: FrameLayout
    private lateinit var appUpdater: AppUpdater
    private var predictiveBackCallback: Any? = null
    private var selectedProtocol = Protocol.WIREGUARD
    // v1.8.7: English keeps the exact v1.8.5 layout; fa/zh get tighter text
    // blocks and a dial no smaller than the English one. See fitConsoleToViewport.
    private val localizedTypography: Boolean get() = AppLanguage.current() != "en"
    /**
     * Where the one-time Auto Scan is in [AUTO_SCAN_LADDER], or -1 when it is not
     * running.
     *
     * The scan exists for the user who does not know what MASQUE is: the first
     * connect walks the four transports that need no account and no setup, keeps
     * the one that actually carries traffic, and never asks again. It is UI-side on
     * purpose — the service already knows how to raise one transport, and the
     * decision of *which* to raise is exactly what this screen owns.
     */
    private var autoScanIndex = -1
    /**
     * The transport selected before the scan started, restored if the whole ladder
     * fails.
     *
     * Without this a failed scan would leave the user pinned to the last rung it
     * tried (SHARD), which is the one they understand least and the one least
     * likely to be right on the next network.
     */
    private var autoScanBefore: Protocol? = null
    /**
     * Invalidates the per-attempt watchdog. Incremented on every attempt and on
     * every abort, so a timeout posted for attempt N cannot advance attempt N+1.
     */
    private var autoScanToken = 0

    /**
     * True between abandoning one rung and dialling the next.
     *
     * Without it the ladder skips rungs. A rung can be abandoned by the watchdog
     * while its own FAILED broadcast is still in flight — or its teardown produces
     * one — and the second report would advance the ladder again, so a network where
     * MASQUE works could jump from WireGuard to SHARD. Cleared when the next rung's
     * connect actually fires.
     */
    private var autoScanSettling = false
    private var pendingConfig: String? = null
    /**
     * The backup JSON built before the file picker opened.
     *
     * Held here because `ACTION_CREATE_DOCUMENT` returns asynchronously and the
     * snapshot must be the one the user saw when they tapped, not whatever the
     * preferences hold when the picker finally comes back.
     */
    private var pendingBackupJson: String? = null
    private var settingsBackupRow: OrbitSettingsRow? = null
    private var profileRow: OrbitSettingsRow? = null
    private var batteryRow: LinearLayout? = null
    private var manualEndpointRow: OrbitSettingsRow? = null
    private var innerEndpointRow: OrbitSettingsRow? = null
    private var gatewayCacheRow: OrbitSettingsRow? = null
    private var dnsRow: OrbitSettingsRow? = null
    private var visualState = OrbitDialView.State.DISCONNECTED
    private var receiverRegistered = false
    private var autoPingRunning = false
    /**
     * Whether the UI is in the foreground.
     *
     * Everything periodic on this screen — the session timer, the status poll,
     * the auto-ping — exists to keep *visible* widgets truthful. While the app
     * is backgrounded or the screen is off there is nothing to keep truthful,
     * and on a phone that periodic work is the expensive part: each auto-ping is
     * an HTTP request that pulls the radio out of its low-power state, and each
     * timer tick denies the CPU a long idle window.
     *
     * The tunnel itself is unaffected. It lives in the service and the Rust
     * core, which keep their own health checks running; this flag only gates
     * work whose entire purpose is repainting a screen nobody is looking at.
     */
    private var uiForeground = false
    /** elapsedRealtime at the moment the tunnel came up; 0 when down. */
    private var sessionStartedAt = 0L
    private val sessionHandler = Handler(Looper.getMainLooper())
    private val sessionTicker = object : Runnable {
        override fun run() {
            // Backgrounded means the timer text is not on screen, so ticking it
            // every second is work with no observer. The elapsed time is derived
            // from `sessionStartedAt` on the next resume, so nothing drifts.
            if (sessionStartedAt == 0L || !uiForeground) return
            orbitDial.timerText = formatUptime(android.os.SystemClock.elapsedRealtime() - sessionStartedAt)
            sessionHandler.postDelayed(this, 1_000L)
        }
    }
    private val autoPingHandler = Handler(Looper.getMainLooper())
    private val autoPingRunnable = object : Runnable {
        override fun run() {
            // The foreground check is what makes this cheap: a real HTTP request
            // every 5s wakes the radio, and in the background nothing consumes
            // the result. Liveness is not lost — the core's own health check
            // (every 3s, 10s staleness limit) drops a dead tunnel regardless of
            // whether this screen is up.
            if (isTunnelActive() && autoPingRunning && uiForeground) {
                pingConnection()
                autoPingHandler.postDelayed(this, 5000L)
            }
        }
    }
    private var showingSettings = false
    /**
     * Settings rows that outlive the builder that created them.
     *
     * The settings page is built imperatively and then navigated away from — to the
     * mode screen, to a choice sheet — so any row whose value can change while the
     * page is still alive has to be reachable afterwards. Nulled in
     * [closeSettingsScreen] so a destroyed view is never repainted.
     */
    private var connectionModeRow: OrbitSettingsRow? = null
    private var psiphonChainRow: OrbitToggleRow? = null
    private var chainOuterRow: OrbitSettingsRow? = null
    private var torChainOuterRow: OrbitSettingsRow? = null
    private var egressRegionRow: OrbitSettingsRow? = null
    private var psiphonModeRow: OrbitSettingsRow? = null
    private var cdnEdgeIpsRow: OrbitSettingsRow? = null
    private var cdnSniRow: OrbitSettingsRow? = null

    /** LAN-sharing switch; its subtitle carries the live proxy address. */
    private var lanSharingRow: OrbitToggleRow? = null

    /** Settings row showing the Tor connection mode; repainted after a pick. */
    private var torModeRowRef: OrbitSettingsRow? = null

    /** Tor's own over-WARP switch, in the TOR section. */
    private var torChainRowRef: OrbitToggleRow? = null

    /** Settings row showing the preferred Tor exit country. */
    private var torRegionRowRef: OrbitSettingsRow? = null

    /** Settings row opening the manual bridge editor; shows a count and kinds. */
    private var torBridgeRowRef: OrbitSettingsRow? = null

    /** The Tunnel type picker (VPN vs SOCKS proxy) in the CONNECTION section. */
    private var tunnelTypeRow: OrbitSettingsRow? = null

    /**
     * The proxy-port row: greyed while the tunnel type is VPN, live in SOCKS mode.
     *
     * Held as a field because the type picker has to enable it in place — the user
     * chooses SOCKS and the port box under it must light up immediately, which is
     * the whole interaction the request describes.
     */
    private var proxyPortRow: OrbitSettingsRow? = null

    private var showingLogs = false
    private var showingScanner = false
    private var showingMode = false
    private var settingsPage: View? = null
    private var tunnelControlsPage: View? = null
    private var logsPage: View? = null
    private var scannerPage: View? = null
    private var modePage: View? = null
    private var splitTunnelPage: View? = null
    private var splitTunnelAppsPage: View? = null
    private var splitTunnelSummaryButton: OrbitSettingsRow? = null
    /** Repainted when the verbosity sheet picks a new level. */
    private var logVerbosityRow: OrbitSettingsRow? = null

    /**
     * The endpoint-scanner row, kept so it can be greyed per transport.
     *
     * Only MASQUE and WireGuard have endpoints to scan. Psiphon, Tor and SHARD each
     * find their own paths, so on those the row would open a screen whose every
     * setting is ignored.
     */
    private var scannerRow: OrbitSettingsRow? = null

    /** SHARD's node-list row; its subtitle carries the pool count and staleness. */
    private var shardPoolRow: OrbitSettingsRow? = null

    /**
     * The settings mirror of the home-screen Smart Split card.
     *
     * Nullable and re-read on every settings build, like [psiphonChainRow]: the
     * settings page is constructed on demand and thrown away, so a strong reference
     * held across pages would repaint a detached view.
     */
    private var smartSplitRow: OrbitToggleRow? = null

    /**
     * The SHARD section's other rows, gated on SHARD being the selected transport.
     *
     * Psiphon and Tor grey their rows the same way — nothing under them can take
     * effect while a different transport is active — and SHARD's rows are the same
     * shape of nothing: the node list, the custom IP, Smart Split and its
     * re-measure all feed a config that is not built when SHARD is not selected.
     * Kept as fields so [refreshShardRows] can grey them from the mode picker,
     * exactly as [refreshPsiphonRows] does for its three.
     */
    private var shardCustomIpRow: LinearLayout? = null
    private var shardReMeasureRow: OrbitSettingsRow? = null
    private var splitTunnelDraftMode: SplitTunnelSettings.Mode? = null
    private var splitTunnelDraftPackages: MutableSet<String>? = null
    private var trafficMonitorPage: View? = null
    private var dnsPage: View? = null
    private var trafficSpeedValue: TextView? = null
    private var trafficSessionValue: TextView? = null
    private var trafficMonthValue: TextView? = null
    private var trafficTx = 0L
    private var trafficRx = 0L
    private var trafficSpeedTx = 0L
    private var trafficSpeedRx = 0L
    private var trafficMonthTx = 0L
    private var trafficMonthRx = 0L
    @Volatile private var cachedUserApps: List<ApplicationInfo>? = null
    private var latencyRequest = 0
    @Volatile private var pingInFlight = false
    /**
     * Connection verification. STATUS_CONNECTED from the service only means
     * "the transport handshake finished" — on MCI/Hamrah-e-Aval a WireGuard
     * handshake can complete while no payload ever crosses, which is how the UI
     * ended up showing Connected with byte-level counters and no reachable
     * sites. Nothing calls itself Connected until [verifyDataPlane] has pulled a
     * real HTTP response through the tunnel.
     */
    private var verifyRequest = 0
    @Volatile private var verifyInFlight = false
    /** Consecutive failed health checks while nominally connected. */
    private var pingFailureStreak = 0
    /**
     * [trafficRx] as it stood when the last health check was judged.
     *
     * The delta against the current value is what separates "this tunnel is
     * dead" from "this tunnel is busy". Measured on this project's own server
     * through a real three-hop circuit: with 32 concurrent bulk streams on one
     * tor instance (40.8 MB in 30s, 1375 KB/s), probe RTT went from a 351 ms
     * median to a 687 ms median with a 4567 ms worst case, and the tail kept
     * growing the longer the load ran — 336, 1036, 844, 1531, 4567 ms. Zero
     * streams were refused, so nothing was broken; the queue was simply full.
     *
     * That is the regime a speed test puts the phone in, and with a 12 s
     * per-probe timeout and a three-strike budget it is close enough to the
     * teardown threshold to cross it. Tearing a tunnel down there would kill a
     * session that is moving a megabyte a second.
     */
    private var rxAtLastProbe = 0L

    /**
     * Set when we tore a tunnel down ourselves because it never passed traffic.
     * The teardown makes the service broadcast DISCONNECTED, which would repaint
     * the screen as a plain "Not connected" and hide the real reason — this flag
     * makes the receiver keep the failure message on screen.
     */
    private var suppressNextDisconnectedPaint = false
    private var ipRequest = 0
    @Volatile private var ipRefreshInFlight = false
    @Volatile private var ipRefreshPending = false
    /**
     * Retry bookkeeping for the window right after a teardown.
     *
     * A disconnect does not restore the carrier link immediately — on the
     * tun2socks paths (SHARD, Psiphon VPN, Tor) the native thread unwinds and the
     * TUN is closed after it, and Android only re-plumbs the default network when
     * that interface is gone. The three fast attempts inside [refreshPublicIp] all
     * fall inside that window, so the card used to settle on "IP unavailable" and
     * stay there until the user tapped it. These retries are spaced for the
     * interface teardown rather than for a flaky endpoint.
     */
    private var ipRetryAttempt = 0
    private val ipRetryHandler = Handler(Looper.getMainLooper())
    private val ipRetryRunnable = Runnable { refreshPublicIp(resetRetry = false) }
    /**
     * Exit address as measured by the core from inside the tunnel, and its
     * country. Empty until the core reports one.
     *
     * This is the trustworthy number. [fetchPublicIp] runs in our own process,
     * which `applySplitTunneling()` deliberately keeps off the TUN via
     * `addDisallowedApplication(packageName)`, so its HTTP request exits over the
     * carrier and returns the carrier's address — Iran — while the tunnel really
     * exits elsewhere. Once this is set, the HTTP result is ignored.
     */
    private var coreExitIp = ""
    private var coreExitCountry = ""
    /** Generation counter for country lookups, so a stale one cannot repaint. */
    private var countryRequest = 0
    /**
     * The address the in-flight country lookup is about.
     *
     * Not the same thing as [coreExitIp]: in Tor and Psiphon mode the address
     * comes from an HTTP fetch through the local SOCKS port, so [coreExitIp] is
     * blank and could not be used to decide whether a late answer is still
     * relevant.
     */
    private var countryLookupIp = ""
    private val statusHandler = Handler(Looper.getMainLooper())
    private val statusPoll = object : Runnable {
        override fun run() {
            if (!uiForeground) return
            renderStatus()
            statusHandler.postDelayed(this, STATUS_POLL_MS)
        }
    }
    private lateinit var palette: AppAppearance.Palette
    private val CANVAS get() = palette.canvas
    // Accents split in two on a light palette: the vivid value paints shapes,
    // the *_TEXT value paints letters. See AppAppearance.Palette.
    private val PRIMARY_TEXT get() = palette.primaryText
    private val AMBER_TEXT get() = palette.amberText
    private val ERROR_TEXT get() = palette.error
    private val SURFACE get() = palette.surface
    private val SURFACE_VARIANT get() = palette.surfaceVariant
    private val INK get() = palette.ink
    private val MUTED get() = palette.muted
    private val DIVIDER get() = palette.divider
    private val primary get() = palette.primary
    private val primaryContainer get() = palette.primaryContainer
    private val selectedSurface get() = palette.selectedSurface
    private val connected get() = palette.connected
    private val connectedContainer get() = palette.connectedContainer
    private val motionInterpolator = PathInterpolator(0.2f, 0f, 0f, 1f)

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            // The core measured the exit address from inside the tunnel. It wins
            // over anything fetchPublicIp() could produce, so handle it first and
            // return: in native TUN mode our own HTTP request bypasses the tunnel.
            intent.getStringExtra(MsnGuardVpnService.EXTRA_EXIT_IP)?.let { ip ->
                if (ip.isNotBlank()) {
                    coreExitIp = ip
                    coreExitCountry = ""
                    // An in-flight HTTP lookup must not overwrite this with the
                    // carrier's address when it finishes late.
                    ipRequest++
                    exitNodeCard.render(ip, null, isTunnelActive())
                    if (isTunnelActive()) updateNotificationHealth(ip = ip)
                    // The country is a property of the address, not of the link the
                    // question travels over, so it can be asked over the carrier.
                    resolveExitCountry(ip)
                }
                return
            }
            if (intent.hasExtra(MsnGuardVpnService.EXTRA_TRAFFIC_TX)) {
                trafficTx = intent.getLongExtra(MsnGuardVpnService.EXTRA_TRAFFIC_TX, 0)
                trafficRx = intent.getLongExtra(MsnGuardVpnService.EXTRA_TRAFFIC_RX, 0)
                trafficSpeedTx = intent.getLongExtra(MsnGuardVpnService.EXTRA_TRAFFIC_SPEED_TX, 0)
                trafficSpeedRx = intent.getLongExtra(MsnGuardVpnService.EXTRA_TRAFFIC_SPEED_RX, 0)
                trafficMonthTx = intent.getLongExtra(MsnGuardVpnService.EXTRA_TRAFFIC_MONTH_TX, 0)
                trafficMonthRx = intent.getLongExtra(MsnGuardVpnService.EXTRA_TRAFFIC_MONTH_RX, 0)
                renderTrafficMonitor()
                renderHomeMetrics()
                return
            }
            when (intent.getStringExtra(MsnGuardVpnService.EXTRA_STATUS)) {
                MsnGuardVpnService.STATUS_CONNECTING -> showConnecting(
                    intent.getStringExtra(MsnGuardVpnService.EXTRA_DETAIL),
                    intent.getIntExtra(MsnGuardVpnService.EXTRA_PROGRESS, -1),
                )
                MsnGuardVpnService.STATUS_STARTING -> showStarting()
                MsnGuardVpnService.STATUS_SCANNING -> showScanning()
                // NOT showConnected(). The service's CONNECTED only means the
                // transport handshake finished; it is not proof that payload
                // crosses. beginVerification() proves it before the UI claims it.
                MsnGuardVpnService.STATUS_CONNECTED -> beginVerification()
                MsnGuardVpnService.STATUS_FAILED -> {
                    // A rung of the Auto Scan died: move to the next transport instead
                    // of painting a red dial the user cannot act on. advanceAutoScan()
                    // returns false when the ladder is exhausted, and then the failure
                    // is shown normally.
                    if (!advanceAutoScan()) {
                        showFailure(intent.getStringExtra(MsnGuardVpnService.EXTRA_DETAIL))
                    }
                }
                MsnGuardVpnService.STATUS_DISCONNECTED -> {
                    // Our own verification teardown produces this broadcast. Keep
                    // the "no traffic passes" message instead of overwriting it
                    // with a generic "Not connected".
                    if (suppressNextDisconnectedPaint) {
                        suppressNextDisconnectedPaint = false
                        // NOT while the Auto Scan is between rungs. Re-enabling here
                        // un-dims the rail and the OVER WARP card for the 1.5s settle,
                        // and the next rung's CONNECTING dims them again — on the
                        // phone that is the lower half of the screen blinking once
                        // per rung. The scan keeps the controls locked throughout.
                        if (autoScanIndex < 0) setModeEnabled(true)
                    } else if (autoScanIndex >= 0) {
                        // A SECOND disconnected broadcast from the same teardown: the
                        // native worker's exit branch and stopTunnel()'s tail can each
                        // emit one depending on which finishes first, and only the
                        // first is consumed by the flag above. Painting it would drop
                        // "Not connected" over the scan's own progress line and reset
                        // the metrics mid-search. The scan owns this screen until it
                        // ends.
                        ConnectionLog.record("Auto Scan: teardown broadcast ignored between rungs")
                    } else {
                        showDisconnected()
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // No DynamicColors. The two Orbit palettes are fixed, and letting the OS
        // inject Material You colours repainted theme-derived surfaces (ripple
        // tints, dialog backgrounds) in the phone's wallpaper hues, which is
        // exactly the multi-palette behaviour that was removed with the old theme
        // picker. A user-chosen dark/light switch is not that: it selects one of
        // two designed palettes, and nothing is derived from the wallpaper.
        //
        // setTheme() BEFORE super.onCreate(): the framework resolves the window's
        // background, decor and system-bar attributes while the window is being
        // attached inside super.onCreate(). Called after, the light theme would
        // apply to dialogs but the window itself would stay dark.
        if (!AppAppearance.isNight(this)) setTheme(R.style.Theme_MsnGuard_Light)
        super.onCreate(savedInstanceState)
        // First thing after super: the service reads the language preference on
        // its own status sends, and t() needs a context to resolve "system".
        // The application context outlives this activity, so a mid-session
        // recreate() never orphans it.
        AppLanguage.appContext = applicationContext
        palette = AppAppearance.load(this)
        // Profiles: prefix any settings key written before this feature existed,
        // so an upgrade keeps every value the user set. Idempotent — a second
        // run finds nothing bare and returns 0.
        Profiles.migrateIfNeeded(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // A registered OnBackInvokedCallback ALWAYS consumes the gesture — its
            // `onBackInvoked()` returns Unit, so unlike `onBackPressed()` there is
            // no "return false and let the system handle it". The old code passed
            // `handleBack()` in and discarded its result, so wherever this callback
            // is the live back path, the app could not be exited with Back at all:
            // with no page open, handleBack() returned false and nothing happened.
            //
            // Why only SOME phones (the field report): whether this callback or
            // onBackPressed() receives Back depends on the OS version, because this
            // app targets SDK 36 and does not set
            // `android:enableOnBackInvokedCallback`.
            //   - Android 13/14: the flag defaults to false, the callback is
            //     ignored, Back goes to onBackPressed() -> exits correctly.
            //   - Android 15+: predictive back is on by default for targetSdk 35+,
            //     the callback becomes authoritative, onBackPressed() is no longer
            //     called -> Back did nothing on the home screen.
            //
            // finish() is what super.onBackPressed() does for a root launcher
            // activity, so both paths now behave identically.
            OnBackInvokedCallback { if (!handleBack()) finish() }.also { callback ->
                predictiveBackCallback = callback
                onBackInvokedDispatcher.registerOnBackInvokedCallback(
                    OnBackInvokedDispatcher.PRIORITY_DEFAULT,
                    callback,
                )
            }
        }
        requestNotificationPermission()
        // Version stamped in, so an update drops the previous build's mirror: its
        // lines were coded by that build's rules, and a mixed log is a leak.
        // Read from PackageManager rather than BuildConfig, which this module does
        // not generate — same pattern as ShardManager's geo-asset stamp.
        ConnectionLog.bind(
            File(filesDir, "connection.log"),
            runCatching {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(packageName, 0).versionCode.toString()
            }.getOrDefault(""),
        )

        appUpdater = AppUpdater(this)
        // Registers the periodic SHARD list refresh. Idempotent, so calling it on
        // every launch is how the job gets re-registered after an app update — a
        // package replace clears JobScheduler's registrations for the app.
        ShardRefreshJob.schedule(this)
        // And one opportunistic refresh now. The job's window is up to six hours
        // wide; someone who installs the app and taps SHARD immediately should not
        // have to wait for it. Returns without I/O if the list is already fresh.
        ShardSubscription.refreshIfDue(this)
        // Same trigger for the edge and geo-blocked lists. Separate file, separate
        // ETag, same 6-hour floor — see [RemotePolicy]. Cheap enough to sit next to
        // the subscription fetch: a 304 is a few hundred bytes.
        RemotePolicy.refreshIfDue(this)
        // And the Smart Split fragment profiles, on the same triggers and the
        // same floor — see [SmartSplitSub]. Same shape: a 304 costs nothing.
        SmartSplitSub.refreshIfDue(this)

        // Orbit console. Every control below is built in onCreate so a single
        // pass wires the whole screen; no XML layouts exist in this app.
        orbitDial = OrbitDialView(this, palette).apply {
            setOnClickListener { toggleTunnel() }
        }
        connectionTitle = label(
            textSize = if (localizedTypography) 25f else 21f,
            color = INK,
            style = TypefaceStyle.MEDIUM,
        ).apply {
            gravity = Gravity.CENTER
            val localizedTypography = this@MainActivity.localizedTypography
            if (localizedTypography) {
                typeface = Typefaces.extraBold(this@MainActivity)
                // Vertical padding 0: the font's own line box already carries
                // generous headroom (see Typefaces.lineHeightMult), and every
                // dp of padding here was dp the console took away from the dial.
                setPadding(dp(10), 0, dp(10), 0)
            }
            // One line, always. Every headline this view shows is short ("Connecting",
            // "Auto Scan", "Connection degraded"), and a wrap would change the
            // console's height — see connectionDetail below for why that is the
            // expensive kind of change.
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        connectionDetail = label(textSize = 13.5f, color = MUTED).apply {
            gravity = Gravity.CENTER
            // TWO LINES, ALWAYS — this is a layout fix, not a typographic choice.
            //
            // The status line changes text on every broadcast of a connect, and its
            // messages straddle the wrap point: "Starting WireGuard tunnel" is one
            // line, "Tunnel handshake succeeded but no traffic passes — try another
            // protocol" is two. Each change of line COUNT changed the console's
            // measured height, and [fitConsoleToViewport] answers a height change by
            // rescaling the dial — which relayouts the whole column, which is the
            // "screen goes and comes back" the user sees under the OVER WARP card.
            // With the Auto Scan the messages change several times per connect, so
            // what used to be one settle became a series of them: the flicker.
            //
            // Fixed at two lines the height is constant, the fit pass settles once,
            // and nothing below the dial moves for the rest of the session. Ellipsis
            // rather than three lines because two is enough for every message the app
            // produces (the longest is 71 characters).
            minLines = 2
            maxLines = 2
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        chipLatency = label(Strings.t("Latency —"), 12f, MUTED, TypefaceStyle.MEDIUM).apply {
            gravity = Gravity.CENTER
            contentDescription = "سنجش پینگ اتصال"
            isClickable = true
            isFocusable = true
            setOnClickListener { pingConnection() }
        }
        chipProtocol = label(selectedProtocol.label.uppercase(), 12f, MUTED, TypefaceStyle.MEDIUM).apply {
            gravity = Gravity.CENTER
            letterSpacing = spacing(0.08f)
        }
        selectedProtocol = savedProtocol()
        chipProtocol.text = selectedProtocol.label.uppercase()
        // One accent per tile, as in the approved mock: download mint, upload
        // violet, speed amber. They were all `primary` before, which is why every
        // sparkline looked identical.
        tileDown = MetricTile(
            this, palette, Strings.t("↓ DOWN"),
            palette.mint, Sculpt.lighten(palette.mint, 0.30f), palette.mintText,
        ) { openTrafficMonitorScreen() }
        tileUp = MetricTile(
            this, palette, Strings.t("↑ UP"),
            palette.violet, Sculpt.lighten(palette.violet, 0.30f), palette.violetText,
        ) { openTrafficMonitorScreen() }
        tileSpeed = MetricTile(
            this, palette, Strings.t("SPEED"),
            palette.amber, Sculpt.lighten(palette.amber, 0.30f), palette.amberText,
        ) { openTrafficMonitorScreen() }
        exitNodeCard = ExitNodeCard(this, palette) { refreshPublicIp() }
        chainCard = ChainModeCard(this, palette) { armed -> setChainArmed(armed) }
        mimCard = MimCard(this, palette) { armed -> setMimArmed(armed) }
        smartSplitCard = SmartSplitCard(this, palette) { on -> setSmartSplitEnabled(on) }
        transportRail = TransportRail(this, palette, Protocol.entries.map { railLabel(it) }) { index ->
            updateConnectionMode(Protocol.entries[index])
        }
        // Height follows the grid rather than being a constant: the rail decides how
        // many rows six transports need, and a hardcoded dp(46) would squash them.
        // v1.8.7: fa/zh cells are 34dp — the localized fonts' line boxes are taller
        // than Latin at the same sp, so the same 38dp reads looser; 34 + the tighter
        // lineHeightMult reclaims two rows' worth of height for the dial. English
        // keeps the v1.8.5 38dp exactly.
        transportRailHeight = dp(8) + transportRail.rowCount *
            (if (localizedTypography) dp(34) else dp(38))
        transportRail.select(Protocol.entries.indexOf(selectedProtocol), animate = false)
        renderChainCard()
        // The dead space under the action bar looked like a rendering bug. It is
        // now a thin signal trace that idles flat and grey, and ripples in the
        // connected accent once traffic is flowing. One 48-point path repainted at
        // 20fps only while connected — no bitmaps, no extra APK weight.
        footerWave = OrbitFooterWave(this, palette, Strings.t("SECURED BY MSN-GUARD"))
        statusLed = View(this).apply {
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density,
                Sculpt.withAlpha(MUTED, 0.5f),
                999,
            )
        }

        mainRoot = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            // Mirror the UI language: Persian lays out right-to-left, the
            // Latin/Chinese consoles left-to-right. Views inherit this once.
            layoutDirection = when (AppLanguage.current()) {
                "fa" -> android.view.View.LAYOUT_DIRECTION_RTL
                else -> android.view.View.LAYOUT_DIRECTION_LTR
            }
        }
        val header = createHeader()
        val console = createConnectionConsole()
        // The console can still scroll, but it is meant not to need it: the dial
        // shrinks first (see [fitConsoleToViewport]) and scrolling is only the
        // last resort on a screen too short even for the smallest dial. Clipping
        // the connect button would be the single worst failure this screen could
        // have, so the ScrollView stays as the safety net.
        val consoleScroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
            // Deliberately NOT isFillViewport: see [fitConsoleToViewport], which
            // needs the console's real measured height to know how much room is
            // free.
            // The dial paints its halo and pulse rings outside its own bounds, so
            // every ancestor in the chain has to stop clipping — one clipping
            // parent anywhere above the view is enough to cut the glow off.
            clipChildren = false
            clipToPadding = false
            addView(console, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ))
        }
        mainRoot.clipChildren = false
        mainRoot.addView(consoleScroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ).apply { topMargin = dp(52) })
        fitConsoleToViewport(consoleScroll, console)
        mainRoot.addView(header, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply {
            leftMargin = dp(20)
            rightMargin = dp(20)
            topMargin = dp(10)
        })
        mainRoot.setOnApplyWindowInsetsListener { _, insets ->
            (header.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(10)
                header.layoutParams = this
            }
            (consoleScroll.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(52)
                bottomMargin = insets.systemWindowInsetBottom
                consoleScroll.layoutParams = this
            }
            insets
        }
        pageHost = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            addView(mainRoot, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            ))
        }
        setContentView(pageHost)
        configureSystemBars()
        showOpeningOverlay()
        // The one-time language prompt. Sits over a fully built first frame, so
        // the user picks a language while the real UI is already behind it — not
        // a blank splash. Records a choice on any exit path, so it shows once.
        showLanguagePickerOnce()
        // Reattach to a tunnel that is already up. Without this the dial opens in
        // the disconnected state while the VPN is running, and the session timer
        // would only start on the next status broadcast. [adoptRunningTunnel]
        // keeps the elapsed time honest by reading the service's connect
        // timestamp, and runs again on every resume — see its own comment.
        if (!adoptRunningTunnel()) refreshPublicIp()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(MsnGuardVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(statusReceiver, filter)
        }
        receiverRegistered = true
    }

    override fun onStop() {
        if (receiverRegistered) {
            unregisterReceiver(statusReceiver)
            receiverRegistered = false
        }
        super.onStop()
    }

    override fun onDestroy() {
        // The session ticker is a Handler post, not tied to a view, so it has to
        // be cancelled by hand. The dial's own animators already stop in
        // onDetachedFromWindow.
        sessionHandler.removeCallbacks(sessionTicker)
        autoPingHandler.removeCallbacks(autoPingRunnable)
        ipRetryHandler.removeCallbacks(ipRetryRunnable)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            (predictiveBackCallback as? OnBackInvokedCallback)?.let {
                onBackInvokedDispatcher.unregisterOnBackInvokedCallback(it)
            }
        }
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        uiForeground = true
        // Restart everything the pause stopped. Each of these is idempotent and
        // cheap; the point is that the screen is correct the instant it appears
        // rather than after one poll interval.
        statusHandler.removeCallbacks(statusPoll)
        statusPoll.run()
        if (sessionStartedAt != 0L) {
            sessionHandler.removeCallbacks(sessionTicker)
            sessionHandler.post(sessionTicker)
        }
        if (isTunnelActive() && autoPingRunning) {
            // Fire one immediately: the latency shown on screen was measured
            // before the pause and may be minutes stale.
            autoPingHandler.removeCallbacks(autoPingRunnable)
            autoPingHandler.post(autoPingRunnable)
        }
        renderStatus()
        // A tunnel can be raised while this screen is merely STOPPED rather than
        // destroyed — the Quick Settings tile is the normal way — and the status
        // receiver is unregistered between onStop and onStart, so the CONNECTED
        // broadcast reaches nobody. onCreate's adoption does not help then,
        // because there is no onCreate: the same activity instance simply resumes
        // with a dial still painted "Not connected" over a working tunnel that is
        // visibly passing traffic. Field report, and the exact reason this call is
        // here and not only in onCreate.
        adoptRunningTunnel()
        // The LAN-sharing subtitle carries a live network address, and the usual way
        // to get one is to leave for the system Wi-Fi/hotspot screen and come back.
        // Every row this touches is null unless the settings page is on screen, so
        // this is a no-op everywhere else.
        refreshPsiphonRows()
        refreshShardRows()
    }

    /**
     * Stops every periodic repaint while the screen is not visible.
     *
     * onPause rather than onStop deliberately: onStop does not fire for a screen
     * merely dimmed or partially covered, and those are exactly the long idle
     * stretches where a 1-second ticker and a 5-second HTTP probe cost the most.
     */
    override fun onPause() {
        uiForeground = false
        statusHandler.removeCallbacks(statusPoll)
        sessionHandler.removeCallbacks(sessionTicker)
        autoPingHandler.removeCallbacks(autoPingRunnable)
        super.onPause()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == BACKUP_EXPORT_REQUEST) {
            // A cancelled picker must drop the pending payload, or the next
            // successful export would write a snapshot taken before whatever the
            // user changed in between.
            if (resultCode == RESULT_OK) data?.data?.let(::writeBackup) else pendingBackupJson = null
            return
        }
        if (requestCode == BACKUP_IMPORT_REQUEST) {
            if (resultCode == RESULT_OK) data?.data?.let(::readBackup)
            return
        }
        if (requestCode == VPN_REQUEST && resultCode == RESULT_OK) {
            pendingConfig?.let(::connect)
        } else if (requestCode == VPN_REQUEST) {
            showDisconnected(Strings.t("VPN permission required"))
        }
        pendingConfig = null
    }

    private fun showOpeningOverlay() {
        val overlay = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val logo = ImageView(this).apply {
            setImageResource(R.drawable.msnguard_splash_logo)
            contentDescription = getString(R.string.app_name)
            scaleType = ScaleType.FIT_CENTER
            alpha = 0f
            scaleX = 0.82f
            scaleY = 0.82f
        }
        overlay.addView(logo, FrameLayout.LayoutParams(dp(198), dp(276), Gravity.CENTER))
        pageHost.addView(overlay)

        logo.animate()
            .alpha(1f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(500)
            .setInterpolator(PathInterpolator(0.2f, 0f, 0f, 1f))
            .withEndAction {
                logo.animate()
                    .scaleX(1.05f)
                    .scaleY(1.05f)
                    .setDuration(700)
                    .setInterpolator(PathInterpolator(0.4f, 0f, 0.2f, 1f))
                    .withEndAction {
                        overlay.animate()
                            .alpha(0f)
                            .setDuration(300)
                            .withEndAction {
                                pageHost.removeView(overlay)
                                orbitDial.requestFocus()
                            }
                            .start()
                    }
                    .start()
            }
            .start()
    }

    private fun startAutoPing() {
        autoPingRunning = true
        autoPingHandler.removeCallbacks(autoPingRunnable)
        autoPingHandler.postDelayed(autoPingRunnable, 5000L)
    }

    private fun stopAutoPing() {
        autoPingRunning = false
        autoPingHandler.removeCallbacks(autoPingRunnable)
    }

    private fun pingConnection() {
        if (!isTunnelActive() || pingInFlight) return
        pingInFlight = true
        val request = ++latencyRequest
        chipLatency.text = Strings.t("Latency …")
        Thread {
            // Try each endpoint until one answers. A single unreachable probe URL
            // must not be reported as a degraded tunnel.
            val result: Pair<String, Float?> = pingAnyEndpoint() ?: ("Ping unavailable" to null)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                pingInFlight = false
                if (request == latencyRequest && isTunnelActive()) {
                    chipLatency.text = result.second?.let { Strings.tf("Latency %s ms", it.toInt()) } ?: Strings.t("Latency n/a")
                    val reachable = result.second
                    // Bytes moved since the previous judgement, taken before the
                    // branches below because both of them need it.
                    val movedBytes = trafficRx - rxAtLastProbe
                    // The counter restarting means the service began a new tunnel
                    // under us (documented on watchForTunnelBytes) — the delta is
                    // then meaningless rather than zero, so re-baseline and treat
                    // this round as "cannot tell".
                    val counterRestarted = trafficRx < rxAtLastProbe
                    rxAtLastProbe = trafficRx
                    // Whether the probe actually rode the tunnel. The app is
                    // excluded from its own TUN (addDisallowedApplication on the
                    // native path), so in native mode the probe leaves over the
                    // carrier link. That makes it a latency sample, not a health
                    // verdict: a carrier-side block or a Psiphon mid-rotation
                    // looks identical to a dead tunnel from out here. Only a
                    // probe that went through the tunnel may be allowed to tear
                    // one down.
                    val probeRodeTunnel = TunnelStatus.isActive() &&
                        (Tun2SocksManager.isRunning || TunnelStatus.isProxyMode || !TunnelStatus.isNativeTunMode)
                    if (reachable != null) {
                        pingFailureStreak = 0
                        if (visualState == OrbitDialView.State.DEGRADED) showConnected(restored = true)
                    } else if (movedBytes >= BUSY_TUNNEL_RX_BYTES || counterRestarted) {
                        // A probe that timed out while the TUN carried real payload
                        // says nothing about the tunnel's health. Measured: under a
                        // speed-test-shaped load one shared tor pushed probe RTT to
                        // 4.5s with an ever-growing tail while moving 1375 KB/s and
                        // refusing zero streams. Counting that as a strike is how a
                        // perfectly good session gets torn down mid-download — the
                        // opposite of what the streak is for.
                        //
                        // The streak is not merely skipped, it is RESET: the tunnel
                        // just proved itself with bytes, which is stronger evidence
                        // than the probe that failed, and a half-full streak carried
                        // across a busy patch would tear down on the next single miss
                        // after the load ended.
                        pingFailureStreak = 0
                        ConnectionLog.record(
                            "Probe timed out but the tunnel moved ${formatTraffic(movedBytes)}" +
                                " since the last check — busy, not dead"
                        )
                        // If a previous round already painted amber, take it back.
                        // Bytes crossing the TUN is the same evidence
                        // watchForTunnelBytes() trusts, and it is measured inside
                        // the tunnel rather than over the carrier link — so leaving
                        // the dial amber through a whole download because the
                        // probes lost their race would be the mirror image of the
                        // dead-green bug this screen exists to prevent.
                        if (visualState == OrbitDialView.State.DEGRADED) showConnected(restored = true)
                    } else if (!probeRodeTunnel) {
                        // The probe never went through the tunnel at all — the app
                        // is split-tunnel-excluded, so this failure happened on the
                        // carrier link while the tunnel itself was untouched. This
                        // is the case in the field log: a mid-rotation Psiphon made
                        // the carrier path briefly unreachable, the probe saw three
                        // consecutive misses, and a tunnel that stayed up for an hour
                        // afterwards was torn down at 18:32:14.
                        //
                        // Tearing down here is not a verdict, it is a guess — and a
                        // wrong guess costs the session. Skip the streak, keep the
                        // dial honest with amber, and let the next round's bytes or
                        // the core's own counters be the judge.
                        pingFailureStreak = 0
                        ConnectionLog.record(
                            "Health probe failed but it left over the carrier link, not the tunnel — not counting against the session"
                        )
                        showDegraded()
                    } else {
                        // A session that stops passing traffic is a dead tunnel,
                        // not a cosmetic "degraded" badge. Show degraded for the
                        // first misses (a carrier hiccup recovers), then stop
                        // pretending and tear it down.
                        pingFailureStreak++
                        if (pingFailureStreak >= MAX_PING_FAILURES) {
                            ConnectionLog.record(
                                "Tunnel stopped passing traffic ($pingFailureStreak consecutive failed probes) — dropping it"
                            )
                            failFakeConnection()
                            return@runOnUiThread
                        }
                        showDegraded()
                    }
                    updateNotificationHealth(ping = result.first)
                }
            }
        }.start()
    }

    /**
     * Per-probe timeout, widened while Tor is the transport.
     *
     * Measured through a real three-hop circuit on the server: ten fresh
     * circuits fetching `google/generate_204` gave a median of 1.19s and a
     * worst case of 1.62s, and the field log's own successful probes took
     * 3180ms, 2251ms and 3359ms. So 5s is *almost* enough, which is the worst
     * kind of budget — it passes in testing and fails on a slow circuit.
     */
    private fun pingTimeoutMs(): Int =
        if (TorManager.isTorActive) TOR_PING_TIMEOUT_MS else PING_TIMEOUT_MS

    /**
     * How long the gate may keep probing before it declares the tunnel dead.
     *
     * Must be comfortably larger than one full sweep of [PING_URLS], or the
     * sweep itself eats the whole budget and the gate fails after a single
     * attempt. That is exactly what the 1.4.1 field log recorded on Tor:
     * `No reachability after 1 probe(s)` — four endpoints × 5s = 20s worst case
     * against an 18s deadline, so a healthy tunnel was torn down without ever
     * getting a second try.
     */
    private fun verifyTimeoutMs(): Long =
        if (TorManager.isTorActive) TOR_VERIFY_TIMEOUT_MS else VERIFY_TIMEOUT_MS

    /**
     * Probe every health-check endpoint in turn, returning the first success.
     *
     * Returns null only when all of them failed, which is the one case that
     * genuinely warrants the degraded state.
     */
    private fun pingAnyEndpoint(): Pair<String, Float>? {
        val timeout = pingTimeoutMs()
        for (url in PING_URLS) {
            val attempt = runCatching {
                val startedAt = System.nanoTime()
                val connection = openTunnelConnection(url)
                try {
                    connection.connectTimeout = timeout
                    connection.readTimeout = timeout
                    connection.requestMethod = "GET"
                    connection.instanceFollowRedirects = false
                    check(connection.responseCode in 200..399) { "HTTP ${connection.responseCode}" }
                    val ms = (System.nanoTime() - startedAt) / 1_000_000
                    "${ms} ms" to ms.toFloat()
                } finally {
                    connection.disconnect()
                }
            }
            attempt.getOrNull()?.let { return it }
        }
        return null
    }

    /**
     * Gate between "the transport says it is up" and "the UI says Connected".
     *
     * Why this exists: on Hamrah-e-Aval a WireGuard handshake completes but no
     * payload ever crosses. The service broadcast CONNECTED, the dial went green,
     * and the counters sat at a few bytes while Telegram and every site stayed
     * dark — a connection that is connected to nothing. A handshake is not a data
     * plane, so it is not allowed to paint Connected on its own.
     *
     * The gate is a real HTTP fetch pulled through the tunnel, retried for up to
     * [VERIFY_TIMEOUT_MS]. Pass → Connected. Fail → tear the tunnel down and say
     * so, instead of leaving the user on a dead green dial. Protocol-agnostic on
     * purpose: it verifies bytes, so it covers WireGuard, MASQUE, WoW and
     * Psiphon without per-protocol special cases.
     */
    /**
     * Waits for the core's own byte counters to move, which is the only signal
     * on this screen that is measured *inside* the tunnel.
     *
     * Needed because in native TUN mode our own package is excluded from the VPN
     * (otherwise the core's control sockets would route into their own tunnel),
     * so an HTTP probe from this process leaves over the carrier link and
     * succeeds even when the tunnel carries nothing. That is exactly how a dead
     * Hamrah-e-Aval WireGuard session produced "Reachability probe passed in 1
     * attempt — 479 ms" followed by zero bytes. A probe that cannot enter the
     * tunnel cannot be evidence about the tunnel.
     *
     * Returns true as soon as [trafficRx] exceeds [rxAtStart].
     */
    private fun awaitTunnelBytes(request: Int, rxAtStart: Long, deadline: Long): Boolean {
        // Not "> 0": the core's own WireGuard health probe sends a small DNS query
        // every few seconds and its reply crosses the TUN, so a completely dead
        // tunnel still drips a few hundred bytes. That drip is what made the
        // counters show a trickle while nothing loaded. Requiring
        // [VERIFY_MIN_RX_BYTES] puts the bar above the probe traffic and below
        // anything a real app does on connect.
        var base = rxAtStart
        var target = base + VERIFY_MIN_RX_BYTES
        while (System.currentTimeMillis() < deadline && request == verifyRequest) {
            // The counter going backwards means the core started a fresh tunnel
            // (its totals are per-tunnel locals) — its own reconnect loop can do
            // that mid-verification. Re-baseline instead of waiting out the
            // deadline against a target the new counter can never reach.
            if (trafficRx < base) {
                base = trafficRx
                target = base + VERIFY_MIN_RX_BYTES
            }
            if (trafficRx >= target) return true
            Thread.sleep(VERIFY_RETRY_DELAY_MS)
        }
        return trafficRx >= target
    }

    private fun beginVerification() {
        // Already verified and live: a Psiphon rotation and the native core's own
        // reconnect loop both re-broadcast CONNECTED mid-session, and neither must
        // restart the whole gate. DEGRADED counts as live — the auto-ping owns
        // recovery from there.
        if (visualState == OrbitDialView.State.CONNECTED ||
            visualState == OrbitDialView.State.DEGRADED
        ) return
        if (verifyInFlight) return
        verifyInFlight = true
        val request = ++verifyRequest

        // DIAGNOSTIC BYPASS — plain SHARD only.
        //
        // Plain SHARD connects (the race picks a node, xray boots, the SOCKS
        // listener comes up) and then the verification gate kills the session
        // anyway. This skips the gate for that one transport so we can see whether
        // the tunnel itself is healthy: if Telegram connects and the byte counters
        // move with the gate out of the way, the tunnel is fine and the problem is
        // the probe; if nothing loads, the tunnel is really dead.
        //
        // Smart Split is deliberately NOT covered: that path already passes the
        // gate, so skipping it would tell us nothing and only weaken the check we
        // know works.
        //
        // The transport check is not cosmetic. Psiphon and Tor reach the device
        // through Tun2Socks too, so `Tun2SocksManager.isRunning` is true on all
        // three and the condition without it skipped verification for Psiphon as
        // well — logs 13-15 show the bypass firing on a Psiphon-over-WARP session,
        // where the gate is the only thing that would have caught a handshake-only
        // tunnel. Restricted to the one transport it was written for.
        val plainShard = selectedProtocol == Protocol.SHARD &&
            TunnelStatus.isActive() &&
            Tun2SocksManager.isRunning &&
            !TunnelStatus.isNativeTunMode &&
            !SmartSplit.enabled(this)
        if (plainShard) {
            ConnectionLog.record("Verification skipped — plain SHARD diagnostic bypass")
            showVerifying()
            showConnected()
            verifyInFlight = false
            return
        }

        // Byte counter at the moment the transport claimed to be up. The probe
        // below cannot see the tunnel in native mode (see pingAnyEndpoint: our
        // package is disallowed on the TUN, so the request leaves over the
        // carrier link), but this counter is emitted by the core from inside the
        // TUN bridge and therefore cannot be faked by the carrier.
        val rxAtStart = trafficRx
        showVerifying()
        Thread {
            val budget = verifyTimeoutMs()
            val deadline = System.currentTimeMillis() + budget
            // In native TUN mode the HTTP probe rides the carrier link, not the
            // tunnel, so it proves nothing. Gate on in-tunnel bytes instead and
            // use the probe only for the latency figure afterwards.
            val nativeMode = TunnelStatus.isNativeTunMode
            if (nativeMode) {
                val moved = awaitTunnelBytes(request, rxAtStart, deadline)
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    verifyInFlight = false
                    if (request != verifyRequest) return@runOnUiThread
                    if (moved) {
                        ConnectionLog.record("Tunnel is passing traffic — verified from inside the tunnel")
                        showConnected()
                        // Latency is cosmetic, so a failure here must not undo a
                        // verification that already succeeded on real bytes.
                        Thread {
                            val probe = pingAnyEndpoint()
                            runOnUiThread {
                                if (isFinishing || isDestroyed) return@runOnUiThread
                                if (request != verifyRequest) return@runOnUiThread
                                probe?.let { chipLatency.text = Strings.tf("Latency %s ms", it.second.toInt()) }
                            }
                        }.start()
                    } else {
                        ConnectionLog.record(
                            "Tunnel moved no bytes in ${budget / 1000}s — handshake succeeded but nothing passes"
                        )
                        failFakeConnection()
                    }
                }
                return@Thread
            }
            var proof: Pair<String, Float>? = null
            var attempts = 0
            while (System.currentTimeMillis() < deadline && request == verifyRequest) {
                attempts++
                proof = pingAnyEndpoint()
                if (proof != null) break
                // The tunnel may still be settling (routes, DNS, lwIP warm-up),
                // so retry rather than failing on the first miss.
                Thread.sleep(VERIFY_RETRY_DELAY_MS)
            }
            val verified = proof
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                verifyInFlight = false
                if (request != verifyRequest) return@runOnUiThread
                if (verified != null) {
                    ConnectionLog.record("Reachability probe passed in $attempts attempt(s) — ${verified.first}")
                    showConnected()
                    chipLatency.text = Strings.tf("Latency %s ms", verified.second.toInt())
                    // Second opinion, from inside the tunnel. A probe that rode
                    // the carrier link proves nothing about the TUN, so if the
                    // core has still not moved a single byte after the settle
                    // window, do not leave the user on a confident green dial.
                    watchForTunnelBytes(request, rxAtStart)
                } else {
                    ConnectionLog.record(
                        "No reachability after $attempts probe(s) — treating the tunnel as dead"
                    )
                    failFakeConnection()
                }
            }
        }.start()
    }

    /**
     * Watches the core's own byte counters after the UI has gone green.
     *
     * The counters come from [core] tun.rs, which increments them as packets
     * cross the TUN fd — the one number on this screen that is measured inside
     * the tunnel. If it has not budged [BYTE_WATCH_MS] after connect, the tunnel
     * is carrying nothing regardless of what the handshake said, and the dial
     * drops to DEGRADED with a message that says so. It is not torn down: the
     * core's own 10s stale-timeout owns teardown, and killing a tunnel that is
     * merely idle would be worse than labelling it.
     *
     * @param rebased guards the single re-arm below, so a counter that keeps
     *   restarting cannot schedule this forever.
     */
    private fun watchForTunnelBytes(request: Int, rxAtStart: Long, rebased: Boolean = false) {
        sessionHandler.postDelayed({
            if (isFinishing || isDestroyed) return@postDelayed
            if (request != verifyRequest) return@postDelayed
            if (visualState != OrbitDialView.State.CONNECTED) return@postDelayed
            if (trafficRx > rxAtStart) return@postDelayed
            // The counter went BACKWARDS, so the baseline this watch was armed with
            // no longer refers to the same tunnel: the core's totals are per-tunnel
            // locals and its own reconnect loop restarts them at zero without the
            // UI being told. `trafficRx > rxAtStart` is then false no matter how
            // much traffic flows, which reported a healthy tunnel as degraded —
            // the same class of bug as the monthly-total inflation, from the same
            // discontinuity. Re-arm once against the new baseline instead of
            // judging the tunnel on a stale one.
            if (trafficRx < rxAtStart && !rebased) {
                ConnectionLog.record("Byte counter restarted — re-checking traffic from the new baseline")
                watchForTunnelBytes(request, trafficRx, rebased = true)
                return@postDelayed
            }
            ConnectionLog.record("Tunnel moved no bytes in ${BYTE_WATCH_MS / 1000}s — reporting degraded")
            visualState = OrbitDialView.State.DEGRADED
            orbitDial.state = OrbitDialView.State.DEGRADED
            connectionTitle.setTextColor(AMBER_TEXT)
            connectionDetail.text = Strings.t("Tunnel is up but no traffic is passing")
            renderStatusLed()
        }, BYTE_WATCH_MS)
    }

    /** Cancels an in-flight verification (user disconnect, real failure, stop). */
    private fun cancelVerification() {
        verifyRequest++
        verifyInFlight = false
    }

    /**
     * A handshake-only tunnel: tear it down and report it honestly.
     *
     * Leaving it running would keep the TUN installed and silently blackhole the
     * whole device, which is worse than being disconnected.
     */
    private fun failFakeConnection() {
        suppressNextDisconnectedPaint = true
        startService(Intent(this, MsnGuardVpnService::class.java)
            .setAction(MsnGuardVpnService.ACTION_DISCONNECT))
        // A rung that handshook but carried nothing is exactly the Hamrah-e-Aval
        // WireGuard case the Auto Scan exists for, and it is the reason the ladder
        // is driven from this screen: the service thinks that session succeeded.
        // stopCurrent = false because the teardown above IS the disconnect.
        if (advanceAutoScan(stopCurrent = false)) return
        showFailure(Strings.t("Tunnel handshake succeeded but no traffic passes — try another protocol"))
    }

    /** The state between handshake and proof. Keeps the dial in its CONNECTING look. */
    private fun showVerifying() {
        showConnectionProgress(Strings.t("Verifying"), Strings.t("Checking that traffic really passes"))
    }

    private fun createHeader(): LinearLayout = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        // No mark in the header. The brand lives on the launcher icon and the
        // opening splash; repeating it above a single connect button was upstream
        // furniture, not information. What belongs here is live state: a small
        // LED that mirrors the dial, plus the settings entry.
        statusLed.layoutParams = LinearLayout.LayoutParams(dp(9), dp(9)).apply {
            rightMargin = dp(8)
        }
        addView(statusLed, statusLed.layoutParams)
        addView(label(Strings.t("MSN-GUARD"), 13f, MUTED, TypefaceStyle.MEDIUM).apply {
            letterSpacing = spacing(0.14f)
        })
        addView(View(this@MainActivity), LinearLayout.LayoutParams(0, 1, 1f))
        addView(ImageView(this@MainActivity).apply {
            setImageResource(R.drawable.ic_settings)
            contentDescription = "تنظیمات"
            isClickable = true
            isFocusable = true
            val p = dp(12)
            setPadding(p, p, p, p)
            setColorFilter(INK)
            val outValue = android.util.TypedValue()
            context.theme.resolveAttribute(android.R.attr.selectableItemBackgroundBorderless, outValue, true)
            setBackgroundResource(outValue.resourceId)
            setOnClickListener { openSettingsScreen() }
        }, LinearLayout.LayoutParams(dp(44), dp(44)))
    }

    private fun railLabel(protocol: Protocol): String = when (protocol) {
        // "WoW" is the table key for the short rail label; the enum's own label
        // is the longer "WARP-on-WARP" which would not fit the rail cells.
        Protocol.WARP_IN_WARP -> Strings.t("WoW")
        else -> protocol.label
    }

    /** Status LED colour + glow for the header chip. */
    private fun renderStatusLed() {
        val (fill, glow) = when (visualState) {
            OrbitDialView.State.CONNECTED -> connected to true
            OrbitDialView.State.DEGRADED -> palette.amber to true
            OrbitDialView.State.CONNECTING -> primary to true
            OrbitDialView.State.FAILED -> palette.danger to false
            OrbitDialView.State.DISCONNECTED -> MUTED to false
        }
        statusLed.background = Sculpt.sculptedBackground(
            resources.displayMetrics.density,
            if (glow) fill else Sculpt.withAlpha(MUTED, 0.4f),
            999,
            accent = if (glow) Sculpt.lighten(fill, 0.4f) else null,
        )
    }

    /**
     * Shrink the dial until the console fits the viewport, instead of scrolling.
     *
     * The main screen used to scroll on a 1080x2400 phone: the column measured
     * taller than the space between the header and the navigation bar, so the
     * action bar sat partly below the fold and the user had to drag the screen
     * to reach it. A one-tap-connect app must not hide its controls.
     *
     * The fix scales the dial, which is by far the tallest element, rather than
     * squeezing the cards or the type — those are already at their minimum
     * legible size. The scale is applied to the dial's whole measured box (ring
     * AND bleed together), so no amount of shrinking can crop the halo or the
     * pulse rings: that was the previous bug and it must not come back.
     *
     * Runs on every layout pass because the viewport changes with rotation,
     * multi-window, and the inset listener firing after the first measure. It is
     * idempotent: [OrbitDialView.sizeScale] ignores a value it already has, so a
     * settled layout costs one comparison and no relayout.
     */
    private fun fitConsoleToViewport(scroll: ScrollView, console: LinearLayout) {
        // isFillViewport must stay false for this to work. With it on, a console
        // shorter than the viewport is stretched to the viewport height, so
        // console.height would read "exactly fits" no matter how much room is
        // actually free and the dial could never grow back after a rotation.
        scroll.isFillViewport = false
        scroll.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ ->
            val viewport = scroll.height
            val natural = console.height
            val dialBox = orbitDial.height
            if (viewport <= 0 || natural <= 0 || dialBox <= 0) return@addOnLayoutChangeListener

            // Signed: > 0 means the column overflows, < 0 means room to spare.
            // The dial is the only element that scales, so the whole delta has to
            // come out of (or go into) its box.
            val delta = natural - viewport - dp(FIT_SLACK_DP)
            // ASYMMETRIC, and this is the anti-flicker rule.
            //
            // Shrinking is obligatory — an overflowing column hides controls. Growing
            // back is not: it is a cosmetic gain, and doing it for every few free
            // pixels turns any height change in the column into a shrink-then-grow
            // pair. That pair is a full relayout of everything under the dial, twice,
            // which on the phone reads as the lower half of the screen blinking. The
            // status line changing between one and two lines during a connect was
            // producing exactly that, several times per attempt.
            //
            // So the dial only grows when there is a whole line of slack to reclaim,
            // which no text change can produce on its own — only a real viewport
            // change (rotation, multi-window, the inset listener landing) can.
            if (delta < 0 && -delta < dp(GROW_SLACK_DP)) return@addOnLayoutChangeListener
            val current = orbitDial.sizeScale
            // v1.8.7, fa/zh: the localized fonts' tall line boxes made the
            // console overflow, so fitConsoleToViewport shrank the dial — the
            // "small connect button" گزارش. The block is compact now
            // (Typefaces.lineHeightMult, 34dp rail cells), and the dial must
            // never end up smaller than the English layout's, even on a short
            // screen: it floors at LOCALIZED_DIAL_FLOOR and lets the console
            // scroll instead, exactly as it did before the fit existed.
            //
            // v1.9.4: the floor rose 0.90 → 0.94. v1.9.3's AI MODE chip made
            // the chip line 8dp taller, and on fa/zh consoles the fit pass
            // answered by pushing the dial UNDER the old 0.90 floor-down
            // path — the user saw a dial smaller than any 1.8.x build. The
            // chip line has been compacted (2dp vertical padding, 2dp top
            // margin) so 0.94 fits; anything left over scrolls.
            val floor = if (localizedTypography) LOCALIZED_DIAL_FLOOR else OrbitDialView.MIN_SIZE_SCALE
            val target = (current * (dialBox - delta).toFloat() / dialBox)
                .coerceIn(floor, 1f)

            // Tolerance, not equality: two adjacent float values would otherwise
            // keep re-triggering layout and the screen would dither forever.
            // 0.004 of the dial is well under one pixel at any density.
            if (kotlin.math.abs(target - current) > 0.004f) {
                // Posted, not applied inline: this runs inside a layout pass, and
                // requestLayout() from there is either dropped or logged as
                // "improperly called during layout" depending on the Android
                // version. The post lands it on the next frame instead.
                orbitDial.post { orbitDial.sizeScale = target }
            }
        }
    }

    private fun createConnectionConsole(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER_HORIZONTAL
        setPadding(dp(20), 0, dp(20), dp(20))
        // The dial's halo and its two pulse rings are drawn outside its own 266dp
        // box, on purpose, exactly as the mock's `inset:-24px` / `scale(1.32)` do.
        // With the default clipChildren=true Android cut them off at the box edge,
        // which is why the glow looked amputated at the bottom and the heartbeat
        // seemed to burst out of an invisible frame. Both flags are required:
        // clipChildren for the ring, clipToPadding for the 20dp side padding.
        clipChildren = false
        clipToPadding = false

        addView(orbitDial, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply {
            topMargin = dp(14)
            // Cancel the console's 20dp side padding for this one child.
            //
            // The dial measures (RING + BLEED) * 2 so its glow has canvas to land
            // on. The console's own padding would clamp that box and force the
            // ring below its intended size; negative margins give the dial the
            // full width back, so the ring keeps its size and the bleed still
            // fits. clipToPadding=false (set above) is what lets it draw there.
            leftMargin = -dp(20)
            rightMargin = -dp(20)
        })

        // v1.8.7: English keeps the v1.8.5 margins exactly. fa/zh get a
        // tighter block (title closer to the dial, detail closer to the title)
        // to hand the reclaimed height back to the dial — see
        // fitConsoleToViewport, which must net-neutral for English.
        val titleGap = if (localizedTypography) dp(10) else dp(14)
        val detailGap = if (localizedTypography) dp(1) else dp(3)
        addView(connectionTitle, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = titleGap })
        addView(connectionDetail, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = detailGap })

        val chipLine = LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            chipLatency.setTextColor(Sculpt.withAlpha(MUTED, 0.95f))
            chipProtocol.setTextColor(Sculpt.withAlpha(MUTED, 0.95f))
            addView(chipLatency)
            addView(label("  ·  ", 12f, Sculpt.withAlpha(MUTED, 0.5f)))
            addView(chipProtocol)
        }
        addView(chipLine, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply {
            // 7dp → 2dp: the chip line sits between the dial block and the
            // metric tiles, and the 5dp handed back here goes straight back
            // to the dial through fitConsoleToViewport — part of restoring
            // the pre-v1.9.3 dial size ("the connect button got smaller").
            topMargin = dp(2)
        })

        val tiles = LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(tileDown, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(9) })
            addView(tileUp, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(0); rightMargin = dp(9) })
            addView(tileSpeed, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(0) })
        }
        addView(tiles, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(14) })

        addView(exitNodeCard, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(12) })

        addView(transportRail, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            transportRailHeight,
        ).apply { topMargin = dp(12) })

        // Below the rail, not on it: the rail picks the transport, this wraps the
        // Psiphon one in WARP. Same dp(56) as the action bar so every full-width
        // control on this screen is the same height.
        addView(chainCard, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(56),
        ).apply { topMargin = dp(10) })

        // Smart Split occupies the same slot, and exactly one of the two is ever
        // visible: the chain card applies to Psiphon/Tor, this one to SHARD.
        // [renderChainCard] does the swap, so the home screen keeps its height
        // whichever transport is selected.
        addView(smartSplitCard, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(56),
        ).apply { topMargin = dp(10) })

        // Masque-over-masque, the third occupant of the same slot: MASQUE's own
        // chained mode. [renderChainCard] keeps exactly one of the three cards
        // visible, so the screen keeps its height here too.
        addView(mimCard, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(56),
        ).apply { topMargin = dp(10) })

        // The LOG / SPLIT / SCAN MODE action bar used to sit here. Its three
        // destinations are now rows in Settings, next to the other things that
        // configure a session, and the space it occupied is what the transport
        // rail's second row uses — so adding SHARD cost the home screen no height.
        //
        // None of the three belonged on the first screen: SPLIT was already
        // duplicated as a Settings row, SCAN MODE only applies to MASQUE and
        // WireGuard, and LOG is where you go after something has gone wrong.

        // Fills the gap that used to sit between the action bar and the bottom
        // inset. Weight is one Path; it only animates while connected.
        addView(footerWave, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(44),
        ).apply { topMargin = dp(8) })
    }

    private fun refreshPublicIp(resetRetry: Boolean = true) {
        // Any retry armed by a previous failure belongs to that attempt; this call
        // supersedes it.
        ipRetryHandler.removeCallbacks(ipRetryRunnable)
        if (resetRetry) ipRetryAttempt = 0
        // A tunnel raised from the Quick Settings tile measured its exit before
        // this activity existed, and that broadcast is long gone — the receiver
        // only lives between onStart and onStop. The service kept the answer, so
        // adopt it rather than sitting on "measuring…" for the whole session.
        if (coreExitIp.isBlank() && isTunnelActive()) {
            MsnGuardVpnService.lastMeasuredExitIp()
                .takeIf { it.isNotBlank() }
                ?.let { coreExitIp = it }
        }
        // The core already told us, from inside the tunnel. Nothing an HTTP
        // request from this process could add is more accurate.
        if (coreExitIp.isNotBlank()) {
            ipRequest++
            exitNodeCard.render(
                coreExitIp,
                coreExitCountry.takeIf { it.isNotBlank() },
                isTunnelActive(),
            )
            // A tap on the card with the country still missing should retry it.
            if (coreExitCountry.isBlank()) resolveExitCountry(coreExitIp)
            return
        }
        // Native TUN mode and no measurement yet: our own request would leave over
        // the carrier link and paint the carrier's country. Wait for the core
        // instead of showing a number we know to be wrong.
        if (TunnelStatus.isActive() &&
            TunnelStatus.isNativeTunMode &&
            !Tun2SocksManager.isRunning
        ) {
            ipRequest++
            exitNodeCard.render("", null, isTunnelActive(), measuring = true)
            return
        }
        if (ipRefreshInFlight) {
            ipRefreshPending = true
            return
        }
        ipRefreshInFlight = true
        val request = ++ipRequest
        exitNodeCard.render("", null, isTunnelActive())
        Thread {
            val result = runCatching {
                repeat(IP_FETCH_ATTEMPTS) { attempt ->
                    runCatching { fetchPublicIp() }.getOrNull()?.let { return@runCatching it }
                    if (attempt + 1 < IP_FETCH_ATTEMPTS) Thread.sleep(IP_RETRY_DELAY_MS)
                }
                error("IP unavailable")
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                ipRefreshInFlight = false
                if (ipRefreshPending) {
                    ipRefreshPending = false
                    refreshPublicIp()
                    return@runOnUiThread
                }
                if (request != ipRequest) return@runOnUiThread
                val (ip, country) = result.getOrElse { "IP unavailable" to "" }
                if (ip == "IP unavailable" && !isTunnelActive() && ipRetryAttempt < IP_POST_TEARDOWN_RETRIES) {
                    // THE SHARD-DISCONNECT CASE. A teardown does not hand the
                    // carrier link back instantly: tun2socks unwinds on its own
                    // native thread, the VpnService's TUN is closed after it, and
                    // Android only restores the default network once that
                    // interface is really gone. The SHARD path is the slow one in
                    // this log — "tun2socks stopping (native thread unwinding)"
                    // is followed by a burst of BConnection/BSocksClient failures
                    // and only then "tun2socks exited", ~1s later — so our three
                    // attempts at 300 ms all land inside the gap and every one of
                    // them fails. MASQUE has no tun2socks at all: NativeCore.stop()
                    // returns and the link is back before the card even repaints,
                    // which is exactly why the bug looks protocol-specific.
                    //
                    // "IP unavailable / tap to retry" here is the app telling the
                    // user to do by hand what it should have done itself. Wait for
                    // the interface teardown to finish and ask again.
                    ipRetryAttempt++
                    exitNodeCard.render(
                        "", null, false,
                        measuring = true,
                        note = "waiting for the network to come back",
                    )
                    ipRetryHandler.postDelayed(ipRetryRunnable, IP_POST_TEARDOWN_DELAY_MS)
                    return@runOnUiThread
                }
                ipRetryAttempt = 0
                exitNodeCard.render(ip, country.takeIf { it.isNotBlank() }, isTunnelActive())
                if (isTunnelActive() && ip != "IP unavailable") {
                    updateNotificationHealth(ip = ip)
                    // Tor is the case that needs this: Cloudflare reports loc=T1
                    // for every exit, fetchPublicIp() drops it as unmappable, and
                    // without a second lookup the card would keep a globe forever
                    // while showing a perfectly good address. Asking geojs/ipwho
                    // about the address itself returns the real country (verified
                    // on live exits: 171.25.193.25 SE, 80.67.167.81 FR,
                    // 89.58.26.216 DE, 109.70.100.4 AT).
                    if (country.isBlank()) resolveExitCountry(ip)
                }
                exitNodeCard.alpha = 0.45f
                exitNodeCard.animate().alpha(1f).setDuration(240)
                    .setInterpolator(motionInterpolator).start()
            }
        }.start()
    }

    private fun fetchPublicIp(): Pair<String, String> {
        var failure: Throwable? = null
        for (url in IP_INFO_URLS) {
            try {
                val connection = openTunnelConnection(url)
                try {
                    connection.connectTimeout = IP_TIMEOUT_MS
                    connection.readTimeout = IP_TIMEOUT_MS
                    connection.requestMethod = "GET"
                    check(connection.responseCode in 200..399) { "HTTP ${connection.responseCode}" }
                    val body = connection.inputStream.bufferedReader().use { it.readText().trim() }
                    val values = body.lineSequence().mapNotNull { line -> line.split('=', limit = 2).let { pair ->
                        pair.takeIf { it.size == 2 }?.let { it[0] to it[1] }
                    } }.toMap()
                    val ip = values["ip"] ?: body.takeIf { it.matches(IP_ADDRESS) }.orEmpty()
                    check(ip.isNotBlank()) { "IP unavailable" }
                    // Cloudflare answers loc=T1 for every Tor exit — T1 is its
                    // pseudo-code for the Tor network, not a country — so it maps
                    // to no flag. Dropping it here (rather than passing it on as a
                    // "known" country) is what lets the caller fall back to a geo
                    // lookup on the address, which does return the real country.
                    val loc = values["loc"].orEmpty()
                    return ip to (if (IpFormatter.isRealCountry(loc)) loc.uppercase() else "")
                } finally {
                    connection.disconnect()
                }
            } catch (error: Throwable) {
                failure = error
            }
        }
        throw failure ?: IllegalStateException("IP unavailable")
    }

    private fun openTunnelConnection(url: String): HttpURLConnection {
        // OURS, deliberately kept over upstream's
        // `PROXY mode && NativeCore.isRunning()` (proxy mode has since been removed).
        //
        // In Psiphon VPN mode the service calls addDisallowedApplication(packageName),
        // so our own process is excluded from the TUN and its traffic leaves over
        // the carrier link. Upstream's condition would skip the proxy in VPN mode
        // and the IP/ping checks would report the real Iranian IP instead of the
        // tunnel exit. Routing through the local SOCKS port whenever any tunnel is
        // active is what makes the header IP and flag correct.
        //
        // But a local SOCKS listener only exists when something is actually
        // listening. Psiphon VPN mode has one (port 1819, which tun2socks also
        // dials). WireGuard and MASQUE VPN mode do NOT: the Rust core takes the
        // `tun_fd` branch in main.rs and binds a TUN bridge instead of calling
        // socks::serve, which only runs in the `else` (proxy) branch. Sending the
        // health check to 127.0.0.1:1819 there gets connection-refused on every
        // poll, pingConnection() lands in its `?: showDegraded()` arm, and the UI
        // says "Connection degraded" while the tunnel is carrying traffic fine.
        //
        // So: use the proxy only when a proxy is really there. In native VPN mode
        // go direct.
        //
        // LIMIT OF THIS PROBE — read before trusting it. applySplitTunneling()
        // calls addDisallowedApplication(packageName) on the native path too, so
        // this request leaves over the CARRIER link, not the tunnel. It therefore
        // proves the phone has internet; it does not prove the tunnel carries
        // anything. That is exactly how a WireGuard session with a completed
        // handshake and a dead data plane still passed the gate.
        //
        // The exclusion cannot simply be dropped: on the native path the core
        // provisions its identity (account.rs, plain reqwest, unprotected
        // sockets) *after* establish(), so those calls would be routed into a TUN
        // whose tunnel does not exist yet and connect would deadlock.
        //
        // So the honest signal is elsewhere: watchForTunnelBytes() reads the byte
        // counters the core emits from inside the TUN bridge. Keep both.
        val useSocksProxy = TunnelStatus.isActive() &&
            // tun2socks is up, which only happens in Psiphon VPN mode, and it
            // implies a live SOCKS listener on this port. Otherwise the Rust core
            // is running: it only has a SOCKS listener in proxy mode, never when
            // it is driving a TUN directly.
            //
            // Proxy mode is the third case and it MUST go through the proxy: there is
            // no TUN, so an unproxied request leaves over the carrier link and would
            // paint the user's real IP on the card while the proxy works fine.
            (Tun2SocksManager.isRunning || TunnelStatus.isProxyMode || !TunnelStatus.isNativeTunMode)

        val target = URL(url)
        val connection = if (useSocksProxy) {
            target.openConnection(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort())))
        } else {
            target.openConnection()
        }
        return (connection as HttpURLConnection).apply {
            connectTimeout = IP_TIMEOUT_MS
            readTimeout = IP_TIMEOUT_MS
        }
    }

    private fun updateNotificationHealth(ip: String? = null, ping: String? = null, country: String? = null) {
        if (!TunnelStatus.isActive()) return
        startService(Intent(this, MsnGuardVpnService::class.java)
            .setAction(MsnGuardVpnService.ACTION_NOTIFICATION_HEALTH)
            .apply {
                ip?.let { putExtra(MsnGuardVpnService.EXTRA_NOTIFICATION_IP, it) }
                ping?.let { putExtra(MsnGuardVpnService.EXTRA_NOTIFICATION_PING, it) }
                country?.let { putExtra(MsnGuardVpnService.EXTRA_NOTIFICATION_COUNTRY, it) }
            })
    }

    /**
     * Forgets the core's exit measurement, so the next tunnel measures afresh.
     *
     * Called on failure and disconnect. Without this a reconnect through a
     * different endpoint would keep showing the previous exit until the new
     * measurement lands, which is the same class of lie this change removes.
     */
    private fun clearCoreExitIp() {
        coreExitIp = ""
        coreExitCountry = ""
        countryRequest++
    }

    /**
     * Resolves which country [ip] is in, and repaints the card when it lands.
     *
     * Why this is a separate HTTP call rather than part of the core's in-tunnel
     * measurement: the core can only ask DNS, and DNS exposes the RIR
     * *registration* country, not a geolocation. Those disagree badly here —
     * 104.28.214.161 is registered to ARIN in the US and geolocates to Tehran,
     * and its neighbours in the same /24 sit in PT, CA, GB and CO — because
     * Cloudflare hands out anycast egress addresses per user, not per region.
     *
     * Unlike the address itself, this question is safe to ask over any link: the
     * answer is a property of [ip], not of the route the query takes. Both
     * endpoints are Cloudflare-fronted, so they are reachable from Iran, and both
     * were verified returning IR for the two addresses above.
     */
    private fun resolveExitCountry(ip: String) {
        if (ip.isBlank()) return
        val request = ++countryRequest
        // The address this lookup is about. The core-measured path can compare
        // against coreExitIp, but the HTTP path (Tor and Psiphon, where the
        // address comes from cdn-cgi/trace rather than from the core) has
        // coreExitIp blank, so it needs its own record of what was asked.
        countryLookupIp = ip
        Thread {
            val country = runCatching { fetchCountryFor(ip) }.getOrNull()
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                // A newer measurement (or a disconnect) superseded this lookup.
                if (request != countryRequest || countryLookupIp != ip) return@runOnUiThread
                if (country.isNullOrBlank()) return@runOnUiThread
                coreExitCountry = country
                exitNodeCard.render(ip, country, isTunnelActive())
                // The notification names the exit country too. Psiphon reports
                // its own through onConnectedServerRegion and wins; this is the
                // fallback for transports that cannot self-report.
                updateNotificationHealth(country = country)
            }
        }.start()
    }

    /** Two-letter country code for [ip], or null when no endpoint answers. */
    private fun fetchCountryFor(ip: String): String? {
        for (template in COUNTRY_LOOKUP_URLS) {
            try {
                val connection = (URL(template.format(ip)).openConnection() as HttpURLConnection)
                    .apply {
                        connectTimeout = IP_TIMEOUT_MS
                        readTimeout = IP_TIMEOUT_MS
                        requestMethod = "GET"
                    }
                try {
                    if (connection.responseCode !in 200..299) continue
                    val body = connection.inputStream.bufferedReader().use { it.readText() }
                    COUNTRY_CODE_JSON.find(body)?.groupValues?.get(1)?.let { return it.uppercase() }
                } finally {
                    connection.disconnect()
                }
            } catch (_: Throwable) {
                // Try the next endpoint.
            }
        }
        return null
    }

    // The four main-screen selector rows (MODE / LOG / PERF / SCAN) are gone.
    // MODE became the sliding TransportRail, LOG and SCAN became sculpted entries
    // in the ActionBar, and PERF moved into Settings — it is a once-a-year knob
    // that was occupying a quarter of the home screen.

    private fun openLogsScreen() {
        showingLogs = true
        logsPage?.let(pageHost::removeView)
        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { closeLogsScreen() }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(label(Strings.t("Logs"), 22f, INK, TypefaceStyle.MEDIUM), LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f,
            ))
            // COPY and SHARE act on the whole log FILE, not on the text above.
            // What is on screen is the ring buffer (100 entries) plus
            // NativeCore.lastLog(), and both drop their oldest lines — which is
            // exactly why the beginning of a long log was unreachable. The file
            // that ConnectionLog mirrors to keeps everything up to its 256KB cap.
            addView(createLogActionButton(Strings.t("COPY")) { copyFullLog() })
            addView(createLogActionButton(Strings.t("SHARE")) { shareFullLog() })
            // Log Key is gone from this screen: the export is plain text now, so
            // there is nothing left to decrypt. LogRedactor's tokenisation is the
            // only privacy layer, and that needs no key — it is stable, so a code
            // book read from the same source answers any question about a token.
        }
        content.addView(header)
        content.addView(label(Strings.t("Tunnel and VPN events"), 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(16) })
        // The five ERROR/WARN/INFO/DEBUG/TRACE chips that used to sit here are
        // gone. They wrote `log_level` to preferences, and CoreConfig does read
        // that key — but only when a config is BUILT, i.e. at the next connect.
        // Tapping one while looking at a live log therefore did nothing
        // observable, which is exactly what it looked like. The verbosity knob
        // now lives only in Settings, next to the other once-a-year knobs, and
        // this row carries three controls that act on what is on screen right
        // now.
        //
        // Declared before the row so the button lambdas can flip them.
        var paused = false
        var wrapLines = true
        val logTabs = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        var selectedLogTab = LogTab.ALL
        val tabViews = mutableMapOf<LogTab, TextView>()
        LogTab.entries.forEach { tab ->
            val tabView = label(tab.label, 13f, INK, TypefaceStyle.MEDIUM).apply {
                gravity = Gravity.CENTER
                setPadding(dp(12), dp(8), dp(12), dp(8))
                isClickable = true
                isFocusable = true
                setOnClickListener {
                    selectedLogTab = tab
                    tabViews.forEach { (item, view) ->
                        val active = item == tab
                        view.setTextColor(if (active) primaryContainer else INK)
                        view.background = roundedBackground(if (active) primary else SURFACE_VARIANT, 14, if (active) primary else DIVIDER)
                    }
                }
            }
            tabViews[tab] = tabView
            logTabs.addView(tabView, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                rightMargin = dp(4)
            })
        }
        tabViews.forEach { (tab, view) ->
            val active = tab == selectedLogTab
            view.setTextColor(if (active) primaryContainer else INK)
            view.background = roundedBackground(if (active) primary else SURFACE_VARIANT, 14, if (active) primary else DIVIDER)
        }
        content.addView(logTabs, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(12) })

        // The log text view and its scroller are built before the tool row
        // because the row's buttons act on them directly (wrap toggles the view's
        // scrolling mode, clear forces a repaint). They are ADDED to the content
        // afterwards, so the on-screen order is still tabs → tools → log.
        val events = label(textSize = 13f, color = INK).apply {
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        var followLatest = true
        // Wrap-off needs a horizontal scroller, not just setHorizontallyScrolling:
        // that call only stops the TextView wrapping, and without a scroller
        // beside it the long lines are simply clipped at the right edge. The pair
        // is ScrollView → HorizontalScrollView → TextView, so the log pans in
        // both axes when wrap is off and behaves exactly as before when it is on.
        val hScroll = HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
            addView(events)
        }
        val scroll = ScrollView(this).apply {
            addView(hScroll)
            setOnScrollChangeListener { _, _, scrollY, _, _ ->
                val contentHeight = getChildAt(0)?.height ?: 0
                followLatest = scrollY >= contentHeight - height - dp(8)
            }
        }
        // Held here rather than inside the refresh Runnable so Clear can null it
        // and force the next tick to repaint even if the text is unchanged.
        var renderedLogs: String? = null

        // The three controls that replace the dead verbosity chips. Every one of
        // them changes something visible immediately, which is the whole test the
        // old row failed.
        val toolRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        fun paintChip(chip: TextView, on: Boolean) {
            chip.setTextColor(if (on) primaryContainer else INK)
            chip.background = roundedBackground(
                if (on) primary else SURFACE_VARIANT,
                14,
                if (on) primary else DIVIDER,
            )
        }

        fun toolChip(caption: String, onClick: (TextView) -> Unit): TextView =
            label(caption, 13f, INK, TypefaceStyle.MEDIUM).apply {
                gravity = Gravity.CENTER
                setPadding(dp(12), dp(8), dp(12), dp(8))
                background = roundedBackground(SURFACE_VARIANT, 14, DIVIDER)
                isClickable = true
                isFocusable = true
                setOnClickListener {
                    performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
                    onClick(this)
                }
            }

        // PAUSE freezes the view so a line can actually be read. Without it the
        // 750ms refresh yanks the scroll position away mid-read whenever the core
        // is chatty, which during a connect is always.
        val pauseChip = toolChip(Strings.t("Pause")) {
            paused = !paused
            it.text = if (paused) Strings.t("Resume") else Strings.t("Pause")
            paintChip(it, paused)
        }
        // WRAP off makes the text view scroll horizontally instead, so long
        // Psiphon JSON notices stop wrapping into six-line paragraphs.
        val wrapChip = toolChip(Strings.t("Wrap")) {
            wrapLines = !wrapLines
            paintChip(it, wrapLines)
            events.setHorizontallyScrolling(!wrapLines)
            events.requestLayout()
        }
        val clearChip = toolChip(Strings.t("Clear")) {
            ConnectionLog.clear()
            renderedLogs = null
            Toast.makeText(this, Strings.t("App log cleared"), Toast.LENGTH_SHORT).show()
        }
        paintChip(wrapChip, true)
        toolRow.addView(pauseChip, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            rightMargin = dp(4)
        })
        toolRow.addView(wrapChip, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            rightMargin = dp(4)
        })
        toolRow.addView(clearChip, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        content.addView(toolRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(12) })
        content.addView(scroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            0,
            1f,
        ))
        page.addView(content, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ).apply {
            leftMargin = dp(24)
            rightMargin = dp(24)
            topMargin = dp(16)
            bottomMargin = dp(16)
        })
        page.setOnApplyWindowInsetsListener { _, insets ->
            (content.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(16)
                bottomMargin = insets.systemWindowInsetBottom + dp(16)
                content.layoutParams = this
            }
            insets
        }
        val refreshHandler = Handler(Looper.getMainLooper())
        val refresh = object : Runnable {
            override fun run() {
                // Paused keeps polling but stops touching the view, so the text
                // and the scroll position both hold still while a line is read.
                if (!paused) {
                    val updatedLogs = connectionLogText(selectedLogTab)
                    if (updatedLogs != renderedLogs) {
                        val keepAtBottom = followLatest || renderedLogs == null
                        events.text = updatedLogs
                        renderedLogs = updatedLogs
                        if (keepAtBottom) {
                            scroll.post {
                                scroll.scrollTo(0, (scroll.getChildAt(0)?.height ?: 0) - scroll.height)
                            }
                        }
                    }
                }
                if (showingLogs) refreshHandler.postDelayed(this, LOG_REFRESH_MS)
            }
        }
        page.addOnAttachStateChangeListener(object : View.OnAttachStateChangeListener {
            override fun onViewAttachedToWindow(view: View) = refresh.run()
            override fun onViewDetachedFromWindow(view: View) = refreshHandler.removeCallbacks(refresh)
        })
        logsPage = page
        pageHost.addView(page)
        page.requestApplyInsets()
        animatePageOpen(page)
    }

    private fun closeLogsScreen() {
        showingLogs = false
        logsPage?.let { animatePageClose(it) { logsPage = null } }
    }

    /**
     * Pages whose closing animation is still running.
     *
     * [animatePageClose] removes its page inside the animation's end action, so
     * for the whole animation the view is still a child of [pageHost]. Two pages
     * closing in the same frame — exactly what the Apps screen's Done button
     * does, closing itself and the Split page — then both resolved "the page
     * behind" by child-index arithmetic and landed on the same view, so
     * [mainRoot] never got its alpha and scale restored. The home screen stayed
     * dimmed, taps still worked, and only a process restart cleared it.
     */
    private val closingPages = mutableSetOf<View>()

    /**
     * The view that should carry the lit backdrop below [page].
     *
     * Searched by identity from the top of the stack rather than by index
     * arithmetic, and skipping anything already on its way out: restoring a page
     * that is about to be removed loses the restore entirely.
     */
    private fun backdropBelow(page: View): View {
        for (i in pageHost.childCount - 1 downTo 0) {
            val child = pageHost.getChildAt(i)
            if (child !== page && child !in closingPages) return child
        }
        return mainRoot
    }

    private fun animatePageOpen(page: View) {
        page.alpha = 0f
        page.translationY = dp(24).toFloat()
        page.scaleX = 0.92f
        page.scaleY = 0.92f

        val behind = backdropBelow(page)
        behind.animate()
            .alpha(0.5f)
            .scaleX(0.94f)
            .scaleY(0.94f)
            .setDuration(PAGE_ANIMATION_MS)
            .setInterpolator(motionInterpolator)
            .start()

        page.animate()
            .alpha(1f)
            .translationY(0f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(PAGE_ANIMATION_MS)
            .setInterpolator(motionInterpolator)
            .start()
    }

    private fun animatePageClose(page: View, onEnd: () -> Unit) {
        // Marked before the backdrop is resolved so a second page closing in the
        // same frame cannot pick this one as its backdrop.
        closingPages.add(page)
        page.animate()
            .alpha(0f)
            .translationY(dp(24).toFloat())
            .scaleX(0.92f)
            .scaleY(0.92f)
            .setDuration(LOG_CLOSE_ANIMATION_MS)
            .setInterpolator(motionInterpolator)
            .withEndAction {
                closingPages.remove(page)
                if (page.parent == pageHost) pageHost.removeView(page)
                onEnd()
                // The stack is only truly known once every closing page is gone:
                // the last one out restores whatever is left underneath. Without
                // this, closing two pages at once left the winner dimmed.
                if (closingPages.isEmpty()) restoreTopBackdrop()
            }
            .start()

        val behind = backdropBelow(page)
        behind.animate()
            .alpha(1f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(LOG_CLOSE_ANIMATION_MS)
            .setInterpolator(motionInterpolator)
            .start()
    }

    /**
     * Force the visible top of the stack back to full opacity and scale.
     *
     * The safety net for the dimmed-home-screen bug: whatever ends up on top
     * after a close is asserted lit, without animating, so no ordering of
     * overlapping page transitions can leave a dimmed view on screen.
     */
    private fun restoreTopBackdrop() {
        val top = if (pageHost.childCount > 0) {
            pageHost.getChildAt(pageHost.childCount - 1)
        } else {
            mainRoot
        }
        top.animate().cancel()
        top.alpha = 1f
        top.scaleX = 1f
        top.scaleY = 1f
        top.translationY = 0f
        top.translationX = 0f
    }

    /**
     * Fade the children in one after another.
     *
     * Animates to each child's OWN target opacity, not to 1f. A disabled row is
     * drawn at [DISABLED_ROW_ALPHA] and this animation used to overwrite that with
     * full opacity — so on the settings page every Psiphon and Tor row looked live
     * while MASQUE was selected, and tapping them did nothing because isClickable
     * was still false underneath. That mismatch is exactly the "greyed rows are not
     * grey" bug; the animation was the cause, not the availability logic.
     */
    private fun staggerListItems(container: ViewGroup) {
        for (i in 0 until container.childCount) {
            val child = container.getChildAt(i)
            val target = if (child.isEnabled) 1f else DISABLED_ROW_ALPHA
            child.alpha = 0f
            child.translationY = dp(12).toFloat()
            child.animate()
                .alpha(target)
                .translationY(0f)
                .setDuration(PAGE_ANIMATION_MS)
                .setStartDelay(80L + i * 32L)
                .setInterpolator(motionInterpolator)
                .start()
        }
    }

    private fun connectionLogText(tab: LogTab = LogTab.ALL): String {
        val appEvents = ConnectionLog.snapshot()
        // The core's lines never pass through ConnectionLog.record(), so they are
        // coded here instead — otherwise the one thing the screen shows in plain
        // text is the transport's own address and port layout.
        val coreEvents = NativeCore.lastLog().lineSequence()
            .filter(String::isNotBlank)
            .map(LogRedactor::redact)
            .toList()
        val events = when (tab) {
            LogTab.ALL -> appEvents + coreEvents
            LogTab.APP -> appEvents
            LogTab.CORE -> coreEvents
        }
        return events.joinToString("\n").ifBlank { Strings.t("No connection events yet") }
    }

    /**
     * A small text button for the logs header.
     *
     * Not an OrbitActionBar entry: those are full-height pills with a glyph, and
     * three of them already sit at the bottom of the main screen. These live inline
     * next to the title.
     */
    private fun createLogActionButton(caption: String, onClick: () -> Unit): TextView =
        label(caption, 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply {
            letterSpacing = spacing(0.1f)
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(7), dp(12), dp(7))
            background = roundedBackground(SURFACE_VARIANT, 12, DIVIDER)
            isClickable = true
            isFocusable = true
            contentDescription = "$caption، نمایش کامل گزارش"
            setOnClickListener {
                performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
                onClick()
            }
            // Set here rather than via layoutParams: the view is not attached yet
            // when this returns, so layoutParams is still null.
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = dp(6) }
        }

    private fun appVersionOrNull(): String? =
        runCatching { packageManager.getPackageInfo(packageName, 0).versionName }.getOrNull()

    /**
     * The whole log, oldest line first, read from disk.
     *
     * Why the file and not the screen: the visible text is capped twice over — the
     * ring buffer holds 100 entries and `NativeCore.lastLog()` keeps only its own
     * recent window — so on a long session the first lines are simply gone, which
     * is precisely the case where they matter. `ConnectionLog` mirrors every line
     * to `connection.log`, self-truncating at 256KB, so that file is the complete
     * record.
     *
     * Falls back to the in-memory snapshot if the file is missing or unreadable,
     * so the button always produces something.
     */
    private fun fullLogText(): String {
        val fromDisk = runCatching {
            File(filesDir, "connection.log").takeIf { it.isFile }?.readText()
        }.getOrNull()
        // Same reason as connectionLogText(): the core writes its own buffer and
        // never goes through ConnectionLog.record(), so it is coded on the way out.
        val core = NativeCore.lastLog().lineSequence()
            .filter(String::isNotBlank)
            .map(LogRedactor::redact)
            .toList()
        val app = fromDisk?.takeIf { it.isNotBlank() } ?: ConnectionLog.snapshot().joinToString("\n")
        return buildString {
            append("MSN-GUARD ")
            append(appVersionOrNull() ?: "?")
            append(" · ")
            append(selectedProtocol.label)
            if (chainRunning()) append(" over WARP")
            append('\n')
            append(app.trimEnd())
            if (core.isNotEmpty()) {
                append("\n--- core ---\n")
                append(core.joinToString("\n"))
            }
        }
    }

    /**
     * The full log, as plain text, for both COPY and SHARE.
     *
     * It was encrypted once (AES-256-GCM, [LogCipher]) on the theory that the
     * export carries a wiring diagram of the bypass. In practice the user could
     * never read their own log without hunting down a key file — which made the
     * export useless exactly when it is needed: reporting a connection failure.
     * The [LogRedactor] already tokenises user-identifying parts, and that is
     * the privacy line that matters.
     */
    private fun plainExport(): String = fullLogText()

    /**
     * Copies the full log to the clipboard on a background thread.
     *
     * The read is off the main thread because the file can be a quarter of a
     * megabyte and this is invoked from a tap; the clipboard write itself has to be
     * on the main thread. Nothing is ever put into a TextView, which is what would
     * actually freeze the UI on a long log.
     */
    private fun copyFullLog() {
        Thread({
            val text = runCatching { plainExport() }.getOrElse { Strings.tf("Could not read the log: %s", it.message.toString()) }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                val clipboard = getSystemService(ClipboardManager::class.java)
                clipboard?.setPrimaryClip(ClipData.newPlainText(Strings.t("MSN-GUARD log"), text))
                // Always confirm, on every Android version. Android 13+ shows its
                // own clipboard chip, so this is briefly a duplicate there — but a
                // silent COPY on a long log is indistinguishable from a broken
                // button, and being told twice is better than not being told.
                Toast.makeText(
                    this,
                    Strings.tf("Log copied (%s KB)", text.length / 1024),
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }, "log-copy").start()
    }

    /**
     * Shares the full log as a file.
     *
     * The escape hatch for a log too big to paste: clipboards and chat apps both
     * truncate very long text, and a 256KB log is well past what either handles.
     * Written into cacheDir/logs, which the FileProvider exposes.
     */
    private fun shareFullLog() {
        Thread({
            val result = runCatching {
                val dir = File(cacheDir, "logs").apply { mkdirs() }
                val target = File(dir, "msn-guard-log.txt")
                target.writeText(plainExport())
                target
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                result.onFailure {
                    Toast.makeText(this, "Could not write the log: ${it.message}", Toast.LENGTH_LONG).show()
                }.onSuccess { file ->
                    val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
                    startActivity(
                        Intent.createChooser(
                            Intent(Intent.ACTION_SEND)
                                .setType("text/plain")
                                .putExtra(Intent.EXTRA_SUBJECT, "MSN-GUARD log")
                                .putExtra(Intent.EXTRA_STREAM, uri)
                                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION),
                            Strings.t("Share log"),
                        )
                    )
                }
            }
        }, "log-share").start()
    }

    /**
     * Shares the Log Key file. Retained for debug builds only — the export has
     * been plain text since the cipher was dropped, so on a shipped build this
     * key decrypts nothing.
     */
    private fun shareKeyFile() {
        Thread({
            val result = runCatching {
                val dir = File(cacheDir, "logs").apply { mkdirs() }
                val target = File(dir, "Log Key.txt")
                LogCipher.writeKeyFile(target)
                target
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                result.onFailure {
                    Toast.makeText(this, Strings.tf("Could not write the key file: %s", it.message.toString()), Toast.LENGTH_LONG).show()
                }.onSuccess { file ->
                    val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
                    startActivity(
                        Intent.createChooser(
                            Intent(Intent.ACTION_SEND)
                                .setType("text/plain")
                                .putExtra(Intent.EXTRA_SUBJECT, "MSN-GUARD Log Key")
                                .putExtra(Intent.EXTRA_STREAM, uri)
                                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION),
                            Strings.t("Log Key"),
                        )
                    )
                }
            }
        }, "log-key").start()
    }

    /**
     * Subtitle for the backup row: how many stored values a file would carry.
     *
     * A count, not a date: nothing is written until the user picks a location, so
     * there is no "last backup" to report, and a plain number is what tells them
     * the file is not empty.
     */
    private fun backupSummary(): String {
        val count = SettingsBackup.valueCount(this)
        return if (count == 0) Strings.t("Nothing saved yet") else Strings.tf("%s settings", count)
    }

    /**
     * Writes a settings backup to a location the user chooses.
     *
     * `ACTION_CREATE_DOCUMENT` rather than an app-private file plus a share
     * sheet: the point of a backup is to survive uninstall, and anything under
     * `filesDir` or `cacheDir` is deleted with the app. The system picker puts
     * the file in Downloads or Drive, which does not need a storage permission on
     * any supported API level.
     */
    private fun exportSettings() {
        pendingBackupJson = runCatching { SettingsBackup.export(this, appVersion()) }
            .getOrElse {
                toastShort(Strings.tf("Could not read the settings: %s", it.message.toString()))
                return
            }
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/json")
            .putExtra(Intent.EXTRA_TITLE, SettingsBackup.suggestedFileName(appVersion()))
        runCatching { startActivityForResult(intent, BACKUP_EXPORT_REQUEST) }
            .onFailure {
                pendingBackupJson = null
                toastShort(Strings.t("This device has no file picker"))
            }
    }

    /**
     * Reads a settings backup the user picks and applies it.
     *
     * A wildcard MIME filter, not `application/json`: files that arrived through
     * Telegram or a mail client are frequently stored as
     * `application/octet-stream` or with no type at all, and a strict filter hides
     * exactly the file the user is looking for. [SettingsBackup.restore] validates
     * the content, which is the honest place to reject a wrong pick.
     */
    private fun importSettings() {
        if (TunnelStatus.isActive() || visualState == OrbitDialView.State.CONNECTING) {
            toastShort(Strings.t("Disconnect first — a restore changes what the tunnel uses"))
            return
        }
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("*/*")
        runCatching { startActivityForResult(intent, BACKUP_IMPORT_REQUEST) }
            .onFailure { toastShort(Strings.t("This device has no file picker")) }
    }

    /** Writes [pendingBackupJson] into the document the picker returned. */
    private fun writeBackup(uri: Uri) {
        val payload = pendingBackupJson
        pendingBackupJson = null
        if (payload == null) {
            toastShort(Strings.t("The backup was not ready — try again"))
            return
        }
        val result = runCatching {
            contentResolver.openOutputStream(uri, "wt")
                ?.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
                ?: error("the file could not be opened for writing")
        }
        result.onSuccess {
            ConnectionLog.record("Settings backed up (${SettingsBackup.valueCount(this)} values)")
            toastShort(Strings.t("Settings saved — this file holds no passwords"))
            settingsBackupRow?.setValue(backupSummary())
        }.onFailure {
            toastShort(Strings.tf("Could not write the backup: %s", it.message.toString()))
        }
    }

    /**
     * Applies the backup in [uri], then rebuilds the screen from the new values.
     *
     * `recreate()` is the honest way to repaint: settings are read into fields
     * and row subtitles all over this activity (the protocol rail, the chain
     * card, every summary line), and refreshing them one by one after a wholesale
     * replacement would leave whichever one was forgotten showing the old value.
     */
    private fun readBackup(uri: Uri) {
        val text = runCatching {
            contentResolver.openInputStream(uri)?.use { stream ->
                stream.bufferedReader().readText()
            } ?: error("the file could not be opened")
        }.getOrElse {
            toastShort(Strings.tf("Could not read the file: %s", it.message.toString()))
            return
        }
        val outcome = runCatching { SettingsBackup.restore(this, text) }.getOrElse {
            toastShort(it.message ?: Strings.t("This file is not a settings backup"))
            return
        }
        ConnectionLog.record(
            "Settings restored from a v${outcome.version} backup: " +
                "${outcome.restored} value(s)" +
                if (outcome.skipped > 0) ", ${outcome.skipped} skipped" else ""
        )
        toastShort(Strings.tf("Restored %s settings from v%s", outcome.restored, outcome.version))
        recreate()
    }

    /**
     * Confirms, then clears every setting.
     *
     * Confirmed because it is not undoable and the row sits one tap away from the
     * backup rows. The sheet names what survives — monthly traffic totals — so
     * the user is not left wondering whether their data counter was wiped too.
     */
    private fun confirmResetSettings() {
        if (TunnelStatus.isActive() || visualState == OrbitDialView.State.CONNECTING) {
            toastShort(Strings.t("Disconnect first — a reset changes what the tunnel uses"))
            return
        }
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Reset to defaults"), 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(
            "Every setting goes back to how the app arrived: connection mode, " +
                "tunnel type, SOCKS port, countries, manual bridges, split " +
                "tunnelling and anti-DPI shaping. Your monthly data total is kept. " +
                "Back up first if you may want these choices again.",
            14f, MUTED,
        ), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        val buttons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        buttons.addView(createSettingsButton(Strings.t("Cancel")) { dialog.dismiss() }, LinearLayout.LayoutParams(0, dp(52), 1f))
        buttons.addView(createSettingsButton(
            Strings.t("Reset"),
            backgroundOverride = primary,
            textColorOverride = primaryContainer,
        ) {
            SettingsBackup.resetToDefaults(this)
            ConnectionLog.record("Settings reset to defaults")
            dialog.dismiss()
            toastShort(Strings.t("Settings reset to defaults"))
            recreate()
        }, LinearLayout.LayoutParams(0, dp(52), 1f).apply { leftMargin = dp(10) })
        sheet.addView(buttons, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(52),
        ).apply { topMargin = dp(16) })
        dialog.setContentView(ScrollView(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    /**
     * Wipes the saved WARP/MASQUE registrations so the next connect enrolls fresh
     * accounts. Deliberately allowed while connected: the service action stops the
     * tunnel before it touches a single file, so the core never sees its identity
     * vanish underneath it.
     */
    private fun confirmResetIdentities() {
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Reset identity"), 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(
            Strings.t("Deletes every saved WARP and MASQUE account on this device. The next connect registers new ones from scratch, which can move the tunnel to a different exit address. Your manual endpoint and other settings are kept. Any open tunnel is closed first."),
            14f, MUTED,
        ), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        val buttons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        buttons.addView(createSettingsButton(Strings.t("Cancel")) { dialog.dismiss() }, LinearLayout.LayoutParams(0, dp(52), 1f))
        buttons.addView(createSettingsButton(
            Strings.t("Reset"),
            backgroundOverride = primary,
            textColorOverride = primaryContainer,
        ) {
            // The service owns the tunnel and the files together. Sending the
            // action rather than deleting from the activity keeps the stop and
            // the delete in one place, in the right order, on the same thread.
            startService(Intent(this, MsnGuardVpnService::class.java)
                .setAction(MsnGuardVpnService.ACTION_RESET_IDENTITIES))
            showDisconnected(Strings.t("Identity reset"))
            dialog.dismiss()
        }, LinearLayout.LayoutParams(0, dp(52), 1f).apply { leftMargin = dp(10) })
        sheet.addView(buttons, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(52),
        ).apply { topMargin = dp(16) })
        dialog.setContentView(ScrollView(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    private fun openScannerScreen(animate: Boolean = true) {
        if (visualState == OrbitDialView.State.CONNECTING ||
            visualState == OrbitDialView.State.CONNECTED ||
            TunnelStatus.isActive()
        ) return

        showingScanner = true
        scannerPage?.let(pageHost::removeView)

        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val scroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(24))
        }

        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(CANVAS)
            addView(createHeaderBackButton { closeScannerScreen() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Scanner options"), 22f, INK, TypefaceStyle.MEDIUM).apply {
                setPadding(dp(4), 0, 0, 0)
            })
        }
        content.addView(label(Strings.t("Choose Aether's endpoint-discovery budget and address families"), 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(4); bottomMargin = dp(24) })

        val options = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val discoveryOptions = mutableMapOf<EndpointDiscovery, SelectionOption>()
        val transportOptions = mutableMapOf<MasqueTransport, SelectionOption>()
        val modeOptions = mutableMapOf<ScanMode, SelectionOption>()
        val targetOptions = mutableMapOf<ScanTarget, SelectionOption>()

        options.addView(label(if (selectedProtocol == Protocol.MASQUE) "MASQUE GATEWAY DISCOVERY" else "WIREGUARD ENDPOINT DISCOVERY", 12f, MUTED).apply { letterSpacing = spacing(0.1f) })
        EndpointDiscovery.entries.forEachIndexed { index, discovery ->
            val option = createEndpointDiscoveryOption(discovery) { chosen ->
                preferences().edit()
                    .putString(ENDPOINT_DISCOVERY, chosen.coreName)
                    .apply()
                discoveryOptions.forEach { (item, view) -> setSelectionState(view, item == chosen, animate = true) }
            }
            discoveryOptions[discovery] = option
            options.addView(option.row, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(68),
            ).apply { topMargin = if (index == 0) dp(10) else dp(8) })
        }

        if (selectedProtocol == Protocol.MASQUE) {
            options.addView(label(Strings.t("MASQUE TRANSPORT"), 12f, MUTED).apply { letterSpacing = spacing(0.1f) }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(20) })
            MasqueTransport.entries.forEachIndexed { index, transport ->
                val option = createMasqueTransportOption(transport) { chosen ->
                    preferences().edit().putString(DEFAULT_MASQUE_TRANSPORT, chosen.coreName).apply()
                    transportOptions.forEach { (item, view) -> setSelectionState(view, item == chosen, animate = true) }
                }
                transportOptions[transport] = option
                options.addView(option.row, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    dp(68),
                ).apply { topMargin = if (index == 0) dp(10) else dp(8) })
            }
        }

        options.addView(label(Strings.t("SCAN MODE"), 12f, MUTED).apply { letterSpacing = spacing(0.1f) }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(20) })
        ScanMode.entries.forEachIndexed { index, mode ->
            val option = createScanModeOption(mode) { chosen ->
                preferences().edit().putString(DEFAULT_SCAN_MODE, chosen.coreName).apply()
                modeOptions.forEach { (item, view) -> setSelectionState(view, item == chosen, animate = true) }
            }
            modeOptions[mode] = option
            options.addView(option.row, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(68),
            ).apply { topMargin = if (index == 0) dp(10) else dp(8) })
        }

        options.addView(label(Strings.t("IP VERSION"), 12f, MUTED).apply { letterSpacing = spacing(0.1f) }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(20) })
        ScanTarget.entries.forEachIndexed { index, target ->
            val option = createScannerOption(target) { chosen ->
                preferences().edit().putString(DEFAULT_SCAN, chosen.coreName).apply()
                targetOptions.forEach { (item, view) -> setSelectionState(view, item == chosen, animate = true) }
            }
            targetOptions[target] = option
            options.addView(option.row, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(68),
            ).apply { topMargin = if (index == 0) dp(10) else dp(8) })
        }

        content.addView(options)
        scroll.addView(content)
        page.addView(scroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ).apply { topMargin = dp(56) })
        page.addView(header, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(48),
            Gravity.TOP,
        ).apply { leftMargin = dp(24); rightMargin = dp(24); topMargin = dp(8) })

        page.setOnApplyWindowInsetsListener { _, insets ->
            (scroll.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(56)
                bottomMargin = insets.systemWindowInsetBottom
                scroll.layoutParams = this
            }
            (header.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(8)
                header.layoutParams = this
            }
            insets
        }

        scannerPage = page
        pageHost.addView(page, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ))
        page.requestApplyInsets()
        if (animate) {
            animatePageOpen(page)
            staggerListItems(options)
        }
    }

    private fun closeScannerScreen() {
        showingScanner = false
        scannerPage?.let { animatePageClose(it) { scannerPage = null } }
    }

    private fun createScannerOption(target: ScanTarget, onSelect: (ScanTarget) -> Unit): SelectionOption {
        val selected = target == defaultScan()
        val title = label(target.label, 16f, INK, TypefaceStyle.MEDIUM)
        val indicator = label(Strings.t("SELECTED"), 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = spacing(0.08f) }
        val row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            contentDescription = "اسکن پایانه‌های ${target.label}"
            isClickable = true
            isFocusable = true
            setOnClickListener { onSelect(target) }
            val labels = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
            labels.addView(title)
            labels.addView(label(target.description, 13f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
            addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            // 12dp between the label column and the SELECTED chip: "انتخاب‌شده"
            // read as glued to the option title in Persian.
            addView(indicator, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = dp(12) })
        }
        return SelectionOption(row, title, indicator, 18).also { setSelectionState(it, selected, animate = false) }
    }

    private fun createEndpointDiscoveryOption(
        discovery: EndpointDiscovery,
        onSelect: (EndpointDiscovery) -> Unit,
    ): SelectionOption {
        val selected = discovery == defaultEndpointDiscovery()
        val title = label(discovery.label, 16f, INK, TypefaceStyle.MEDIUM)
        val indicator = label(Strings.t("SELECTED"), 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = spacing(0.08f) }
        val row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            contentDescription = "استفاده از ${discovery.label} برای کشف دروازه MASQUE"
            isClickable = true
            isFocusable = true
            setOnClickListener { onSelect(discovery) }
            val labels = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
            labels.addView(title)
            labels.addView(label(discovery.description, 13f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
            addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            // 12dp between the label column and the SELECTED chip: "انتخاب‌شده"
            // read as glued to the option title in Persian.
            addView(indicator, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = dp(12) })
        }
        return SelectionOption(row, title, indicator, 18).also { setSelectionState(it, selected, animate = false) }
    }

    private fun createScanModeOption(mode: ScanMode, onSelect: (ScanMode) -> Unit): SelectionOption {
        val selected = mode == defaultScanMode()
        val title = label(mode.label, 16f, INK, TypefaceStyle.MEDIUM)
        val indicator = label(Strings.t("SELECTED"), 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = spacing(0.08f) }
        val row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            contentDescription = "استفاده از حالت اسکن ${mode.label}"
            isClickable = true
            isFocusable = true
            setOnClickListener { onSelect(mode) }
            val labels = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
            labels.addView(title)
            labels.addView(label(mode.description, 13f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
            addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            // 12dp between the label column and the SELECTED chip: "انتخاب‌شده"
            // read as glued to the option title in Persian.
            addView(indicator, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = dp(12) })
        }
        return SelectionOption(row, title, indicator, 18).also { setSelectionState(it, selected, animate = false) }
    }

    private fun createMasqueTransportOption(
        transport: MasqueTransport,
        onSelect: (MasqueTransport) -> Unit,
    ): SelectionOption {
        val selected = transport == defaultMasqueTransport()
        val title = label(transport.label, 16f, INK, TypefaceStyle.MEDIUM)
        val indicator = label(Strings.t("SELECTED"), 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = spacing(0.08f) }
        val row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            contentDescription = "استفاده از ${transport.label} برای اسکن MASQUE"
            isClickable = true
            isFocusable = true
            setOnClickListener { onSelect(transport) }
            val labels = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
            labels.addView(title)
            labels.addView(label(transport.description, 13f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
            addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            // 12dp between the label column and the SELECTED chip: "انتخاب‌شده"
            // read as glued to the option title in Persian.
            addView(indicator, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = dp(12) })
        }
        return SelectionOption(row, title, indicator, 18).also { setSelectionState(it, selected, animate = false) }
    }

    private fun openModeScreen() {
        if (visualState == OrbitDialView.State.CONNECTING ||
            visualState == OrbitDialView.State.CONNECTED ||
            TunnelStatus.isActive()
        ) return

        showingMode = true
        modePage?.let(pageHost::removeView)

        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(24))
        }

        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { closeModeScreen() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Connection mode"), 22f, INK, TypefaceStyle.MEDIUM).apply {
                setPadding(dp(4), 0, 0, 0)
            })
        }
        content.addView(header, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(8) })

        content.addView(label(Strings.t("Choose how MSN-GUARD connects"), 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(4); bottomMargin = dp(24) })

        val options = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        Protocol.entries.forEachIndexed { index, protocol ->
            options.addView(createModeOption(protocol), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(76),
            ).apply { if (index > 0) topMargin = dp(12) })
        }

        content.addView(options)
        page.addView(content, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ))

        page.setOnApplyWindowInsetsListener { _, insets ->
            content.setPadding(dp(24), insets.systemWindowInsetTop + dp(16), dp(24), insets.systemWindowInsetBottom + dp(24))
            insets
        }

        modePage = page
        pageHost.addView(page)
        page.requestApplyInsets()
        animatePageOpen(page)
        staggerListItems(options)
    }

    private fun closeModeScreen() {
        showingMode = false
        modePage?.let { animatePageClose(it) { modePage = null } }
    }

    private fun createModeOption(protocol: Protocol): LinearLayout {
        val selected = protocol == selectedProtocol
        return LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(20), 0, dp(20), 0)
            background = roundedBackground(
                if (selected) selectedSurface else SURFACE_VARIANT,
                20,
                if (selected) primary else SURFACE_VARIANT,
            )
            isClickable = protocol.androidAvailable
            isFocusable = protocol.androidAvailable
            alpha = if (protocol.androidAvailable) 1f else DISABLED_ALPHA
            setOnClickListener {
                if (!protocol.androidAvailable) return@setOnClickListener
                if (protocol != selectedProtocol) updateConnectionMode(protocol)
                closeModeScreen()
            }

            val texts = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
            texts.addView(label(protocol.label, 16f, INK, TypefaceStyle.MEDIUM))
            texts.addView(label(protocol.description, 13f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })

            addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            if (selected) addView(label(Strings.t("CURRENT"), 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply {
                letterSpacing = spacing(0.08f)
            }) else if (!protocol.androidAvailable) addView(label(Strings.t("DESKTOP ONLY"), 11f, MUTED, TypefaceStyle.MEDIUM).apply {
                letterSpacing = spacing(0.05f)
            })
        }
    }


    private fun openSettingsScreen(animate: Boolean = true) {
        showingSettings = true
        settingsPage?.let(pageHost::removeView)

        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val scroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(24))
        }

        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(CANVAS)
            addView(createHeaderBackButton { closeSettingsScreen() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Settings"), 22f, INK, TypefaceStyle.MEDIUM).apply {
                setPadding(dp(4), 0, 0, 0)
            })
        }
        // PROFILE sits above everything, because the profile decides what every
        // row below it means. It is the only section that rebuilds the whole
        // page on a change, so it has to be read first and built first.
        content.addView(expandableSection(Strings.t("PROFILE"), id = "PROFILE") { body ->
            profileRow = navRow(Strings.t("Profile"), Profiles.activeName(this)) { chooseProfile() }
            body.addView(profileRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        content.addView(expandableSection(Strings.t("PROTECTION"), id = "PROTECTION") { body ->
            body.addView(createToggleRow(Strings.t("Kill switch"), Strings.t("Block all traffic if the tunnel drops"), killSwitchEnabled()) {
                preferences().edit().putBoolean(KILL_SWITCH, it).apply()
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })

            // Auto-reconnect sits next to the kill switch because the two answer the
            // same question — "the tunnel just died, now what?" — and a user who wants
            // one usually wants the other. It is deliberately NOT tied to the kill
            // switch: blocking traffic and retrying are independent choices, and
            // pairing them would mean you cannot retry without blocking.
            body.addView(createToggleRow(
                Strings.t("Auto reconnect"),
                Strings.t("Reconnect automatically if the tunnel drops"),
                autoReconnectEnabled(),
            ) {
                preferences().edit().putBoolean(MsnGuardVpnService.AUTO_RECONNECT_PREF, it).apply()
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })

            // BATTERY OPTIMIZATION. Not a toggle: it is a row that opens the
            // system's doze-whitelist dialog, so it reads the current state and
            // shows it as the row's value the way a toggle would.
            //
            // This is the single most-asked-for row on Huawei and Xiaomi, whose
            // vendor power managers kill a foreground service the doze whitelist
            // does not name. An auto-reconnect cannot help when the process is
            // dead, and the kill switch cannot stay up either — so on those
            // devices this row is what makes the tunnel survive a locked screen.
            batteryRow = navRow(
                Strings.t("Battery Optimization"),
                Strings.t("Background Running"),
            ) { requestBatteryOptimization() }
            body.addView(batteryRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        content.addView(expandableSection(Strings.t("ROUTING & DATA"), id = "ROUTING & DATA") { body ->
            body.addView(navRow(Strings.t("Traffic monitor"), trafficHeadline()) { openTrafficMonitorScreen() }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
            splitTunnelSummaryButton = navRow(Strings.t("Split tunneling"), splitTunnelSummary()) { openSplitTunnelScreen() }
            body.addView(splitTunnelSummaryButton, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // The switch this writes existed before, fed only the removed proxy mode's
            // SOCKS bind, and was deleted because in VPN mode it changed nothing the
            // user could see. It changes something now: the service applies the
            // preference on every VPN path — SHARD, Psiphon, Tor and the chain included,
            // not just the Rust core — so a printer, NAS or router page reached by its
            // local address stays reachable while the tunnel is up.
            //
            // Off by default, and it must stay that way: sending LAN destinations around
            // the tunnel is a routing decision the user should make, and on Tor it means
            // those destinations leave the circuit.
            body.addView(createToggleRow(
                Strings.t("Local network access"),
                Strings.t("Reach printers, NAS and your router while connected"),
                lanBypassEnabled(),
            ) {
                preferences().edit().putBoolean(MsnGuardVpnService.LAN_BYPASS_PREF, it).apply()
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })

            // BYPASS IRAN. Iranian IP ranges leave through the carrier link and
            // never enter the tunnel. Implemented as Android excludeRoute() on
            // the TUN, which is the only layer every transport passes through —
            // see MsnGuardVpnService.applyIranBypass for why a rule inside any
            // one transport would leave the others uncovered.
            //
            // Off by default. An Iranian destination the user was deliberately
            // tunnelling (a bank that blocks foreign source addresses, an
            // exit-country choice) stops working the moment this is on, so this
            // is the user's routing decision to make.
            body.addView(createToggleRow(
                Strings.t("Bypass Iran"),
                Strings.t("Iranian sites and apps go direct, outside the tunnel"),
                iranBypassEnabled(),
            ) {
                preferences().edit().putBoolean(MsnGuardVpnService.IRAN_BYPASS_PREF, it).apply()
                // The TUN is already up with the old route table; the exclusion
                // only takes effect on the next establish(). Reconnecting is the
                // honest way to say "this needs a second" rather than silently
                // leaving the old routing in place until the next reboot.
                if (it) toastShort(Strings.t("Reconnect to apply the new routing"))
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // PERF moved here off the home screen: a once-a-year knob does not earn
            // a quarter of the first thing the user sees.
            var perfRow: OrbitSettingsRow? = null
            perfRow = navRow(Strings.t("Performance"), perfProfile().label) {
                choosePerfProfile { perfRow?.setValue(perfProfile().label) }
            }
            body.addView(perfRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        content.addView(expandableSection(Strings.t("CONNECTION"), id = "CONNECTION") { body ->
            // Tunnel type comes FIRST in this section, above the transport picker.
            //
            // It is the most consequential switch in the app — it decides whether the
            // whole phone is tunnelled or only the apps the user points at a port —
            // and it changes what every row below it means. Burying it under Psiphon/Tor
            // detail would repeat the mistake the log-level chips made: a real decision
            // parked where nobody looks.
            tunnelTypeRow = navRow(Strings.t("Tunnel type"), tunnelTypeLabel()) { chooseTunnelType() }
            body.addView(tunnelTypeRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
            // The port box: directly under the type it belongs to, and inert until SOCKS
            // is chosen. Greyed rather than hidden, so the user can see that choosing
            // SOCKS is what unlocks it instead of a row appearing out of nowhere.
            proxyPortRow = navRow(Strings.t("SOCKS port"), proxyPortValue()) { editProxyPort() }
            body.addView(proxyPortRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // Share over LAN, directly under the port it publishes.
            //
            // Moved out of the PSIPHON section: it is not Psiphon's any more. Every
            // transport can be shared now — Psiphon in both tunnel types, MASQUE/
            // WireGuard/WoW in SOCKS mode, Tor through its own SocksPort in VPN mode —
            // so keeping it under a PSIPHON header would say the opposite of what it
            // does. It belongs next to Tunnel type and SOCKS port, which are the two
            // rows that decide what actually gets shared.
            lanSharingRow = OrbitToggleRow(
                this,
                palette,
                Strings.t("Share over LAN"),
                lanSharingSubtitle(),
                lanSharingEnabled() && lanSharingCapable(),
            ) { on ->
                preferences().edit().putBoolean(CoreConfig.LAN_SHARING_PREF, on).apply()
                ConnectionLog.record(
                    if (on) {
                        Strings.t("LAN sharing enabled — applies on the next connect")
                    } else {
                        Strings.t("LAN sharing disabled — applies on the next connect")
                    }
                )
                // Log the interface survey whenever sharing is switched on. Two builds
                // in a row advertised an unreachable address and the only evidence was
                // a screenshot of the result; this records the inputs.
                if (on) {
                    ConnectionLog.record("LAN survey: " + CoreConfig.describeLocalNetworks(this))
                }
                lanSharingRow?.setSubtitle(lanSharingSubtitle())
                refreshPsiphonRows()
        refreshShardRows()
                refreshShardRows()
            }
            body.addView(lanSharingRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // Held in a field, not a local: the mode screen is a separate page that
            // writes the preference and pops back here, so the row that shows the
            // current mode has to be repaintable from outside this builder. Without
            // that, picking a mode only appeared after leaving and re-entering
            // settings, because this row was built once with the old value.
            connectionModeRow = navRow(Strings.t("Connection mode"), selectedProtocol.label) { openModeScreen() }
            body.addView(connectionModeRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
            body.addView(navRow(Strings.t("Tunnel controls"), Strings.t("Shaping · Anti-DPI")) { openTunnelControlsScreen() }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // Log verbosity: moved here from the Logs screen, where five chips looked
            // like live filters and were in fact a build-time core setting — a tap did
            // nothing until the next connect. Here the value is visible in the row and
            // the "next connection" wording sets the expectation.
            logVerbosityRow = navRow(Strings.t("Log verbosity"), logLevel().label) { chooseLogLevel() }
            body.addView(logVerbosityRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // Both rows came off the home screen's action bar, which was removed to make
            // room for a six-transport rail. They sit under Log verbosity because that is
            // the row that decides what the log will contain.
            body.addView(navRow(Strings.t("Log"), Strings.t("What the tunnel did")) { openLogsScreen() }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // Names the two transports it applies to. As an unlabelled action-bar button
            // it looked global, and on Psiphon, Tor or SHARD there is nothing to scan —
            // those transports find their own paths.
            scannerRow = navRow(Strings.t("Scan Mode"), scanModeSummary()) { openScannerScreen() }
            body.addView(scannerRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        // Psiphon gets its own section: all three controls below are meaningless
        // unless the chain is armed, and grouping them says that structurally
        // instead of relying on the user to infer it from a mixed list.
        content.addView(expandableSection(Strings.t("PSIPHON"), id = "PSIPHON") { body ->
            // The mode row sits FIRST: it decides the dial model for every connect,
            // and the two CDN fields below only exist to feed it. Reading order
            // matches the packet — mode first, then what the chain carries.
            psiphonModeRow = navRow(Strings.t("Connection mode"), psiphonModeLabel()) {
                choosePsiphonMode()
            }
            body.addView(psiphonModeRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
            // Only reachable in CDN Fronting mode. In Auto the rows are gone, and
            // the config builder ignores whatever they hold.
            cdnEdgeIpsRow = navRow(Strings.t("CDN edge IPs"), cdnEdgeIpsLabel()) {
                editCdnEdgeIps()
            }
            body.addView(cdnEdgeIpsRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            cdnSniRow = navRow(Strings.t("CDN SNI hostnames"), cdnSniLabel()) {
                editCdnSni()
            }
            body.addView(cdnSniRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            refreshPsiphonModeRows()

            // The switch comes after the mode row because it gates the two rows
            // under it. Toggling it repaints them in place — and the home-screen
            // card too, which is the same setting shown twice and must never
            // disagree.
            //
            // Built as an OrbitToggleRow directly rather than through createToggleRow():
            // that helper returns LinearLayout, and this row has to be re-checked and
            // re-enabled from outside the builder (the home-screen card writes the same
            // preference, and the chain is only available on the PSIPHON transport).
            psiphonChainRow = OrbitToggleRow(
                this,
                palette,
                Strings.t("Psiphon over WARP"),
                Strings.t("Tunnel Psiphon inside a WARP transport"),
                // The EFFECTIVE state, not the stored preference: the key is global, but
                // this switch is Psiphon's. Showing the raw preference made the switch
                // sit lit-and-disabled on MASQUE — green, so it read as "on", while being
                // greyed, so it read as "off". Displaying the effective value makes the
                // two agree.
                chainArmed(Protocol.PSIPHON) && selectedProtocol == Protocol.PSIPHON,
            ) { armed ->
                setChainArmed(armed, Protocol.PSIPHON)
                renderChainCard()
                refreshPsiphonRows()
        refreshShardRows()
                refreshShardRows()
            }
            body.addView(psiphonChainRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })

            chainOuterRow = navRow(Strings.t("Outer transport"), chainOuterMode().label) {
                chooseChainOuterMode { chainOuterRow?.setValue(chainOuterMode().label) }
            }
            body.addView(chainOuterRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // Last of the three: the transport row decides what carries Psiphon, this
            // one decides where Psiphon comes out. Reading downwards follows the packet.
            egressRegionRow = navRow(Strings.t("Preferred country"), egressRegionLabel()) {
                chooseEgressRegion { egressRegionRow?.setValue(egressRegionLabel()) }
            }
            body.addView(egressRegionRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        // Tor section, mirroring the Psiphon one: the mode picker is the only
        // control, and it is meaningful regardless of what else is set.
        content.addView(expandableSection(Strings.t("TOR"), id = "TOR") { body ->
            torModeRowRef = navRow(Strings.t("Connection mode"), torMode().label) {
                chooseTorMode {
                    torModeRowRef?.setValue(torMode().label)
                    // The mode decides whether the chain can apply at all, so both the
                    // switch below and the home card have to be repainted after a pick —
                    // otherwise arming stays lit under a freshly pinned obfs4.
                    refreshPsiphonRows()
        refreshShardRows()
                refreshShardRows()
                    renderChainCard()
                }
            }
            body.addView(torModeRowRef, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
            // The user's own bridges, directly under the mode row that consumes them.
            //
            // Placed here rather than behind an "advanced" screen because a user who
            // has a bridge got it from somewhere and is looking for exactly this box;
            // burying it is what makes people conclude the app cannot use their bridge.
            //
            // Gated on the TOR transport exactly like every other row in this section.
            // It was briefly left live everywhere, on the theory that pasting a bridge
            // before switching Tor on is the normal order of operations — but that made
            // it the one row on a MASQUE page that looked fully interactive while
            // configuring a transport the next connect would not use, which is the same
            // lie the greyed rows exist to prevent. Nothing is lost: the mode row above
            // is gated the same way, so a user who cannot reach this box cannot reach
            // the mode that consumes it either.
            torBridgeRowRef = navRow(Strings.t("Manual bridge"), TorManualBridges.summary(this)) {
                editTorBridges()
            }
            body.addView(torBridgeRowRef, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // Tor's own chain switch, separate from Psiphon's. Placed directly under the
            // mode row because the mode is what decides whether it can apply: Direct and
            // Meek can be chained, obfs4 and Snowflake cannot, and Manual depends on
            // what the pasted lines use.
            torChainRowRef = OrbitToggleRow(
                this,
                palette,
                Strings.t("Tor over WARP"),
                Strings.t("Direct, Meek and your own bridges, inside a WARP transport"),
                chainArmed(Protocol.TOR) && selectedProtocol == Protocol.TOR &&
                    TorManager.isChainable(this, torMode()),
            ) { armed ->
                setChainArmed(armed, Protocol.TOR)
                renderChainCard()
                refreshPsiphonRows()
        refreshShardRows()
                refreshShardRows()
            }
            body.addView(torChainRowRef, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // Tor's outer transport, mirroring Psiphon's row and in the same position
            // relative to its switch: which WARP tunnel carries Tor. Writes Tor's own
            // key, so pinning WoW for Psiphon leaves Tor on Auto.
            torChainOuterRow = navRow(Strings.t("Outer transport"), torChainOuterMode().label) {
                chooseTorChainOuterMode { torChainOuterRow?.setValue(torChainOuterMode().label) }
            }
            body.addView(torChainOuterRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            // Same control as Psiphon's "Preferred country", same wording, same
            // preference-not-a-pin semantics — deliberately, because to the user it is
            // the same question. Underneath it is tor's ExitNodes with StrictNodes 0.
            torRegionRowRef = navRow(Strings.t("Preferred country"), torRegionLabel()) {
                chooseTorRegion { torRegionRowRef?.setValue(torRegionLabel()) }
            }
            body.addView(torRegionRowRef, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        // Only after BOTH sections' rows are constructed and their refs assigned.
        //
        // This call used to sit right after the Psiphon rows, where torChainRowRef
        // and torRegionRowRef were still null — so the Tor rows were built and
        // never had their availability applied, and both stayed fully live on a
        // page where MASQUE or Psiphon was the selected transport.
        //
        // It also cannot sit at the top level any more: expandableSection's body
        // runs while the section is built, so refs are assigned there — but the
        // sections below (SHARD, APPEARANCE, BACKUP, ABOUT) have not been built
        // yet at this point in the function. Nothing in them is read by
        // refreshPsiphonRows, but moving the call past the last section keeps the
        // invariant the comment describes literally true: every row the call
        // touches exists by the time it runs.
        //
        // ↓ moved to after ABOUT, see below.

        // SHARD has exactly one setting, and it is not really a setting: the node
        // list. Everything else about this transport is automatic by design — the
        // user asked for a button that connects, not a config screen — so the only
        // thing worth surfacing is whether the list is current and a way to
        // refresh it by hand when someone is standing in front of a fresh block.
        //
        // No "Over WARP" row here, unlike Psiphon and Tor. It was considered and
        // rejected: SHARD's nodes are reached over TLS on 443 through Cloudflare,
        // which is what the chain exists to achieve for Psiphon, and wrapping
        // fragmented TLS inside a second tunnel both doubles the latency and
        // destroys the fragmentation's effect — the DPI sees the outer tunnel.
        content.addView(expandableSection(Strings.t("SHARD"), id = "SHARD") { body ->
            shardPoolRow = navRow(Strings.t("Node list"), shardPoolSummary()) {
                // force = true: the whole point of tapping this is to bypass the
                // six-hour interval the background job honours.
                shardPoolRow?.setValue(Strings.t("Updating…"))
                // The policy file rides the same tap. It is what decides how many paths
                // each node has, so refreshing the node list without it would leave the
                // count in the summary computed from stale edges.
                RemotePolicy.refreshIfDue(this@MainActivity, force = true)
                // The Smart Split profiles ride the same tap: the mirror is part of
                // what makes SHARD connect, and refreshing the node list without it
                // would leave a stale fragment ladder for the next Smart Split
                // connect.
                SmartSplitSub.refreshIfDue(this@MainActivity, force = true)
                ShardSubscription.refreshIfDue(this@MainActivity, force = true) { count ->
                    runOnUiThread {
                        shardPoolRow?.setValue(shardPoolSummary())
                        toastShort(
                            if (count > 0) Strings.tf("%s nodes available", count) else Strings.t("Could not update the list")
                        )
                    }
                }
            }
            body.addView(shardPoolRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })

            // Custom Cloudflare IP row: user can enter their own Cloudflare IP and apply it
            // to all SHARD configs. When set, this IP replaces the node address in the
            // outbound config, so SHARD connects through the user's chosen edge.
            shardCustomIpRow = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(16), dp(12), dp(16), dp(12))
                background = Sculpt.sculptedBackground(
                    resources.displayMetrics.density,
                    Sculpt.recess(SURFACE, 0.16f),
                    14,
                    Sculpt.withAlpha(DIVIDER, 0.15f),
                )
            }
            val customIpRow = shardCustomIpRow!!
            val customIpTitle = TextView(this).apply {
                text = Strings.t("Enter Your Cloudflare IP")
                textSize = 13.5f
                typeface = Typefaces.medium(this@MainActivity)
                if (AppLanguage.current() != "en") {
                    setLineSpacing(0f, Typefaces.lineHeightMult())
                }
                setTextColor(INK)
            }
            customIpRow.addView(customIpTitle)

            val customIpSubtitle = TextView(this).apply {
                text = Strings.t("This IP will replace all node addresses in SHARD configs")
                textSize = 10.5f
                setTextColor(MUTED)
                setPadding(0, dp(2), 0, dp(8))
            }
            customIpRow.addView(customIpSubtitle)

            val inputRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val customIpInput = EditText(this).apply {
                hint = "e.g. 104.16.0.1"
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                    rightMargin = dp(8)
                }
                // Load current value if set
                val prefs = profiled()
                val current = prefs.getString("shard_custom_cf_ip", "")?.trim().orEmpty()
                if (current.isNotEmpty()) setText(current)
                setBackground(Sculpt.sculptedBackground(
                    resources.displayMetrics.density,
                    Sculpt.recess(SURFACE, 0.16f),
                    8,
                    Sculpt.withAlpha(DIVIDER, 0.15f),
                ))
                setPadding(dp(12), dp(10), dp(12), dp(10))
                setTextColor(INK)
                setHintTextColor(MUTED)
                setSingleLine(true)
            }
            inputRow.addView(customIpInput)

            val applyButton = TextView(this).apply {
                text = Strings.t("Apply")
                textSize = 12f
                typeface = Typefaces.medium(this@MainActivity)
                if (AppLanguage.current() != "en") {
                    setLineSpacing(0f, Typefaces.lineHeightMult())
                }
                gravity = Gravity.CENTER
                setTextColor(palette.mint)
                setPadding(dp(16), dp(10), dp(16), dp(10))
                setBackground(Sculpt.sculptedBackground(
                    resources.displayMetrics.density,
                    Sculpt.withAlpha(palette.mint, 0.12f),
                    8,
                    Sculpt.withAlpha(palette.mint, 0.3f),
                ))
                isClickable = true
                isFocusable = true
                setOnClickListener {
                    val ip = customIpInput.text.toString().trim()
                    val prefs = profiled().edit()
                    if (ip.isEmpty()) {
                        prefs.remove("shard_custom_cf_ip")
                    } else {
                        // Basic validation: must be an IP address format
                        if (ip.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) {
                            val octets = ip.split(".").map { it.toIntOrNull() ?: -1 }
                            if (octets.all { it in 0..255 }) {
                                prefs.putString("shard_custom_cf_ip", ip)
                                toastShort(Strings.tf("Custom Cloudflare IP applied: %s", ip))
                            } else {
                                toastShort(Strings.t("Invalid IP address"))
                                return@setOnClickListener
                            }
                        } else {
                            toastShort(Strings.t("Invalid IP format (use IPv4)"))
                            return@setOnClickListener
                        }
                    }
                    prefs.apply()
                    if (ip.isEmpty()) toastShort(Strings.t("Custom IP cleared"))
                }
            }
            inputRow.addView(applyButton)
            customIpRow.addView(inputRow)
            body.addView(customIpRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })

            // The home-screen card's mirror, for the same reason the Psiphon chain has
            // one: someone looking for a feature they saw on the main screen looks in
            // settings, and a control that exists in only one of the two places reads as
            // a bug. Both write the same key through [setSmartSplitEnabled].
            // Built as an OrbitToggleRow directly, not through createToggleRow(): that
            // helper returns LinearLayout, and this row's subtitle has to be rewritten
            // from outside the builder — the measurement it reports changes on connect
            // and when the user clears it.
            smartSplitRow = OrbitToggleRow(
                this,
                palette,
                Strings.t("Smart Split"),
                SmartSplit.summary(this),
                SmartSplit.enabled(this),
            ) { on ->
                setSmartSplitEnabled(on)
                smartSplitRow?.setSubtitle(SmartSplit.summary(this))
                renderChainCard()
            }
            body.addView(smartSplitRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })

            // The escape hatch for a wrong measurement, and the only reason the user
            // ever needs to know a measurement happened at all. A carrier that changes
            // its DPI, or a cached "not effective here" from a bad minute on the
            // network, would otherwise be sticky until the app's data is cleared.
            shardReMeasureRow = navRow(Strings.t("Re-measure network"), "") {
                SmartSplit.forgetMeasurements(this)
                smartSplitRow?.setSubtitle(SmartSplit.summary(this))
                renderChainCard()
                toastShort(Strings.t("Will re-measure on the next connect"))
            }
            body.addView(shardReMeasureRow!!, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        // APPEARANCE, like BACKUP below it, is about the app rather than about a
        // tunnel, so it sits out here and not under Tunnel Controls.
        content.addView(expandableSection(Strings.t("APPEARANCE"), id = "APPEARANCE") { body ->
            // No stored reference: picking a theme calls recreate(), so the row is
            // rebuilt with the new value rather than being repainted in place.
            body.addView(navRow(Strings.t("Theme"), AppAppearance.mode(this@MainActivity).label) { chooseTheme() }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
            // Language sits directly under Theme: both are appearance-scale choices
            // that repaint the whole app via recreate(). No stored reference for
            // the same reason — the settings page is rebuilt, not repainted.
            body.addView(navRow(Strings.t("Language"), AppLanguage.label(currentLanguagePref())) { chooseLanguage() }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        // BACKUP sits outside Tunnel Controls, next to ABOUT: it is about the
        // app's own state, not about how a tunnel is shaped, and burying it in a
        // troubleshooting sub-page is where a user would never look for it after
        // reinstalling.
        content.addView(expandableSection(Strings.t("BACKUP"), id = "BACKUP") { body ->
            settingsBackupRow = navRow(Strings.t("Back up settings"), backupSummary()) { exportSettings() }
            body.addView(settingsBackupRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
            body.addView(navRow(Strings.t("Restore settings"), Strings.t("From a backup file")) { importSettings() }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            body.addView(navRow(Strings.t("Reset to defaults"), Strings.t("Forget every setting")) { confirmResetSettings() }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        content.addView(expandableSection(Strings.t("ABOUT"), id = "ABOUT") { body ->
            body.addView(navRow(Strings.t("Check for updates"), "v${appVersion()}") {
                appUpdater.checkForUpdate()
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10) })
            body.addView(navRow(Strings.t("Source on GitHub"), iconRes = R.drawable.ic_github) {
                openLink("https://github.com/mbm110/MSN-GUARD")
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            body.addView(navRow(Strings.t("Telegram Channel"), iconRes = R.drawable.ic_telegram) {
                openLink("https://t.me/MSN_GUARD")
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(8) })
            body.addView(label("MSN-GUARD ${appVersion()}", 11.5f, Sculpt.withAlpha(MUTED, 0.7f)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                letterSpacing = spacing(0.06f)
                setPadding(0, dp(22), 0, 0)
            })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        // Now every row refreshPsiphonRows touches — Psiphon's three and Tor's
        // five — has been built and its ref assigned by the sections above.
        refreshPsiphonRows()
        refreshShardRows()

        scroll.addView(content)
        page.addView(scroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ).apply { topMargin = dp(56) })
        page.addView(header, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(48),
            Gravity.TOP,
        ).apply { leftMargin = dp(24); rightMargin = dp(24); topMargin = dp(8) })

        page.setOnApplyWindowInsetsListener { _, insets ->
            (scroll.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(56)
                bottomMargin = insets.systemWindowInsetBottom
                scroll.layoutParams = this
            }
            (header.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(8)
                header.layoutParams = this
            }
            insets
        }

        settingsPage = page
        pageHost.addView(page, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ))
        page.requestApplyInsets()
        if (animate) {
            animatePageOpen(page)
            // Ordering matters and is the whole fix: refreshPsiphonRows() ran at the
            // end of the builder above, so every row already carries its real
            // isEnabled state, and staggerListItems reads that state to pick each
            // row's target opacity. Re-asserting availability AFTER this call would
            // be worse than redundant — setAvailable cancels a running animation, so
            // it would snap the enabled rows to full opacity while the ungated ones
            // (labels, section headers) kept fading, which looks like a broken page.
            staggerListItems(content)
        }
    }

    private fun openTunnelControlsScreen() {
        tunnelControlsPage?.let(pageHost::removeView)

        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val scroll = ScrollView(this).apply { isVerticalScrollBarEnabled = false }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(24))
        }
        content.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { closeTunnelControlsScreen() }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(label(Strings.t("Tunnel controls"), 22f, INK, TypefaceStyle.MEDIUM))
        })
        content.addView(label(Strings.t("Applied on your next connection"), 13.5f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(22) })
        // Title and current value are separate columns now, so a long value
        // (a manual endpoint) truncates on its own instead of shoving the title.
        fun addControl(title: String, value: String?, action: () -> Unit): OrbitSettingsRow =
            navRow(title, value, onClick = action).also { row ->
                content.addView(row, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = dp(9) })
            }
        // The sub-page's own sections get expandable bodies. Each carries its own
        // state, same as the main settings page. The rows are nullable locals
        // because their click handlers read them back after a user pick — a
        // lateinit local cannot be captured before assignment without crashing.
        var obfRow: OrbitSettingsRow? = null
        var retryRow: OrbitSettingsRow? = null
        content.addView(expandableSection(Strings.t("CONNECTION SHAPING"), id = "CONNECTION SHAPING") { body ->
            obfRow = navRow(Strings.t("Obfuscation"), obfuscationProfile().label) {
                chooseObfuscation { obfRow?.setValue(obfuscationProfile().label) }
            }
            body.addView(obfRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
            body.addView(navRow(Strings.t("Advanced obfuscation"), advancedObfuscationSummary()) { editAdvancedObfuscation() }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
            retryRow = navRow(Strings.t("WireGuard retries"), if (retryObfuscationProfiles()) Strings.t("On") else Strings.t("Off")) {
                preferences().edit().putBoolean(RETRY_OBFUSCATION, !retryObfuscationProfiles()).apply()
                retryRow?.setValue(if (retryObfuscationProfiles()) Strings.t("On") else Strings.t("Off"))
            }
            body.addView(retryRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        content.addView(expandableSection(Strings.t("ROUTING"), id = "ROUTING") { body ->
            // v1.9.8: assign to the class fields, not local vals. A previous build
            // declared `val manualEndpointRow` here, which shadowed the field —
            // later setValue() calls hit a null field and the displayed value never
            // refreshed until the screen was rebuilt.
            manualEndpointRow = navRow(Strings.t("Manual endpoint"), manualEndpoint() ?: Strings.t("Automatic")) { editManualEndpoint() }
            body.addView(manualEndpointRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
            // The inner hop of a nested transport. Hidden unless the user picked
            // one: on a single-hop protocol the row is meaningless, and showing a
            // control that cannot do anything is worse than not having it.
            innerEndpointRow = navRow(Strings.t("Inner hop endpoint"), manualInnerEndpoint() ?: Strings.t("Same as outer")) { editInnerEndpoint() }
            body.addView(innerEndpointRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
            gatewayCacheRow = navRow(Strings.t("Gateway cache"), defaultEndpointDiscovery().label) { manageGatewayCache() }
            body.addView(gatewayCacheRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
            // The "my exit is stuck on Iran" lever. Wipes the saved WARP/MASQUE
            // registrations so the core enrolls fresh accounts on the next connect —
            // a different device id can land on a different anycast egress.
            // Manual endpoint stays: the user pinned it by hand.
            body.addView(navRow(Strings.t("Reset identity"), Strings.t("New account")) {
                confirmResetIdentities()
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
            // v2.0.0: the AI Mode row is gone. The Smart DNS Split engine it
            // toggled never produced a working Gemini lookup in the field, and
            // the DNS screen now owns resolver configuration outright.
            dnsRow = navRow(Strings.t("Custom DNS"), customDnsLabel()) {
                openDnsScreen()
            }
            body.addView(dnsRow!!, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })

        content.addView(expandableSection(Strings.t("TROUBLESHOOTING"), id = "TROUBLESHOOTING") { body ->
            // Local rows, not class fields: nothing outside this sub-page repaints
            // them, so the fields the originals used were never written from anywhere
            // else either — keeping the same shape as locals is the minimal change.
            var tlsRow: OrbitSettingsRow? = null
            tlsRow = navRow(Strings.t("TLS fingerprint"), tlsCurvePreset().label) {
                chooseTlsCurvePreset { tlsRow?.setValue(tlsCurvePreset().label) }
            }
            body.addView(tlsRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
            var verificationRow: OrbitSettingsRow? = null
            verificationRow = navRow(Strings.t("WireGuard verification"), if (wireGuardDataCheck()) Strings.t("Strict") else Strings.t("Fast")) {
                preferences().edit().putBoolean(WIREGUARD_DATA_CHECK, !wireGuardDataCheck()).apply()
                verificationRow?.setValue(if (wireGuardDataCheck()) Strings.t("Strict") else Strings.t("Fast"))
            }
            body.addView(verificationRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        // The "VPN CORE" section is gone. It held DNS resolvers, Destination
        // routing, and Zero Trust — all three are proxy-mode features:
        //
        //   * DNS resolvers   -> socks.rs::resolver_addresses(), and socks::serve
        //                        never runs in VPN mode (tun::bridge takes its
        //                        place). The device's real resolvers come from
        //                        applyDns() on the Builder.
        //   * Dest. routing   -> RuleSet::from_env(), read only from socks.rs.
        //   * Zero Trust      -> Cloudflare organization accounts, unused here.
        //
        // The underlying prefs and the core's env bridge are untouched, so the
        // knobs still exist for the CLI; they are simply no longer surfaced as
        // settings that silently do nothing on this device.
        content.addView(expandableSection(Strings.t("ANTI-DPI"), id = "ANTI-DPI") { body ->
            var fragRow: OrbitSettingsRow? = null
            fragRow = navRow(Strings.t("TLS fragmentation"), if (h2Fragmentation() == H2Fragmentation.ON) Strings.t("On") else Strings.t("Off")) {
                chooseH2Fragmentation {
                    fragRow?.setValue(if (h2Fragmentation() == H2Fragmentation.ON) Strings.t("On") else Strings.t("Off"))
                }
            }
            body.addView(fragRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
            // Mixed-case SNI (L×Box spec 028): randomise the casing of the SNI on
            // every ClientHello. A single toggle, because there is nothing to tune
            // — it is either changing the bytes on the wire or it is not.
            var sniRow: OrbitSettingsRow? = null
            sniRow = navRow(Strings.t("Mixed-case SNI"), if (mixedCaseSni()) Strings.t("On") else Strings.t("Off")) {
                chooseMixedCaseSni {
                    sniRow?.setValue(if (mixedCaseSni()) Strings.t("On") else Strings.t("Off"))
                }
            }
            body.addView(sniRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(9) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        scroll.addView(content)
        page.addView(scroll)
        page.setOnApplyWindowInsetsListener { _, insets ->
            content.setPadding(dp(24), insets.systemWindowInsetTop + dp(16), dp(24), insets.systemWindowInsetBottom + dp(24))
            insets
        }
        tunnelControlsPage = page
        pageHost.addView(page)
        page.requestApplyInsets()
        content.alpha = 0f
        content.translationY = dp(12).toFloat()
        page.alpha = 0f
        page.translationX = dp(20).toFloat()
        page.animate().alpha(1f).translationX(0f).setDuration(PAGE_ANIMATION_MS)
            .setInterpolator(motionInterpolator)
            .start()
        content.animate().alpha(1f).translationY(0f).setStartDelay(70)
            .setDuration(PAGE_ANIMATION_MS)
            .setInterpolator(motionInterpolator)
            .start()
    }

    private fun closeTunnelControlsScreen(animate: Boolean = true) {
        val page = tunnelControlsPage ?: return
        tunnelControlsPage = null
        if (!animate) {
            pageHost.removeView(page)
            return
        }
        page.animate().alpha(0f).translationX(dp(20).toFloat())
            .setDuration(LOG_CLOSE_ANIMATION_MS)
            .setInterpolator(DecelerateInterpolator())
            .withEndAction { if (page.parent == pageHost) pageHost.removeView(page) }
            .start()
    }

    private fun chooseObfuscation(after: (() -> Unit)? = null) {
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Obfuscation"), 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(Strings.t("Adjust traffic-shape padding for filtered networks"), 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        val options = mutableMapOf<ObfuscationProfile, SelectionOption>()
        ObfuscationProfile.entries.forEachIndexed { index, profile ->
            val title = label(profile.label, 16f, INK, TypefaceStyle.MEDIUM)
            val indicator = label(Strings.t("SELECTED"), 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = spacing(0.08f) }
            val row = LinearLayout(this).apply {
                gravity = Gravity.CENTER_VERTICAL
                orientation = LinearLayout.HORIZONTAL
                setPadding(dp(18), 0, dp(18), 0)
                isClickable = true
                isFocusable = true
                val labels = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
                labels.addView(title)
                labels.addView(label(profile.description, 13f, MUTED), LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = dp(2) })
                addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(indicator, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { leftMargin = dp(12) })
                setOnClickListener {
                    preferences().edit().putString(OBFUSCATION_PROFILE, profile.coreName).apply()
                    options.forEach { (item, option) -> setSelectionState(option, item == profile, animate = true) }
                    after?.invoke()
                }
            }
            val option = SelectionOption(row, title, indicator, 18)
            options[profile] = option
            setSelectionState(option, profile == obfuscationProfile(), animate = false)
            sheet.addView(row, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(72),
            ).apply { topMargin = if (index == 0) 0 else dp(8) })
        }
        dialog.setContentView(FrameLayout(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    private fun chooseTlsCurvePreset(after: (() -> Unit)? = null) = showChoiceSheet(
        title = Strings.t("TLS fingerprint"),
        subtitle = Strings.t("Choose TLS curve ordering for QUIC connections"),
        options = TlsCurvePreset.entries.toList(),
        selected = tlsCurvePreset(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit().putString(TLS_CURVE_PRESET, chosen.coreName).apply()
        after?.invoke()
    }

    private fun choosePerfProfile(after: (() -> Unit)? = null) = showChoiceSheet(
        title = Strings.t("Performance"),
        subtitle = Strings.t("Scale scan concurrency and buffers to match your hardware"),
        options = PerfProfile.entries.toList(),
        selected = perfProfile(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit().putString(PERF_PROFILE, chosen.coreName).apply()
        after?.invoke()
    }

    /**
     * Which transport the chain pins for its outer leg, or Auto.
     *
     * Reads through [CoreConfig.chainOuterCandidates] rather than the raw preference,
     * so an unknown or stale stored value resolves to AUTO in exactly the same way
     * the service resolves it. The two must never disagree: the settings row would
     * then show a pin the connect path ignores.
     */
    private fun chainOuterMode(): ChainOuterMode {
        val candidates = CoreConfig.chainOuterCandidates(this)
        if (candidates.size > 1) return ChainOuterMode.AUTO
        return ChainOuterMode.entries.firstOrNull { it.coreName == candidates.first() }
            ?: ChainOuterMode.AUTO
    }

    private fun lanSharingEnabled(): Boolean =
        preferences().getBoolean(CoreConfig.LAN_SHARING_PREF, false)

    /**
     * Subtitle for the LAN-sharing switch.
     *
     * Carries the actual address and both ports when sharing is on, so the user does
     * not have to know or remember them — the whole point of the row is that they
     * can read it off and type it into Windows. States the exposure when off, since
     * that is the decision they are being asked to make.
     */
    private fun lanSharingSubtitle(): String {
        if (!lanSharingCapable()) {
            // Say what to change, not just that it is unavailable. The one transport
            // that cannot share in SOCKS mode is Tor, and the one combination that
            // cannot share at all is a WARP transport in VPN mode — where the core
            // binds no listener because it is driving the TUN directly.
            return if (selectedProtocol == Protocol.TOR && CoreConfig.proxyOnly(this)) {
                Strings.t("Tor cannot run as a SOCKS proxy — set Tunnel type to VPN")
            } else if (selectedProtocol == Protocol.SHARD) {
                Strings.t("SHARD shares from VPN mode — set Tunnel type to VPN")
            } else {
                Strings.tf("Set Tunnel type to SOCKS proxy to share %s", selectedProtocol.label)
            }
        }
        if (!lanSharingEnabled()) {
            return Strings.t("Let other devices use this tunnel")
        }
        val host = CoreConfig.localNetworkAddress(this)
            ?: return Strings.t("No local network — turn on the hotspot or join Wi-Fi")
        // SHARD's listener is xray's own, on its own port. CoreConfig.sharedSocksPort
        // answers for the Rust core and Psiphon and would print 1819 here — a port
        // nothing is listening on during a SHARD session, so anyone who typed it
        // into another device would get a refused connection and no explanation.
        val socksPort = if (selectedProtocol == Protocol.SHARD) {
            ShardManager.SOCKS_PORT
        } else {
            CoreConfig.sharedSocksPort(this)
        }
        return Strings.tf("SOCKS5 %s · HTTP %s · no password",
            "$host:$socksPort", "$host:${CoreConfig.HTTP_PROXY_PORT}")
    }

    /**
     * Whether the selected transport can publish a listener on the LAN at all.
     *
     * Per transport, because each reaches the network differently:
     *
     *  - PSIPHON: always. Its Go controller binds the listener in both tunnel types
     *    (1819 in VPN mode, the user's port in SOCKS mode) and `ListenInterface:
     *    "any"` moves it off loopback.
     *  - TOR: only in VPN mode, which is also the only mode Tor supports. The torrc
     *    adds a second SocksPort plus an HTTPTunnelPort on 0.0.0.0, restricted to
     *    private ranges by SocksPolicy.
     *  - MASQUE / WireGuard / WoW: only in SOCKS mode. In VPN mode the core takes the
     *    `tun_fd` branch and binds nothing, so there is genuinely nothing to share —
     *    which is what the old "Psiphon only" wording was really describing.
     */
    private fun lanSharingCapable(): Boolean = when (selectedProtocol) {
        Protocol.PSIPHON -> true
        Protocol.TOR -> !CoreConfig.proxyOnly(this)
        // VPN mode only, and that is not a limitation — SHARD has no proxy mode at
        // all (the service refuses it, for want of a byte counter in the path).
        // xray binds its SOCKS and HTTP inbounds to 0.0.0.0 while tun2socks keeps
        // dialling loopback, so the phone stays fully routed while a Windows machine
        // uses the same tunnel.
        Protocol.SHARD -> !CoreConfig.proxyOnly(this)
        else -> CoreConfig.proxyOnly(this)
    }

    /** Tor's outer-transport pin, read from Tor's own key. */
    private fun torChainOuterMode(): ChainOuterMode {
        val candidates = CoreConfig.chainOuterCandidates(this, forTor = true)
        if (candidates.size > 1) return ChainOuterMode.AUTO
        return ChainOuterMode.entries.firstOrNull { it.coreName == candidates.first() }
            ?: ChainOuterMode.AUTO
    }

    /**
     * Same sheet as Psiphon's, writing Tor's key.
     *
     * Deliberately a separate function rather than a parameterised one: the log line
     * and the preference key both differ, and threading a boolean through would make
     * the two call sites read as if they shared state, which is the bug this whole
     * split exists to avoid.
     */
    private fun chooseTorChainOuterMode(after: (() -> Unit)? = null) = showChoiceSheet(
        title = Strings.t("Outer transport"),
        subtitle = Strings.t("Which WARP tunnel carries Tor in Tor over WARP"),
        options = ChainOuterMode.entries.toList(),
        selected = torChainOuterMode(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit()
            .putString(CoreConfig.CHAIN_OUTER_MODE_TOR_PREF, chosen.coreName)
            .apply()
        ConnectionLog.record(
            if (chosen == ChainOuterMode.AUTO) {
                "Tor-over-WARP outer transport set to Auto"
            } else {
                "Tor-over-WARP outer transport pinned to ${chosen.label}"
            }
        )
        renderChainCard()
        after?.invoke()
    }

    private fun chooseChainOuterMode(after: (() -> Unit)? = null) = showChoiceSheet(
        title = Strings.t("Outer transport"),
        subtitle = Strings.t("Which WARP tunnel carries Psiphon in Psiphon over WARP"),
        options = ChainOuterMode.entries.toList(),
        selected = chainOuterMode(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit()
            .putString(CoreConfig.CHAIN_OUTER_MODE_PREF, chosen.coreName)
            .apply()
        ConnectionLog.record(
            if (chosen == ChainOuterMode.AUTO) {
                "Psiphon-over-WARP outer transport set to Auto"
            } else {
                "Psiphon-over-WARP outer transport pinned to ${chosen.label}"
            }
        )
        // The card's subtitle names the transport, so it has to be repainted.
        renderChainCard()
        after?.invoke()
    }

    /**
     * The user's Tor connection mode, defaulting to [TorManager.TorMode.AUTO].
     */
    private fun torMode(): TorManager.TorMode = TorManager.selectedMode(this)

    /**
     * Psiphon's connection mode: Auto (the ladder and Psiphon's own tactics,
     * everything as it was before this setting existed) or CDN Fronting only.
     *
     * The choice sheet mirrors Shirokhorshid's protocol-selection preference,
     * narrowed to the two options that make sense here: this app has no Conduit
     * relays of its own, and "Direct" is already what rung D of the ladder does.
     */
    private fun choosePsiphonMode(after: (() -> Unit)? = null) = showChoiceSheet(
        title = Strings.t("Connection mode"),
        subtitle = Strings.t("Choose how the app connects to servers"),
        options = listOf(CoreConfig.PSIPHON_MODE_AUTO, CoreConfig.PSIPHON_MODE_CDN),
        selected = CoreConfig.psiphonConnectionMode(this),
        label = { if (it == CoreConfig.PSIPHON_MODE_CDN) Strings.t("CDN Fronting") else Strings.t("Automatic") },
        description = { mode ->
            if (mode == CoreConfig.PSIPHON_MODE_CDN) {
                Strings.t("CDN Fronting - Use CDN fronting only")
            } else {
                Strings.t("Auto - The app chooses the best protocol, including CDN fronting")
            }
        },
    ) { chosen ->
        preferences().edit()
            .putString(CoreConfig.PSIPHON_MODE_PREF, chosen)
            .apply()
        ConnectionLog.record(
            if (chosen == CoreConfig.PSIPHON_MODE_CDN) {
                "Psiphon connection mode: CDN Fronting only"
            } else {
                "Psiphon connection mode: Auto"
            }
        )
        refreshPsiphonModeRows()
        after?.invoke()
    }

    /**
     * Repaints the mode row and toggles the two CDN field rows.
     *
     * The fields are only meaningful in CDN Fronting mode, so they are hidden in
     * Auto. Hiding is deliberate rather than disabling: a disabled row invites
     * the user to tap it, and there is nothing to type until the mode is on.
     */
    private fun refreshPsiphonModeRows() {
        // The three rows above the chain switch are Psiphon's dial model. On any
        // other transport they are inert — WoW/MASQUE/WireGuard never read them —
        // and leaving them lit made a WoW user think they had a connection mode.
        // Greyed rather than hidden: the section still shows what Psiphon offers,
        // but nothing under it can be set while another transport is selected.
        val psiphonSelected = selectedProtocol == Protocol.PSIPHON
        psiphonModeRow?.apply {
            setValue(psiphonModeLabel())
            setAvailable(psiphonSelected)
        }
        val cdn = psiphonSelected && CoreConfig.isCdnFronting(this)
        cdnEdgeIpsRow?.apply {
            visibility = if (cdn) View.VISIBLE else View.GONE
            setAvailable(cdn)
        }
        cdnSniRow?.apply {
            visibility = if (cdn) View.VISIBLE else View.GONE
            setAvailable(cdn)
        }
    }

    private fun editCdnEdgeIps() {
        editMultilineField(
            title = Strings.t("CDN edge IPs"),
            hint = Strings.t("e.g. 23.215.0.206, 23.12.147.13/32"),
            description = Strings.t(
                "Optional extra CDN edge IPs or CIDRs separated by commas, spaces, or new lines. " +
                    "Tried before the built-in list."
            ),
            current = CoreConfig.cdnEdgeIps(this),
            pref = CoreConfig.PSIPHON_CDN_IPS_PREF,
            row = cdnEdgeIpsRow,
            after = { cdnEdgeIpsRow?.setValue(cdnEdgeIpsLabel()) },
        )
    }

    private fun editCdnSni() {
        editMultilineField(
            title = Strings.t("CDN SNI hostnames"),
            hint = Strings.t("e.g. a.akamaized.net, www.fastly.com"),
            description = Strings.t(
                "Optional extra SNI hostnames separated by commas, spaces, or new lines. " +
                    "No-SNI variants are also tested."
            ),
            current = CoreConfig.cdnSniHostnames(this),
            pref = CoreConfig.PSIPHON_CDN_SNI_PREF,
            row = cdnSniRow,
            after = { cdnSniRow?.setValue(cdnSniLabel()) },
        )
    }

    /**
     * Shared text editor for the two CDN fields. Both accept a free-form list, so
     * they share one dialog — multiline, since these are lists and a single-line
     * field would hide everything after the first entry.
     */
    private fun editMultilineField(
        title: String,
        hint: String,
        description: String,
        current: String,
        pref: String,
        row: OrbitSettingsRow?,
        after: () -> Unit,
    ) {
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val field = EditText(this).apply {
            setText(current)
            this.hint = hint
            setTextColor(INK)
            setHintTextColor(MUTED)
            setSingleLine(false)
            setLines(4)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            setPadding(dp(18), dp(12), dp(18), dp(12))
            background = roundedBackground(SURFACE_VARIANT, 16, SURFACE_VARIANT)
        }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(title, 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(description, 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        sheet.addView(field, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { height = dp(140) })
        val buttons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        buttons.addView(createSettingsButton(Strings.t("Clear")) {
            preferences().edit().remove(pref).apply()
            field.setText("")
            after()
        }, LinearLayout.LayoutParams(0, dp(52), 1f))
        buttons.addView(createSettingsButton(Strings.t("Save")) {
            preferences().edit().putString(pref, field.text.toString()).apply()
            after()
            dialog.dismiss()
        }, LinearLayout.LayoutParams(0, dp(52), 1f).apply { leftMargin = dp(10) })
        sheet.addView(buttons, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)).apply { topMargin = dp(16) })
        dialog.setContentView(FrameLayout(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    /**
     * Pick how Tor connects.
     *
     * Auto walks Direct → obfs4 → Meek → Snowflake on every connect, starting
     * from whichever worked last. A pinned mode is exactly that: one method, no
     * silent fallback — the service surfaces "try Auto" in its error instead.
     */
    private fun chooseTorMode(after: (() -> Unit)? = null) {
        val modes = TorManager.TorMode.entries.toList()
        showChoiceSheet(
            title = Strings.t("Connection mode"),
            subtitle = Strings.t("How Tor reaches the network. Auto tries each method until one works."),
            options = modes,
            selected = torMode(),
            label = { it.label },
            description = { mode ->
                // Manual's description carries its own state, because picking it
                // with an empty box is the one choice in this sheet that cannot
                // work — and the sheet is where the user decides.
                if (mode == TorManager.TorMode.MANUAL && !TorManualBridges.isConfigured(this)) {
                    Strings.t("Enter a bridge first, in the row below this one")
                } else if (mode == TorManager.TorMode.MANUAL) {
                    TorManualBridges.summary(this)
                } else {
                    mode.description
                }
            },
            scrollable = false,
            // Refused rather than saved: a pinned Manual with nothing to use makes
            // tor reject its own config, so the connect would fail with a message
            // about bridges the user never saw a chance to enter. Refusing here
            // also leaves the SELECTED marker where it was, so the sheet keeps
            // telling the truth about which mode is stored.
            refuse = { chosen ->
                if (chosen == TorManager.TorMode.MANUAL && !TorManualBridges.isConfigured(this)) {
                    editTorBridges()
                    Strings.t("Enter a bridge in Manual bridge first")
                } else {
                    null
                }
            },
        ) { chosen ->
            preferences().edit().putString(TorManager.MODE_PREF, chosen.key).apply()
            ConnectionLog.record(
                if (chosen == TorManager.TorMode.AUTO) {
                    Strings.t("Tor connection mode set to Auto")
                } else {
                    "Tor connection mode pinned to ${chosen.label}"
                }
            )
            after?.invoke()
        }
    }

    /**
     * The manual bridge editor.
     *
     * A multi-line box and nothing else, because that is the shape of the thing
     * users hold: bridge lines arrive as two or three lines of text from BridgeDB
     * mail, a Telegram channel or a friend, and any per-field form would have them
     * dismantling a line by hand. [TorManualBridges.validate] enforces what tor
     * actually accepts, and its messages name the specific defect — a hostname
     * where tor demands a numeric address, an obfs4 line whose `cert=` was lost to
     * a line wrap — because "invalid bridge" tells a user nothing they can act on.
     *
     * Saving does not switch Tor to Manual. Storing a bridge and deciding to use it
     * are separate acts, and silently repinning the transport under someone who was
     * only pasting for later is the kind of surprise this app avoids; the toast
     * points at the mode row instead.
     */
    private fun editTorBridges() {
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val field = settingsField(
            value = TorManualBridges.raw(this),
            hintText = "obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0",
            multiline = true,
        ).apply {
            // Bridge lines are case-sensitive base64 and hex; autocorrect and
            // auto-capitalisation would quietly corrupt a pasted cert.
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setHorizontallyScrolling(false)
            maxLines = 8
        }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Manual bridge"), 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(
            Strings.t("One bridge per line, exactly as you received it. obfs4, meek_lite, webtunnel and snowflake are supported, as is a plain IP:port."),
            14f, MUTED,
        ), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(16) })
        sheet.addView(field, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(132),
        ))
        val buttons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        buttons.addView(createSettingsButton(Strings.t("Clear")) {
            TorManualBridges.save(this, "")
            field.setText("")
            // A cleared box cannot back a pinned Manual mode, so the pin goes with
            // it rather than being left to fail at the next connect.
            if (torMode() == TorManager.TorMode.MANUAL) {
                preferences().edit()
                    .putString(TorManager.MODE_PREF, TorManager.TorMode.AUTO.key).apply()
                ConnectionLog.record("Manual bridges cleared — Tor mode back to Auto")
            }
            torBridgeRowRef?.setValue(TorManualBridges.summary(this))
            torModeRowRef?.setValue(torMode().label)
            refreshPsiphonRows()
        refreshShardRows()
            renderChainCard()
        }, LinearLayout.LayoutParams(0, dp(52), 1f))
        buttons.addView(createSettingsButton(
            Strings.t("Save"),
            backgroundOverride = primary,
            textColorOverride = primaryContainer,
        ) {
            val text = field.text.toString()
            TorManualBridges.validate(text)?.let { problem ->
                field.error = problem
                toastShort(problem)
                return@createSettingsButton
            }
            TorManualBridges.save(this, text)
            val parsed = TorManualBridges.bridges(this)
            ConnectionLog.record(
                "Manual bridges saved: ${parsed.size} line(s), " +
                    parsed.map { it.transport ?: "plain" }.distinct().joinToString(", ")
            )
            torBridgeRowRef?.setValue(TorManualBridges.summary(this))
            // A saved change can make a pinned Manual chainable or not — a pasted
            // snowflake line cannot ride inside WARP — so both the switch and the
            // home card are repainted before the sheet closes.
            refreshPsiphonRows()
        refreshShardRows()
            renderChainCard()
            dialog.dismiss()
            if (torMode() != TorManager.TorMode.MANUAL) {
                toastShort(Strings.t("Saved — set Connection mode to Manual bridge to use it"))
            } else {
                toastShort(Strings.t("Saved — applies on the next connect"))
            }
        }, LinearLayout.LayoutParams(0, dp(52), 1f).apply { leftMargin = dp(10) })
        sheet.addView(buttons, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(52),
        ).apply { topMargin = dp(16) })
        dialog.setContentView(ScrollView(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    /**
     * The preferred Tor exit country, or "auto".
     */
    private fun torRegion(): String = TorRegions.selected(this) ?: TorRegions.AUTO

    /** What the settings row shows: "Automatic" or "🇩🇪 Germany". */
    private fun torRegionLabel(): String {
        val code = torRegion()
        return if (code == TorRegions.AUTO) Strings.t("Automatic") else TorRegions.label(code)
    }

    /**
     * Pick the country Tor should try to exit in.
     *
     * Worded as a preference throughout, because that is what it is: the torrc
     * gets `ExitNodes {cc}` with `StrictNodes 0`, so tor leaves the country when
     * it cannot build a circuit there. A hard pin would mean no connection at all
     * on a country whose handful of exits are down, which is a worse outcome than
     * exiting somewhere else.
     *
     * Only countries with at least five running exit relays are offered — see
     * [TorRegions]. Below that the preference is honoured so rarely that the
     * control would be theatre.
     */
    private fun chooseTorRegion(after: (() -> Unit)? = null) {
        val options = listOf(TorRegions.AUTO) + TorRegions.options()
        showChoiceSheet(
            title = Strings.t("Preferred country"),
            subtitle = Strings.t("Tor tries to exit here. If it cannot, another country is used."),
            options = options,
            selected = torRegion(),
            label = { code ->
                if (code == TorRegions.AUTO) Strings.t("Automatic") else TorRegions.label(code)
            },
            description = { code ->
                if (code == TorRegions.AUTO) {
                    Strings.t("Fastest — Tor picks from every exit relay")
                } else {
                    TorRegions.detail(code)
                }
            },
            scrollable = true,
        ) { chosen ->
            preferences().edit().putString(TorRegions.REGION_PREF, chosen).apply()
            ConnectionLog.record(
                if (chosen == TorRegions.AUTO) {
                    Strings.t("Tor exit country cleared — Tor chooses")
                } else {
                    "Tor exit country set to ${TorRegions.name(chosen)} ($chosen)"
                }
            )
            after?.invoke()
        }
    }

    private fun chooseH2Fragmentation(after: (() -> Unit)? = null) = showChoiceSheet(
        title = Strings.t("TLS fragmentation"),
        subtitle = Strings.t("Fragment the TLS ClientHello to look like ordinary HTTPS traffic"),
        options = H2Fragmentation.entries.toList(),
        selected = h2Fragmentation(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit().putString(H2_FRAGMENTATION, chosen.coreName).apply()
        after?.invoke()
    }

    /**
     * The preferred egress country, or "auto".
     *
     * Stored as the two-letter code (or [CoreConfig.EGRESS_REGION_AUTO]) so the
     * service can hand it straight to Psiphon without a lookup table on that side.
     */
    private fun egressRegion(): String =
        CoreConfig.egressRegion(this) ?: CoreConfig.EGRESS_REGION_AUTO

    /** What the settings row shows: "Automatic" or "🇩🇪 Germany". */
    private fun egressRegionLabel(): String {
        val code = egressRegion()
        return if (code == CoreConfig.EGRESS_REGION_AUTO) Strings.t("Automatic") else PsiphonRegions.label(code)
    }

    private fun psiphonModeLabel(): String =
        if (CoreConfig.isCdnFronting(this)) Strings.t("CDN Fronting") else Strings.t("Automatic")

    /**
     * CDN edge IPs subtitle. Mirrors Shirokhorshid's
     * `cdnFrontingCustomIpListPreferenceSummaryConfigured` — the count is what
     * the user actually needs to see, because a typo that silently dropped an
     * entry would otherwise look like a saved setting that does nothing.
     */
    private fun cdnEdgeIpsLabel(): String {
        val count = CoreConfig.parseCdnIpList(CoreConfig.cdnEdgeIps(this)).size
        return if (count == 0) {
            Strings.t("Built-in CDN edges") + " (${CoreConfig.CDN_EDGE_IPS.size})"
        } else {
            Strings.t("Using N entries").replace("N", count.toString())
        }
    }

    private fun cdnSniLabel(): String {
        val list = CoreConfig.parseCdnSniList(CoreConfig.cdnSniHostnames(this))
        return when {
            list.isEmpty() -> Strings.t("No custom SNI")
            list.size == 1 -> Strings.t("Using SNI").replace("SNI", list[0])
            else -> Strings.t("Using N hostnames").replace("N", list.size.toString())
        }
    }

    /**
     * Pick the country Psiphon should try first.
     *
     * Deliberately worded as a preference everywhere in this sheet. Psiphon's
     * `EgressRegion` is a hard filter, so a country the carrier cannot reach would
     * mean no connection at all — the service works around that by giving the
     * choice one short attempt and then falling back to every country. The subtitle
     * says so, because a control that silently disobeys is worse than one that
     * explains its limits.
     *
     * Applies to every Psiphon connect, plain or over WARP: the row is live
     * whenever Psiphon is selected, and the service honours the choice either
     * way (armRegionPhase no longer gates on chainMode).
     */
    /**
     * Dark or light.
     *
     * `recreate()` rather than repainting in place: the palette is read into
     * fields and baked into ~200 drawables at construction time, plus
     * [Sculpt.lighting] which decides how every surface is lit. Walking the tree
     * to re-tint all of it would leave whatever the walk missed in the old
     * palette, and the app already uses recreate() for the same reason after a
     * settings restore.
     *
     * The tunnel is untouched by this: the VPN lives in a foreground service, not
     * in the activity, so a connected session survives the recreate. Worth being
     * sure of before shipping a switch a user might tap mid-session.
     */
    private fun chooseTheme(after: (() -> Unit)? = null) {
        showChoiceSheet(
            title = Strings.t("Theme"),
            subtitle = Strings.t("Applies straight away. A running tunnel is not interrupted."),
            options = AppAppearance.Mode.entries.toList(),
            selected = AppAppearance.mode(this),
            label = { mode -> mode.label },
            description = { mode -> mode.description },
        ) { chosen ->
            if (chosen == AppAppearance.mode(this)) return@showChoiceSheet
            AppAppearance.setMode(this, chosen)
            ConnectionLog.record("Theme set to ${chosen.label}")
            after?.invoke()
            recreate()
        }
    }

    /**
     * What the Language row displays.
     *
     * Reads through [AppLanguage.current] rather than the raw stored string: an
     * install that has not answered the picker yet still follows the device
     * locale, so the row must say the language actually on screen, not "en".
     * Once a pick is recorded the stored code and the resolved one agree.
     */
    private fun currentLanguagePref(): String = AppLanguage.current(this)

    /**
     * Pick the UI language: English, Persian, Chinese.
     *
     * Exactly the theme's shape: write the preference, recreate(), and the
     * whole tree is rebuilt reading [Strings.t] at every label. The tunnel is
     * untouched — it lives in the service, not the activity. The service's
     * own status strings pick the new language on their next sendStatus
     * because AppLanguage reads the preference per call.
     *
     * "Follow system" was removed: the one-time picker on first launch asks
     * once and records a concrete choice, and this row offers the same three.
     * A device on a locale we do not translate shows English, which is what
     * "system" resolved to anyway.
     */
    /**
     * Picks which of the four profiles is active.
     *
     * Modelled on [chooseLanguage] deliberately: the same bottom sheet, the same
     * single-tap row, the same immediate rebuild. Switching a profile changes
     * what every row below the picker says, and recreate() is the only way to be
     * sure none of them keeps showing the profile the user just left.
     *
     * Refuses while the tunnel is up, for the same reason a restore does: the
     * running tunnel was configured by the old profile, and a hot swap would
     * leave the UI and the tunnel disagreeing about which settings are in force.
     */
    private fun chooseProfile() {
        showChoiceSheet(
            title = Strings.t("Profile"),
            subtitle = Strings.t("Each profile keeps its own settings. Disconnect first — the running tunnel uses the current profile's configuration."),
            options = Profiles.NAMES.toList(),
            selected = Profiles.NAMES[Profiles.active(this)],
            label = { it },
            description = { "" },
        ) { chosen ->
            val index = Profiles.NAMES.indexOf(chosen)
            if (index < 0 || index == Profiles.active(this)) return@showChoiceSheet
            if (TunnelStatus.isActive() || visualState == OrbitDialView.State.CONNECTING) {
                toastShort(Strings.t("Disconnect first — switching profile changes what the tunnel uses"))
                return@showChoiceSheet
            }
            val moved = Profiles.switch(this, index)
            ConnectionLog.record("Switched to $chosen ($moved settings keys)")
            recreate()
        }
    }

    private fun chooseLanguage() {
        showChoiceSheet(
            title = Strings.t("Language"),
            subtitle = Strings.t("Applies straight away. A running tunnel is not interrupted."),
            options = AppLanguage.SUPPORTED,
            selected = currentLanguagePref(),
            label = { code -> AppLanguage.label(code) },
            // The named languages do not repeat their own name under the label —
            // that reads as a doubled title.
            description = { "" },
        ) { chosen ->
            if (chosen == currentLanguagePref()) return@showChoiceSheet
            AppLanguage.set(this, chosen)
            ConnectionLog.record("UI language set to ${AppLanguage.label(chosen)}")
            recreate()
        }
    }

    /**
     * The one-time language prompt, shown exactly once per install.
     *
     * Fresh installs and updates alike land here the first time the activity
     * opens without a recorded choice, because [AppLanguage.PREF_CHOSEN] is
     * only written by a picker. The user picks once; from then on the row in
     * Settings owns the choice.
     *
     * Shown after onCreate's view setup so the first frame is already on
     * screen — the sheet is a dialog over a live UI, not a splash. Cancelling
     * it without a choice still records a choice (the current language, which
     * is English on a locale we do not translate), so the prompt never
     * recurs and the user is never left without a working language.
     */
    /**
     * The one-time language prompt, shown exactly once per install.
     *
     * Fresh installs and updates alike land here the first time the activity
     * opens without a recorded choice, because [AppLanguage.PREF_CHOSEN] is
     * only written by a picker. The user picks once; from then on the row in
     * Settings owns the choice.
     *
     * The sheet is built with the same geometry as [showChoiceSheet] rather
     * than a hand-rolled dialog: the same SURFACE fill and corner radius, the
     * same bottom-anchored MATCH_PARENT window, the same row height and
     * padding, and the same SELECTED marker. Three full-width rows stack
     * vertically, so "فارسی", "English" and "中文" each get a whole line and
     * none of them can be squeezed into a sliver again.
     */
    /**
     * The typeface for a *specific* language's label, unlike [Typefaces.regular]
     * / [Typefaces.medium], which pick by the language currently in effect.
     *
     * Used by the first-run picker, whose three rows are each a different
     * language before any of them has been chosen.
     */
    private fun faceFor(code: String): Typeface = when (code) {
        "fa" -> runCatching { ResourcesCompat.getFont(this, R.font.vazirmatn_bold) }
            .getOrNull() ?: Typeface.SANS_SERIF
        "zh" -> runCatching { ResourcesCompat.getFont(this, R.font.noto_sc_medium) }
            .getOrNull() ?: Typeface.SANS_SERIF
        else -> Typeface.create("sans-serif-medium", Typeface.NORMAL)
    }

    private fun showLanguagePickerOnce() {
        if (AppLanguage.hasChosen(this)) return
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        dialog.setCancelable(false)
        dialog.setCanceledOnTouchOutside(false)

        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(label(Strings.t("Language"), 22f, INK, TypefaceStyle.MEDIUM))
        sheet.addView(
            label(Strings.t("Choose the app's language. You can change it later in Settings."), 14f, MUTED),
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(4); bottomMargin = dp(20) },
        )

        val rows = mutableMapOf<String, SelectionOption>()
        AppLanguage.SUPPORTED.forEachIndexed { index, code ->
            val optionTitle = label(AppLanguage.label(code), 16f, INK, TypefaceStyle.MEDIUM).apply {
                // The row label renders in this language's own font, so "فارسی"
                // is crisp joined-script and "中文" has full glyph coverage even
                // on a device whose system font lacks them.
                typeface = faceFor(code)
            }
            val indicator = label(Strings.t("SELECTED"), 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM)
                .apply { letterSpacing = spacing(0.08f) }
            val row = LinearLayout(this).apply {
                gravity = Gravity.CENTER_VERTICAL
                orientation = LinearLayout.HORIZONTAL
                setPadding(dp(18), 0, dp(18), 0)
                isClickable = true
                isFocusable = true
                addView(optionTitle, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ))
                addView(indicator, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { leftMargin = dp(12) })
                setOnClickListener {
                    AppLanguage.set(this@MainActivity, code)
                    ConnectionLog.record("First-run language chosen: ${AppLanguage.label(code)}")
                    rows.forEach { (value, option) ->
                        setSelectionState(option, value == code, animate = true)
                        option.title.typeface = faceFor(value)
                    }
                    dialog.dismiss()
                    recreate()
                }
            }
            val option = SelectionOption(row, optionTitle, indicator, 18)
            rows[code] = option
            setSelectionState(option, code == AppLanguage.current(this), animate = false)
            // setSelectionState retypes the title through Typefaces, which pick
            // by *the active language*. In this sheet that is the wrong language
            // by construction — the labels are the three languages the user has
            // not chosen between yet, and the row's own font is the one that
            // makes its glyphs render at all. Restore it after styling.
            option.title.typeface = faceFor(code)
            sheet.addView(row, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(72),
            ).apply { topMargin = if (index == 0) 0 else dp(8) })
        }

        // A user who dismisses the sheet any other way (back is disabled, but a
        // launcher crash or a theme recreate can land here) still gets a recorded
        // default rather than a recurring prompt on every launch.
        dialog.setOnDismissListener {
            if (!AppLanguage.hasChosen(this)) AppLanguage.set(this, AppLanguage.current(this))
        }
        dialog.setContentView(FrameLayout(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    private fun chooseEgressRegion(after: (() -> Unit)? = null) {
        val options = listOf(CoreConfig.EGRESS_REGION_AUTO) + PsiphonRegions.options(this)
        showChoiceSheet(
            title = Strings.t("Preferred country"),
            subtitle = Strings.t("Psiphon tries this country first. If it will not connect, all countries are tried."),
            options = options,
            selected = egressRegion(),
            label = { code ->
                if (code == CoreConfig.EGRESS_REGION_AUTO) Strings.t("Automatic") else PsiphonRegions.label(code)
            },
            description = { code ->
                if (code == CoreConfig.EGRESS_REGION_AUTO) {
                    Strings.t("Fastest — Psiphon picks whichever server answers first")
                } else {
                    PsiphonRegions.detail(code)
                }
            },
            scrollable = true,
        ) { chosen ->
            preferences().edit().putString(CoreConfig.EGRESS_REGION_PREF, chosen).apply()
            ConnectionLog.record(
                if (chosen == CoreConfig.EGRESS_REGION_AUTO) {
                    Strings.t("Preferred exit country cleared — Psiphon chooses")
                } else {
                    "Preferred exit country set to ${PsiphonRegions.name(chosen)} ($chosen)"
                }
            )
            after?.invoke()
        }
    }


    private fun chooseLogLevel() = showChoiceSheet(
        title = Strings.t("Log verbosity"),
        // Says when it takes effect, because it does not take effect now: the
        // value is read while the core config is assembled, i.e. at connect.
        subtitle = Strings.t("How much the core logs · applies next connection"),
        options = LogLevel.entries.toList(),
        selected = logLevel(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit().putString(LOG_LEVEL, chosen.coreName).apply()
        logVerbosityRow?.setValue(chosen.label)
    }

    /** Label for the Tunnel type row: what the whole-phone/one-port choice is set to. */
    private fun tunnelTypeLabel(): String =
        if (CoreConfig.proxyOnly(this)) Strings.t("SOCKS proxy") else Strings.t("VPN (whole device)")

    /** Value shown on the port row — the port, or why it is inert. */
    private fun proxyPortValue(): String {
        val port = CoreConfig.proxyListenPort(this)
        return if (CoreConfig.proxyOnly(this)) "$port"
        // LRM keeps "10808 · …" in that order under the RTL paragraph
        // direction Persian runs in; without it the port jumps to the far side.
        else "\u200E$port · ${Strings.t("VPN mode")}"
    }

    /**
     * The tunnel-type picker.
     *
     * Locked while a session is live, exactly like the transport rail: switching
     * from VPN to proxy mid-session would mean tearing down a TUN and rebuilding the
     * data path under the user, and the honest thing is to say "disconnect first"
     * rather than to half-apply it.
     */
    private fun chooseTunnelType() {
        if (!modeControlsEnabled || TunnelStatus.isActive()) {
            toastShort(Strings.t("Disconnect first to change the tunnel type"))
            return
        }
        showChoiceSheet(
            title = Strings.t("Tunnel type"),
            subtitle = Strings.t("How MSN-GUARD carries your traffic"),
            options = listOf(CoreConfig.TUNNEL_MODE_VPN, CoreConfig.TUNNEL_MODE_PROXY),
            selected = CoreConfig.tunnelMode(this),
            label = { if (it == CoreConfig.TUNNEL_MODE_VPN) Strings.t("VPN (whole device)") else Strings.t("SOCKS proxy") },
            description = {
                if (it == CoreConfig.TUNNEL_MODE_VPN) {
                    Strings.t("Every app goes through the tunnel")
                } else {
                    // Names the transports that cannot do it, since that is the only
                    // way the choice can fail and the user should learn it here
                    // rather than from a failed connect.
                    Strings.t("Only apps you point at the port · not Tor or SHARD")
                }
            },
        ) { chosen ->
            preferences().edit().putString(CoreConfig.TUNNEL_MODE_PREF, chosen).apply()
            tunnelTypeRow?.setValue(tunnelTypeLabel())
            // Tor has no general-purpose local listener to publish: tun2socks talks
            // to TorSocksFront, which speaks udpgw and refuses UDP ASSOCIATE, so an
            // app pointed at it would break on its first UDP flow. Say so at the
            // moment of the choice instead of letting the connect fail later.
            if (chosen == CoreConfig.TUNNEL_MODE_PROXY && selectedProtocol == Protocol.TOR) {
                toastShort(Strings.t("Tor cannot run as a SOCKS proxy — pick another transport"))
            } else if (chosen == CoreConfig.TUNNEL_MODE_PROXY && selectedProtocol == Protocol.SHARD) {
                // SHARD's refusal has a different cause — no byte counter in a proxy
                // data path — but the same remedy, and it also has a better answer:
                // Share over LAN already works in VPN mode.
                toastShort(Strings.t("SHARD runs as a VPN — use Share over LAN instead"))
            }
            // The port row is the thing that visibly reacts to this choice, so it is
            // repainted and re-enabled in the same gesture, and the LAN row with it:
            // what can be shared depends on the tunnel type now.
            // refreshPsiphonRows() ends by calling refreshTunnelTypeRows(), so this
            // one call repaints the port row, the LAN row and every gated row at once.
            refreshPsiphonRows()
        refreshShardRows()
            ConnectionLog.record(
                if (chosen == CoreConfig.TUNNEL_MODE_PROXY) {
                    "Tunnel type: SOCKS proxy on port ${CoreConfig.proxyListenPort(this)} — " +
                        "applies on the next connect"
                } else {
                    "Tunnel type: whole-device VPN — applies on the next connect"
                }
            )
        }
    }

    /**
     * Port editor for proxy mode, with an explicit Apply.
     *
     * Apply rather than save-on-type because the port only means anything once it is
     * validated: [CoreConfig.portRejection] refuses privileged and internally-used
     * ports, and a silently-rejected value would leave the user pointing Telegram at
     * a port nothing is listening on.
     */
    private fun editProxyPort() {
        if (!CoreConfig.proxyOnly(this)) {
            toastShort(Strings.t("Set Tunnel type to SOCKS proxy first"))
            return
        }
        if (TunnelStatus.isActive()) {
            toastShort(Strings.t("Disconnect first to change the port"))
            return
        }
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val field = settingsField(
            value = CoreConfig.proxyListenPort(this).toString(),
            hintText = "1024–65535",
        ).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            setSingleLine(true)
        }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("SOCKS port"), 22f, INK, TypefaceStyle.MEDIUM))
        })
        // The address is stated here because it is the question every user of this
        // feature actually has, and getting it wrong is the most likely way for the
        // feature to look broken: an app on THIS phone must dial 127.0.0.1. 0.0.0.0
        // is a bind address, not a destination — it belongs to LAN sharing, where
        // another device connects to this phone's LAN IP.
        sheet.addView(label(
            "In the app, use host 127.0.0.1 with this port. " +
                "Applies on the next connect.",
            14f, MUTED,
        ), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        val entry = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        entry.addView(field, LinearLayout.LayoutParams(0, dp(56), 1f))
        entry.addView(createSettingsButton(Strings.t("Apply")) {
            val typed = field.text.toString().trim().toIntOrNull()
            if (typed == null) {
                field.error = Strings.t("Numbers only")
                return@createSettingsButton
            }
            val rejection = CoreConfig.portRejection(typed)
            if (rejection != null) {
                field.error = rejection
                return@createSettingsButton
            }
            preferences().edit().putInt(CoreConfig.PROXY_PORT_PREF, typed).apply()
            proxyPortRow?.setValue(proxyPortValue())
            ConnectionLog.record(Strings.tf("SOCKS port set to %s — applies on the next connect", typed))
            toastShort(Strings.tf("SOCKS port set to %s", typed))
            dialog.dismiss()
        }, LinearLayout.LayoutParams(dp(112), dp(56)).apply { leftMargin = dp(10) })
        sheet.addView(entry, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ))
        dialog.setContentView(FrameLayout(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    /**
     * Repaint the tunnel-type pair for the current setting.
     *
     * The port row's enabled state is the visible half of the type choice, so the
     * two must always be rendered together — a live-looking port box in VPN mode
     * would be a control that does nothing, which is the class of bug the log-level
     * chips already were.
     */
    private fun refreshTunnelTypeRows() {
        val proxy = CoreConfig.proxyOnly(this)
        // The transport picker itself. Locked mid-session for the same reason the
        // rail is: the running tunnel cannot change transport, and a row that opens
        // a picker whose choice is ignored until the next connect is the same bug as
        // the greyed-looking-live rows below.
        connectionModeRow?.setAvailable(modeControlsEnabled)
        tunnelTypeRow?.apply {
            setValue(tunnelTypeLabel())
            setAvailable(modeControlsEnabled)
        }
        proxyPortRow?.apply {
            setValue(proxyPortValue())
            setAvailable(proxy && modeControlsEnabled)
        }
        // Split tunneling is a property of the TUN — it works by allowing or
        // disallowing packages on the VpnService. In proxy mode there is no TUN, and
        // which apps use the proxy is decided by whoever types the port into their
        // settings, so the row cannot do anything. Greyed for the same reason the
        // port row is greyed in VPN mode: a control that does nothing is a bug.
        splitTunnelSummaryButton?.apply {
            setValue(if (proxy) Strings.t("Not used in SOCKS mode") else splitTunnelSummary())
            setAvailable(!proxy)
        }
        // Repainted here rather than only at build time: the transport can change
        // while this screen is open (the Connection mode row is right above it), and
        // the row's subtitle names the transports it applies to.
        val scannable = selectedProtocol == Protocol.MASQUE ||
            selectedProtocol == Protocol.WIREGUARD ||
            selectedProtocol == Protocol.WARP_IN_WARP
        scannerRow?.apply {
            setValue(scanModeSummary())
            setAvailable(scannable)
        }
    }

    /** Short toast; `toast(...)` does not exist in this class. */
    private fun toastShort(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun manageGatewayCache() = showChoiceSheet(
        title = Strings.t("Gateway cache"),
        subtitle = Strings.t("Control saved MASQUE gateway discovery data"),
        options = listOf("Cache & refresh", "Fresh scan next time", "Clear saved gateways"),
        selected = if (defaultEndpointDiscovery() == EndpointDiscovery.CACHE) "Cache & refresh" else "Fresh scan next time",
        label = { it },
        description = {
            when (it) {
                "Cache & refresh" -> Strings.t("Try saved gateways first")
                "Fresh scan next time" -> Strings.t("Ignore saved gateways once")
                else -> Strings.t("Remove saved gateway latency data")
            }
        },
        onSelected = { chosen ->
            when (chosen) {
                "Cache & refresh" -> preferences().edit().putString(ENDPOINT_DISCOVERY, EndpointDiscovery.CACHE.coreName).apply()
                "Fresh scan next time" -> preferences().edit().putString(ENDPOINT_DISCOVERY, EndpointDiscovery.FRESH.coreName).apply()
                else -> {
                    File(filesDir, "masque-gateway-cache.json").delete()
                    toastShort(Strings.t("Saved gateways cleared"))
                }
            }
            gatewayCacheRow?.setValue(defaultEndpointDiscovery().label)
        }
    )

    /** Row value for the custom-DNS box: the servers, or Automatic. */
    private fun customDnsLabel(): String {
        // v2.0.0: the row summarises all three transport lists, not just the
        // legacy UDP one, so a user who entered only DoH is not shown
        // "Automatic" for a setting they did configure.
        val udp = readDnsField(CUSTOM_DNS_UDP)
        val dot = readDnsField(CUSTOM_DNS_DOT)
        val doh = readDnsField(CUSTOM_DNS_DOH)
        if (udp.isEmpty() && dot.isEmpty() && doh.isEmpty()) return Strings.t("Automatic")
        return listOf(
            udp.takeIf { it.isNotEmpty() }?.let { "UDP ${it.size}" },
            dot.takeIf { it.isNotEmpty() }?.let { "DoT ${it.size}" },
            doh.takeIf { it.isNotEmpty() }?.let { "DoH ${it.size}" },
        ).filterNotNull().joinToString(" · ")
    }

    /**
     * Editor for the resolvers the tunnel's own DNS answers from.
     *
     * The plumbing is entirely existing: CoreConfig.json already forwards
     * `dns_servers` to the core, which uses it for every name it resolves
     * inside the tunnel (socks.rs `resolver_addresses`), and applyDns puts
     * the same list on the TUN. This dialog is only the tap that fills it.
     *
     * Plain UDP, DoT and DoH are all accepted. Prefixes select the transport:
     * `tls://` for DoT, `https://` (or `doh:`) for DoH; bare hosts stay plain
     * UDP. Encrypted entries are handled by the Rust core, because Android
     * itself cannot speak DoT/DoH to a VpnService resolver list.
     */
    private fun editManualEndpoint() {
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val field = EditText(this).apply {
            setText(manualEndpoint().orEmpty())
            hint = Strings.t("IP:port, blank for automatic")
            setTextColor(INK)
            setHintTextColor(MUTED)
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT
            setPadding(dp(18), 0, dp(18), 0)
            background = roundedBackground(SURFACE_VARIANT, 16, SURFACE_VARIANT)
        }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Manual endpoint"), 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(Strings.t("Numeric IPv4 or bracketed IPv6 address with port. Bypasses discovery."), 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        sheet.addView(field, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(56)))
        val buttons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        buttons.addView(createSettingsButton(Strings.t("Clear")) {
                    preferences().edit().remove(MANUAL_ENDPOINT).apply()
                    field.setText("")
                    manualEndpointRow?.setValue(Strings.t("Automatic"))
                }, LinearLayout.LayoutParams(0, dp(52), 1f))
        buttons.addView(createSettingsButton(Strings.t("Save")) {
                            val endpoint = field.text.toString().trim()
                            val validEndpoint = endpoint.isBlank() || Regex("^(?:\\d{1,3}(?:\\.\\d{1,3}){3}|\\[[0-9a-fA-F:]+]):([1-9]\\d{0,4})$")
                                .matchEntire(endpoint)?.groupValues?.get(1)?.toIntOrNull()?.let { it in 1..65535 } == true
                            if (!validEndpoint) {
                                field.error = Strings.t("Use numeric IP:port")
                                return@createSettingsButton
                            }
                            preferences().edit().apply {
                                if (endpoint.isBlank()) remove(MANUAL_ENDPOINT) else putString(MANUAL_ENDPOINT, endpoint)
                            }.apply()
                            manualEndpointRow?.setValue(manualEndpoint() ?: Strings.t("Automatic"))
                            dialog.dismiss()
                        }, LinearLayout.LayoutParams(0, dp(52), 1f).apply { leftMargin = dp(10) })
                sheet.addView(buttons, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)).apply { topMargin = dp(16) })
        dialog.setContentView(FrameLayout(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    /**
     * The inner hop of WoW / MIM. Blank reverts to "same as the outer endpoint",
     * which is what every version before this did, so Clear is a real undo.
     *
     * Deliberately NOT gated on the selected protocol here. The row is offered
     * wherever the user is, because the point is to set it up before switching
     * to a nested transport — the same reason Manual endpoint is not gated.
     */
    private fun editInnerEndpoint() {
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val field = EditText(this).apply {
            setText(manualInnerEndpoint().orEmpty())
            hint = Strings.t("IP:port, blank for automatic")
            setTextColor(INK)
            setHintTextColor(MUTED)
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT
            setPadding(dp(18), 0, dp(18), 0)
            background = roundedBackground(SURFACE_VARIANT, 16, SURFACE_VARIANT)
        }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Inner hop endpoint"), 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(Strings.t("The second hop of a nested tunnel (WoW, Masque over Masque). Blank means the inner tunnel uses the same address as the outer one."), 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        sheet.addView(field, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(56)))
        val buttons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        buttons.addView(createSettingsButton(Strings.t("Clear")) {
            preferences().edit().remove(MANUAL_INNER_ENDPOINT).apply()
            field.setText("")
            innerEndpointRow?.setValue(Strings.t("Same as outer"))
        }, LinearLayout.LayoutParams(0, dp(52), 1f))
        buttons.addView(createSettingsButton(Strings.t("Save")) {
            val endpoint = field.text.toString().trim()
            val validEndpoint = endpoint.isBlank() || Regex("^(?:\\d{1,3}(?:\\.\\d{1,3}){3}|\\[[0-9a-fA-F:]+]):([1-9]\\d{0,4})$")
                .matchEntire(endpoint)?.groupValues?.get(1)?.toIntOrNull()?.let { it in 1..65535 } == true
            if (!validEndpoint) {
                field.error = Strings.t("Use numeric IP:port")
                return@createSettingsButton
            }
            preferences().edit().apply {
                if (endpoint.isBlank()) remove(MANUAL_INNER_ENDPOINT) else putString(MANUAL_INNER_ENDPOINT, endpoint)
            }.apply()
            innerEndpointRow?.setValue(manualInnerEndpoint() ?: Strings.t("Same as outer"))
            dialog.dismiss()
        }, LinearLayout.LayoutParams(0, dp(52), 1f).apply { leftMargin = dp(10) })
        sheet.addView(buttons, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)).apply { topMargin = dp(16) })
        dialog.setContentView(FrameLayout(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    private fun settingsField(
        value: String,
        hintText: String,
        secure: Boolean = false,
        multiline: Boolean = false,
    ) = EditText(this).apply {
        setText(value)
        hint = hintText
        setTextColor(INK)
        setHintTextColor(MUTED)
        textSize = 15f
        inputType = when {
            secure -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            multiline -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            else -> InputType.TYPE_CLASS_TEXT
        }
        setSingleLine(!multiline)
        gravity = if (multiline) Gravity.TOP else Gravity.CENTER_VERTICAL
        setPadding(dp(18), if (multiline) dp(14) else 0, dp(18), if (multiline) dp(14) else 0)
        background = roundedBackground(SURFACE_VARIANT, 16, SURFACE_VARIANT)
    }

    private fun showTextSettingsSheet(
        title: String,
        subtitle: String,
        fields: List<Pair<String, EditText>>,
        validator: ((List<String>) -> Pair<Int, String>?)? = null,
        onSave: (List<String>) -> Unit,
    ) {
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(title, 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(subtitle, 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(16) })
        fields.forEach { (name, field) ->
            sheet.addView(label(name, 11f, MUTED).apply { letterSpacing = spacing(0.08f) }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10); bottomMargin = dp(6) })
            sheet.addView(field, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                if (field.maxLines > 1) dp(104) else dp(56),
            ))
        }
        sheet.addView(createSettingsButton("Save", backgroundOverride = primary, textColorOverride = primaryContainer) {
            val values = fields.map { it.second.text.toString().trim() }
            validator?.invoke(values)?.let { (index, message) ->
                fields[index].second.error = message
                return@createSettingsButton
            }
            onSave(values)
            dialog.dismiss()
            closeTunnelControlsScreen(false)
            openTunnelControlsScreen()
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)).apply { topMargin = dp(18) })
        dialog.setContentView(ScrollView(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    private fun editAdvancedObfuscation() {
        val jc = settingsField(preferences().getString(OBFUSCATION_JC, "").orEmpty(), "0–10").apply {
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        val jmin = settingsField(preferences().getString(OBFUSCATION_JMIN, "").orEmpty(), "0–1024 bytes").apply {
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        val jmax = settingsField(preferences().getString(OBFUSCATION_JMAX, "").orEmpty(), "0–1024 bytes").apply {
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        val i1 = settingsField(preferences().getString(OBFUSCATION_I1, "").orEmpty(), "<r 64>")
        val i2 = settingsField(preferences().getString(OBFUSCATION_I2, "").orEmpty(), "<r 32>")
        showTextSettingsSheet(
            Strings.t("Advanced obfuscation"),
            Strings.t("WireGuard only. Jc/Jmin/Jmax tune junk packets; I1/I2 use Aether CPS packet patterns."),
            listOf(
                Strings.t("JUNK COUNT (JC)") to jc,
                Strings.t("JUNK MIN (JMIN)") to jmin,
                Strings.t("JUNK MAX (JMAX)") to jmax,
                Strings.t("INIT PACKET I1") to i1,
                Strings.t("INIT PACKET I2") to i2,
            ),
            validator = { values ->
                val numbers = values.take(3).map { it.toIntOrNull() }
                when {
                    values.take(3).withIndex().any { (index, value) -> value.isNotBlank() && numbers[index] == null } -> 0 to Strings.t("Use whole numbers")
                    numbers[0]?.let { it !in 0..10 } == true -> 0 to Strings.t("Jc must be 0–10")
                    numbers[1]?.let { it !in 0..1024 } == true -> 1 to Strings.t("Jmin must be 0–1024")
                    numbers[2]?.let { it !in 0..1024 } == true -> 2 to Strings.t("Jmax must be 0–1024")
                    numbers[1] != null && numbers[2] != null && numbers[2]!! < numbers[1]!! -> 2 to Strings.t("Jmax must be at least Jmin")
                    values.drop(3).any { it.length > 2048 } -> 3 to Strings.t("Packet pattern is too long")
                    else -> null
                }
            },
        ) { values ->
            preferences().edit().apply {
                listOf(OBFUSCATION_JC, OBFUSCATION_JMIN, OBFUSCATION_JMAX, OBFUSCATION_I1, OBFUSCATION_I2)
                    .zip(values)
                    .forEach { (key, value) -> if (value.isBlank()) remove(key) else putString(key, value) }
            }.apply()
        }
    }

    private fun <T> showChoiceSheet(
        title: String,
        subtitle: String,
        options: List<T>,
        selected: T,
        label: (T) -> String,
        description: (T) -> String,
        onSelected: (T) -> Unit,
    ) = showChoiceSheet(title, subtitle, options, selected, label, description, false, null, onSelected)

    /**
     * @param scrollable caps the option list at 55% of the screen and scrolls it.
     *   Needed once a list can be long — the country picker has 25+ entries, and
     *   without this the sheet grows past the top of the screen and the rows at
     *   both ends become unreachable.
     * @param refuse consulted before a pick is accepted. Returning a message keeps
     *   the current selection, shows the message, and does not call [onSelected].
     *   Needed because the click handler moves the SELECTED marker on its own: a
     *   caller that merely declined to save would leave the sheet showing a choice
     *   the app is not using, which is the same lie as a greyed row that looks live.
     */
    private fun <T> showChoiceSheet(
        title: String,
        subtitle: String,
        options: List<T>,
        selected: T,
        label: (T) -> String,
        description: (T) -> String,
        scrollable: Boolean,
        refuse: ((T) -> String?)? = null,
        onSelected: (T) -> Unit,
    ) {
        // `after` is invoked by the caller's onSelected lambda; see chooseObfuscation
        // and friends, which pass a refresh for the row that opened the sheet.
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { dialog.dismiss() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(title, 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(subtitle, 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        // Rows live in their own container so a long list can be wrapped in a
        // ScrollView without the header and subtitle scrolling away with it.
        val optionsHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val rows = mutableMapOf<T, SelectionOption>()
        options.forEachIndexed { index, item ->
            val optionTitle = label(label(item), 16f, INK, TypefaceStyle.MEDIUM)
            val indicator = label(Strings.t("SELECTED"), 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = spacing(0.08f) }
            val row = LinearLayout(this).apply {
                gravity = Gravity.CENTER_VERTICAL
                orientation = LinearLayout.HORIZONTAL
                setPadding(dp(18), 0, dp(18), 0)
                isClickable = true
                isFocusable = true
                val labels = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
                labels.addView(optionTitle)
                // A blank description renders as an empty line under the title
                // (the language picker showed its own name twice); skip it.
                val desc = description(item)
                if (desc.isNotBlank()) {
                    labels.addView(label(desc, 13f, MUTED), LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                    ).apply { topMargin = dp(2) })
                }
                addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(indicator, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { leftMargin = dp(12) })
                setOnClickListener {
                    // Refusal comes first, and nothing moves if it fires: the
                    // marker, the callback and the stored preference all stay on
                    // the previous choice.
                    val refusal = refuse?.invoke(item)
                    if (refusal != null) {
                        toastShort(refusal)
                        return@setOnClickListener
                    }
                    onSelected(item)
                    rows.forEach { (value, option) -> setSelectionState(option, value == item, animate = true) }
                    // A tap is a decision, not an inspection: leaving the sheet open
                    // after the choice reads as "nothing happened", and the user
                    // backs out manually only to find the row still unchanged
                    // (which was the Gateway cache report). Dismiss on accept.
                    dialog.dismiss()
                }
            }
            val option = SelectionOption(row, optionTitle, indicator, 18)
            rows[item] = option
            setSelectionState(option, item == selected, animate = false)
            optionsHost.addView(row, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(72)).apply {
                topMargin = if (index == 0) 0 else dp(8)
            })
        }
        if (scrollable) {
            val cap = (resources.displayMetrics.heightPixels * 0.55f).toInt()
            val scroll = ScrollView(this).apply {
                isVerticalScrollBarEnabled = false
                isFillViewport = false
                addView(optionsHost)
            }
            sheet.addView(scroll, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, cap,
            ))
            // Open on the current choice rather than at the top: with 25 countries
            // the selected one is usually off screen, and a picker that hides your
            // own setting reads as if nothing was ever chosen.
            rows[selected]?.row?.let { target ->
                scroll.post { scroll.scrollTo(0, (target.top - dp(72)).coerceAtLeast(0)) }
            }
        } else {
            sheet.addView(optionsHost, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ))
        }
        dialog.setContentView(FrameLayout(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet)
        })
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }


    private fun closeSettingsScreen() {
        showingSettings = false
        // Drop the row references with the page. Repainting a view whose parent has
        // been removed is harmless but pointless, and holding them would keep a
        // destroyed hierarchy alive for as long as the activity lives.
        connectionModeRow = null
        psiphonChainRow = null
        smartSplitRow = null
        chainOuterRow = null
        egressRegionRow = null
        psiphonModeRow = null
        cdnEdgeIpsRow = null
        cdnSniRow = null
        lanSharingRow = null
        torModeRowRef = null
        torChainRowRef = null
        torChainOuterRow = null
        torRegionRowRef = null
        torBridgeRowRef = null
        // Same reason as the rows above: these two point at views that are about to
        // be destroyed, and a stale reference would have the next repaint writing
        // into a detached view instead of the new page's row.
        tunnelTypeRow = null
        proxyPortRow = null
        logVerbosityRow = null
        scannerRow = null
        shardPoolRow = null
        shardCustomIpRow = null
        shardReMeasureRow = null
        settingsBackupRow = null
        settingsPage?.let { animatePageClose(it) { settingsPage = null } }
    }

    /**
     * Repaint the Psiphon and Tor sections for the current armed state.
     *
     * Both rows below the Psiphon switch only affect a chained connect, so with the
     * chain off they are shown greyed and inert rather than hidden: the user can
     * still see what arming would give them, and cannot set a value that silently
     * does nothing. Also refreshes the values, since a choice sheet may have changed
     * them while this page stayed open.
     */
    private fun refreshPsiphonRows() {
        // The Psiphon switch is scoped to PSIPHON explicitly, not to whatever is
        // selected: it sits in the PSIPHON section and writes the Psiphon key, so
        // reading the generic selection here would make it mirror Tor's state while
        // Tor was selected.
        val psiphonSelected = selectedProtocol == Protocol.PSIPHON
        val chainAvailable = psiphonSelected && modeControlsEnabled
        val psiphonChained = chainArmed(Protocol.PSIPHON) && psiphonSelected
        psiphonChainRow?.apply {
            // Show the EFFECTIVE state, not the stored preference.
            //
            // Field report: with MASQUE selected, this switch was green *and* greyed
            // out. Green says "the chain is on", grey says "you cannot change it" —
            // together they claim the app is chaining through something the user
            // cannot turn off, which is not true at all. The chain simply does not
            // apply off the PSIPHON transport.
            //
            // So the switch reads off on MASQUE/WireGuard/WoW/TOR, and the stored
            // preference is left untouched underneath, so switching back to Psiphon
            // restores it.
            setChecked(psiphonChained)
            setAvailable(chainAvailable)
        }
        // The two rows below used to follow the switch's VISIBLE state one for
        // one. They no longer do, and the split is the point:
        //
        // * "Outer transport" is a property of the WARP chain, so it stays
        //   alive exactly while the chain is armed.
        // * "Preferred country" is a property of PSIPHON itself — the
        //   service honours the choice on a plain connect too (armRegionPhase
        //   reads it regardless of chainMode), so the row is live the moment
        //   Psiphon is selected, chain off or on. Field request: the row used
        //   to grey out with the chain off, which read as "the setting is
        //   dead" while the picker behind it had been fully functional for
        //   plain connects all along.
        val childrenAvailable = chainAvailable && psiphonChained
        chainOuterRow?.apply {
            setValue(chainOuterMode().label)
            setAvailable(childrenAvailable)
        }
        egressRegionRow?.apply {
            setValue(egressRegionLabel())
            setAvailable(chainAvailable)
        }
        // The mode row and the two CDN fields above the switch are gated here too,
        // so that every path which repaints this section also dims the dial model
        // when the transport is not Psiphon. Callers that switch the transport go
        // through updateConnectionMode, which calls this directly.
        refreshPsiphonModeRows()
        // LAN sharing is no longer Psiphon-only: MASQUE/WireGuard/WoW publish a real
        // SOCKS5 listener in SOCKS tunnel type, and Tor publishes its own SocksPort
        // in VPN mode. [lanSharingCapable] holds the per-transport rule; the row is
        // greyed only for the combinations that bind no listener at all.
        //
        // Left live while connected on purpose — flipping it mid-session is
        // legitimate and the subtitle says the change lands on the next connect.
        lanSharingRow?.apply {
            setChecked(lanSharingEnabled() && lanSharingCapable())
            setSubtitle(lanSharingSubtitle())
            setAvailable(lanSharingCapable())
        }

        // Tor's own switch, same rules, plus the mode condition: obfs4 and Snowflake
        // cannot be chained, so with either pinned the switch reads off and greyed
        // instead of promising something the service will refuse.
        val torSelected = selectedProtocol == Protocol.TOR
        val torChainable = TorManager.isChainable(this, torMode())
        torChainRowRef?.apply {
            setChecked(chainArmed(Protocol.TOR) && torSelected && torChainable)
            setAvailable(torSelected && torChainable && modeControlsEnabled)
        }
        // Tor's outer transport follows its switch's VISIBLE state, exactly as
        // Psiphon's does: it only affects a chained Tor connect, so with the chain
        // off — or with obfs4/Snowflake pinned, which cannot be chained at all — it
        // is greyed rather than hidden.
        val torChained = chainArmed(Protocol.TOR) && torSelected && torChainable
        torChainOuterRow?.apply {
            setValue(torChainOuterMode().label)
            setAvailable(torSelected && torChainable && modeControlsEnabled && torChained)
        }
        // Tor's exit-country picker, greyed off the TOR transport for the same
        // reason Psiphon's is: it configures a transport that is not selected, and
        // a live-looking row that changes nothing about the next connect is a lie.
        //
        // NOT gated on the chain switch, unlike Psiphon's country row. There the
        // country only reaches Psiphon through the chained config; here ExitNodes
        // is written to torrc on every Tor session, chained or not — so the only
        // conditions are "Tor is selected" and "not locked mid-session".
        torRegionRowRef?.setAvailable(torSelected && modeControlsEnabled)
        // The manual bridge box, gated exactly like the mode row that consumes it.
        //
        // It was initially left live on every transport so a bridge could be pasted
        // before selecting Tor. Field report: on a MASQUE page the row was the only
        // one in the section that looked fully interactive, which reads as "this
        // setting applies now" when it does not. Same rule as the rest of the
        // section: only on TOR, only while not locked mid-session. The stored lines
        // are untouched by the greying, so switching back to Tor shows them again.
        torBridgeRowRef?.apply {
            setValue(TorManualBridges.summary(this@MainActivity))
            setAvailable(torSelected && modeControlsEnabled)
        }
        // Tor's OWN "Connection mode" row (Direct/Meek/obfs4/Snowflake). It was the
        // last row in either section with no availability rule at all, so on a page
        // where MASQUE was selected it stayed fully live and opened a sheet that
        // configured a transport the next connect would not use. Same rule as every
        // other Tor row: only on TOR, only while not locked mid-session.
        torModeRowRef?.setAvailable(torSelected && modeControlsEnabled)
        // Chained onto this repaint rather than wired into all nine call sites
        // separately: every one of them (protocol change, connect, disconnect,
        // returning from a sheet) is also a moment the tunnel-type pair can go stale,
        // and one entry point means the two cannot drift apart.
        refreshTunnelTypeRows()
    }

    /**
     * Grey the SHARD section unless SHARD is the selected transport.
     *
     * Psiphon and Tor do this in [refreshPsiphonRows]; SHARD needs the same
     * treatment but for its own rows. Every row below the section's switch only
     * feeds the SHARD outbound, so on a MASQUE or WireGuard page a live row is
     * a row that promises a change the next connect will ignore. Greying — not
     * hiding — matches Psiphon and Tor, and keeps the rows visible so the user
     * can read the pool count and the stored custom IP while they sit greyed.
     */
    private fun refreshShardRows() {
        val shardSelected = selectedProtocol == Protocol.SHARD
        // modeControlsEnabled is only false for the brief window while a connect is
        // in flight; the rest of the time it is true and gating on it alone would
        // leave the rows live on a wrong transport.
        val available = shardSelected && modeControlsEnabled
        shardPoolRow?.apply {
            setValue(shardPoolSummary())
            setAvailable(available)
        }
        // The custom IP box is a raw LinearLayout, not an OrbitSettingsRow, so it
        // has no setAvailable(). alpha + isClickable are the grey: it stops the
        // row from answering a tap, and it is the same dim Psiphon's rows take on
        // through setAvailable. isEnabled is left true on the container because
        // the EditText inside reads it for its own visuals.
        shardCustomIpRow?.apply {
            alpha = if (available) 1.0f else 0.45f
            isClickable = !available
            isFocusable = !available
        }
        // Smart Split's card and the re-measure row both write to the same SHARD
        // outbound, so they follow the section.
        smartSplitRow?.setAvailable(available)
        shardReMeasureRow?.setAvailable(available)
    }


    private fun openTrafficMonitorScreen() {
        trafficMonitorPage?.let(pageHost::removeView)
        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val scroll = ScrollView(this).apply { isVerticalScrollBarEnabled = false }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(24))
        }
        content.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { closeTrafficMonitorScreen() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("Traffic monitor"), 22f, INK, TypefaceStyle.MEDIUM).apply { setPadding(dp(4), 0, 0, 0) })
        })
        content.addView(label(Strings.t("Traffic carried by MSN-GUARD. Per-app attribution is not available from encrypted tunnel counters."), 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(4); bottomMargin = dp(24) })
        trafficSpeedValue = addTrafficMetric(content, Strings.t("LIVE SPEED"))
        trafficSessionValue = addTrafficMetric(content, Strings.t("THIS SESSION"))
        trafficMonthValue = addTrafficMetric(content, Strings.t("THIS MONTH"))
        scroll.addView(content)
        page.addView(scroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ))
        page.setOnApplyWindowInsetsListener { _, insets ->
            content.setPadding(dp(24), insets.systemWindowInsetTop + dp(16), dp(24), insets.systemWindowInsetBottom + dp(24))
            insets
        }
        trafficMonitorPage = page
        pageHost.addView(page)
        page.requestApplyInsets()
        renderTrafficMonitor()
        animatePageOpen(page)
    }

    private fun addTrafficMetric(parent: LinearLayout, title: String): TextView {
        val value = label(Strings.t("Waiting for tunnel traffic"), 18f, INK, TypefaceStyle.MEDIUM)
        parent.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(15), dp(18), dp(15))
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density,
                SURFACE_VARIANT,
                18,
                stroke = DIVIDER,
            )
            addView(OrbitSectionHeader(this@MainActivity, palette, title))
            addView(value, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(7) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(11) })
        return value
    }

    private fun closeTrafficMonitorScreen() {
        trafficMonitorPage?.let { animatePageClose(it) { trafficMonitorPage = null } }
        trafficSpeedValue = null
        trafficSessionValue = null
        trafficMonthValue = null
    }

    /**
     * The DNS screen (v2.0.0).
     *
     * Replaces the single-line Custom DNS dialog with a full page: one field per
     * transport (plain UDP, DoT, DoH), each with its own description and its own
     * Test button that pings the resolver over that transport and reports
     * reachable / unreachable.
     *
     * Testing is done from inside the app's own process, NOT through the tunnel:
     * a DNS server that answers from the carrier is useless when reached through
     * a foreign exit, and one that answers through the exit is useless if the
     * carrier blocks it. The probe speaks the transport itself — a raw UDP
     * datagram for UDP, a TLS handshake on :853 for DoT, an HTTPS POST for DoH —
     * so "Test passed" means "this resolver answered on this transport from the
     * network this device is on right now."
     */
    private fun openDnsScreen() {
        dnsPage?.let(pageHost::removeView)
        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val scroll = ScrollView(this).apply { isVerticalScrollBarEnabled = false }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(16), dp(24), dp(24))
        }
        content.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { closeDnsScreen() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label(Strings.t("DNS"), 22f, INK, TypefaceStyle.MEDIUM).apply { setPadding(dp(4), 0, 0, 0) })
        })
        content.addView(label(
            Strings.t("Resolvers the tunnel answers DNS from. Each transport has its own list, comma-separated. Test before you save — a resolver that does not answer here will not answer through the tunnel either."),
            14f, MUTED,
        ), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(4); bottomMargin = dp(20) })

        // The three fields are kept here so the Save button below can read what the
        // user actually typed. saveDnsLists() reads from SharedPreferences, and
        // nothing else ever wrote the typed text there — Save closed the page and
        // left the preferences empty, so Custom DNS read "Automatic" for a list
        // the user had just filled in and tested.
        val fields = mutableMapOf<String, EditText>()

        addDnsField(content, Strings.t("Plain UDP"), CUSTOM_DNS_UDP,
            Strings.t("Bare IP addresses, optionally with a port. The default port is 53. Fastest, but unencrypted — a carrier can see and hijack these lookups."),
            Strings.t("1.1.1.1, 10.202.10.202:53")) { fields[CUSTOM_DNS_UDP] = it }
        addDnsField(content, Strings.t("DNS over TLS (DoT)"), CUSTOM_DNS_DOT,
            Strings.t("Hostnames or IPs with a tls:// prefix, on port 853. The lookup is encrypted; the carrier sees only that you talked to this server."),
            Strings.t("tls://dns.google, tls://1.1.1.1")) { fields[CUSTOM_DNS_DOT] = it }
        addDnsField(content, Strings.t("DNS over HTTPS (DoH)"), CUSTOM_DNS_DOH,
            Strings.t("Full https:// URLs, or a host with a doh: prefix. The lookup rides an ordinary HTTPS request, so it is the hardest to block."),
            Strings.t("https://cloudflare-dns.com/dns-query, doh:dns.quad9.net")) { fields[CUSTOM_DNS_DOH] = it }

        content.addView(createSettingsButton(Strings.t("Save")) {
            // Commit the typed text before anything else reads it.
            val editors = preferences().edit()
            for ((key, field) in fields) {
                val raw = field.text.toString().trim()
                val entries = raw.split(',', ';', ' ', '\n')
                    .map(String::trim).filter(String::isNotEmpty).distinct()
                val transport = when (key) {
                    CUSTOM_DNS_DOT -> "dot"
                    CUSTOM_DNS_DOH -> "doh"
                    else -> "udp"
                }
                for (entry in entries) {
                    CoreConfig.validateDnsEntry(transport, entry)?.let { problem ->
                        field.error = "$entry: $problem"
                        return@createSettingsButton
                    }
                }
                if (entries.isEmpty()) editors.remove(key)
                else editors.putString(key, entries.joinToString(", "))
            }
            editors.apply()
            saveDnsLists()
            // The row summary is not a live view of the preferences; without this
            // it still reads "Automatic" until the page is rebuilt.
            dnsRow?.setValue(customDnsLabel())
            closeDnsScreen()
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(52),
        ).apply { topMargin = dp(8) })

        scroll.addView(content)
        page.addView(scroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT,
        ))
        page.setOnApplyWindowInsetsListener { _, insets ->
            content.setPadding(dp(24), insets.systemWindowInsetTop + dp(16), dp(24), insets.systemWindowInsetBottom + dp(24))
            insets
        }
        dnsPage = page
        pageHost.addView(page)
        page.requestApplyInsets()
        animatePageOpen(page)
    }

    private fun closeDnsScreen() {
        dnsPage?.let { animatePageClose(it) { dnsPage = null } }
    }

    /**
     * One labelled field + Test button for one DNS transport.
     *
     * The Test button probes the entries that are currently in the field, NOT the
     * saved preference — the point is to let the user try a server before
     * committing to it.
     */
    private fun addDnsField(
        content: LinearLayout,
        title: String,
        prefKey: String,
        description: String,
        hint: String,
        onField: (EditText) -> Unit = {},
    ) {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(15), dp(18), dp(15))
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density, SURFACE_VARIANT, 18, stroke = DIVIDER)
        }
        card.addView(OrbitSectionHeader(this, palette, title))
        card.addView(label(description, 13f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(6); bottomMargin = dp(10) })

        val status = label("", 12.5f, MUTED)
        val field = EditText(this).apply {
            setText(preferences().getString(prefKey, "").orEmpty())
            this.hint = hint
            setTextColor(INK)
            setHintTextColor(MUTED)
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = roundedBackground(SURFACE_VARIANT, 14, DIVIDER)
        }
        card.addView(field, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ))
        onField(field)
        card.addView(status, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })

        card.addView(createSettingsButton(Strings.t("Test")) {
            val raw = field.text.toString().trim()
            val entries = raw.split(',', ';', ' ', '\n')
                .map(String::trim).filter(String::isNotEmpty).distinct()
            if (entries.isEmpty()) {
                field.error = Strings.t("Enter at least one address first")
                return@createSettingsButton
            }
            // A probe that can never connect wastes four seconds a host, and the
            // failure reads as "unreachable" for a server that is fine — the
            // entry just is not shaped the way the transport needs. Reject those
            // here, before the network call, with the reason.
            val transport = when (prefKey) {
                CUSTOM_DNS_DOT -> "dot"
                CUSTOM_DNS_DOH -> "doh"
                else -> "udp"
            }
            for (entry in entries) {
                CoreConfig.validateDnsEntry(transport, entry)?.let { problem ->
                    field.error = "$entry: $problem"
                    return@createSettingsButton
                }
            }
            status.text = Strings.t("Testing…")
            testDnsServers(prefKey, entries) { result ->
                runOnUiThread { status.text = result }
            }
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(46),
        ).apply { topMargin = dp(10) })

        // A second button that checks the thing the DNS probe cannot: whether a
        // page can actually be fetched through the tunnel. "Ping works but the
        // site does not open" looks identical to a passing DNS probe, and this
        // is the only way to tell them apart from the DNS screen.
        card.addView(createSettingsButton(
            Strings.t("Real fetch test"),
            backgroundOverride = SURFACE_VARIANT,
        ) {
            status.text = Strings.t("Fetching…")
            Thread {
                val report = StringBuilder()
                for (target in CONTENT_TEST_TARGETS) {
                    val outcome = probeContent(target.url, target.expect)
                    report.append(Strings.tf("%s → %s", target.label, outcome)).append(" · ")
                }
                val summary = report.toString().trimEnd(' ', '·')
                runOnUiThread { status.text = summary }
            }.start()
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(46),
        ).apply { topMargin = dp(8) })

        content.addView(card, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(14) })
    }

    /**
     * Probes [entries] and reports, in words, whether they answered.
     *
     * Runs on a background thread: each probe is a network call, and doing it on
     * the UI thread would freeze the screen for the full timeout on every miss.
     */
    private fun testDnsServers(prefKey: String, entries: List<String>, report: (String) -> Unit) {
        val transport = when (prefKey) {
            CUSTOM_DNS_DOT -> "dot"
            CUSTOM_DNS_DOH -> "doh"
            else -> "udp"
        }
        Thread {
            val results = ArrayList<String>()
            for (entry in entries) {
                val ok = probeDns(transport, entry)
                results.add(if (ok) Strings.tf("%s: OK", entry) else Strings.tf("%s: unreachable", entry))
            }
            val okCount = results.count { it.contains("OK") }
            // "%d" reached the user untouched because the translation table only
            // substitutes %s; tf() now normalises it. Kept readable in both
            // numberings so the line still makes sense translated.
            report(Strings.tf("%d of %d answered", okCount, results.size) + " · " + results.joinToString(" · "))
        }.start()
    }

    /**
     * One probe, one transport. Returns true on any answer.
     *
     * The UDP probe sends a real A query for example.com and accepts any DNS
     * response (even NXDOMAIN proves the server is answering DNS). The DoT probe
     * is a TCP connect to :853 plus a TLS handshake — the certificate is not
     * verified, because the question being asked is "is this reachable", not
     * "is this trustworthy". The DoH probe POSTs a wire-format query and accepts
     * a 2xx with a non-empty body.
     */
    private fun probeDns(transport: String, entry: String): Boolean = try {
        when (transport) {
            "dot" -> probeDot(entry)
            "doh" -> probeDoh(entry)
            else -> probeUdp(entry)
        }
    } catch (e: Exception) {
        false
    }

    private fun probeDot(entry: String): Boolean {
        // Strip the scheme the field's own placeholder tells the user to type.
        // Without this, splitHostPort sees "tls://dns.google" as one host and
        // createSocket resolves it literally — UnknownHostException, reported
        // to the user as "unreachable" for a server that is perfectly fine.
        // probeDoh strips its own prefix; this had to match.
        val stripped = entry
            .removePrefix("tls://")
            .removePrefix("dot://")
            .trim()
        val (host, port) = splitHostPort(stripped, 853)
        val socket = javax.net.ssl.SSLSocketFactory.getDefault().createSocket(host, port)
            as javax.net.ssl.SSLSocket
        return socket.use {
            it.soTimeout = 4000
            it.startHandshake()
            true
        }
    }

    private fun probeDoh(entry: String): Boolean {
        val url = if (entry.startsWith("http", ignoreCase = true)) entry
        else if (entry.startsWith("doh:", ignoreCase = true)) "https://" + entry.substring(4)
        else "https://$entry/dns-query"
        // HttpURLConnection only became Closeable on API 33; this app's floor is
        // 26, so `.use{}` does not compile against the older SDK. Disconnect is
        // the documented release and is idempotent, so it is safe to call after
        // any of the early returns below.
        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.setRequestProperty("content-type", "application/dns-message")
            conn.doOutput = true
            conn.outputStream.use { it.write(dnsProbeQuery()) }
            if (conn.responseCode !in 200..299) return false
            return conn.inputStream?.use { it.read() >= 0 } ?: false
        } finally {
            conn.disconnect()
        }
    }

    /**
     * A real end-to-end check: fetch a URL and look at the content.
     *
     * The DNS probes above prove a server answers; this proves a connection
     * through the tunnel can actually retrieve a page. A DNS answer plus a
     * blocked HTTP path is exactly the "ping works but the site does not open"
     * failure this reports separately.
     *
     * Runs on the calling thread; callers must be off the UI thread.
     */
    private fun probeContent(url: String, expect: String): String {
        val conn = try {
            (java.net.URL(url).openConnection() as java.net.HttpURLConnection)
        } catch (e: java.io.IOException) {
            return Strings.tf("Unreachable (%s)", e.javaClass.simpleName)
        }
        // try as an expression, so each catch arm supplies the value and the
        // finally only closes the connection — a finally on a statement try
        // throws the result away and the function has nothing to return.
        val verdict = try {
            conn.requestMethod = "GET"
            conn.connectTimeout = 6000
            conn.readTimeout = 6000
            conn.setRequestProperty("accept-encoding", "identity")
            conn.setRequestProperty("cache-control", "no-cache")
            val code = conn.responseCode
            if (code !in 200..299) return Strings.tf("HTTP %s", code)
            // read() returning -1 means a body was promised and the stream was
            // cut — a half-open connection is not a working one.
            val body = conn.inputStream?.bufferedReader()?.use { it.readText() } ?: ""
            if (body.isEmpty()) {
                Strings.t("Empty response")
            } else if (expect.isNotEmpty() && !body.contains(expect, ignoreCase = true)) {
                Strings.t("Content mismatch")
            } else {
                Strings.tf("%s bytes OK", String.format("%,d", body.length))
            }
        } catch (e: java.net.SocketTimeoutException) {
            Strings.t("Timeout")
        } catch (e: java.net.UnknownHostException) {
            Strings.t("DNS failed")
        } catch (e: javax.net.ssl.SSLException) {
            Strings.t("TLS failed")
        } catch (e: java.io.IOException) {
            Strings.tf("Unreachable (%s)", e.javaClass.simpleName)
        } finally {
            conn.disconnect()
        }
        return verdict
    }
    private fun probeUdp(entry: String): Boolean {
        val (host, port) = splitHostPort(entry, 53)
        val query = dnsProbeQuery()
        return java.net.DatagramSocket().use { s ->
            s.soTimeout = 4000
            s.connect(java.net.InetAddress.getByName(host), port)
            s.send(java.net.DatagramPacket(query, query.size))
            val buf = ByteArray(512)
            val resp = java.net.DatagramPacket(buf, buf.size)
            s.receive(resp)
            resp.length >= 12
        }
    }

    /** A minimal standard-query A lookup for example.com, on the wire. */
    private fun dnsProbeQuery(): ByteArray {
        // Header is 12 bytes: id, flags, 1 question, 0 answers, 0 authority,
        // 0 additional. Question is: 7 "example" 3 "com" 0, type A, class IN.
        val q = ByteArray(29)
        q[0] = 0x12; q[1] = 0x34          // id
        q[2] = 0x01; q[3] = 0x00          // standard query, recursion desired
        q[4] = 0x00; q[5] = 0x01          // QDCOUNT = 1
        q[12] = 7
        "example".toByteArray().copyInto(q, 13)
        q[20] = 3
        "com".toByteArray().copyInto(q, 21)
        q[24] = 0                         // root label
        q[25] = 0x00; q[26] = 0x01        // QTYPE = A
        q[27] = 0x00; q[28] = 0x01        // QCLASS = IN
        return q
    }

    /** Splits "host", "host:port", "[v6]:port" into the host and a port. */
    private fun splitHostPort(entry: String, defaultPort: Int): Pair<String, Int> {
        val v6 = entry.startsWith('[')
        val host: String
        val port: Int
        if (v6) {
            val close = entry.indexOf(']')
            host = entry.substring(1, close)
            port = entry.drop(close + 1).removePrefix(":").toIntOrNull() ?: defaultPort
        } else {
            val colon = entry.lastIndexOf(':')
            if (colon > 0 && entry.substring(colon + 1).toIntOrNull() != null) {
                host = entry.substring(0, colon)
                port = entry.substring(colon + 1).toInt()
            } else {
                host = entry
                port = defaultPort
            }
        }
        return host to port
    }

    /**
     * Writes the three transport lists to their own preferences and rebuilds the
     * legacy single list that the tunnel still consumes.
     *
     * [CUSTOM_DNS] remains the union of the plain-UDP entries — that is what
     * Android's resolver list can speak — and the encrypted lists are picked up
     * by the core at connect time. Splitting them keeps Android from being handed
     * a tls:// URL it cannot parse.
     */
    private fun saveDnsLists() {
        val udp = readDnsField(CUSTOM_DNS_UDP)
        val dot = readDnsField(CUSTOM_DNS_DOT)
        val doh = readDnsField(CUSTOM_DNS_DOH)
        preferences().edit().apply {
            putOrRemove(CUSTOM_DNS_UDP, udp)
            putOrRemove(CUSTOM_DNS_DOT, dot)
            putOrRemove(CUSTOM_DNS_DOH, doh)
            // The legacy list the tunnel reads: plain UDP only. Encrypted
            // entries are parsed by the core, never handed to Android.
            putOrRemove(CUSTOM_DNS, udp)
        }.apply()
        val parts = listOfNotNull(
            udp.takeIf { it.isNotEmpty() }?.let { "UDP ${it.size}" },
            dot.takeIf { it.isNotEmpty() }?.let { "DoT ${it.size}" },
            doh.takeIf { it.isNotEmpty() }?.let { "DoH ${it.size}" },
        )
        ConnectionLog.record(
            if (parts.isEmpty()) Strings.t("Custom DNS cleared — the default resolvers answer")
            else Strings.t("Custom DNS saved:") + " " + parts.joinToString(", ")
        )
    }

    private fun readDnsField(prefKey: String): List<String> =
        preferences().getString(prefKey, "").orEmpty()
            .split(',', ';', ' ', '\n').map(String::trim)
            .filter(String::isNotEmpty).distinct()

    private fun SharedPreferences.Editor.putOrRemove(key: String, values: List<String>) {
        if (values.isEmpty()) remove(key) else putString(key, values.joinToString(", "))
    }

    private fun renderTrafficMonitor() {
        trafficSpeedValue?.text = "↓ ${formatTraffic(trafficSpeedRx)}/s   ↑ ${formatTraffic(trafficSpeedTx)}/s"
        trafficSessionValue?.text = "↓ ${formatTraffic(trafficRx)}   ↑ ${formatTraffic(trafficTx)}"
        trafficMonthValue?.text = "↓ ${formatTraffic(trafficMonthRx)}   ↑ ${formatTraffic(trafficMonthTx)}"
    }

    /** One-line month total, shown as the Traffic monitor row's value. */
    private fun trafficHeadline(): String =
        if (trafficMonthRx + trafficMonthTx == 0L) Strings.t("No data yet")
        else "\u200E" + formatTraffic(trafficMonthRx + trafficMonthTx) + " " + Strings.t("this month")

    private fun formatTraffic(bytes: Long): String = when {
        bytes < 1_024 -> "$bytes B"
        bytes < 1_048_576 -> "${bytes / 1_024} KB"
        bytes < 1_073_741_824 -> "${bytes / 1_048_576} MB"
        else -> String.format(java.util.Locale.US, "%.2f GB", bytes / 1_073_741_824.0)
    }

    private fun openSplitTunnelScreen() {
        splitTunnelPage?.let(pageHost::removeView)
        val settings = SplitTunnelSettings(this)
        val selected = settings.packages().toMutableSet()
        splitTunnelDraftMode = settings.mode()
        splitTunnelDraftPackages = selected
        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { closeSplitTunnelScreen() }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(label(Strings.t("Split tunneling"), 22f, INK, TypefaceStyle.MEDIUM), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(createSettingsButton(Strings.t("Done"), backgroundOverride = primary, textColorOverride = primaryContainer) {
                settings.save(settings.mode(), selected)
                closeSplitTunnelScreen()
            }, LinearLayout.LayoutParams(dp(88), dp(40)).apply { marginEnd = dp(4) })
        }
        content.addView(header)
        content.addView(label(Strings.t("Choose which apps use MSN-GUARD. Changes apply next connection."), 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(20) })
        content.addView(label(Strings.t("MODE"), 12f, MUTED).apply { letterSpacing = spacing(0.1f) })
        val modeOptions = mutableMapOf<SplitTunnelSettings.Mode, SelectionOption>()
        SplitTunnelSettings.Mode.entries.forEachIndexed { index, mode ->
            val option = createSplitModeOption(mode, settings.mode()) { chosen ->
                modeOptions.forEach { (m, opt) -> setSelectionState(opt, m == chosen, animate = true) }
                splitTunnelDraftMode = chosen
                splitTunnelDraftPackages = selected
                settings.save(chosen, selected.toHashSet())
                if (chosen == SplitTunnelSettings.Mode.ALL) {
                    closeSplitTunnelScreen()
                } else {
                    openSplitTunnelAppsScreen(chosen, selected)
                }
            }
            modeOptions[mode] = option
            content.addView(option.row, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(58),
            ).apply { topMargin = if (index == 0) dp(10) else dp(8) })
        }

        page.addView(content, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ).apply {
            leftMargin = dp(24)
            rightMargin = dp(24)
            topMargin = dp(16)
            bottomMargin = dp(16)
        })
        page.setOnApplyWindowInsetsListener { _, insets ->
            (content.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(16)
                bottomMargin = insets.systemWindowInsetBottom + dp(16)
                content.layoutParams = this
            }
            insets
        }
        splitTunnelPage = page
        pageHost.addView(page)
        page.requestApplyInsets()
        animatePageOpen(page)
        staggerListItems(content)
    }

    private fun openSplitTunnelAppsScreen(mode: SplitTunnelSettings.Mode, selected: MutableSet<String>) {
        splitTunnelAppsPage?.let(pageHost::removeView)
        splitTunnelDraftMode = mode
        splitTunnelDraftPackages = selected
        val settings = SplitTunnelSettings(this)
        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val appList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        content.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { closeSplitTunnelAppsScreen() }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(label(Strings.t("Apps"), 22f, INK, TypefaceStyle.MEDIUM), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(createSettingsButton(Strings.t("Done"), backgroundOverride = primary, textColorOverride = primaryContainer) {
                settings.save(mode, selected.toHashSet())
                closeSplitTunnelAppsScreen()
                closeSplitTunnelScreen()
            }, LinearLayout.LayoutParams(dp(88), dp(40)).apply { marginEnd = dp(4) })
        })
        content.addView(label(Strings.t(if (mode == SplitTunnelSettings.Mode.INCLUDE) "Select apps to include" else "Select apps to exclude"), 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(16) })

        val searchField = EditText(this).apply {
            hint = Strings.t("Search apps…")
            setHintTextColor(MUTED)
            setTextColor(INK)
            textSize = 15f
            setSingleLine(true)
            background = roundedBackground(SURFACE_VARIANT, 12, DIVIDER)
            setPadding(dp(16), dp(10), dp(16), dp(10))
            val searchIcon = getDrawable(android.R.drawable.ic_menu_search)?.apply {
                setTint(MUTED)
                setBounds(0, 0, dp(20), dp(20))
            }
            setCompoundDrawablesRelativeWithIntrinsicBounds(searchIcon, null, null, null)
            compoundDrawablePadding = dp(10)
        }
        content.addView(searchField, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(16); leftMargin = dp(4); rightMargin = dp(4) })

        val progressBar = ProgressBar(this).apply {
            isIndeterminate = true
            indeterminateDrawable?.setTint(primary)
        }
        val loading = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            addView(progressBar, LinearLayout.LayoutParams(dp(44), dp(44)))
            // Explicit WRAP_CONTENT width, and that alone is the fix for the
            // caption appearing on device as "Scanni" — the string was never
            // misspelled, it was being laid out 44dp wide.
            //
            // addView() with no params hands out generateDefaultLayoutParams(),
            // which for a VERTICAL LinearLayout is MATCH_PARENT x WRAP_CONTENT.
            // This box is WRAP_CONTENT itself (see the FrameLayout below), so its
            // width spec is AT_MOST, and measureVertical() then takes the
            // alternativeMaxWidth branch: `!allFillParent && widthMode != EXACTLY`
            // makes the box's width come from alternativeMaxWidth, where a
            // MATCH_PARENT child contributes its margins only (0) instead of its
            // measured text width. The only real contribution left was the 44dp
            // spinner, so the box became 44dp, and the second pass remeasured the
            // caption at EXACTLY 44dp — about six characters at 14sp, i.e. exactly
            // "Scanni" on the first line with the rest wrapped out of sight.
            //
            // WRAP_CONTENT keeps the caption out of that branch: it is measured
            // AT_MOST the page width, counts its real width toward the box, and a
            // longer translation still wraps normally instead of being clipped.
            addView(label(Strings.t("Scanning installed apps…"), 14f, MUTED).apply {
                gravity = Gravity.CENTER
                setPadding(0, dp(16), 0, 0)
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ))
        }
        val listScroll = ScrollView(this).apply {
            alpha = 0f
            visibility = View.INVISIBLE
            addView(appList)
        }
        content.addView(FrameLayout(this).apply {
            addView(loading, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER,
            ))
            addView(listScroll, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            ))
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            0,
            1f,
        ))
        page.addView(content, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ).apply {
            leftMargin = dp(24)
            rightMargin = dp(24)
            topMargin = dp(16)
            bottomMargin = dp(16)
        })
        page.setOnApplyWindowInsetsListener { _, insets ->
            (content.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(16)
                bottomMargin = insets.systemWindowInsetBottom + dp(16)
                content.layoutParams = this
            }
            insets
        }
        splitTunnelAppsPage = page
        pageHost.addView(page)
        page.requestApplyInsets()
        page.alpha = 0f
        page.translationX = dp(20).toFloat()
        page.animate().alpha(1f).translationX(0f)
            .setDuration(PAGE_ANIMATION_MS)
            .setInterpolator(motionInterpolator)
            .start()
        loadUserApps { apps ->
            if (splitTunnelAppsPage !== page) return@loadUserApps
            
            settings.cleanup(apps.map { it.packageName }.toSet())
            selected.clear()
            selected.addAll(settings.packages())

            val sortedApps = apps.sortedWith(compareByDescending<ApplicationInfo> { it.packageName in selected }
                .thenBy { packageManager.getApplicationLabel(it).toString().lowercase() })

            sortedApps.forEach { app ->
                appList.addView(createSplitTunnelAppOption(app, mode, selected, settings, appList), LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    dp(72),
                ).apply { bottomMargin = dp(8) })
            }
            loading.animate().alpha(0f).scaleX(0.9f).scaleY(0.9f).setDuration(220)
                .setInterpolator(motionInterpolator)
                .withEndAction {
                    loading.visibility = View.GONE
                    listScroll.visibility = View.VISIBLE
                    listScroll.animate().alpha(1f).setDuration(250).start()
                    staggerListItems(appList)
                }.start()

            searchField.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    val query = s?.toString()?.lowercase() ?: ""
                    for (i in 0 until appList.childCount) {
                        val row = appList.getChildAt(i)
                        val name = (row.tag as? String)?.lowercase() ?: ""
                        val pkg = (row.contentDescription as? String)?.lowercase() ?: ""
                        row.visibility = if (query.isEmpty() || name.contains(query) || pkg.contains(query)) View.VISIBLE else View.GONE
                    }
                }
                override fun afterTextChanged(s: android.text.Editable?) {}
            })
        }
    }

    private fun createSplitTunnelAppOption(
        app: ApplicationInfo,
        mode: SplitTunnelSettings.Mode,
        selected: MutableSet<String>,
        settings: SplitTunnelSettings,
        container: ViewGroup,
    ): LinearLayout {
        val packageName = app.packageName
        lateinit var row: LinearLayout
        fun updateSelection(checked: Boolean, animate: Boolean) {
            row.background = roundedBackground(
                if (checked) selectedSurface else SURFACE_VARIANT,
                16,
                if (checked) primary else SURFACE_VARIANT,
            )
            if (animate) {
                row.animate().cancel()
                row.animate().scaleX(0.98f).scaleY(0.98f)
                    .setDuration(80)
                    .setInterpolator(DecelerateInterpolator())
                    .withEndAction {
                        row.animate().scaleX(1f).scaleY(1f)
                            .setDuration(160)
                            .setInterpolator(DecelerateInterpolator())
                            .start()
                    }
                    .start()
            }
        }
        val checkbox = CheckBox(this).apply {
            isChecked = packageName in selected
            contentDescription = "انتخاب ${packageManager.getApplicationLabel(app)}"
            setOnCheckedChangeListener { _, checked ->
                if (checked) {
                    selected += packageName
                    if (container.indexOfChild(row) != 0) {
                        container.removeView(row)
                        container.addView(row, 0)
                    }
                } else {
                    selected -= packageName
                }
                settings.save(mode, selected.toHashSet())
                updateSelection(checked, animate = true)
            }
        }
        row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), 0, dp(8), 0)
            isClickable = true
            isFocusable = true
            tag = packageManager.getApplicationLabel(app).toString()
            contentDescription = packageName
            setOnClickListener { checkbox.isChecked = !checkbox.isChecked }
            addView(ImageView(this@MainActivity).apply {
                setImageDrawable(app.loadIcon(packageManager))
                scaleType = ImageView.ScaleType.CENTER_INSIDE
            }, LinearLayout.LayoutParams(dp(40), dp(40)))
            val labels = LinearLayout(this@MainActivity).apply { 
                orientation = LinearLayout.VERTICAL
                setPadding(dp(14), 0, 0, 0)
            }
            labels.addView(label(packageManager.getApplicationLabel(app).toString(), 16f, INK, TypefaceStyle.MEDIUM))
            labels.addView(label(packageName, 11f, MUTED).apply { 
                ellipsize = android.text.TextUtils.TruncateAt.END
                setSingleLine(true)
            })
            addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(checkbox, LinearLayout.LayoutParams(dp(48), dp(48)))
        }
        updateSelection(checkbox.isChecked, animate = false)
        return row
    }

    private fun createSplitModeOption(
        mode: SplitTunnelSettings.Mode,
        selected: SplitTunnelSettings.Mode,
        onSelect: (SplitTunnelSettings.Mode) -> Unit,
    ): SelectionOption {
        val title = label(mode.label, 16f, INK, TypefaceStyle.MEDIUM)
        val indicator = label(Strings.t("SELECTED"), 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = spacing(0.08f) }
        val row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), 0, dp(18), 0)
            isClickable = true
            isFocusable = true
            setOnClickListener { onSelect(mode) }
            addView(title, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(indicator)
        }
        return SelectionOption(row, title, indicator, 18).also { setSelectionState(it, mode == selected, animate = false) }
    }

    private fun setSelectionState(option: SelectionOption, selected: Boolean, animate: Boolean) {
        option.row.background = roundedBackground(
            if (selected) selectedSurface else SURFACE_VARIANT,
            option.radius,
            if (selected) primary else SURFACE_VARIANT,
        )
        option.title.typeface = if (selected) {
            Typefaces.medium(this)
        } else {
            Typefaces.regular(this)
        }
        if (AppLanguage.current() != "en") {
            option.title.setLineSpacing(0f, Typefaces.lineHeightMult())
        }
        option.indicator.animate().cancel()
        if (selected) {
            option.indicator.visibility = View.VISIBLE
            option.indicator.alpha = if (animate) 0f else 1f
            if (animate) option.indicator.animate().alpha(1f).setDuration(160).start()
        } else if (animate) {
            option.indicator.animate().alpha(0f).setDuration(120).withEndAction {
                option.indicator.visibility = View.INVISIBLE
            }.start()
        } else {
            option.indicator.alpha = 0f
            option.indicator.visibility = View.INVISIBLE
        }
    }

    private fun closeSplitTunnelScreen() {
        persistSplitTunnelDraft()
        splitTunnelPage?.let { animatePageClose(it) { splitTunnelPage = null } }
        splitTunnelSummaryButton?.setValue(splitTunnelSummary())
    }

    private fun closeSplitTunnelAppsScreen() {
        persistSplitTunnelDraft()
        splitTunnelAppsPage?.let { animatePageClose(it) { splitTunnelAppsPage = null } }
        splitTunnelSummaryButton?.setValue(splitTunnelSummary())
    }

    private fun persistSplitTunnelDraft() {
        val mode = splitTunnelDraftMode ?: return
        val packages = splitTunnelDraftPackages ?: return
        SplitTunnelSettings(this).save(mode, packages.toHashSet())
    }

    private fun loadUserApps(onLoaded: (List<ApplicationInfo>) -> Unit) {
        cachedUserApps?.let(onLoaded) ?: Thread {
            val apps = installedUserApps()
            cachedUserApps = apps
            runOnUiThread { if (!isFinishing && !isDestroyed) onLoaded(apps) }
        }.start()
    }

    @Suppress("DEPRECATION")
    private fun installedUserApps(): List<ApplicationInfo> = packageManager.queryIntentActivities(
        Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),
        0,
    )
        .asSequence()
        .map { it.activityInfo.applicationInfo }
        .filter { it.packageName != packageName }
        .distinctBy { it.packageName }
        .sortedBy { packageManager.getApplicationLabel(it).toString().lowercase() }
        .toList()

    override fun onBackPressed() {
        if (!handleBack()) super.onBackPressed()
    }

    private fun handleBack(): Boolean {
        when {
            splitTunnelAppsPage != null -> closeSplitTunnelAppsScreen()
            splitTunnelPage != null -> closeSplitTunnelScreen()
            trafficMonitorPage != null -> closeTrafficMonitorScreen()
            dnsPage != null -> closeDnsScreen()
            tunnelControlsPage != null -> closeTunnelControlsScreen()
            showingLogs -> closeLogsScreen()
            showingScanner -> closeScannerScreen()
            showingMode -> closeModeScreen()
            showingSettings -> closeSettingsScreen()
            else -> return false
        }
        return true
    }

    private fun updateConnectionMode(protocol: Protocol) {
        if (selectedProtocol == protocol) return
        selectedProtocol = protocol
        preferences().edit().putString(DEFAULT_PROTOCOL, protocol.coreName).apply()
        // The chain's outer leg follows the rail, so re-record it whenever the
        // pick changes while the card is armed. Without this, arming on MASQUE and
        // then switching to WireGuard would still tunnel Psiphon through MASQUE.
        if (chainArmed()) setChainArmed(true)
        renderChainCard()
        // The settings page may still be behind the mode screen the user just used.
        // Repaint its rows now rather than on the next rebuild: this is exactly the
        // bug the field report caught — the mode row kept the previous value until
        // settings was left and re-entered.
        connectionModeRow?.setValue(protocol.label)
        refreshPsiphonRows()
        // refreshPsiphonRows() now repaints the mode row and the two CDN fields as
        // well, so the dial model dims on a non-Psiphon transport on the same
        // refresh that dims the chain rows — one source of truth for the section.
        refreshShardRows()

        // Keep the rail in sync when the change came from somewhere else (the
        // mode screen, a restored preference) rather than from a rail tap.
        // Animated for a user tap, instant for a scan-driven change. The 330ms
        // overshoot slide plus the chip's fade-to-zero-and-back is the right
        // feedback for somebody who just pressed a cell; run once per rung by the
        // Auto Scan it is three more blinks in the area the user is already
        // watching. The labels still change, so the search stays visible.
        val animate = autoScanIndex < 0
        transportRail.select(Protocol.entries.indexOf(protocol), animate = animate)
        chipProtocol.animate().cancel()
        if (!animate) {
            // Alpha reset explicitly: cancel() leaves whatever value the fade had
            // reached, so a scan starting mid-animation could freeze the chip
            // half-transparent.
            chipProtocol.alpha = 1f
            chipProtocol.text = protocol.label.uppercase()
            return
        }
        chipProtocol.animate().alpha(0f).setDuration(80)
            .setInterpolator(DecelerateInterpolator())
            .withEndAction {
                chipProtocol.text = protocol.label.uppercase()
                chipProtocol.animate().alpha(1f)
                    .setDuration(160)
                    .setInterpolator(DecelerateInterpolator())
                    .start()
            }
            .start()
    }

    private fun toggleTunnel() {
        // Cancelling mid-connect must work. Previously this only asked
        // TunnelStatus.isActive(), which is false while Psiphon is still
        // establishing (tun2socks has not started yet). The tap therefore fell
        // through to the connect path, where the service's
        // connected.compareAndSet(false, true) guard rejected it silently — so
        // the UI sat on "Connecting" until the tunnel came up on its own or the
        // user force-stopped the app.
        if (TunnelStatus.isActive() || visualState == OrbitDialView.State.CONNECTING) {
            // A tap during the ladder is the user overruling it, so the scan stops
            // here and the transport they started from comes back. Left running, the
            // next rung would dial 1.5s after they asked everything to stop.
            if (autoScanIndex >= 0) {
                ConnectionLog.record("Auto Scan: cancelled by the user")
                endAutoScan(restoreSelection = true)
            }
            startService(Intent(this, MsnGuardVpnService::class.java).setAction(MsnGuardVpnService.ACTION_DISCONNECT))
            showDisconnected(Strings.t("Disconnecting"))
            return
        }

        // Decided BEFORE the consent dialog, because the answer depends on the
        // selection and the user is about to be able to change nothing else.
        if (shouldAutoScan()) beginAutoScan()
        val config = configJson()
        // Proxy mode needs no VPN consent at all — no TUN is created, so asking for
        // it would put a system dialog in front of a feature that does not use the
        // permission. VPN mode still always asks; it is the only mode that builds a
        // TUN, and Android requires consent before establish().
        if (CoreConfig.proxyOnly(this)) {
            connect(config)
            return
        }
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent == null) connect(config) else {
            pendingConfig = config
            startActivityForResult(permissionIntent, VPN_REQUEST)
        }
    }

    private fun connect(config: String) {
        // Clear our mirrors of the core's per-tunnel byte counters before the new
        // tunnel starts. The service broadcasts a zero sample too, but the
        // verification baseline must not depend on that broadcast having been
        // delivered first, and the receiver is only registered while this screen
        // is started.
        trafficTx = 0
        trafficRx = 0
        // Reset with them, for the same reason: a baseline left over from the
        // previous session would be larger than the new tunnel's counter, so the
        // first health check would read a negative delta, take the
        // counter-restarted branch and waste a round before it could judge
        // anything.
        rxAtLastProbe = 0
        trafficSpeedTx = 0
        trafficSpeedRx = 0
        showConnecting()
        // Every rung gets its own deadline, armed here so it covers the paths that
        // never report anything back — see [armAutoScanWatchdog]. A no-op when no
        // scan is running.
        armAutoScanWatchdog()
        startForegroundService(Intent(this, MsnGuardVpnService::class.java)
            .setAction(MsnGuardVpnService.ACTION_CONNECT)
            .putExtra(MsnGuardVpnService.EXTRA_CONFIG, config))
    }

    // ---------------------------------------------------------------- Auto Scan

    /**
     * Whether this connect should start the one-time transport search.
     *
     * Three conditions, and each one closes a way the scan could be the wrong
     * behaviour rather than a helpful one:
     *
     *  - the latch is unset. That is what "only once, then remembered" means.
     *  - the selection is ON the ladder. Somebody who deliberately picked Tor or
     *    Psiphon has expressed a choice this must not overrule — and that same check
     *    covers the chain, since Psiphon/Tor-over-WARP is only reachable from those
     *    two selections and neither is on the ladder.
     *  - VPN mode. Every rung after the first needs a TUN; in SOCKS mode SHARD has
     *    no data path at all and switching transports under a user who is pointing
     *    apps at a local port would break them silently.
     */
    private fun shouldAutoScan(): Boolean {
        if (preferences().getBoolean(AUTO_SCAN_DONE, false)) return false
        if (selectedProtocol !in AUTO_SCAN_LADDER) return false
        if (CoreConfig.proxyOnly(this)) return false
        return true
    }

    /**
     * Arms the ladder at the selected transport.
     *
     * Starts from where the USER is, not from rung 0: the selection is WireGuard by
     * default, so the common case starts at the top anyway, and a user who moved the
     * rail before their first connect gets their pick tried first.
     */
    private fun beginAutoScan() {
        autoScanBefore = selectedProtocol
        autoScanIndex = AUTO_SCAN_LADDER.indexOf(selectedProtocol).coerceAtLeast(0)
        autoScanToken++
        ConnectionLog.record(
            "Auto Scan: first connect — trying ${AUTO_SCAN_LADDER.drop(autoScanIndex).joinToString(", ") { it.label }}"
        )
    }

    /**
     * Advances the ladder after a rung failed, or ends the scan when none is left.
     *
     * Three callers, because a rung can die three ways and only one of them is a
     * clean failure report:
     *  - the service's FAILED broadcast;
     *  - this screen's verification gate (handshake up, no traffic);
     *  - [armAutoScanWatchdog], which is the one that matters most — with
     *    auto-reconnect on (the default) the service does NOT broadcast FAILED for a
     *    core that exited; it re-dials the same blocked transport on a backoff. A
     *    ladder listening only for FAILED would sit on rung one forever.
     *
     * @param stopCurrent sends ACTION_DISCONNECT before moving on. Also what cancels
     *   the service's own retry loop (it sets `userInitiatedStop`), so the abandoned
     *   rung cannot come back under the next one. False only when the caller has
     *   already sent it.
     * @return true when it took over the paint and started another rung, so the
     *   caller must not draw its own failure.
     */
    private fun advanceAutoScan(stopCurrent: Boolean = true): Boolean {
        if (autoScanIndex < 0) return false
        // A rung already being replaced must not be replaced twice — see
        // [autoScanSettling]. Returns true so the caller still suppresses its own
        // failure paint: a handover IS in progress, just not a new one.
        if (autoScanSettling) return true
        // Invalidate the watchdog for the rung that just died before starting the
        // next one, or its timeout would fire into the new attempt.
        autoScanToken++
        val next = autoScanIndex + 1
        if (next >= AUTO_SCAN_LADDER.size) {
            ConnectionLog.record("Auto Scan: no transport carried traffic on this network")
            endAutoScan(restoreSelection = true)
            return false
        }
        autoScanIndex = next
        autoScanSettling = true
        val protocol = AUTO_SCAN_LADDER[next]
        ConnectionLog.record("Auto Scan: ${protocol.label} next")
        if (stopCurrent) {
            // Keeps the abandoned rung's DISCONNECTED broadcast from painting "Not
            // connected" over the scan's own progress line.
            suppressNextDisconnectedPaint = true
            startService(Intent(this, MsnGuardVpnService::class.java)
                .setAction(MsnGuardVpnService.ACTION_DISCONNECT))
        }
        // Repaints the rail and the chip as well as writing the preference, so the
        // user watches the search move — this is the whole point of doing it here
        // rather than inside the service.
        updateConnectionMode(protocol)
        showConnectionProgress(Strings.t("Auto Scan"), "Trying ${protocol.label}…")
        // The previous rung's session may still be unwinding. Consent is already
        // granted at this point (the first rung asked for it), so this goes straight
        // to the service.
        val token = autoScanToken
        sessionHandler.postDelayed({
            if (isFinishing || isDestroyed) return@postDelayed
            // A user tap or a fresh connect between the schedule and here moved the
            // token on; this attempt is stale.
            if (token != autoScanToken || autoScanIndex != next) return@postDelayed
            autoScanSettling = false
            connect(configJson())
        }, AUTO_SCAN_HANDOVER_MS)
        return true
    }

    /**
     * How long a rung gets to reach a VERIFIED connection before the ladder moves on.
     *
     * Per transport, because their failure modes differ in kind. WireGuard either
     * handshakes in a few seconds or is being dropped, so waiting longer only wastes
     * the user's time. MASQUE does not fail fast when blocked — it keeps trying
     * gateways — so its number is a cap on that search. WoW raises two tunnels in
     * sequence. SHARD races a slice of its node pool and then has to bring up xray
     * plus tun2socks.
     *
     * Each budget already contains [VERIFY_TIMEOUT_MS] (18s), because the clock
     * starts at the connect and the gate runs after the handshake.
     */
    private fun autoScanBudgetMs(protocol: Protocol): Long = when (protocol) {
        // On a fresh install the WARP transports have to register through SHARD
        // before they can handshake, and that is what this budget has to cover:
        // raising xray, racing the pool, the registration itself, then the scan.
        // 32 s fit only the scan, so on a phone with no saved identity the ladder
        // gave up on WireGuard before the identity it was waiting for had landed —
        // the scan advanced to MASQUE, which then connected on the identity SHARD
        // had just fetched, and WireGuard looked broken when it had only been
        // timed out.
        Protocol.WIREGUARD -> if (!IdentityProvisioner.hasIdentity(this, "wireguard")) {
            120_000L
        } else {
            32_000L
        }
        // Same reasoning for the other WARP transports: without an identity they
        // all have to register through SHARD first, and their budgets were sized
        // for a phone that already had one.
        Protocol.MASQUE -> if (!IdentityProvisioner.hasIdentity(this, "masque")) {
            120_000L
        } else if (CoreConfig.mimArmed(this)) {
            75_000L
        } else {
            48_000L
        }
        Protocol.WARP_IN_WARP -> if (!IdentityProvisioner.hasIdentity(this, "gool")) {
            120_000L
        } else {
            55_000L
        }
        else -> 45_000L
    }

    /**
     * Per-rung deadline. Armed by [connect] for every attempt while a scan is running.
     *
     * This is the ladder's real driver: it does not care WHY a rung did not arrive,
     * only that it did not. It fires on a blocked handshake, on a core that keeps
     * silently retrying itself, and on a Psiphon-style path that never reports
     * anything at all.
     */
    private fun armAutoScanWatchdog() {
        if (autoScanIndex < 0) return
        val rung = autoScanIndex
        val token = autoScanToken
        sessionHandler.postDelayed({
            if (isFinishing || isDestroyed) return@postDelayed
            if (token != autoScanToken || autoScanIndex != rung) return@postDelayed
            // Verified and live — nothing to do. completeAutoScan() has normally
            // already moved the token by now; this is the belt to that braces.
            if (visualState == OrbitDialView.State.CONNECTED ||
                visualState == OrbitDialView.State.DEGRADED
            ) return@postDelayed
            val protocol = AUTO_SCAN_LADDER[rung]
            ConnectionLog.record(
                "Auto Scan: ${protocol.label} did not carry traffic in" +
                    " ${autoScanBudgetMs(protocol) / 1000}s"
            )
            // Cancels the verification gate too: it may still be waiting on bytes
            // from the tunnel this abandons, and its own failure path would then
            // advance the ladder a second time.
            cancelVerification()
            if (!advanceAutoScan()) {
                showFailure(Strings.t("No transport connected on this network — try again or pick one yourself"))
            }
        }, autoScanBudgetMs(AUTO_SCAN_LADDER[rung]))
    }

    /**
     * Records the winner and stops the search.
     *
     * The transport is already selected and persisted by [updateConnectionMode], so
     * all that is left is the latch — which is written only from here, on a rung
     * that verified, so a scan interrupted by a dead network can run again.
     */
    private fun completeAutoScan() {
        if (autoScanIndex < 0) return
        ConnectionLog.record("Auto Scan: ${selectedProtocol.label} works — remembered for next time")
        preferences().edit().putBoolean(AUTO_SCAN_DONE, true).apply()
        endAutoScan(restoreSelection = false)
    }

    /** Clears the scan's state. [restoreSelection] puts the user's own pick back. */
    private fun endAutoScan(restoreSelection: Boolean) {
        autoScanIndex = -1
        autoScanToken++
        autoScanSettling = false
        val before = autoScanBefore
        autoScanBefore = null
        if (restoreSelection && before != null && before != selectedProtocol) {
            updateConnectionMode(before)
        }
        // The card slot was frozen for the whole search ([renderChainCard]), and the
        // winner is only known now. Called unconditionally: updateConnectionMode()
        // above is a no-op when the selection did not change, and the SHARD winner
        // reaches this line with the chain card still occupying the slot.
        renderChainCard()
    }

    /**
     * The config for the next connect.
     *
     * The chain marker replaces the protocol only when PSIPHON is selected and the
     * card is armed: it is Psiphon's chain marker specifically, and the service
     * dispatches on it into the Psiphon-over-WARP path.
     *
     * Tor deliberately has no marker. Its config stays plain `tor` and the service
     * asks [TorManager.chainArmed] on the way in, because the answer also depends on
     * the Tor mode (obfs4 and Snowflake cannot be chained) and that rule already
     * lives in TorManager. Encoding it in the protocol string here would put the
     * same decision in two places.
     */
    private fun configJson(): String {
        val chained = chainArmed(Protocol.PSIPHON) && selectedProtocol == Protocol.PSIPHON
        return if (chained) {
            CoreConfig.json(this, MsnGuardVpnService.CHAIN_PROTOCOL_MARKER.lowercase())
        } else {
            CoreConfig.json(this, selectedProtocol.coreName)
        }
    }
    private fun renderStatus() {
        if (!TunnelStatus.isActive() && isTunnelActive()) {
            NativeCore.lastError().takeIf(String::isNotBlank)?.let(::showFailure) ?: showDisconnected(Strings.t("Tunnel stopped unexpectedly"))
        }
    }

    /**
     * Paints the screen as connected when a tunnel is already up but this UI never
     * saw the broadcast that said so.
     *
     * Two ways in, and both are normal use rather than edge cases:
     *  - the activity was destroyed and is being recreated (rotation, process
     *    restart, launched fresh from the launcher while the service runs);
     *  - the activity was only STOPPED and is resuming. [statusReceiver] is
     *    registered in onStart and unregistered in onStop, so a tunnel raised from
     *    the Quick Settings tile while the app sat in Recents broadcasts CONNECTED
     *    to nobody. The instance survives, so onCreate does not run again, and the
     *    dial stayed on "Not connected" while the metrics underneath it counted
     *    real traffic.
     *
     * Deliberately does NOT run the verification gate. That gate exists to catch a
     * handshake that passes while no payload crosses, and it belongs to the
     * connect that is in progress; a tunnel that is already established and
     * carrying traffic has answered the question. Adopting through the gate would
     * also paint "Verifying" over a working session every time the user opens the
     * app.
     *
     * @return true when it took over the paint, so the caller can skip the
     *   disconnected-path work it would otherwise do.
     */
    private fun adoptRunningTunnel(): Boolean {
        if (!TunnelStatus.isActive()) return false
        // A connect this screen started is mid-verification: leave it alone, the
        // gate owns the paint until it proves or fails the tunnel.
        if (verifyInFlight || visualState == OrbitDialView.State.CONNECTING) return false
        // Already painted live — nothing to adopt. DEGRADED counts: the auto-ping
        // owns recovery from there and must not be reset to CONNECTED here.
        if (isTunnelActive()) return false
        showConnected(restored = true)
        // showConnected(restored = true) deliberately skips these so a mid-session
        // health check does not re-probe on every ping. Adoption is not that case:
        // the latency chip and the IP card have never been filled in for this
        // session, so ask once now and keep the poller running.
        startAutoPing()
        pingConnection()
        refreshPublicIp()
        return true
    }

    private fun showConnecting(detail: String? = null, progress: Int = -1) {
        // The percentage arrives on its own broadcasts, most of which carry no new
        // text, so it is applied before the shared progress renderer rather than
        // through it.
        orbitDial.progressPercent = progress
        showConnectionProgress(Strings.t("Connecting"), detail ?: Strings.tf("Starting %s tunnel", selectedProtocol.label))
    }

    private fun showStarting() {
        // STARTING and SCANNING are also CONNECTING on the dial, so a stale
        // percentage from the previous attempt would still be drawn.
        orbitDial.progressPercent = -1
        showConnectionProgress(Strings.t("Starting"), "Preparing ${selectedProtocol.label} tunnel")
    }

    private fun showScanning() {
        orbitDial.progressPercent = -1
        showConnectionProgress(Strings.t("Scanning"), Strings.t("Finding the best MASQUE gateway"))
    }

    private fun showConnectionProgress(title: String, detail: String) {
        latencyRequest++
        chipLatency.text = Strings.t("Latency —")
        visualState = OrbitDialView.State.CONNECTING
        orbitDial.state = visualState
        renderStatusLed()
        // The headline is text, so it takes the text-safe accent. On the dark
        // palette PRIMARY_TEXT == primary, so this is a no-op there.
        connectionTitle.setTextColor(PRIMARY_TEXT)
        // During the one-time Auto Scan every progress broadcast is relabelled here,
        // in the single place they all pass through. Without it the service's own
        // STARTING/SCANNING/CONNECTING lines ("Preparing MASQUE tunnel") overwrite
        // the ladder's line a moment after it is drawn, and a user watching the
        // screen cannot tell an automatic search from an ordinary connect.
        if (autoScanIndex >= 0) {
            connectionTitle.text = Strings.t("Auto Scan")
            connectionDetail.text = Strings.tf("Trying %s", AUTO_SCAN_LADDER[autoScanIndex].label) +
                Strings.tf(" (%s of %s)", autoScanIndex + 1, AUTO_SCAN_LADDER.size)
        } else {
            connectionTitle.text = title
            connectionDetail.text = detail
        }
        footerWave.setLit(false)
        setModeEnabled(false)
    }

    private fun showConnected(restored: Boolean = false) {
        // The winner of a one-time Auto Scan is recorded here and nowhere else: this
        // is the only point in the app that means "traffic really passes", which is
        // the whole bar the ladder was searching for. A no-op when no scan is running.
        completeAutoScan()
        visualState = OrbitDialView.State.CONNECTED
        orbitDial.state = visualState
        orbitDial.progressPercent = -1
        renderStatusLed()
        pingFailureStreak = 0
        connectionTitle.setTextColor(palette.connectedText)
        connectionTitle.text = Strings.t("Connected")
        connectionDetail.text = when {
            // Proxy mode first: it is the one case where "tunnel is active" would be
            // read as "my phone is protected", which is exactly what it is not. The
            // port is repeated here because this is the line the user looks at right
            // after connecting, and it is what they must type into Telegram.
            //
            // The chain is named when it is running, because in SOCKS mode the two
            // sessions look identical on this line otherwise — same port, same
            // "SOCKS proxy" — while one of them is riding a WARP leg that is the
            // reason it works at all on a blocking carrier.
            CoreConfig.proxyOnly(this) && chainRunning() ->
                Strings.tf("SOCKS proxy on %s · over WARP", proxyReachLine())
            CoreConfig.proxyOnly(this) ->
                Strings.tf("SOCKS proxy on %s", proxyReachLine())
            // Say what is actually carrying traffic. With the chain armed the rail
            // reads PSIPHON or TOR, so "<transport> tunnel is active" hides the WARP
            // leg that is doing the circumvention.
            chainRunning() && restored -> Strings.tf("%s over WARP recovered", selectedProtocol.label)
            chainRunning() -> Strings.tf("%s over WARP is active", selectedProtocol.label)
            restored -> Strings.tf("%s tunnel recovered", selectedProtocol.label)
            else -> Strings.tf("%s tunnel is active", selectedProtocol.label)
        }
        footerWave.setLit(true)
        chipLatency.text = Strings.t("Latency …")
        startSessionTimer(restored)
        setModeEnabled(false)
        if (!restored) {
            pingConnection()
            startAutoPing()
            refreshPublicIp()
        }
    }

    private fun showDegraded() {
        if (!isTunnelActive()) return
        visualState = OrbitDialView.State.DEGRADED
        orbitDial.state = visualState
        renderStatusLed()
        // Amber, but the readable amber: this is text on the card, and on the
        // light palette the vivid amber sits at 4.4:1 while the text amber is 7.3:1.
        connectionTitle.setTextColor(AMBER_TEXT)
        connectionTitle.text = Strings.t("Connection degraded")
        connectionDetail.text = Strings.t("Tunnel is active; HTTP health check failed")
        footerWave.setLit(false)
        chipLatency.text = Strings.t("Latency n/a")
    }

    private fun showFailure(detail: String? = null) {
        latencyRequest++
        cancelVerification()
        // Belongs to the tunnel that just died; keeping it would show a stale exit
        // next to a failure message.
        clearCoreExitIp()
        chipLatency.text = Strings.t("Latency —")
        visualState = OrbitDialView.State.FAILED
        orbitDial.state = visualState
        renderStatusLed()
        stopSessionTimer()
        connectionTitle.setTextColor(ERROR_TEXT)
        connectionTitle.text = Strings.t("Connection failed")
        footerWave.setLit(false)
        connectionDetail.text = detail ?: Strings.t("Check the server and try again")
        setModeEnabled(true)
    }

    private fun showDisconnected(detail: String = Strings.t("Tap the dial to connect")) {
        latencyRequest++
        cancelVerification()
        clearCoreExitIp()
        stopAutoPing()
        chipLatency.text = Strings.t("Latency —")
        visualState = OrbitDialView.State.DISCONNECTED
        orbitDial.state = visualState
        renderStatusLed()
        stopSessionTimer()
        resetMetrics()
        connectionTitle.setTextColor(INK)
        connectionTitle.text = Strings.t("Not connected")
        footerWave.setLit(false)
        connectionDetail.text = detail
        setModeEnabled(true)
        refreshPublicIp()
    }

    /**
     * Session timer. [restored] means the UI reattached to a tunnel that was
     * already up — the service knows when it connected, so ask it rather than
     * restarting the clock at zero and lying to the user.
     */
    private fun startSessionTimer(restored: Boolean) {
        val serviceStart = MsnGuardVpnService.connectedSinceElapsed()
        sessionStartedAt = when {
            serviceStart > 0L -> serviceStart
            sessionStartedAt > 0L && restored -> sessionStartedAt
            else -> android.os.SystemClock.elapsedRealtime()
        }
        sessionHandler.removeCallbacks(sessionTicker)
        sessionHandler.post(sessionTicker)
    }

    private fun stopSessionTimer() {
        sessionHandler.removeCallbacks(sessionTicker)
        sessionStartedAt = 0L
        orbitDial.timerText = ""
    }

    private fun formatUptime(elapsedMs: Long): String {
        val total = (elapsedMs / 1000L).coerceAtLeast(0L)
        val hours = total / 3600L
        val minutes = (total % 3600L) / 60L
        val seconds = total % 60L
        return String.format(java.util.Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)
    }

    private fun resetMetrics() {
        tileDown.setValue("0", "B")
        tileUp.setValue("0", "B")
        tileSpeed.setValue("0", "B/S")
        tileDown.resetBars()
        tileUp.resetBars()
        tileSpeed.resetBars()
        exitNodeCard.resetSpark()
    }

    /** Splits a byte count into a scaled number and its unit for the tiles. */
    private fun scaleBytes(bytes: Long): Pair<String, String> = when {
        bytes < 1_024L -> bytes.toString() to "B"
        bytes < 1_048_576L -> (bytes / 1_024L).toString() to "KB"
        bytes < 1_073_741_824L -> String.format(java.util.Locale.US, "%.1f", bytes / 1_048_576.0) to "MB"
        else -> String.format(java.util.Locale.US, "%.2f", bytes / 1_073_741_824.0) to "GB"
    }

    /**
     * Splits a byte-per-second rate into a scaled number and its unit.
     *
     * Separate from [scaleBytes] only in its unit strings, but the bottom tier is
     * the point: at Iranian mobile speeds a KB/s-floored tile spent most of its
     * time reading a flat `0` on a tunnel that was moving data, so idle and broken
     * looked identical. Showing B/S under a kilobyte keeps a live number on screen.
     */
    private fun scaleSpeed(bytesPerSecond: Long): Pair<String, String> = when {
        bytesPerSecond < 1_024L -> bytesPerSecond.toString() to "B/S"
        bytesPerSecond < 1_048_576L -> (bytesPerSecond / 1_024L).toString() to "KB/S"
        else -> String.format(java.util.Locale.US, "%.1f", bytesPerSecond / 1_048_576.0) to "MB/S"
    }

    /** Pushes the latest traffic sample into the three home-screen tiles. */
    private fun renderHomeMetrics() {
        val (downValue, downUnit) = scaleBytes(trafficRx)
        val (upValue, upUnit) = scaleBytes(trafficTx)
        tileDown.setValue(downValue, downUnit)
        tileUp.setValue(upValue, upUnit)
        val combined = trafficSpeedRx + trafficSpeedTx
        val (speedValue, speedUnit) = scaleSpeed(combined)
        tileSpeed.setValue(speedValue, speedUnit)
        // Bars are relative to a 512 KB/s ceiling — a realistic mobile-tunnel
        // full scale. The old 4 MB/s ceiling squashed every real sample into the
        // bottom 5% of the sparkline, so the bars never visibly moved.
        val ceiling = 512.0
        val kbPerSecond = combined / 1_024.0
        tileDown.push((trafficSpeedRx / 1_024.0 / ceiling).toFloat().coerceIn(0.04f, 1f))
        tileUp.push((trafficSpeedTx / 1_024.0 / ceiling).toFloat().coerceIn(0.04f, 1f))
        tileSpeed.push((kbPerSecond / ceiling).toFloat().coerceIn(0.04f, 1f))
        exitNodeCard.pushSample((kbPerSecond / ceiling).toFloat().coerceIn(0.04f, 1f))
    }

    private fun setModeEnabled(enabled: Boolean) {
        // Idempotent, because this is the hot path. Every CONNECTING broadcast ends
        // in showConnectionProgress(), which ends here, and a single connect emits a
        // dozen of them — Tor alone reports 15 bootstrap percentages. The work below
        // rebuilds both cards from scratch (four RippleDrawables for the chain card,
        // three for Smart Split, plus their badge backgrounds), so repeating it for
        // a flag that has not moved was pure repaint: the OVER WARP / Smart Split
        // area ticked its way through every connect.
        //
        // The rail is asked as well as the flag: it is the one control whose enabled
        // state can be out of step with [modeControlsEnabled] after a page rebuild,
        // and a return that left it wrong would lock or unlock it for good.
        if (modeControlsEnabled == enabled && transportRail.isEnabled == enabled) return
        transportRail.isEnabled = enabled
        // Arming or disarming mid-session would leave the running tunnel and the
        // card disagreeing, and the change only takes effect on the next connect
        // anyway. Locked while connected, like the rail.
        modeControlsEnabled = enabled
        renderChainCard()
        // The settings page can be open behind the dial while a connect completes,
        // and every gated row reads this flag. Without this repaint the rows keep
        // whatever availability they were given when the page was built, so a
        // session started from the dial left the whole page live and tapping a row
        // opened a sheet whose choice could not apply. The refs are null when the
        // page is closed, so this is a no-op then.
        refreshPsiphonRows()
        refreshShardRows()
    }

    /**
     * Which preference key holds the over-WARP switch for [protocol].
     *
     * Two keys, not one. The chain applies to Psiphon and to Tor, but they are
     * separate features with separate evidence behind them, and one shared key
     * would mean arming the chain for Psiphon silently changed how Tor connects —
     * a setting the user never touched altering a transport they did not select.
     * [TorManager.chainArmed] reads the Tor one on the service side, so the two
     * sides cannot drift.
     */
    private fun chainPrefKey(protocol: Protocol): String =
        if (protocol == Protocol.TOR) TorManager.CHAIN_ARMED_PREF else CHAIN_ARMED

    /**
     * Whether the chain applies to the current selection at all.
     *
     * Tor adds a second condition Psiphon does not have: only Direct and Meek were
     * measured working inside a proxy, so with obfs4 or Snowflake pinned there is
     * nothing the chain could carry. Mirrors [TorManager.isChainable] — the same
     * rule has to hold on both sides or the switch would offer something the
     * service refuses to do.
     */
    private fun chainApplies(): Boolean = when (selectedProtocol) {
        Protocol.PSIPHON -> true
        Protocol.TOR -> TorManager.isChainable(this, torMode())
        else -> false
    }

    /** Whether the chain choice applies to the tunnel that is running now. */
    private fun chainRunning(): Boolean = chainArmed() && chainApplies()

    /**
     * Paints the chain card for the current transport and connection state.
     *
     * Three independent reasons it can be unavailable, in the order the user can
     * act on them:
     *
     *  - a Tor mode that cannot be chained: obfs4 and Snowflake were never
     *    measured working through a proxy, so the chain is refused for them
     *    rather than offered and then ignored. Naming the mode makes the fix
     *    obvious — switch Tor to Auto, Direct or Meek.
     *  - not on PSIPHON or TOR: the chain wraps one of those two in WARP, so on
     *    MASQUE/WireGuard/WoW there is nothing to wrap. Disabled rather than
     *    hidden, so the feature stays discoverable with its precondition visible.
     *  - connected: the same lock the transport rail gets, since the choice only
     *    takes effect on the next connect.
     *
     * The armed preference is deliberately left untouched while unavailable, so
     * switching away and back restores the user's choice instead of clearing it.
     */
    private fun renderChainCard() {
        val applies = chainApplies()
        val reason = when {
            selectedProtocol == Protocol.TOR && !TorManager.isChainable(this, torMode()) ->
                // Manual is refused for a reason that lives in the pasted lines,
                // not in the mode, so the blocker names the line to fix. Saying
                // "not available with Manual bridge" would send the user looking
                // for a setting to change instead.
                if (torMode() == TorManager.TorMode.MANUAL) {
                    TorManager.manualChainBlocker(this) ?: Strings.t("not available with your bridges")
                } else {
                    Strings.tf("not available with %s", torMode().label)
                }
            !applies -> Strings.t("only for the PSIPHON and TOR transports")
            !modeControlsEnabled -> Strings.t("disconnect to change")
            else -> null
        }
        // Which transport is being wrapped, so the card cannot read
        // "PSIPHON OVER WARP" while the rail has Tor selected.
        chainCard.setInner(if (selectedProtocol == Protocol.TOR) Strings.t("Tor") else Strings.t("Psiphon"))
        // Two separate facts, and collapsing them was a bug: "locked" is not the
        // same as "does not apply". Connected on Psiphon is locked but fully
        // applicable — the chain is carrying the session — so the card must keep
        // showing CHAINED instead of dropping to N/A and going dark.
        chainCard.setUnavailable(reason, applicable = applies)
        // Name the pinned transport on the card. Without this, a pin set in settings
        // is invisible here and the card would still read "auto transport" while the
        // connect path used only WireGuard.
        //
        // Reads whichever pin belongs to the selected inner tunnel — the two keys are
        // independent, so showing Psiphon's while Tor is selected would misreport
        // what the next connect will actually do.
        val activeOuter = if (selectedProtocol == Protocol.TOR) {
            torChainOuterMode()
        } else {
            chainOuterMode()
        }
        chainCard.setOuterSummary(
            if (activeOuter == ChainOuterMode.AUTO) {
                Strings.t("auto transport")
            } else {
                Strings.tf("via %s", activeOuter.label)
            }
        )
        chainCard.setArmed(chainArmed())
        // Exactly one of the three slot cards is shown, and the swap happens
        // here so there is a single place that decides which control the user
        // sees. GONE and not merely disabled: a permanently-N/A card in the
        // SHARD or MASQUE case would be dead furniture on the app's most-used
        // screen.
        val shardSelected = selectedProtocol == Protocol.SHARD
        val masqueSelected = selectedProtocol == Protocol.MASQUE
        // Frozen while the Auto Scan is walking the ladder. The swap is one card
        // disappearing and another taking its place, and the ladder changes the
        // selection three times in a single connect — so the user watched the OVER
        // WARP card vanish and come back mid-search, which is the flicker they
        // reported. [endAutoScan] repaints once the search is over, so the slot
        // always catches up to the transport that actually won.
        if (autoScanIndex < 0) {
            chainCard.visibility = if (!shardSelected && !masqueSelected) View.VISIBLE else View.GONE
            smartSplitCard.visibility = if (shardSelected) View.VISIBLE else View.GONE
            mimCard.visibility = if (masqueSelected) View.VISIBLE else View.GONE
        }
        renderSmartSplitCard()
        renderMimCard()
        // The AI MODE chip rides the chip line, but the same repaint decides
        // transport applicability and the connected lock, so it is painted here
        // too — one place, the same rules as the cards.
        // The settings page carries the same switch, so keep it in step whenever the
        // card is repainted — arming from the home screen must not leave a stale
        // "off" behind in settings.
        refreshPsiphonRows()
        refreshShardRows()

    }

    /**
     * Whether the next connect should chain the selected transport over WARP.
     *
     * Defaults to ON. The chain is the configuration that actually gets through on
     * the hostile Iranian carriers this app exists for, so a user who picks Psiphon
     * and connects should get it without having to find a second switch first —
     * which is the same one-click-connect rule the rest of the app follows.
     *
     * The default only applies until the user expresses a preference. [setChainArmed]
     * records that they did, so an explicit "off" is remembered and is NOT quietly
     * re-armed on the next launch.
     */
    private fun chainArmed(protocol: Protocol = selectedProtocol): Boolean =
        preferences().getBoolean(chainPrefKey(protocol), CHAIN_ARMED_DEFAULT)

    /**
     * Persist whether the next connect chains the selected transport inside WARP.
     *
     * Deliberately does NOT touch [CoreConfig.CHAIN_OUTER_PREF]. That key holds an
     * index the service writes after an outer transport actually works, and it used
     * to be written from here as a protocol *string* — reading it back with getInt
     * would have thrown ClassCastException. Which transport carries the outer leg is
     * discovered by trying them (MASQUE, then WireGuard, then WoW), not chosen here.
     */
    private fun setChainArmed(armed: Boolean, protocol: Protocol = selectedProtocol) {
        preferences().edit().putBoolean(chainPrefKey(protocol), armed).apply()
        val inner = if (protocol == Protocol.TOR) "Tor" else "Psiphon"
        if (armed) {
            ConnectionLog.record("$inner-over-WARP armed: outer MASQUE, $inner inside it")
        } else {
            ConnectionLog.record("$inner-over-WARP disarmed")
        }
    }

    /**
     * Paints the Smart Split card. Only meaningful on SHARD.
     *
     * Two reasons it can be unavailable, in the order the user can act on them:
     *
     *  - not on SHARD: the split needs the node as one of its two legs, so there
     *    is nothing to split on the other transports.
     *  - connected: the same lock the transport rail and the chain card get, since
     *    the routing table is fixed when the config is written.
     */
    private fun renderSmartSplitCard() {
        val applies = selectedProtocol == Protocol.SHARD
        val reason = when {
            !applies -> Strings.t("only for the SHARD transport")
            !modeControlsEnabled -> Strings.t("disconnect to change")
            else -> null
        }
        smartSplitCard.setUnavailable(reason, applicable = applies)
        // Whether this network has been measured, in the user's terms — never which
        // fragment profile won. See [SmartSplit] for why the profile is not shown.
        smartSplitCard.setTuningSummary(
            if (SmartSplit.cachedProfile(this) != null) Strings.t("tuned for this network") else ""
        )
        smartSplitCard.setSplitEnabled(SmartSplit.enabled(this))
    }

    /**
     * Records the Smart Split choice. Takes effect on the next connect.
     *
     * On by default. What makes that safe is that the feature gates itself on a
     * measurement: if neither fragment profile can carry a blocked SNI on this
     * network, [SmartSplit.recordNoProfile] remembers it and the session silently
     * uses the historical all-through-the-node config. So the worst case is the old
     * behaviour, reached automatically — see [SmartSplit.ENABLED_PREF].
     */
    private fun setSmartSplitEnabled(on: Boolean) {
        SmartSplit.setEnabled(this, on)
        if (on) {
            ConnectionLog.record(
                "Smart Split on: Iranian sites direct, sanctioned and Telegram via node"
            )
        } else {
            ConnectionLog.record("Smart Split off: everything via node")
        }
    }

    /**
     * Paints the masque-over-masque card for the current selection and state.
     *
     * Same two reasons to be unavailable as the other slot cards, in the order
     * the user can act on them:
     *
     *  - not on MASQUE: the second hop chains *inside* a MASQUE connect, so on
     *    the other transports there is nothing to chain into. Disabled rather
     *    than hidden while MASQUE is not selected is unnecessary here — the
     *    card itself is GONE off MASQUE — but the rule still holds for the
     *    repaint that lands while the rail is mid-animation.
     *  - connected: the same lock the transport rail gets, since the choice
     *    only takes effect on the next connect.
     */
    private fun renderMimCard() {
        val applies = selectedProtocol == Protocol.MASQUE
        val reason = when {
            !applies -> Strings.t("only for the MASQUE transport")
            !modeControlsEnabled -> Strings.t("disconnect to change")
            else -> null
        }
        mimCard.setUnavailable(reason, applicable = applies)
        mimCard.setArmed(CoreConfig.mimArmed(this))
    }

    /**
     * Records the masque-over-masque choice. Takes effect on the next connect,
     * like every other slot-card switch.
     *
     * OFF by default; see [CoreConfig.MIM_ARMED_PREF] for why this one inverts
     * the chain card's default rather than following it.
     */
    private fun setMimArmed(armed: Boolean) {
        preferences().edit().putBoolean(CoreConfig.MIM_ARMED_PREF, armed).apply()
        if (armed) {
            ConnectionLog.record(
                "Masque-over-Masque armed: outer hop from this network, inner hop dialled through it"
            )
        } else {
            ConnectionLog.record("Masque-over-Masque disarmed")
        }
    }

    private fun isTunnelActive(): Boolean = visualState == OrbitDialView.State.CONNECTED ||
        visualState == OrbitDialView.State.DEGRADED


    private fun configureSystemBars() {
        window.statusBarColor = CANVAS
        window.navigationBarColor = CANVAS
        val lightBars = !isDarkCanvas()
        val applied = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val flags = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
            runCatching {
                window.insetsController?.setSystemBarsAppearance(if (lightBars) flags else 0, flags)
            }.isSuccess
        } else {
            false
        }
        if (!applied) {
            @Suppress("DEPRECATION")
            var visibility = 0
            if (lightBars) {
                visibility = visibility or View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    visibility = visibility or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
                }
            }
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = visibility
        }
    }

    private fun isDarkCanvas(): Boolean {
        val color = CANVAS
        val r = color shr 16 and 0xFF
        val g = color shr 8 and 0xFF
        val b = color and 0xFF
        return (r * 299 + g * 587 + b * 114) / 1000 < 140
    }

    private fun createHeaderBackButton(onClick: () -> Unit): ImageView = ImageView(this).apply {
        setImageResource(R.drawable.ic_back)
        contentDescription = "بازگشت"
        isClickable = true
        isFocusable = true
        val p = dp(12)
        setPadding(p, p, p, p)
        setColorFilter(INK)
        val outValue = android.util.TypedValue()
        context.theme.resolveAttribute(android.R.attr.selectableItemBackgroundBorderless, outValue, true)
        setBackgroundResource(outValue.resourceId)
        setOnClickListener { onClick() }
    }

    private fun dynamicColor(resource: Int, fallback: Int): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) getColor(resource) else fallback

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_PERMISSION_REQUEST)
        }
    }

    /**
     * Neon letter-spacing scatters Persian's joined letters, so it is
     * clamped to zero whenever the UI language is Persian.
     */
    private fun spacing(v: Float): Float = if (AppLanguage.current() != "en") 0f else v

    private fun label(
        text: String = "",
        textSize: Float,
        color: Int,
        style: TypefaceStyle = TypefaceStyle.REGULAR,
        singleLine: Boolean = false,
    ): TextView = TextView(this).apply {
        this.text = text
        this.textSize = textSize
        setTextColor(color)
        // Persian/Chinese ship offline fonts; see Typefaces for why per-language.
        if (AppLanguage.current() != "en") {
            setLineSpacing(0f, Typefaces.lineHeightMult())
        }
        if (singleLine) {
            setSingleLine(true)
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        typeface = when (style) {
            TypefaceStyle.REGULAR -> Typefaces.regular(this@MainActivity)
            TypefaceStyle.MEDIUM -> Typefaces.medium(this@MainActivity)
        }
    }

    private fun roundedBackground(fill: Int, radius: Int, stroke: Int, strokeWidth: Int = 1): GradientDrawable =
        GradientDrawable().apply {
            setColor(fill)
            cornerRadius = dp(radius).toFloat()
            setStroke(dp(strokeWidth), stroke)
        }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    private fun appVersion(): String =
        packageManager.getPackageInfo(packageName, 0).versionName ?: "Unknown"

    private fun createSettingsButton(
        text: String,
        icon: Int? = null,
        backgroundOverride: Int? = null,
        textColorOverride: Int? = null,
        tintIcon: Boolean = true,
        onClick: () -> Unit,
    ): TextView = label(text, 15f, textColorOverride ?: INK, TypefaceStyle.MEDIUM).apply {
        gravity = Gravity.CENTER
        setPadding(dp(18), 0, dp(18), 0)
        background = roundedBackground(backgroundOverride ?: SURFACE_VARIANT, 16, backgroundOverride ?: SURFACE_VARIANT)
        isClickable = true
        isFocusable = true
        contentDescription = text
        highlightOnFocus(16, backgroundOverride ?: SURFACE_VARIANT, backgroundOverride ?: SURFACE_VARIANT)
        icon?.let {
            setCompoundDrawablesRelativeWithIntrinsicBounds(it, 0, 0, 0)
            compoundDrawablePadding = dp(12)
            if (tintIcon) compoundDrawablesRelative[0]?.setTint(textColorOverride ?: primary)
            gravity = Gravity.CENTER_VERTICAL
        }
        setOnClickListener { onClick() }
    }

    private fun openLink(url: String) {
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }


    private fun defaultScan(): ScanTarget {
        val name = preferences().getString(DEFAULT_SCAN, ScanTarget.IPV4.coreName)
        return ScanTarget.entries.firstOrNull { it.coreName == name } ?: ScanTarget.IPV4
    }

    private fun defaultScanMode(): ScanMode {
        val name = preferences().getString(DEFAULT_SCAN_MODE, ScanMode.BALANCED.coreName)
        return ScanMode.entries.firstOrNull { it.coreName == name } ?: ScanMode.BALANCED
    }

    private fun defaultEndpointDiscovery(): EndpointDiscovery {
        val name = preferences().getString(ENDPOINT_DISCOVERY, EndpointDiscovery.CACHE.coreName)
        return EndpointDiscovery.entries.firstOrNull { it.coreName == name } ?: EndpointDiscovery.CACHE
    }

    private fun defaultMasqueTransport(): MasqueTransport {
        val name = preferences().getString(DEFAULT_MASQUE_TRANSPORT, MasqueTransport.H3.coreName)
        return MasqueTransport.entries.firstOrNull { it.coreName == name } ?: MasqueTransport.H3
    }

    private fun scanSummary(): String = listOfNotNull(
        defaultScan().label,
        defaultScanMode().label,
        defaultMasqueTransport().label.takeIf { selectedProtocol == Protocol.MASQUE },
    ).joinToString(" · ")

    /**
     * The active profile's preferences.
     *
     * Routed through [profiled] so every one of the 43 settings reads and writes
     * in this class (and the 43 elsewhere) lands in the profile the user picked.
     * Keys that must stay global are named in [Profiles.KEYS_NOT_PROFILED].
     */
    private fun preferences(): SharedPreferences = profiled()

    /**
     * Whether the AI Mode shortcut can act on the selected transport.
     *
     * v1.9.7: WoW (GOOL) ONLY. The field reports on the manual endpoint were
     * unambiguous — 188.114.96.96:890 carried traffic on WoW and never on
     * MASQUE or WireGuard — and the engine's seed/pin/rotation chase is
     * built around a forced GOOL peer. On every other transport the chip is
     * hidden (not pinned-lit): a control that cannot obey is worse than no
     * control, and the user asked for exactly that.
     */
    private fun obfuscationProfile(): ObfuscationProfile = preferences()
        .getString(OBFUSCATION_PROFILE, ObfuscationProfile.BALANCED.coreName)
        ?.let { name -> ObfuscationProfile.entries.firstOrNull { it.coreName == name } }
        ?: ObfuscationProfile.BALANCED

    private fun manualEndpoint(): String? = preferences().getString(MANUAL_ENDPOINT, null)?.takeIf(String::isNotBlank)

    /**
     * The pinned INNER hop, or null when the two hops should share one address.
     *
     * Only read by the nested transports (WoW, MIM); on every other protocol the
     * core ignores it, so this stays blank for a plain-WireGuard or MASQUE user.
     */
    private fun manualInnerEndpoint(): String? = preferences().getString(MANUAL_INNER_ENDPOINT, null)?.takeIf(String::isNotBlank)

    private fun retryObfuscationProfiles(): Boolean = preferences().getBoolean(RETRY_OBFUSCATION, true)

    private fun advancedObfuscationSummary(): String =
        listOf(OBFUSCATION_JC, OBFUSCATION_JMIN, OBFUSCATION_JMAX, OBFUSCATION_I1, OBFUSCATION_I2)
            .any { preferences().getString(it, "").orEmpty().isNotBlank() }
            .let { if (it) Strings.t("Custom") else Strings.t("Preset") }

    private fun tlsCurvePreset(): TlsCurvePreset = preferences()
        .getString(TLS_CURVE_PRESET, TlsCurvePreset.CHROME.coreName)
        ?.let { name -> TlsCurvePreset.entries.firstOrNull { it.coreName == name } }
        ?: TlsCurvePreset.CHROME

    private fun wireGuardDataCheck(): Boolean = preferences().getBoolean(WIREGUARD_DATA_CHECK, true)

    private fun killSwitchEnabled(): Boolean = preferences().getBoolean(KILL_SWITCH, false)

    /**
     * Whether Android's doze whitelist already exempts this app.
     *
     * A missing PowerManager reads as "not exempted" (false), which is the safe
     * direction: the row offers the fix rather than claiming nothing needs doing.
     * The opposite — claiming a whitelist that may not exist — is what hides the
     * setting from the user who needs it most.
     */
    private fun isBatteryExempted(): Boolean {
        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return false
        return pm.isIgnoringBatteryOptimizations(packageName)
    }

    /**
     * Open the system dialog that asks to be exempted from battery
     * optimisation (the doze whitelist).
     *
     * Two shapes, because the direct one is not universal:
     *  - ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS with a `package:` data URI
     *    lands the user on a one-tap "Allow" for this app specifically. This is
     *    what the permission was granted for.
     *  - It throws ActivityNotFoundException on ROMs that do not ship the
     *    intent (some vendor power managers replace it wholesale), and the
     *    fallback is the full battery-optimisation list, where the user finds
     *    the app and toggles it themselves.
     */
    @SuppressLint("BatteryLife")
    private fun requestBatteryOptimization() {
        try {
            val intent = Intent(AndroidSettings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:$packageName")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
        } catch (_: Exception) {
            try {
                val intent = Intent(AndroidSettings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                startActivity(intent)
            } catch (_: Exception) {
                ConnectionLog.record("Battery optimization: no system settings activity available")
                toastShort(Strings.t("This device has no battery optimization settings"))
            }
        }
    }
    /**
     * Auto-reconnect preference, read through the service's own key and default so
     * the toggle and the retry loop can never disagree about what "on" means.
     */
    private fun autoReconnectEnabled(): Boolean = preferences().getBoolean(
        MsnGuardVpnService.AUTO_RECONNECT_PREF,
        MsnGuardVpnService.AUTO_RECONNECT_DEFAULT,
    )

    /**
     * The LAN-bypass preference has a switch again — Settings ▸ ROUTING & DATA.
     *
     * The old switch fed the removed proxy mode's SOCKS bind and was deleted
     * because in VPN mode it changed nothing the user could see. The service now
     * applies it on every VPN path (native core, SHARD, Psiphon, Tor and the
     * chains), so it does something: LAN destinations stay reachable while the
     * tunnel is up. [MsnGuardVpnService.lanBypassEnabled] is still the only
     * reader, and it still migrates the older `lan_sharing` value forward.
     */
    private fun lanBypassEnabled(): Boolean = preferences().getBoolean(
        MsnGuardVpnService.LAN_BYPASS_PREF,
        // Same legacy fallback the service migrates on, so a user who set this in
        // 1.4.x sees the switch already on instead of a switch that reads OFF over
        // routing that is on.
        preferences().getBoolean("lan_sharing", false),
    )

    /** The Bypass Iran toggle. Reads the same key the TUN builder excludes by. */
    private fun iranBypassEnabled(): Boolean = preferences().getBoolean(
        MsnGuardVpnService.IRAN_BYPASS_PREF, false,
    )

    private fun savedProtocol(): Protocol {
        val name = preferences().getString(DEFAULT_PROTOCOL, Protocol.WIREGUARD.coreName)
        return Protocol.entries.firstOrNull { it.coreName == name && it.androidAvailable } ?: Protocol.WIREGUARD
    }


    private fun View.highlightOnFocus(radius: Int, fill: Int, stroke: Int) {
        onFocusChangeListener = View.OnFocusChangeListener { view, focused ->
            view.background = roundedBackground(fill, radius, if (focused) primary else stroke, if (focused) 2 else 1)
        }
    }

    /**
     * Toggle row. Now an [OrbitToggleRow] — a sculpted card with a neon track
     * instead of the old flat grey pill. The return type stays LinearLayout so
     * every existing call site is unchanged.
     */
    private fun createToggleRow(title: String, subtitle: String, checked: Boolean, onToggle: (Boolean) -> Unit): LinearLayout =
        OrbitToggleRow(this, palette, title, subtitle, checked, onToggle)

    /** Section caption with a neon tick, for the settings pages. */
    private fun sectionLabel(text: String): View = OrbitSectionHeader(this, palette, text)

    /**
     * An expandable section of the settings page.
     *
     * Thin wrapper over [ExpandableSection] so call sites read as
     * `expandableSection("PSIPHON") { it.addView(row) }` and stay symmetrical
     * with the plain `sectionLabel(...)` they replace.
     *
     * Expansion state is persisted per section id, so a section a user opened
     * stays open when they leave settings and come back. All collapsed by
     * default: the settings page is long enough that pre-opening anything is
     * a judgement about which section matters, and the user is the one making
     * that judgement.
     */
    private fun expandableSection(
        title: String,
        body: (LinearLayout) -> Unit,
    ): ExpandableSection = expandableSection(title, id = title, body)

    /**
     * An expandable section, whose open/closed state persists under [id].
     *
     * [id] is a stable English key — not [title], which is translated, so a user
     * who switches the app's language does not lose which sections they had
     * open. Callers that have no English key pass the title and get [title],
     * which is stable within one language and is the pre-profile behaviour.
     */
    private fun expandableSection(
        title: String,
        id: String,
        body: (LinearLayout) -> Unit,
    ): ExpandableSection {
        val key = "section_open_" + sectionId(id)
        return ExpandableSection(this, palette, title, initiallyExpanded = false,
            onExpansionChanged = { expanded ->
                profiled().edit().putBoolean(key, expanded).apply()
            },
            body = body,
        ).apply {
            if (profiled().getBoolean(key, false)) setExpanded(true, animate = false)
        }
    }

    /** A stable id from a section key, used as its expansion-state key. */
    private fun sectionId(title: String): String =
        title.lowercase().replace(Regex("[^a-z0-9]+"), "_").trim('_')

    /** A sculpted navigation row: title on the left, current value on the right. */
    private fun navRow(
        title: String,
        value: String? = null,
        iconRes: Int? = null,
        onClick: () -> Unit,
    ): OrbitSettingsRow = OrbitSettingsRow(this, palette, title, value, iconRes = iconRes, onClick = onClick)

    private fun logLevel(): LogLevel = preferences()
        .getString(LOG_LEVEL, LogLevel.INFO.coreName)
        ?.let { name -> LogLevel.entries.firstOrNull { it.coreName == name } }
        ?: LogLevel.INFO

    private fun perfProfile(): PerfProfile = preferences()
        .getString(PERF_PROFILE, PerfProfile.AUTO.coreName)
        ?.let { name -> PerfProfile.entries.firstOrNull { it.coreName == name } }
        ?: PerfProfile.AUTO

    private fun h2Fragmentation(): H2Fragmentation = preferences()
        .getString(H2_FRAGMENTATION, H2Fragmentation.ON.coreName)
        ?.let { name -> H2Fragmentation.entries.firstOrNull { it.coreName == name } }
        ?: H2Fragmentation.OFF

    /** Whether the SNI hostname is re-cased on every ClientHello (spec 028). */
    private fun mixedCaseSni(): Boolean = preferences().getBoolean(MIXED_CASE_SNI, false)

    /**
     * One binary choice, because the transform has no parameters: the SNI is
     * either re-cased on each connection or sent exactly as configured.
     */
    private fun chooseMixedCaseSni(after: (() -> Unit)? = null) = showChoiceSheet(
        title = Strings.t("Mixed-case SNI"),
        subtitle = Strings.t("Randomise the casing of the server name to defeat exact-match DPI"),
        options = listOf(false, true),
        selected = mixedCaseSni(),
        label = { if (it) Strings.t("On") else Strings.t("Off") },
        description = { if (it) Strings.t("Re-cased per connection") else Strings.t("Sent exactly as configured") },
    ) { chosen ->
        preferences().edit().putBoolean(MIXED_CASE_SNI, chosen).apply()
        after?.invoke()
    }

    /**
     * Psiphon's local SOCKS port, fixed.
     *
     * Still needed by openTunnelConnection(): in Psiphon VPN mode tun2socks and
     * the health check both dial this listener. No longer user-configurable —
     * the TUN is created before Psiphon starts, so the port must be known up
     * front.
     */
    /**
     * Where to point a client at this session's SOCKS listener.
     *
     * Quotes the LAN address instead of loopback when sharing is on and the phone
     * has one, because that is the address the user has to type on the OTHER
     * device — and this line is what they read immediately after connecting. Falls
     * back to loopback rather than claiming an address that cannot be reached.
     */
    private fun proxyReachLine(): String {
        val port = CoreConfig.sharedSocksPort(this)
        val host = if (CoreConfig.lanSharingEnabled(this)) {
            CoreConfig.localNetworkAddress(this) ?: "127.0.0.1"
        } else {
            "127.0.0.1"
        }
        return "$host:$port"
    }

    private fun socksPort(): Int =
        if (TunnelStatus.isActive() && TorManager.isTorActive) {
            TorManager.FRONT_SOCKS_PORT
        } else if (TunnelStatus.isActive() && ShardSocksFront.isRunning) {
            // The front-end, not xray's own 1824. Both would work for a CONNECT, but
            // this is also the port whose byte counters feed the tiles, so probing it
            // keeps the measurement and the traffic display on the same object.
            ShardSocksFront.LISTEN_PORT
        } else if (TunnelStatus.isProxyMode) {
            // Proxy mode moves Psiphon's listener to the user's port, so the fixed
            // 1819 would be a closed socket here and every IP/ping measurement
            // would fail — the card would read "IP unavailable" over a working proxy.
            CoreConfig.proxyListenPort(this)
        } else {
            CoreConfig.SOCKS_PORT
        }

    /**
     * Subtitle for SHARD's node-list row: how many nodes, and how old the list is.
     *
     * Ages are rounded to the coarsest useful unit. The number that matters to a
     * user deciding whether to hit refresh is "hours ago" or "days ago", and a
     * precise minute count on a list the publisher rebuilds once a day would be
     * false precision.
     */
    private fun shardPoolSummary(): String {
        val count = ShardSubscription.cachedCount(this)
        val last = ShardSubscription.lastCheckMillis(this)
        if (count <= 0) return Strings.t("Tap to download")
        // Paths, not nodes: each node is tried through several CDN edges, and the
        // number of distinct routes is what actually decides whether a connect
        // finds something. Taken from the refresh rather than multiplied here,
        // because nodes that are not CDN-fronted are not fanned out at all.
        val paths = ShardSubscription.cachedPathCount(this)
        if (last <= 0L) return "$count nodes · $paths paths · built in"
        val ageMs = System.currentTimeMillis() - last
        val age = when {
            ageMs < 60 * 60 * 1000L -> "just now"
            ageMs < 24 * 60 * 60 * 1000L -> "${ageMs / (60 * 60 * 1000L)}h ago"
            else -> "${ageMs / (24 * 60 * 60 * 1000L)}d ago"
        }
        return "$count nodes · $paths paths · $age"
    }

    /**
     * Subtitle for the scanner row: the current mode, or why it does not apply.
     *
     * Naming the two transports that use it is the point — as an action-bar button
     * labelled "SCAN MODE" it looked like a global setting, and a user on Psiphon
     * could set it and reasonably expect something to change.
     */
    private fun scanModeSummary(): String = when (selectedProtocol) {
        Protocol.MASQUE, Protocol.WIREGUARD, Protocol.WARP_IN_WARP ->
            "${defaultScanMode().label} · ${defaultScan().label}"
        else -> Strings.t("Only for MASQUE and WireGuard")
    }

    private fun splitTunnelSummary(): String {
        val settings = SplitTunnelSettings(this)
        val count = settings.packages().size
        return when (settings.mode()) {
            SplitTunnelSettings.Mode.ALL -> Strings.t("All apps use MSN-GUARD")
            SplitTunnelSettings.Mode.INCLUDE ->
                if (count == 1) Strings.t("Only 1 selected app")
                else Strings.tf("Only %s selected apps", count)
            SplitTunnelSettings.Mode.EXCLUDE ->
                if (count == 1) Strings.t("Exclude 1 selected app")
                else Strings.tf("Exclude %s selected apps", count)
        }
    }

    private enum class Protocol(
        val enLabel: String,
        val coreName: String,
        val enDescription: String,
        val androidAvailable: Boolean = true,
    ) {
        /** Localized at call time so a language switch refreshes every rail/page. */
        // ORDER IS THE UI. Both the home-screen rail and the Connection mode page
        // are built from `Protocol.entries`, so this list decides what a first-time
        // user reaches for — and the first cell is what most of them will tap.
        //
        // WireGuard leads on purpose: it is the cheapest handshake of the six and it
        // either works immediately or fails immediately, which is the right first
        // move for a user who does not know what any of these words mean. MASQUE
        // follows because it survives the carriers WireGuard is blocked on, and the
        // one-time Auto Scan ([AUTO_SCAN_LADDER]) walks them in exactly this order.
        WIREGUARD("WireGuard", "wireguard", "WireGuard tunnel", true),
        MASQUE("MASQUE", "masque", "HTTP/3 or HTTP/2 tunnel", true),
        WARP_IN_WARP("WARP-on-WARP", "gool", "Double-layer tunnel", true),
        PSIPHON("Psiphon", "psiphon", "Anti-censorship tunnel", true),
        TOR("Tor", "tor", "Onion routing; slowest but hardest to block", true),

        /**
         * Public proxy nodes, picked automatically.
         *
         * Its core name is not a core transport at all: the Rust core is never
         * started for SHARD. The service branches on it before touching
         * NativeCore, the same way the Psiphon and Tor names do.
         */
        SHARD("SHARD", "shard", "Public nodes, auto-selected; no setup", true);

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class ScanTarget(
        val enLabel: String,
        val coreName: String,
        val enDescription: String,
    ) {
        IPV4("IPv4", "v4", "Scan IPv4 endpoints only"),
        IPV6("IPv6", "v6", "Scan IPv6 endpoints only"),
        BOTH("Both", "both", "Scan IPv4 and IPv6 endpoints");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class ScanMode(
        val enLabel: String,
        val coreName: String,
        val enDescription: String,
    ) {
        TURBO("Turbo", "turbo", "Fastest scan; first verified route wins"),
        BALANCED("Balanced", "balanced", "Default mix of speed and coverage"),
        THOROUGH("Thorough", "thorough", "Deep scan; selects best latency"),
        STEALTH("Stealth", "stealth", "Quiet, patient probing"),
        IRONCLAD("Ironclad", "ironclad", "Strict CONNECT-IP verification before selection");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class MasqueTransport(
        val enLabel: String,
        val coreName: String,
        val enDescription: String,
    ) {
        H3("HTTP/3", "h3", "QUIC first; falls back to HTTP/2 if UDP is blocked"),
        H2("HTTP/2", "h2", "TCP with TLS fragmentation; use on restricted networks");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class EndpointDiscovery(
        val enLabel: String,
        val coreName: String,
        val enDescription: String,
    ) {
        CACHE("Cache & refresh", "cache", "Use verified gateways first, then discover more"),
        FRESH("Fresh scan", "fresh", "Start a new scan every connection");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class ObfuscationProfile(val enLabel: String, val coreName: String, val enDescription: String) {
        OFF("Off", "off", "No traffic-shape padding"),
        LIGHT("Light", "light", "Lower overhead on mild filtering"),
        BALANCED("Balanced", "balanced", "Recommended filtering resistance"),
        AGGRESSIVE("Aggressive", "aggressive", "Highest resistance; slower setup");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class TlsCurvePreset(val enLabel: String, val coreName: String, val enDescription: String) {
        CHROME("Chrome", "chrome", "Chrome TLS curve ordering"),
        COMPATIBILITY("Compatibility", "compatibility", "P-256 and X25519 only");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class LogLevel(val enLabel: String, val coreName: String, val enDescription: String) {
        ERROR("Error", "error", "Only errors"),
        WARN("Warn", "warn", "Warnings and errors"),
        INFO("Info", "info", "Default verbosity"),
        DEBUG("Debug", "debug", "Tunnel internals"),
        TRACE("Trace", "trace", "Full per-packet detail");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class PerfProfile(val enLabel: String, val coreName: String, val enDescription: String) {
        AUTO("Auto", "auto", "Detect hardware and scale accordingly"),
        LOW("Low", "low", "Routers and constrained devices"),
        MEDIUM("Medium", "medium", "Moderate hardware"),
        HIGH("High", "high", "Desktop and powerful devices");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class H2Fragmentation(val enLabel: String, val coreName: String, val enDescription: String) {
        ON("On", "on", "Fragment TLS handshake to evade DPI"),
        OFF("Off", "off", "Standard TLS handshake");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private enum class LogTab(val enLabel: String) {
        ALL("All"),
        APP("App"),
        CORE("Core");

        val label: String get() = Strings.t(enLabel)
    }

    /**
     * How the chain picks the WARP transport that carries Psiphon.
     *
     * AUTO is the default and should stay it: it tries MASQUE, then WireGuard, then
     * WoW, and remembers the winner per device, so it is right on any carrier without
     * being told anything. The pinned entries exist for a user who already knows what
     * their carrier allows and would rather not sit through the search — a pin does
     * NOT fall back, since spending a minute on a transport known to be blocked is
     * the exact cost it is meant to avoid.
     */
    private enum class ChainOuterMode(
        val coreName: String,
        val enLabel: String,
        val enDescription: String,
    ) {
        AUTO(
            CoreConfig.CHAIN_OUTER_AUTO,
            "Auto",
            "Try MASQUE, then WireGuard, then WoW — remembers what works",
        ),
        MASQUE("masque", "MASQUE", "HTTP/3, falling back to HTTP/2 with TLS fragmentation"),
        WIREGUARD("wireguard", "WireGuard", "Single WARP tunnel; blocked on some carriers"),
        WOW("gool", "WoW", "WARP on WARP — slowest, for the most filtered networks");

        val label: String get() = Strings.t(enLabel)
        val description: String get() = Strings.t(enDescription)
    }

    private data class SelectionOption(
        val row: LinearLayout,
        val title: TextView,
        val indicator: TextView,
        val radius: Int,
    )

    private enum class TypefaceStyle { REGULAR, MEDIUM }

    private companion object {
        const val VPN_REQUEST = 100
        const val NOTIFICATION_PERMISSION_REQUEST = 101
        const val BACKUP_EXPORT_REQUEST = 102
        const val BACKUP_IMPORT_REQUEST = 103

        /**
         * One page to fetch for the "does it actually work" test on the DNS
         * screen. [expect] is a string a genuine response must contain; a body
         * without it means something answered that was not the site.
         *
         * These are chosen to be cheap, stable and outside the censored set: a
         * plain 204 proves reachability, and the generated page proves the
         * response body is really read, not just opened.
         */
        val CONTENT_TEST_TARGETS = listOf(
            ContentTestTarget("Cloudflare 204", "https://cloudflare.com/cdn-cgi/trace", ""),
            ContentTestTarget("Google 204", "https://connectivitycheck.gstatic.com/generate_204", ""),
            ContentTestTarget("Example", "https://example.com", "Example Domain"),
        )
        const val LOG_REFRESH_MS = 750L
        const val STATUS_POLL_MS = 2_000L
        const val PAGE_ANIMATION_MS = 220L
        const val LOG_CLOSE_ANIMATION_MS = 160L
        const val PING_TIMEOUT_MS = 5_000
        /**
         * Per-probe timeout while Tor carries the traffic.
         *
         * A three-hop circuit is simply slower than a single VPN hop: measured
         * on this project's own server, ten fresh circuits fetching
         * `generate_204` had a 1.19s median and a 1.62s worst case, and the
         * field log's successful probes ran 2.2–3.4s. 12s leaves headroom for a
         * bad circuit without letting a genuinely dead tunnel hang the sweep.
         */
        const val TOR_PING_TIMEOUT_MS = 12_000
        /**
         * How long a freshly handshaken tunnel gets to prove it passes traffic.
         * 18s covers a slow MASQUE gateway pick and Psiphon's own warm-up while
         * still failing fast enough that the user is not staring at a dead dial.
         */
        const val VERIFY_TIMEOUT_MS = 18_000L
        /**
         * Verification budget while Tor carries the traffic.
         *
         * Sized against the worst-case sweep, not against a guess: four probe
         * endpoints at [TOR_PING_TIMEOUT_MS] each is 48s if every one of them
         * times out, so a budget below that can fail after a single attempt.
         * That is what the 1.4.1 log showed — `No reachability after 1 probe(s)`
         * on a Tor tunnel that had bootstrapped to 100% — and it tore down a
         * working tunnel. 60s allows a full sweep plus a retry.
         */
        const val TOR_VERIFY_TIMEOUT_MS = 60_000L
        const val VERIFY_RETRY_DELAY_MS = 1_200L
        /**
         * Grace period after the dial goes green before the core's own byte
         * counters are checked. 12s is past the point where a working tunnel has
         * carried something (DNS alone does it) but short enough that the user
         * is not left trusting a dead tunnel. See watchForTunnelBytes.
         */
        const val BYTE_WATCH_MS = 12_000L
        /**
         * Bytes that must cross the TUN before a native tunnel counts as verified.
         *
         * Above the core's own keepalive/health-probe traffic (a DNS query every
         * three seconds, tens of bytes a round) and far below what loading any
         * real page moves, so it separates "the tunnel is alive" from "the
         * tunnel is only talking to itself".
         */
        const val VERIFY_MIN_RX_BYTES = 4_096L
        /**
         * Breathing room kept between the console's bottom edge and the viewport
         * when [fitConsoleToViewport] sizes the dial. Without it the action bar
         * ends up flush against the navigation bar, which reads as clipped even
         * though it is fully on screen.
         */
        const val FIT_SLACK_DP = 6
        /**
         * Dial floor for fa/zh, v1.8.7. The localized fonts' tall line boxes
         * used to make fitConsoleToViewport shrink the dial well below the
         * English layout's settled size; the user's requirement is that the
         * connect dial in Persian and Chinese be as large as the English one.
         * Raised 0.90 → 0.94 in v1.9.4: v1.9.3's AI MODE chip had made the
         * chip line 8dp taller, pushing the dial below 0.90 — the "connect
         * button got smaller" report. The chip line is compact again (2dp
         * padding/margins), so 0.94 holds; anything left over scrolls.
         */
        const val LOCALIZED_DIAL_FLOOR = 0.94f
        /**
         * Spare room required before the dial is allowed to grow back.
         *
         * Bigger than one line of the status text (13.5sp ≈ 18dp) on purpose: the
         * gap between "must shrink" and "may grow" is what stops a text change from
         * ping-ponging the dial and relayouting the whole column twice. See
         * [fitConsoleToViewport].
         */
        const val GROW_SLACK_DP = 28
        /**
         * Consecutive failed health checks tolerated on an established session
         * before the tunnel is declared dead and torn down. Three misses at the
         * 5s auto-ping interval ≈ 15s of genuinely no reachable endpoint, which
         * a transient carrier hiccup does not survive but a blackholed tunnel does.
         */
        const val MAX_PING_FAILURES = 3
        /**
         * Bytes the TUN must have carried since the previous health check for a
         * failed probe to be read as "busy" rather than "dead".
         *
         * Sized between two measured quantities:
         *
         *  * FLOOR — the core's own keepalive is a DNS query every three seconds,
         *    tens of bytes a round, so under a kilobyte per 5s ping interval.
         *    A failed probe contributes almost nothing itself: the endpoints are
         *    `generate_204`-style, so a timed-out fetch is headers at most. 64 KB
         *    is far above both, which is what stops a blackholed tunnel from
         *    excusing itself with its own housekeeping traffic.
         *  * CEILING — real use moves vastly more. In the load measurement one
         *    tor instance sustained 1375 KB/s, i.e. ~6.8 MB per interval, and
         *    even a single page load is hundreds of kilobytes.
         *
         * So the gap is about two orders of magnitude wide in both directions,
         * and the exact value inside it does not matter much.
         */
        const val BUSY_TUNNEL_RX_BYTES = 65_536L

        /**
         * Health-check endpoints, tried in order until one answers.
         *
         * Google stays first — it is reachable from Iran and returns an empty
         * 204, which is the cheapest possible probe. The rest exist so a single
         * endpoint having a bad day cannot paint "Connection degraded" over a
         * working tunnel.
         */
        val PING_URLS = arrayOf(
            "https://www.google.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "https://www.gstatic.com/generate_204",
            // DNS-free last resort. Every entry above needs a working resolver,
            // so a tunnel that carries packets but has broken DNS would look
            // completely dead and get torn down by the verification gate. A raw
            // IP literal proves the data plane on its own.
            "https://1.1.1.1/cdn-cgi/trace",
        )
        val IP_INFO_URLS = arrayOf(
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://one.one.one.one/cdn-cgi/trace",
            "https://1.1.1.1/cdn-cgi/trace",
            "https://api64.ipify.org",
            "https://api.ipify.org",
        )
        val IP_ADDRESS = Regex("^[0-9A-Fa-f:.]+$")
        /**
         * Geolocation endpoints for an address the core measured. `%s` is the IP.
         *
         * Both are HTTPS, keyless and Cloudflare-fronted (so reachable from Iran),
         * and both were verified from an uncensored host returning IR for
         * 104.28.214.161 and 104.28.214.167 — the real WARP exits that a
         * registration-based lookup wrongly called US.
         */
        val COUNTRY_LOOKUP_URLS = arrayOf(
            "https://get.geojs.io/v1/ip/country/%s.json",
            "https://ipwho.is/%s?fields=country_code",
        )
        /** Matches `"country":"IR"` and `"country_code":"IR"` alike. */
        val COUNTRY_CODE_JSON = Regex("\"country(?:_code)?\"\\s*:\\s*\"([A-Za-z]{2})\"")
        const val IP_TIMEOUT_MS = 5_000
        const val IP_FETCH_ATTEMPTS = 3
        const val IP_RETRY_DELAY_MS = 300L
        /**
         * Retries after a teardown, and the gap between them.
         *
         * 1.2 s × 4 covers roughly five seconds, which is comfortably past the
         * ~1 s tun2socks unwind measured in the field log while still ending
         * rather than retrying forever on a phone that genuinely has no
         * connectivity — there, "IP unavailable" is the truth and should be shown.
         */
        const val IP_POST_TEARDOWN_RETRIES = 4
        const val IP_POST_TEARDOWN_DELAY_MS = 1_200L
        const val SETTINGS = "settings"
        const val DEFAULT_SCAN = "default_scan"
        const val DEFAULT_SCAN_MODE = "default_scan_mode"
        const val ENDPOINT_DISCOVERY = "endpoint_discovery"
        const val DEFAULT_MASQUE_TRANSPORT = "default_masque_transport"
        const val OBFUSCATION_PROFILE = "obfuscation_profile"
        const val OBFUSCATION_JC = "obfuscation_jc"
        const val OBFUSCATION_JMIN = "obfuscation_jmin"
        const val OBFUSCATION_JMAX = "obfuscation_jmax"
        const val OBFUSCATION_I1 = "obfuscation_i1"
        const val OBFUSCATION_I2 = "obfuscation_i2"
        const val MANUAL_ENDPOINT = "manual_endpoint"
        const val MANUAL_INNER_ENDPOINT = "manual_inner_endpoint"
        const val CUSTOM_DNS = "dns_servers"
        /** v2.0.0: per-transport DNS lists. [CUSTOM_DNS] stays the plain-UDP
         * union, because that is all Android's own resolver list can speak. */
        const val CUSTOM_DNS_UDP = "dns_servers_udp"
        const val CUSTOM_DNS_DOT = "dns_servers_dot"
        const val CUSTOM_DNS_DOH = "dns_servers_doh"
        const val RETRY_OBFUSCATION = "retry_obfuscation_profiles"
        const val TLS_CURVE_PRESET = "tls_curve_preset"
        const val WIREGUARD_DATA_CHECK = "wireguard_data_check"
        const val KILL_SWITCH = "kill_switch"
        /** Whether Psiphon-over-WARP is armed for the next connect. */
        const val CHAIN_ARMED = "chain_armed"

        /**
         * Psiphon-over-WARP is armed by default.
         *
         * It is the combination that survives the carriers this app targets, and the
         * standing requirement here is one-click connect — a user who selects Psiphon
         * should not have to discover a second switch to get the working
         * configuration. An explicit choice by the user always wins over this: the
         * key is written on every toggle, so "off" persists.
         */
        // Off by default. With it on, selecting Psiphon silently meant
        // Psiphon-over-WARP, which on a fresh Iranian install needs an identity
        // the carrier has blocked — so the one independent transport was
        // chained to the one transport that cannot bootstrap, and it failed
        // together with it. "Psiphon" now means Psiphon, alone and independent.
        //
        // The chain is still one switch away for anyone who needs it, and an
        // explicit choice is remembered either way — this only sets the default
        // for a user who has not expressed one.
        const val CHAIN_ARMED_DEFAULT = false

        const val DEFAULT_PROTOCOL = "default_protocol"

        /**
         * Latch: the one-time Auto Scan has already found a transport that works.
         *
         * Set only when a rung actually carried verified traffic. A ladder that ran
         * out of rungs deliberately leaves this unset — the usual cause of "nothing
         * connected" is a phone with no data at all, and holding a permanent verdict
         * from that moment would deny the scan to the network where it would have
         * worked.
         *
         * Learned state, not a choice: listed in SettingsBackup's TRANSIENT_KEYS so a
         * backup cannot carry one device's answer onto another carrier.
         */
        const val AUTO_SCAN_DONE = "auto_scan_done"

        /**
         * The transports the Auto Scan is allowed to try, in order.
         *
         * Psiphon and Tor are absent by instruction: both are deliberate choices with
         * their own costs (an account-free anti-censorship stack and a three-hop
         * onion circuit), and moving a user onto them behind their back is not the
         * same favour as moving them between WARP transports. SHARD is last because
         * it is the only rung whose exit is a public node.
         *
         * The ladder is only entered when the transport that FAILED is itself on it —
         * a user who picked Tor and lost it gets their failure reported, not a silent
         * switch to something else.
         */
        val AUTO_SCAN_LADDER = listOf(
            Protocol.WIREGUARD,
            Protocol.MASQUE,
            Protocol.WARP_IN_WARP,
            Protocol.SHARD,
        )

        /**
         * Gap between abandoning one rung and dialling the next.
         *
         * The service clears its own re-entrancy guard (`connected`) BEFORE
         * stopTunnel() has finished unwinding, so a connect issued the instant a
         * failure arrives races that teardown: on the tun2socks rungs the old TUN is
         * still open, and the new session either loses its establish() or is torn
         * down by the tail of the old one.
         */
        const val AUTO_SCAN_HANDOVER_MS = 1_500L
        const val LOG_LEVEL = "log_level"
        const val PERF_PROFILE = "perf_profile"
        const val H2_FRAGMENTATION = "h2_fragmentation"
        const val MIXED_CASE_SNI = "mixed_case_sni"
        // The FALLBACK_* colours that used to live here are gone: they were the
        // last copy of the retired green-grey palette, unreferenced since the
        // Orbit palette landed, and with a second palette in play a stray hex
        // constant is a light-theme bug waiting to be reintroduced. ERROR went
        // the same way — it is AppAppearance.Palette.error now, so it changes with
        // the theme instead of staying a dark-theme pink on a white card.
        const val DISABLED_ALPHA = 0.48f
    }
}

private class ChevronView(context: Context, private val color: Int) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeWidth = resources.displayMetrics.density * 1.8f
        this.color = this@ChevronView.color
    }

    override fun onDraw(canvas: Canvas) {
        val middleX = width / 2f
        val middleY = height / 2f - resources.displayMetrics.density
        val arm = resources.displayMetrics.density * 4f
        canvas.drawLine(middleX - arm, middleY - arm / 2, middleX, middleY + arm / 2, paint)
        canvas.drawLine(middleX, middleY + arm / 2, middleX + arm, middleY - arm / 2, paint)
    }
}

/**
 * One target for the DNS screen's real-fetch test: a URL plus the string a
 * truthful response must contain.
 */
private data class ContentTestTarget(val label: String, val url: String, val expect: String)
