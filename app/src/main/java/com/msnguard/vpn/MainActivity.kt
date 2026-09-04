package com.msnguard.vpn

import android.app.Activity
import android.app.Dialog
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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
import androidx.core.content.FileProvider
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import kotlin.math.min
import kotlin.math.roundToInt

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
    private var splitTunnelDraftMode: SplitTunnelSettings.Mode? = null
    private var splitTunnelDraftPackages: MutableSet<String>? = null
    private var trafficMonitorPage: View? = null
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
                        setModeEnabled(true)
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
        palette = AppAppearance.load(this)
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

        // Orbit console. Every control below is built in onCreate so a single
        // pass wires the whole screen; no XML layouts exist in this app.
        orbitDial = OrbitDialView(this, palette).apply {
            setOnClickListener { toggleTunnel() }
        }
        connectionTitle = label(textSize = 21f, color = INK, style = TypefaceStyle.MEDIUM).apply {
            gravity = Gravity.CENTER
        }
        connectionDetail = label(textSize = 13.5f, color = MUTED).apply { gravity = Gravity.CENTER }
        chipLatency = label("Latency —", 12f, MUTED, TypefaceStyle.MEDIUM).apply {
            gravity = Gravity.CENTER
            contentDescription = "Ping connection"
            isClickable = true
            isFocusable = true
            setOnClickListener { pingConnection() }
        }
        chipProtocol = label(selectedProtocol.label.uppercase(), 12f, MUTED, TypefaceStyle.MEDIUM).apply {
            gravity = Gravity.CENTER
            letterSpacing = 0.08f
        }
        selectedProtocol = savedProtocol()
        chipProtocol.text = selectedProtocol.label.uppercase()
        // One accent per tile, as in the approved mock: download mint, upload
        // violet, speed amber. They were all `primary` before, which is why every
        // sparkline looked identical.
        tileDown = MetricTile(
            this, palette, "↓ DOWN",
            palette.mint, Sculpt.lighten(palette.mint, 0.30f), palette.mintText,
        ) { openTrafficMonitorScreen() }
        tileUp = MetricTile(
            this, palette, "↑ UP",
            palette.violet, Sculpt.lighten(palette.violet, 0.30f), palette.violetText,
        ) { openTrafficMonitorScreen() }
        tileSpeed = MetricTile(
            this, palette, "SPEED",
            palette.amber, Sculpt.lighten(palette.amber, 0.30f), palette.amberText,
        ) { openTrafficMonitorScreen() }
        exitNodeCard = ExitNodeCard(this, palette) { refreshPublicIp() }
        chainCard = ChainModeCard(this, palette) { armed -> setChainArmed(armed) }
        smartSplitCard = SmartSplitCard(this, palette) { on -> setSmartSplitEnabled(on) }
        transportRail = TransportRail(this, palette, Protocol.entries.map { railLabel(it) }) { index ->
            updateConnectionMode(Protocol.entries[index])
        }
        // Height follows the grid rather than being a constant: the rail decides how
        // many rows six transports need, and a hardcoded dp(46) would squash them.
        transportRailHeight = dp(8) + transportRail.rowCount * dp(38)
        transportRail.select(Protocol.entries.indexOf(selectedProtocol), animate = false)
        renderChainCard()
        // The dead space under the action bar looked like a rendering bug. It is
        // now a thin signal trace that idles flat and grey, and ripples in the
        // connected accent once traffic is flowing. One 48-point path repainted at
        // 20fps only while connected — no bitmaps, no extra APK weight.
        footerWave = OrbitFooterWave(this, palette, "SECURED BY MSN-GUARD")
        statusLed = View(this).apply {
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density,
                Sculpt.withAlpha(MUTED, 0.5f),
                999,
            )
        }

        mainRoot = FrameLayout(this).apply { setBackgroundColor(CANVAS) }
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
            showDisconnected("VPN permission required")
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
        chipLatency.text = "Latency …"
        Thread {
            // Try each endpoint until one answers. A single unreachable probe URL
            // must not be reported as a degraded tunnel.
            val result: Pair<String, Float?> = pingAnyEndpoint() ?: ("Ping unavailable" to null)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                pingInFlight = false
                if (request == latencyRequest && isTunnelActive()) {
                    chipLatency.text = result.second?.let { "Latency ${it.toInt()} ms" } ?: "Latency n/a"
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
                                probe?.let { chipLatency.text = "Latency ${it.second.toInt()} ms" }
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
                    chipLatency.text = "Latency ${verified.second.toInt()} ms"
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
            connectionDetail.text = "Tunnel is up but no traffic is passing"
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
        showFailure("Tunnel handshake succeeded but no traffic passes — try another protocol")
    }

    /** The state between handshake and proof. Keeps the dial in its CONNECTING look. */
    private fun showVerifying() {
        showConnectionProgress("Verifying", "Checking that traffic really passes")
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
        addView(label("MSN-GUARD", 13f, MUTED, TypefaceStyle.MEDIUM).apply {
            letterSpacing = 0.14f
        })
        addView(View(this@MainActivity), LinearLayout.LayoutParams(0, 1, 1f))
        addView(ImageView(this@MainActivity).apply {
            setImageResource(R.drawable.ic_settings)
            contentDescription = "Settings"
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
        Protocol.WARP_IN_WARP -> "WoW"
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
            val current = orbitDial.sizeScale
            // Clamped to the SAME range the setter enforces. If the target were
            // left below the floor, current would sit clamped at the floor while
            // target stayed lower, and the two would never agree — an endless
            // relayout loop on a screen too short to satisfy.
            val target = (current * (dialBox - delta).toFloat() / dialBox)
                .coerceIn(OrbitDialView.MIN_SIZE_SCALE, 1f)

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

        addView(connectionTitle, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(14) })
        addView(connectionDetail, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(3) })

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
        ).apply { topMargin = dp(7) })

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
            addView(label("Logs", 22f, INK, TypefaceStyle.MEDIUM), LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f,
            ))
            // COPY and SHARE act on the whole log FILE, not on the text above.
            // What is on screen is the ring buffer (100 entries) plus
            // NativeCore.lastLog(), and both drop their oldest lines — which is
            // exactly why the beginning of a long log was unreachable. The file
            // that ConnectionLog mirrors to keeps everything up to its 256KB cap.
            addView(createLogActionButton("COPY") { copyFullLog() })
            addView(createLogActionButton("SHARE") { shareFullLog() })
        }
        content.addView(header)
        content.addView(label("Tunnel and VPN events", 14f, MUTED), LinearLayout.LayoutParams(
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
        val pauseChip = toolChip("Pause") {
            paused = !paused
            it.text = if (paused) "Resume" else "Pause"
            paintChip(it, paused)
        }
        // WRAP off makes the text view scroll horizontally instead, so long
        // Psiphon JSON notices stop wrapping into six-line paragraphs.
        val wrapChip = toolChip("Wrap") {
            wrapLines = !wrapLines
            paintChip(it, wrapLines)
            events.setHorizontallyScrolling(!wrapLines)
            events.requestLayout()
        }
        val clearChip = toolChip("Clear") {
            ConnectionLog.clear()
            renderedLogs = null
            Toast.makeText(this, "App log cleared", Toast.LENGTH_SHORT).show()
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
        return events.joinToString("\n").ifBlank { "No connection events yet" }
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
            letterSpacing = 0.1f
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(7), dp(12), dp(7))
            background = roundedBackground(SURFACE_VARIANT, 12, DIVIDER)
            isClickable = true
            isFocusable = true
            contentDescription = "$caption the full log"
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
     * Copies the full log to the clipboard on a background thread.
     *
     * The read is off the main thread because the file can be a quarter of a
     * megabyte and this is invoked from a tap; the clipboard write itself has to be
     * on the main thread. Nothing is ever put into a TextView, which is what would
     * actually freeze the UI on a long log.
     */
    private fun copyFullLog() {
        Thread({
            val text = runCatching { fullLogText() }.getOrElse { "Could not read the log: ${it.message}" }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                val clipboard = getSystemService(ClipboardManager::class.java)
                clipboard?.setPrimaryClip(ClipData.newPlainText("MSN-GUARD log", text))
                // Always confirm, on every Android version. Android 13+ shows its
                // own clipboard chip, so this is briefly a duplicate there — but a
                // silent COPY on a long log is indistinguishable from a broken
                // button, and being told twice is better than not being told.
                Toast.makeText(
                    this,
                    "Log copied (${text.length / 1024} KB)",
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
                target.writeText(fullLogText())
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
                            "Share log",
                        )
                    )
                }
            }
        }, "log-share").start()
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
        return if (count == 0) "Nothing saved yet" else "$count settings"
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
                toastShort("Could not read the settings: ${it.message}")
                return
            }
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/json")
            .putExtra(Intent.EXTRA_TITLE, SettingsBackup.suggestedFileName(appVersion()))
        runCatching { startActivityForResult(intent, BACKUP_EXPORT_REQUEST) }
            .onFailure {
                pendingBackupJson = null
                toastShort("This device has no file picker")
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
            toastShort("Disconnect first — a restore changes what the tunnel uses")
            return
        }
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("*/*")
        runCatching { startActivityForResult(intent, BACKUP_IMPORT_REQUEST) }
            .onFailure { toastShort("This device has no file picker") }
    }

    /** Writes [pendingBackupJson] into the document the picker returned. */
    private fun writeBackup(uri: Uri) {
        val payload = pendingBackupJson
        pendingBackupJson = null
        if (payload == null) {
            toastShort("The backup was not ready — try again")
            return
        }
        val result = runCatching {
            contentResolver.openOutputStream(uri, "wt")
                ?.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
                ?: error("the file could not be opened for writing")
        }
        result.onSuccess {
            ConnectionLog.record("Settings backed up (${SettingsBackup.valueCount(this)} values)")
            toastShort("Settings saved — this file holds no passwords")
            settingsBackupRow?.setValue(backupSummary())
        }.onFailure {
            toastShort("Could not write the backup: ${it.message}")
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
            toastShort("Could not read the file: ${it.message}")
            return
        }
        val outcome = runCatching { SettingsBackup.restore(this, text) }.getOrElse {
            toastShort(it.message ?: "This file is not a settings backup")
            return
        }
        ConnectionLog.record(
            "Settings restored from a v${outcome.version} backup: " +
                "${outcome.restored} value(s)" +
                if (outcome.skipped > 0) ", ${outcome.skipped} skipped" else ""
        )
        toastShort("Restored ${outcome.restored} settings from v${outcome.version}")
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
            toastShort("Disconnect first — a reset changes what the tunnel uses")
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
            addView(label("Reset to defaults", 22f, INK, TypefaceStyle.MEDIUM))
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
        buttons.addView(createSettingsButton("Cancel") { dialog.dismiss() }, LinearLayout.LayoutParams(0, dp(52), 1f))
        buttons.addView(createSettingsButton(
            "Reset",
            backgroundOverride = primary,
            textColorOverride = primaryContainer,
        ) {
            SettingsBackup.resetToDefaults(this)
            ConnectionLog.record("Settings reset to defaults")
            dialog.dismiss()
            toastShort("Settings reset to defaults")
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
            addView(label("Scanner options", 22f, INK, TypefaceStyle.MEDIUM).apply {
                setPadding(dp(4), 0, 0, 0)
            })
        }
        content.addView(label("Choose Aether's endpoint-discovery budget and address families", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(4); bottomMargin = dp(24) })

        val options = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val discoveryOptions = mutableMapOf<EndpointDiscovery, SelectionOption>()
        val transportOptions = mutableMapOf<MasqueTransport, SelectionOption>()
        val modeOptions = mutableMapOf<ScanMode, SelectionOption>()
        val targetOptions = mutableMapOf<ScanTarget, SelectionOption>()

        options.addView(label(if (selectedProtocol == Protocol.MASQUE) "MASQUE GATEWAY DISCOVERY" else "WIREGUARD ENDPOINT DISCOVERY", 12f, MUTED).apply { letterSpacing = 0.1f })
        EndpointDiscovery.entries.forEachIndexed { index, discovery ->
            val option = createEndpointDiscoveryOption(discovery) { chosen ->
                getSharedPreferences(SETTINGS, MODE_PRIVATE).edit()
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
            options.addView(label("MASQUE TRANSPORT", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(20) })
            MasqueTransport.entries.forEachIndexed { index, transport ->
                val option = createMasqueTransportOption(transport) { chosen ->
                    getSharedPreferences(SETTINGS, MODE_PRIVATE).edit().putString(DEFAULT_MASQUE_TRANSPORT, chosen.coreName).apply()
                    transportOptions.forEach { (item, view) -> setSelectionState(view, item == chosen, animate = true) }
                }
                transportOptions[transport] = option
                options.addView(option.row, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    dp(68),
                ).apply { topMargin = if (index == 0) dp(10) else dp(8) })
            }
        }

        options.addView(label("SCAN MODE", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(20) })
        ScanMode.entries.forEachIndexed { index, mode ->
            val option = createScanModeOption(mode) { chosen ->
                getSharedPreferences(SETTINGS, MODE_PRIVATE).edit().putString(DEFAULT_SCAN_MODE, chosen.coreName).apply()
                modeOptions.forEach { (item, view) -> setSelectionState(view, item == chosen, animate = true) }
            }
            modeOptions[mode] = option
            options.addView(option.row, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(68),
            ).apply { topMargin = if (index == 0) dp(10) else dp(8) })
        }

        options.addView(label("IP VERSION", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(20) })
        ScanTarget.entries.forEachIndexed { index, target ->
            val option = createScannerOption(target) { chosen ->
                getSharedPreferences(SETTINGS, MODE_PRIVATE).edit().putString(DEFAULT_SCAN, chosen.coreName).apply()
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
        val indicator = label("SELECTED", 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
        val row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            contentDescription = "Scan ${target.label} endpoints"
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
            addView(indicator)
        }
        return SelectionOption(row, title, indicator, 18).also { setSelectionState(it, selected, animate = false) }
    }

    private fun createEndpointDiscoveryOption(
        discovery: EndpointDiscovery,
        onSelect: (EndpointDiscovery) -> Unit,
    ): SelectionOption {
        val selected = discovery == defaultEndpointDiscovery()
        val title = label(discovery.label, 16f, INK, TypefaceStyle.MEDIUM)
        val indicator = label("SELECTED", 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
        val row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            contentDescription = "Use ${discovery.label} MASQUE gateway discovery"
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
            addView(indicator)
        }
        return SelectionOption(row, title, indicator, 18).also { setSelectionState(it, selected, animate = false) }
    }

    private fun createScanModeOption(mode: ScanMode, onSelect: (ScanMode) -> Unit): SelectionOption {
        val selected = mode == defaultScanMode()
        val title = label(mode.label, 16f, INK, TypefaceStyle.MEDIUM)
        val indicator = label("SELECTED", 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
        val row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            contentDescription = "Use ${mode.label} scan mode"
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
            addView(indicator)
        }
        return SelectionOption(row, title, indicator, 18).also { setSelectionState(it, selected, animate = false) }
    }

    private fun createMasqueTransportOption(
        transport: MasqueTransport,
        onSelect: (MasqueTransport) -> Unit,
    ): SelectionOption {
        val selected = transport == defaultMasqueTransport()
        val title = label(transport.label, 16f, INK, TypefaceStyle.MEDIUM)
        val indicator = label("SELECTED", 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
        val row = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            contentDescription = "Use ${transport.label} for MASQUE scanning"
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
            addView(indicator)
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
            addView(label("Connection mode", 22f, INK, TypefaceStyle.MEDIUM).apply {
                setPadding(dp(4), 0, 0, 0)
            })
        }
        content.addView(header, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(8) })

        content.addView(label("Choose how MSN-GUARD connects", 14f, MUTED), LinearLayout.LayoutParams(
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
            if (selected) addView(label("CURRENT", 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply {
                letterSpacing = 0.08f
            }) else if (!protocol.androidAvailable) addView(label("DESKTOP ONLY", 11f, MUTED, TypefaceStyle.MEDIUM).apply {
                letterSpacing = 0.05f
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
            addView(label("Settings", 22f, INK, TypefaceStyle.MEDIUM).apply {
                setPadding(dp(4), 0, 0, 0)
            })
        }
        content.addView(sectionLabel("PROTECTION"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ))
        lateinit var killSwitchRow: LinearLayout
        killSwitchRow = createToggleRow("Kill switch", "Block all traffic if the tunnel drops", killSwitchEnabled()) {
            preferences().edit().putBoolean(KILL_SWITCH, it).apply()
        }
        content.addView(killSwitchRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })

        // Auto-reconnect sits next to the kill switch because the two answer the
        // same question — "the tunnel just died, now what?" — and a user who wants
        // one usually wants the other. It is deliberately NOT tied to the kill
        // switch: blocking traffic and retrying are independent choices, and
        // pairing them would mean you cannot retry without blocking.
        val autoReconnectRow = createToggleRow(
            "Auto reconnect",
            "Reconnect automatically if the tunnel drops",
            autoReconnectEnabled(),
        ) {
            preferences().edit().putBoolean(MsnGuardVpnService.AUTO_RECONNECT_PREF, it).apply()
        }
        content.addView(autoReconnectRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })

        content.addView(sectionLabel("ROUTING & DATA"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        content.addView(navRow("Traffic monitor", trafficHeadline()) { openTrafficMonitorScreen() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })
        splitTunnelSummaryButton = navRow("Split tunneling", splitTunnelSummary()) { openSplitTunnelScreen() }
        content.addView(splitTunnelSummaryButton, LinearLayout.LayoutParams(
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
        val lanBypassRow = createToggleRow(
            "Local network access",
            "Reach printers, NAS and your router while connected",
            lanBypassEnabled(),
        ) {
            preferences().edit().putBoolean(MsnGuardVpnService.LAN_BYPASS_PREF, it).apply()
        }
        content.addView(lanBypassRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // PERF moved here off the home screen: a once-a-year knob does not earn
        // a quarter of the first thing the user sees.
        lateinit var perfRow: OrbitSettingsRow
        perfRow = navRow("Performance", perfProfile().label) {
            choosePerfProfile { perfRow.setValue(perfProfile().label) }
        }
        content.addView(perfRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })

        content.addView(sectionLabel("CONNECTION"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        // Tunnel type comes FIRST in this section, above the transport picker.
        //
        // It is the most consequential switch in the app — it decides whether the
        // whole phone is tunnelled or only the apps the user points at a port — and
        // it changes what every row below it means. Burying it under Psiphon/Tor
        // detail would repeat the mistake the log-level chips made: a real decision
        // parked where nobody looks.
        val typeRow = navRow("Tunnel type", tunnelTypeLabel()) { chooseTunnelType() }
        tunnelTypeRow = typeRow
        content.addView(typeRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })
        // The port box: directly under the type it belongs to, and inert until SOCKS
        // is chosen. Greyed rather than hidden, so the user can see that choosing
        // SOCKS is what unlocks it instead of a row appearing out of nowhere.
        val portRow = navRow("SOCKS port", proxyPortValue()) { editProxyPort() }
        proxyPortRow = portRow
        content.addView(portRow, LinearLayout.LayoutParams(
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
        val lanRow = OrbitToggleRow(
            this,
            palette,
            "Share over LAN",
            lanSharingSubtitle(),
            lanSharingEnabled() && lanSharingCapable(),
        ) { on ->
            preferences().edit().putBoolean(CoreConfig.LAN_SHARING_PREF, on).apply()
            ConnectionLog.record(
                if (on) {
                    "LAN sharing enabled — applies on the next connect"
                } else {
                    "LAN sharing disabled — applies on the next connect"
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
        }
        lanSharingRow = lanRow
        content.addView(lanRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // Held in a field, not a local: the mode screen is a separate page that
        // writes the preference and pops back here, so the row that shows the
        // current mode has to be repaintable from outside this builder. Without
        // that, picking a mode only appeared after leaving and re-entering
        // settings, because this row was built once with the old value.
        val modeRow = navRow("Connection mode", selectedProtocol.label) { openModeScreen() }
        connectionModeRow = modeRow
        content.addView(modeRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })
        content.addView(navRow("Tunnel controls", "Shaping · Anti-DPI") { openTunnelControlsScreen() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // Log verbosity: moved here from the Logs screen, where five chips looked
        // like live filters and were in fact a build-time core setting — a tap did
        // nothing until the next connect. Here the value is visible in the row and
        // the "next connection" wording sets the expectation.
        val logLevelRow = navRow("Log verbosity", logLevel().label) { chooseLogLevel() }
        logVerbosityRow = logLevelRow
        content.addView(logLevelRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // Both rows came off the home screen's action bar, which was removed to make
        // room for a six-transport rail. They sit under Log verbosity because that is
        // the row that decides what the log will contain.
        content.addView(navRow("Log", "What the tunnel did") { openLogsScreen() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // Names the two transports it applies to. As an unlabelled action-bar button
        // it looked global, and on Psiphon, Tor or SHARD there is nothing to scan —
        // those transports find their own paths.
        val scanRow = navRow("Scan Mode", scanModeSummary()) { openScannerScreen() }
        scannerRow = scanRow
        content.addView(scanRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })

        // Psiphon gets its own section: all three controls below are meaningless
        // unless the chain is armed, and grouping them says that structurally
        // instead of relying on the user to infer it from a mixed list.
        content.addView(sectionLabel("PSIPHON"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        // The switch comes first because it gates the two rows under it. Toggling
        // it repaints them in place — and the home-screen card too, which is the
        // same setting shown twice and must never disagree.
        //
        // Built as an OrbitToggleRow directly rather than through createToggleRow():
        // that helper returns LinearLayout, and this row has to be re-checked and
        // re-enabled from outside the builder (the home-screen card writes the same
        // preference, and the chain is only available on the PSIPHON transport).
        val chainRow = OrbitToggleRow(
            this,
            palette,
            "Psiphon over WARP",
            "Tunnel Psiphon inside a WARP transport",
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
        }
        psiphonChainRow = chainRow
        content.addView(chainRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })

        val outerRow = navRow("Outer transport", chainOuterMode().label) {
            chooseChainOuterMode { chainOuterRow?.setValue(chainOuterMode().label) }
        }
        chainOuterRow = outerRow
        content.addView(outerRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // Last of the three: the transport row decides what carries Psiphon, this
        // one decides where Psiphon comes out. Reading downwards follows the packet.
        val countryRow = navRow("Preferred country", egressRegionLabel()) {
            chooseEgressRegion { egressRegionRow?.setValue(egressRegionLabel()) }
        }
        egressRegionRow = countryRow
        content.addView(countryRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })

        // Tor section, mirroring the Psiphon one: the mode picker is the only
        // control, and it is meaningful regardless of what else is set.
        content.addView(sectionLabel("TOR"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        val torModeRow = navRow("Connection mode", torMode().label) {
            chooseTorMode {
                torModeRowRef?.setValue(torMode().label)
                // The mode decides whether the chain can apply at all, so both the
                // switch below and the home card have to be repainted after a pick —
                // otherwise arming stays lit under a freshly pinned obfs4.
                refreshPsiphonRows()
                renderChainCard()
            }
        }
        torModeRowRef = torModeRow
        content.addView(torModeRow, LinearLayout.LayoutParams(
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
        val torBridgeRow = navRow("Manual bridge", TorManualBridges.summary(this)) {
            editTorBridges()
        }
        torBridgeRowRef = torBridgeRow
        content.addView(torBridgeRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // Tor's own chain switch, separate from Psiphon's. Placed directly under the
        // mode row because the mode is what decides whether it can apply: Direct and
        // Meek can be chained, obfs4 and Snowflake cannot, and Manual depends on
        // what the pasted lines use.
        val torChainRow = OrbitToggleRow(
            this,
            palette,
            "Tor over WARP",
            "Direct, Meek and your own bridges, inside a WARP transport",
            chainArmed(Protocol.TOR) && selectedProtocol == Protocol.TOR &&
                TorManager.isChainable(this, torMode()),
        ) { armed ->
            setChainArmed(armed, Protocol.TOR)
            renderChainCard()
            refreshPsiphonRows()
        }
        torChainRowRef = torChainRow
        content.addView(torChainRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // Tor's outer transport, mirroring Psiphon's row and in the same position
        // relative to its switch: which WARP tunnel carries Tor. Writes Tor's own
        // key, so pinning WoW for Psiphon leaves Tor on Auto.
        val torOuterRow = navRow("Outer transport", torChainOuterMode().label) {
            chooseTorChainOuterMode { torChainOuterRow?.setValue(torChainOuterMode().label) }
        }
        torChainOuterRow = torOuterRow
        content.addView(torOuterRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // Same control as Psiphon's "Preferred country", same wording, same
        // preference-not-a-pin semantics — deliberately, because to the user it is
        // the same question. Underneath it is tor's ExitNodes with StrictNodes 0.
        val torCountryRow = navRow("Preferred country", torRegionLabel()) {
            chooseTorRegion { torRegionRowRef?.setValue(torRegionLabel()) }
        }
        torRegionRowRef = torCountryRow
        content.addView(torCountryRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        // Only now, with BOTH sections' rows constructed and their refs assigned.
        // This call used to sit right after the Psiphon rows, where torChainRowRef
        // and torRegionRowRef were still null — so the Tor rows were built and
        // never had their availability applied, and both stayed fully live on a
        // page where MASQUE or Psiphon was the selected transport.
        refreshPsiphonRows()

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
        content.addView(sectionLabel("SHARD"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        val shardRow = navRow("Node list", shardPoolSummary()) {
            // force = true: the whole point of tapping this is to bypass the
            // six-hour interval the background job honours.
            shardPoolRow?.setValue("Updating…")
            ShardSubscription.refreshIfDue(this, force = true) { count ->
                runOnUiThread {
                    shardPoolRow?.setValue(shardPoolSummary())
                    toastShort(
                        if (count > 0) "$count nodes available" else "Could not update the list"
                    )
                }
            }
        }
        shardPoolRow = shardRow
        content.addView(shardRow, LinearLayout.LayoutParams(
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
        val splitRow = OrbitToggleRow(
            this,
            palette,
            "Smart Split",
            SmartSplit.summary(this),
            SmartSplit.enabled(this),
        ) { on ->
            setSmartSplitEnabled(on)
            smartSplitRow?.setSubtitle(SmartSplit.summary(this))
            renderChainCard()
        }
        smartSplitRow = splitRow
        content.addView(splitRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })

        // The escape hatch for a wrong measurement, and the only reason the user
        // ever needs to know a measurement happened at all. A carrier that changes
        // its DPI, or a cached "not effective here" from a bad minute on the
        // network, would otherwise be sticky until the app's data is cleared.
        val remeasureRow = navRow("Re-measure network", "") {
            SmartSplit.forgetMeasurements(this)
            smartSplitRow?.setSubtitle(SmartSplit.summary(this))
            renderChainCard()
            toastShort("Will re-measure on the next connect")
        }
        content.addView(remeasureRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })

        // APPEARANCE, like BACKUP below it, is about the app rather than about a
        // tunnel, so it sits out here and not under Tunnel Controls.
        content.addView(sectionLabel("APPEARANCE"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        // No stored reference: picking a theme calls recreate(), so the row is
        // rebuilt with the new value rather than being repainted in place.
        content.addView(navRow("Theme", AppAppearance.mode(this).label) { chooseTheme() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })

        // BACKUP sits outside Tunnel Controls, next to ABOUT: it is about the
        // app's own state, not about how a tunnel is shaped, and burying it in a
        // troubleshooting sub-page is where a user would never look for it after
        // reinstalling.
        content.addView(sectionLabel("BACKUP"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        val backupRow = navRow("Back up settings", backupSummary()) { exportSettings() }
        settingsBackupRow = backupRow
        content.addView(backupRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })
        content.addView(navRow("Restore settings", "From a backup file") { importSettings() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        content.addView(navRow("Reset to defaults", "Forget every setting") { confirmResetSettings() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })

        content.addView(sectionLabel("ABOUT"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        content.addView(navRow("Check for updates", "v${appVersion()}") {
            appUpdater.checkForUpdate()
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })
        content.addView(navRow("Source on GitHub", iconRes = R.drawable.ic_github) {
            openLink("https://github.com/mbm110/MSN-GUARD")
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        content.addView(label("MSN-GUARD ${appVersion()}", 11.5f, Sculpt.withAlpha(MUTED, 0.7f)).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            letterSpacing = 0.06f
            setPadding(0, dp(22), 0, 0)
        })

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
            addView(label("Tunnel controls", 22f, INK, TypefaceStyle.MEDIUM))
        })
        content.addView(label("Applied on your next connection", 13.5f, MUTED), LinearLayout.LayoutParams(
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
        content.addView(sectionLabel("CONNECTION SHAPING"))
        lateinit var obfRow: OrbitSettingsRow
        obfRow = addControl("Obfuscation", obfuscationProfile().label) {
            chooseObfuscation { obfRow.setValue(obfuscationProfile().label) }
        }
        addControl("Advanced obfuscation", advancedObfuscationSummary()) { editAdvancedObfuscation() }
        lateinit var retryRow: OrbitSettingsRow
        retryRow = addControl("WireGuard retries", if (retryObfuscationProfiles()) "On" else "Off") {
            preferences().edit().putBoolean(RETRY_OBFUSCATION, !retryObfuscationProfiles()).apply()
            retryRow.setValue(if (retryObfuscationProfiles()) "On" else "Off")
        }
        content.addView(sectionLabel("ROUTING"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        addControl("Manual endpoint", manualEndpoint() ?: "Automatic") { editManualEndpoint() }
        addControl("Gateway cache", defaultEndpointDiscovery().label) { manageGatewayCache() }
        content.addView(sectionLabel("TROUBLESHOOTING"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        lateinit var tlsRow: OrbitSettingsRow
        tlsRow = addControl("TLS fingerprint", tlsCurvePreset().label) {
            chooseTlsCurvePreset { tlsRow.setValue(tlsCurvePreset().label) }
        }
        lateinit var verificationRow: OrbitSettingsRow
        verificationRow = addControl("WireGuard verification", if (wireGuardDataCheck()) "Strict" else "Fast") {
            preferences().edit().putBoolean(WIREGUARD_DATA_CHECK, !wireGuardDataCheck()).apply()
            verificationRow.setValue(if (wireGuardDataCheck()) "Strict" else "Fast")
        }
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
        content.addView(sectionLabel("ANTI-DPI"), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(26) })
        lateinit var fragRow: OrbitSettingsRow
        fragRow = addControl("TLS fragmentation", if (h2Fragmentation() == H2Fragmentation.ON) "On" else "Off") {
            chooseH2Fragmentation {
                fragRow.setValue(if (h2Fragmentation() == H2Fragmentation.ON) "On" else "Off")
            }
        }
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
            addView(label("Obfuscation", 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label("Adjust traffic-shape padding for filtered networks", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        val options = mutableMapOf<ObfuscationProfile, SelectionOption>()
        ObfuscationProfile.entries.forEachIndexed { index, profile ->
            val title = label(profile.label, 16f, INK, TypefaceStyle.MEDIUM)
            val indicator = label("SELECTED", 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
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
                addView(indicator)
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
        title = "TLS fingerprint",
        subtitle = "Choose TLS curve ordering for QUIC connections",
        options = TlsCurvePreset.entries.toList(),
        selected = tlsCurvePreset(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit().putString(TLS_CURVE_PRESET, chosen.coreName).apply()
        after?.invoke()
    }

    private fun choosePerfProfile(after: (() -> Unit)? = null) = showChoiceSheet(
        title = "Performance",
        subtitle = "Scale scan concurrency and buffers to match your hardware",
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
                "Tor cannot run as a SOCKS proxy — set Tunnel type to VPN"
            } else if (selectedProtocol == Protocol.SHARD) {
                "SHARD shares from VPN mode — set Tunnel type to VPN"
            } else {
                "Set Tunnel type to SOCKS proxy to share ${selectedProtocol.label}"
            }
        }
        if (!lanSharingEnabled()) {
            return "Let other devices use this tunnel"
        }
        val host = CoreConfig.localNetworkAddress(this)
            ?: return "No local network — turn on the hotspot or join Wi-Fi"
        // SHARD's listener is xray's own, on its own port. CoreConfig.sharedSocksPort
        // answers for the Rust core and Psiphon and would print 1819 here — a port
        // nothing is listening on during a SHARD session, so anyone who typed it
        // into another device would get a refused connection and no explanation.
        val socksPort = if (selectedProtocol == Protocol.SHARD) {
            ShardManager.SOCKS_PORT
        } else {
            CoreConfig.sharedSocksPort(this)
        }
        return "SOCKS5 $host:$socksPort · " +
            "HTTP $host:${CoreConfig.HTTP_PROXY_PORT} · no password"
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
        title = "Outer transport",
        subtitle = "Which WARP tunnel carries Tor in Tor over WARP",
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
        title = "Outer transport",
        subtitle = "Which WARP tunnel carries Psiphon in Psiphon over WARP",
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
     * Pick how Tor connects.
     *
     * Auto walks Direct → obfs4 → Meek → Snowflake on every connect, starting
     * from whichever worked last. A pinned mode is exactly that: one method, no
     * silent fallback — the service surfaces "try Auto" in its error instead.
     */
    private fun chooseTorMode(after: (() -> Unit)? = null) {
        val modes = TorManager.TorMode.entries.toList()
        showChoiceSheet(
            title = "Connection mode",
            subtitle = "How Tor reaches the network. Auto tries each method until one works.",
            options = modes,
            selected = torMode(),
            label = { it.label },
            description = { mode ->
                // Manual's description carries its own state, because picking it
                // with an empty box is the one choice in this sheet that cannot
                // work — and the sheet is where the user decides.
                if (mode == TorManager.TorMode.MANUAL && !TorManualBridges.isConfigured(this)) {
                    "Enter a bridge first, in the row below this one"
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
                    "Enter a bridge in Manual bridge first"
                } else {
                    null
                }
            },
        ) { chosen ->
            preferences().edit().putString(TorManager.MODE_PREF, chosen.key).apply()
            ConnectionLog.record(
                if (chosen == TorManager.TorMode.AUTO) {
                    "Tor connection mode set to Auto"
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
            addView(label("Manual bridge", 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label(
            "One bridge per line, exactly as you received it. obfs4, meek_lite, " +
                "webtunnel and snowflake are supported, as is a plain IP:port.",
            14f, MUTED,
        ), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(16) })
        sheet.addView(field, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(132),
        ))
        val buttons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        buttons.addView(createSettingsButton("Clear") {
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
            renderChainCard()
        }, LinearLayout.LayoutParams(0, dp(52), 1f))
        buttons.addView(createSettingsButton(
            "Save",
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
            renderChainCard()
            dialog.dismiss()
            if (torMode() != TorManager.TorMode.MANUAL) {
                toastShort("Saved — set Connection mode to Manual bridge to use it")
            } else {
                toastShort("Saved — applies on the next connect")
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
        return if (code == TorRegions.AUTO) "Automatic" else TorRegions.label(code)
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
            title = "Preferred country",
            subtitle = "Tor tries to exit here. If it cannot, another country is used.",
            options = options,
            selected = torRegion(),
            label = { code ->
                if (code == TorRegions.AUTO) "Automatic" else TorRegions.label(code)
            },
            description = { code ->
                if (code == TorRegions.AUTO) {
                    "Fastest — Tor picks from every exit relay"
                } else {
                    TorRegions.detail(code)
                }
            },
            scrollable = true,
        ) { chosen ->
            preferences().edit().putString(TorRegions.REGION_PREF, chosen).apply()
            ConnectionLog.record(
                if (chosen == TorRegions.AUTO) {
                    "Tor exit country cleared — Tor chooses"
                } else {
                    "Tor exit country set to ${TorRegions.name(chosen)} ($chosen)"
                }
            )
            after?.invoke()
        }
    }

    private fun chooseH2Fragmentation(after: (() -> Unit)? = null) = showChoiceSheet(
        title = "TLS fragmentation",
        subtitle = "Fragment the TLS ClientHello to look like ordinary HTTPS traffic",
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
        return if (code == CoreConfig.EGRESS_REGION_AUTO) "Automatic" else PsiphonRegions.label(code)
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
     * Applies to Psiphon over WARP only; a plain Psiphon connect always takes
     * whichever server answers first. That is enforced in the service
     * (armRegionPhase reads the preference only when chained), and this row is
     * disabled with the chain off so the two can never disagree.
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
            title = "Theme",
            subtitle = "Applies straight away. A running tunnel is not interrupted.",
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

    private fun chooseEgressRegion(after: (() -> Unit)? = null) {
        val options = listOf(CoreConfig.EGRESS_REGION_AUTO) + PsiphonRegions.options(this)
        showChoiceSheet(
            title = "Preferred country",
            subtitle = "Psiphon over WARP tries this first. If it will not connect, all countries are tried.",
            options = options,
            selected = egressRegion(),
            label = { code ->
                if (code == CoreConfig.EGRESS_REGION_AUTO) "Automatic" else PsiphonRegions.label(code)
            },
            description = { code ->
                if (code == CoreConfig.EGRESS_REGION_AUTO) {
                    "Fastest — Psiphon picks whichever server answers first"
                } else {
                    PsiphonRegions.detail(code)
                }
            },
            scrollable = true,
        ) { chosen ->
            preferences().edit().putString(CoreConfig.EGRESS_REGION_PREF, chosen).apply()
            ConnectionLog.record(
                if (chosen == CoreConfig.EGRESS_REGION_AUTO) {
                    "Preferred exit country cleared — Psiphon chooses"
                } else {
                    "Preferred exit country set to ${PsiphonRegions.name(chosen)} ($chosen)"
                }
            )
            after?.invoke()
        }
    }


    private fun chooseLogLevel() = showChoiceSheet(
        title = "Log verbosity",
        // Says when it takes effect, because it does not take effect now: the
        // value is read while the core config is assembled, i.e. at connect.
        subtitle = "How much the core logs · applies next connection",
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
        if (CoreConfig.proxyOnly(this)) "SOCKS proxy" else "VPN (whole device)"

    /** Value shown on the port row — the port, or why it is inert. */
    private fun proxyPortValue(): String {
        val port = CoreConfig.proxyListenPort(this)
        return if (CoreConfig.proxyOnly(this)) "$port" else "$port · VPN mode"
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
            toastShort("Disconnect first to change the tunnel type")
            return
        }
        showChoiceSheet(
            title = "Tunnel type",
            subtitle = "How MSN-GUARD carries your traffic",
            options = listOf(CoreConfig.TUNNEL_MODE_VPN, CoreConfig.TUNNEL_MODE_PROXY),
            selected = CoreConfig.tunnelMode(this),
            label = { if (it == CoreConfig.TUNNEL_MODE_VPN) "VPN (whole device)" else "SOCKS proxy" },
            description = {
                if (it == CoreConfig.TUNNEL_MODE_VPN) {
                    "Every app goes through the tunnel"
                } else {
                    // Names the transports that cannot do it, since that is the only
                    // way the choice can fail and the user should learn it here
                    // rather than from a failed connect.
                    "Only apps you point at the port · not Tor or SHARD"
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
                toastShort("Tor cannot run as a SOCKS proxy — pick another transport")
            } else if (chosen == CoreConfig.TUNNEL_MODE_PROXY && selectedProtocol == Protocol.SHARD) {
                // SHARD's refusal has a different cause — no byte counter in a proxy
                // data path — but the same remedy, and it also has a better answer:
                // Share over LAN already works in VPN mode.
                toastShort("SHARD runs as a VPN — use Share over LAN instead")
            }
            // The port row is the thing that visibly reacts to this choice, so it is
            // repainted and re-enabled in the same gesture, and the LAN row with it:
            // what can be shared depends on the tunnel type now.
            // refreshPsiphonRows() ends by calling refreshTunnelTypeRows(), so this
            // one call repaints the port row, the LAN row and every gated row at once.
            refreshPsiphonRows()
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
            toastShort("Set Tunnel type to SOCKS proxy first")
            return
        }
        if (TunnelStatus.isActive()) {
            toastShort("Disconnect first to change the port")
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
            addView(label("SOCKS port", 22f, INK, TypefaceStyle.MEDIUM))
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
        entry.addView(createSettingsButton("Apply") {
            val typed = field.text.toString().trim().toIntOrNull()
            if (typed == null) {
                field.error = "Numbers only"
                return@createSettingsButton
            }
            val rejection = CoreConfig.portRejection(typed)
            if (rejection != null) {
                field.error = rejection
                return@createSettingsButton
            }
            preferences().edit().putInt(CoreConfig.PROXY_PORT_PREF, typed).apply()
            proxyPortRow?.setValue(proxyPortValue())
            ConnectionLog.record("SOCKS port set to $typed — applies on the next connect")
            toastShort("SOCKS port set to $typed")
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
            setValue(if (proxy) "Not used in SOCKS mode" else splitTunnelSummary())
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
        title = "Gateway cache",
        subtitle = "Control saved MASQUE gateway discovery data",
        options = listOf("Cache & refresh", "Fresh scan next time", "Clear saved gateways"),
        selected = if (defaultEndpointDiscovery() == EndpointDiscovery.CACHE) "Cache & refresh" else "Fresh scan next time",
        label = { it },
        description = {
            when (it) {
                "Cache & refresh" -> "Try saved gateways first"
                "Fresh scan next time" -> "Ignore saved gateways once"
                else -> "Remove saved gateway latency data"
            }
        },
        onSelected = { chosen ->
            when (chosen) {
                "Cache & refresh" -> preferences().edit().putString(ENDPOINT_DISCOVERY, EndpointDiscovery.CACHE.coreName).apply()
                "Fresh scan next time" -> preferences().edit().putString(ENDPOINT_DISCOVERY, EndpointDiscovery.FRESH.coreName).apply()
                else -> File(filesDir, "masque-gateway-cache.json").delete()
            }
        }
    )

    private fun editManualEndpoint() {
        val dialog = Dialog(this).apply { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        val field = EditText(this).apply {
            setText(manualEndpoint().orEmpty())
            hint = "IP:port, blank for automatic"
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
            addView(label("Manual endpoint", 22f, INK, TypefaceStyle.MEDIUM))
        })
        sheet.addView(label("Numeric IPv4 or bracketed IPv6 address with port. Bypasses discovery.", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        sheet.addView(field, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(56)))
        val buttons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        buttons.addView(createSettingsButton("Clear") {
            preferences().edit().remove(MANUAL_ENDPOINT).apply()
            field.setText("")
        }, LinearLayout.LayoutParams(0, dp(52), 1f))
        buttons.addView(createSettingsButton("Save") {
            val endpoint = field.text.toString().trim()
            val validEndpoint = endpoint.isBlank() || Regex("^(?:\\d{1,3}(?:\\.\\d{1,3}){3}|\\[[0-9a-fA-F:]+]):([1-9]\\d{0,4})$")
                .matchEntire(endpoint)?.groupValues?.get(1)?.toIntOrNull()?.let { it in 1..65535 } == true
            if (!validEndpoint) {
                field.error = "Use numeric IP:port"
                return@createSettingsButton
            }
            preferences().edit().apply {
                if (endpoint.isBlank()) remove(MANUAL_ENDPOINT) else putString(MANUAL_ENDPOINT, endpoint)
            }.apply()
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
            sheet.addView(label(name, 11f, MUTED).apply { letterSpacing = 0.08f }, LinearLayout.LayoutParams(
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
            "Advanced obfuscation",
            "WireGuard only. Jc/Jmin/Jmax tune junk packets; I1/I2 use Aether CPS packet patterns.",
            listOf("JUNK COUNT (JC)" to jc, "JUNK MIN (JMIN)" to jmin, "JUNK MAX (JMAX)" to jmax, "INIT PACKET I1" to i1, "INIT PACKET I2" to i2),
            validator = { values ->
                val numbers = values.take(3).map { it.toIntOrNull() }
                when {
                    values.take(3).withIndex().any { (index, value) -> value.isNotBlank() && numbers[index] == null } -> 0 to "Use whole numbers"
                    numbers[0]?.let { it !in 0..10 } == true -> 0 to "Jc must be 0–10"
                    numbers[1]?.let { it !in 0..1024 } == true -> 1 to "Jmin must be 0–1024"
                    numbers[2]?.let { it !in 0..1024 } == true -> 2 to "Jmax must be 0–1024"
                    numbers[1] != null && numbers[2] != null && numbers[2]!! < numbers[1]!! -> 2 to "Jmax must be at least Jmin"
                    values.drop(3).any { it.length > 2048 } -> 3 to "Packet pattern is too long"
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
            val indicator = label("SELECTED", 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
            val row = LinearLayout(this).apply {
                gravity = Gravity.CENTER_VERTICAL
                orientation = LinearLayout.HORIZONTAL
                setPadding(dp(18), 0, dp(18), 0)
                isClickable = true
                isFocusable = true
                val labels = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
                labels.addView(optionTitle)
                labels.addView(label(description(item), 13f, MUTED), LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = dp(2) })
                addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(indicator)
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
        // The two rows below follow the switch's VISIBLE state, not the preference,
        // for the same reason: with the switch reading off they must not look live.
        val childrenAvailable = chainAvailable && psiphonChained
        chainOuterRow?.apply {
            setValue(chainOuterMode().label)
            setAvailable(childrenAvailable)
        }
        egressRegionRow?.apply {
            setValue(egressRegionLabel())
            setAvailable(childrenAvailable)
        }
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
            addView(label("Traffic monitor", 22f, INK, TypefaceStyle.MEDIUM).apply { setPadding(dp(4), 0, 0, 0) })
        })
        content.addView(label("Traffic carried by MSN-GUARD. Per-app attribution is not available from encrypted tunnel counters.", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(4); bottomMargin = dp(24) })
        trafficSpeedValue = addTrafficMetric(content, "LIVE SPEED")
        trafficSessionValue = addTrafficMetric(content, "THIS SESSION")
        trafficMonthValue = addTrafficMetric(content, "THIS MONTH")
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
        val value = label("Waiting for tunnel traffic", 18f, INK, TypefaceStyle.MEDIUM)
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

    private fun renderTrafficMonitor() {
        trafficSpeedValue?.text = "↓ ${formatTraffic(trafficSpeedRx)}/s   ↑ ${formatTraffic(trafficSpeedTx)}/s"
        trafficSessionValue?.text = "↓ ${formatTraffic(trafficRx)}   ↑ ${formatTraffic(trafficTx)}"
        trafficMonthValue?.text = "↓ ${formatTraffic(trafficMonthRx)}   ↑ ${formatTraffic(trafficMonthTx)}"
    }

    /** One-line month total, shown as the Traffic monitor row's value. */
    private fun trafficHeadline(): String =
        if (trafficMonthRx + trafficMonthTx == 0L) "No data yet"
        else formatTraffic(trafficMonthRx + trafficMonthTx) + " this month"

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
            addView(label("Split tunneling", 22f, INK, TypefaceStyle.MEDIUM), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(createSettingsButton("Done", backgroundOverride = primary, textColorOverride = primaryContainer) {
                settings.save(settings.mode(), selected)
                closeSplitTunnelScreen()
            }, LinearLayout.LayoutParams(dp(88), dp(40)).apply { marginEnd = dp(4) })
        }
        content.addView(header)
        content.addView(label("Choose which apps use MSN-GUARD. Changes apply next connection.", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(20) })
        content.addView(label("MODE", 12f, MUTED).apply { letterSpacing = 0.1f })
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
            addView(label("Apps", 22f, INK, TypefaceStyle.MEDIUM), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(createSettingsButton("Done", backgroundOverride = primary, textColorOverride = primaryContainer) {
                settings.save(mode, selected.toHashSet())
                closeSplitTunnelAppsScreen()
                closeSplitTunnelScreen()
            }, LinearLayout.LayoutParams(dp(88), dp(40)).apply { marginEnd = dp(4) })
        })
        content.addView(label("Select apps to ${if (mode == SplitTunnelSettings.Mode.INCLUDE) "include" else "exclude"}", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(16) })

        val searchField = EditText(this).apply {
            hint = "Search apps…"
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
            addView(label("Scanning installed apps…", 14f, MUTED).apply {
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
            contentDescription = "Select ${packageManager.getApplicationLabel(app)}"
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
        val indicator = label("SELECTED", 11f, PRIMARY_TEXT, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
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
        option.title.typeface = android.graphics.Typeface.create(
            if (selected) "sans-serif-medium" else "sans",
            android.graphics.Typeface.NORMAL,
        )
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

        // Keep the rail in sync when the change came from somewhere else (the
        // mode screen, a restored preference) rather than from a rail tap.
        transportRail.select(Protocol.entries.indexOf(protocol), animate = true)
        chipProtocol.animate().cancel()
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
            showDisconnected("Disconnecting")
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
        showConnectionProgress("Auto Scan", "Trying ${protocol.label}…")
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
        Protocol.WIREGUARD -> 32_000L
        Protocol.MASQUE -> 48_000L
        Protocol.WARP_IN_WARP -> 55_000L
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
                showFailure("No transport connected on this network — try again or pick one yourself")
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
            NativeCore.lastError().takeIf(String::isNotBlank)?.let(::showFailure) ?: showDisconnected("Tunnel stopped unexpectedly")
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
        showConnectionProgress("Connecting", detail ?: "Starting ${selectedProtocol.label} tunnel")
    }

    private fun showStarting() {
        // STARTING and SCANNING are also CONNECTING on the dial, so a stale
        // percentage from the previous attempt would still be drawn.
        orbitDial.progressPercent = -1
        showConnectionProgress("Starting", "Preparing ${selectedProtocol.label} tunnel")
    }

    private fun showScanning() {
        orbitDial.progressPercent = -1
        showConnectionProgress("Scanning", "Finding the best MASQUE gateway")
    }

    private fun showConnectionProgress(title: String, detail: String) {
        latencyRequest++
        chipLatency.text = "Latency —"
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
            connectionTitle.text = "Auto Scan"
            connectionDetail.text = "Trying ${AUTO_SCAN_LADDER[autoScanIndex].label}" +
                " (${autoScanIndex + 1} of ${AUTO_SCAN_LADDER.size})"
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
        connectionTitle.text = "Connected"
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
                "SOCKS proxy on ${proxyReachLine()} · over WARP"
            CoreConfig.proxyOnly(this) ->
                "SOCKS proxy on ${proxyReachLine()}"
            // Say what is actually carrying traffic. With the chain armed the rail
            // reads PSIPHON or TOR, so "<transport> tunnel is active" hides the WARP
            // leg that is doing the circumvention.
            chainRunning() && restored -> "${selectedProtocol.label} over WARP recovered"
            chainRunning() -> "${selectedProtocol.label} over WARP is active"
            restored -> "${selectedProtocol.label} tunnel recovered"
            else -> "${selectedProtocol.label} tunnel is active"
        }
        footerWave.setLit(true)
        chipLatency.text = "Latency …"
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
        connectionTitle.text = "Connection degraded"
        connectionDetail.text = "Tunnel is active; HTTP health check failed"
        footerWave.setLit(false)
        chipLatency.text = "Latency n/a"
    }

    private fun showFailure(detail: String? = null) {
        latencyRequest++
        cancelVerification()
        // Belongs to the tunnel that just died; keeping it would show a stale exit
        // next to a failure message.
        clearCoreExitIp()
        chipLatency.text = "Latency —"
        visualState = OrbitDialView.State.FAILED
        orbitDial.state = visualState
        renderStatusLed()
        stopSessionTimer()
        connectionTitle.setTextColor(ERROR_TEXT)
        connectionTitle.text = "Connection failed"
        footerWave.setLit(false)
        connectionDetail.text = detail ?: "Check the server and try again"
        setModeEnabled(true)
    }

    private fun showDisconnected(detail: String = "Tap the dial to connect") {
        latencyRequest++
        cancelVerification()
        clearCoreExitIp()
        stopAutoPing()
        chipLatency.text = "Latency —"
        visualState = OrbitDialView.State.DISCONNECTED
        orbitDial.state = visualState
        renderStatusLed()
        stopSessionTimer()
        resetMetrics()
        connectionTitle.setTextColor(INK)
        connectionTitle.text = "Not connected"
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
                    TorManager.manualChainBlocker(this) ?: "not available with your bridges"
                } else {
                    "not available with ${torMode().label}"
                }
            !applies -> "only for the PSIPHON and TOR transports"
            !modeControlsEnabled -> "disconnect to change"
            else -> null
        }
        // Which transport is being wrapped, so the card cannot read
        // "PSIPHON OVER WARP" while the rail has Tor selected.
        chainCard.setInner(if (selectedProtocol == Protocol.TOR) "TOR" else "PSIPHON")
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
                "auto transport"
            } else {
                "via ${activeOuter.label}"
            }
        )
        chainCard.setArmed(chainArmed())
        // Exactly one of the two cards is shown, and the swap happens here so there
        // is a single place that decides which control the SHARD user sees. GONE and
        // not merely disabled: a permanently-N/A card in the SHARD case would be
        // dead furniture on the app's most-used screen.
        val shardSelected = selectedProtocol == Protocol.SHARD
        chainCard.visibility = if (shardSelected) View.GONE else View.VISIBLE
        smartSplitCard.visibility = if (shardSelected) View.VISIBLE else View.GONE
        renderSmartSplitCard()
        // The settings page carries the same switch, so keep it in step whenever the
        // card is repainted — arming from the home screen must not leave a stale
        // "off" behind in settings.
        refreshPsiphonRows()

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
            !applies -> "only for the SHARD transport"
            !modeControlsEnabled -> "disconnect to change"
            else -> null
        }
        smartSplitCard.setUnavailable(reason, applicable = applies)
        // Whether this network has been measured, in the user's terms — never which
        // fragment profile won. See [SmartSplit] for why the profile is not shown.
        smartSplitCard.setTuningSummary(
            if (SmartSplit.cachedProfile(this) != null) "tuned for this network" else ""
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
        contentDescription = "Back"
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
        if (singleLine) {
            setSingleLine(true)
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        typeface = when (style) {
            TypefaceStyle.REGULAR -> android.graphics.Typeface.create("sans", android.graphics.Typeface.NORMAL)
            TypefaceStyle.MEDIUM -> android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL)
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
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE).getString(DEFAULT_SCAN, ScanTarget.IPV4.coreName)
        return ScanTarget.entries.firstOrNull { it.coreName == name } ?: ScanTarget.IPV4
    }

    private fun defaultScanMode(): ScanMode {
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE).getString(DEFAULT_SCAN_MODE, ScanMode.BALANCED.coreName)
        return ScanMode.entries.firstOrNull { it.coreName == name } ?: ScanMode.BALANCED
    }

    private fun defaultEndpointDiscovery(): EndpointDiscovery {
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE)
            .getString(ENDPOINT_DISCOVERY, EndpointDiscovery.CACHE.coreName)
        return EndpointDiscovery.entries.firstOrNull { it.coreName == name } ?: EndpointDiscovery.CACHE
    }

    private fun defaultMasqueTransport(): MasqueTransport {
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE)
            .getString(DEFAULT_MASQUE_TRANSPORT, MasqueTransport.H3.coreName)
        return MasqueTransport.entries.firstOrNull { it.coreName == name } ?: MasqueTransport.H3
    }

    private fun scanSummary(): String = listOfNotNull(
        defaultScan().label,
        defaultScanMode().label,
        defaultMasqueTransport().label.takeIf { selectedProtocol == Protocol.MASQUE },
    ).joinToString(" · ")

    private fun preferences() = getSharedPreferences(SETTINGS, MODE_PRIVATE)

    private fun obfuscationProfile(): ObfuscationProfile = preferences()
        .getString(OBFUSCATION_PROFILE, ObfuscationProfile.BALANCED.coreName)
        ?.let { name -> ObfuscationProfile.entries.firstOrNull { it.coreName == name } }
        ?: ObfuscationProfile.BALANCED

    private fun manualEndpoint(): String? = preferences().getString(MANUAL_ENDPOINT, null)?.takeIf(String::isNotBlank)

    private fun retryObfuscationProfiles(): Boolean = preferences().getBoolean(RETRY_OBFUSCATION, true)

    private fun advancedObfuscationSummary(): String =
        listOf(OBFUSCATION_JC, OBFUSCATION_JMIN, OBFUSCATION_JMAX, OBFUSCATION_I1, OBFUSCATION_I2)
            .any { preferences().getString(it, "").orEmpty().isNotBlank() }
            .let { if (it) "Custom" else "Preset" }

    private fun tlsCurvePreset(): TlsCurvePreset = preferences()
        .getString(TLS_CURVE_PRESET, TlsCurvePreset.CHROME.coreName)
        ?.let { name -> TlsCurvePreset.entries.firstOrNull { it.coreName == name } }
        ?: TlsCurvePreset.CHROME

    private fun wireGuardDataCheck(): Boolean = preferences().getBoolean(WIREGUARD_DATA_CHECK, true)

    private fun killSwitchEnabled(): Boolean = preferences().getBoolean(KILL_SWITCH, false)

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
        if (count <= 0) return "Tap to download"
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
        else -> "Only for MASQUE and WireGuard"
    }

    private fun splitTunnelSummary(): String {
        val settings = SplitTunnelSettings(this)
        val count = settings.packages().size
        return when (settings.mode()) {
            SplitTunnelSettings.Mode.ALL -> "All apps use MSN-GUARD"
            SplitTunnelSettings.Mode.INCLUDE -> "Only $count selected app${if (count == 1) "" else "s"}"
            SplitTunnelSettings.Mode.EXCLUDE -> "Exclude $count selected app${if (count == 1) "" else "s"}"
        }
    }

    private enum class Protocol(
        val label: String,
        val coreName: String,
        val description: String,
        val androidAvailable: Boolean = true,
    ) {
        // ORDER IS THE UI. Both the home-screen rail and the Connection mode page
        // are built from `Protocol.entries`, so this list decides what a first-time
        // user reaches for — and the first cell is what most of them will tap.
        //
        // WireGuard leads on purpose: it is the cheapest handshake of the six and it
        // either works immediately or fails immediately, which is the right first
        // move for a user who does not know what any of these words mean. MASQUE
        // follows because it survives the carriers WireGuard is blocked on, and the
        // one-time Auto Scan ([AUTO_SCAN_LADDER]) walks them in exactly this order.
        WIREGUARD("WireGuard", "wireguard", "WireGuard tunnel"),
        MASQUE("MASQUE", "masque", "HTTP/3 tunnel"),
        WARP_IN_WARP("WARP-on-WARP", "gool", "Double-layer tunnel"),
        PSIPHON("Psiphon", "psiphon", "Anti-censorship tunnel"),
        TOR("Tor", "tor", "Onion routing; slowest but hardest to block"),

        /**
         * Public proxy nodes, picked automatically.
         *
         * Its core name is not a core transport at all: the Rust core is never
         * started for SHARD. The service branches on it before touching
         * NativeCore, the same way the Psiphon and Tor names do.
         */
        SHARD("SHARD", "shard", "Public nodes, auto-selected; no setup"),
    }

    private enum class ScanTarget(
        val label: String,
        val coreName: String,
        val description: String,
    ) {
        IPV4("IPv4", "v4", "Scan IPv4 endpoints only"),
        IPV6("IPv6", "v6", "Scan IPv6 endpoints only"),
        BOTH("Both", "both", "Scan IPv4 and IPv6 endpoints"),
    }

    private enum class ScanMode(
        val label: String,
        val coreName: String,
        val description: String,
    ) {
        TURBO("Turbo", "turbo", "Fastest scan; first verified route wins"),
        BALANCED("Balanced", "balanced", "Default mix of speed and coverage"),
        THOROUGH("Thorough", "thorough", "Deep scan; selects best latency"),
        STEALTH("Stealth", "stealth", "Quiet, patient probing"),
        IRONCLAD("Ironclad", "ironclad", "Strict CONNECT-IP verification before selection"),
    }

    private enum class MasqueTransport(
        val label: String,
        val coreName: String,
        val description: String,
    ) {
        H3("HTTP/3", "h3", "QUIC first; falls back to HTTP/2 if UDP is blocked"),
        H2("HTTP/2", "h2", "TCP with TLS fragmentation; use on restricted networks"),
    }

    private enum class EndpointDiscovery(
        val label: String,
        val coreName: String,
        val description: String,
    ) {
        CACHE("Cache & refresh", "cache", "Use verified gateways first, then discover more"),
        FRESH("Fresh scan", "fresh", "Start a new scan every connection"),
    }

    private enum class ObfuscationProfile(val label: String, val coreName: String, val description: String) {
        OFF("Off", "off", "No traffic-shape padding"),
        LIGHT("Light", "light", "Lower overhead on mild filtering"),
        BALANCED("Balanced", "balanced", "Recommended filtering resistance"),
        AGGRESSIVE("Aggressive", "aggressive", "Highest resistance; slower setup"),
    }

    private enum class TlsCurvePreset(val label: String, val coreName: String, val description: String) {
        CHROME("Chrome", "chrome", "Chrome TLS curve ordering"),
        COMPATIBILITY("Compatibility", "compatibility", "P-256 and X25519 only"),
    }

    private enum class LogLevel(val label: String, val coreName: String, val description: String) {
        ERROR("Error", "error", "Only errors"),
        WARN("Warn", "warn", "Warnings and errors"),
        INFO("Info", "info", "Default verbosity"),
        DEBUG("Debug", "debug", "Tunnel internals"),
        TRACE("Trace", "trace", "Full per-packet detail"),
    }

    private enum class PerfProfile(val label: String, val coreName: String, val description: String) {
        AUTO("Auto", "auto", "Detect hardware and scale accordingly"),
        LOW("Low", "low", "Routers and constrained devices"),
        MEDIUM("Medium", "medium", "Moderate hardware"),
        HIGH("High", "high", "Desktop and powerful devices"),
    }

    private enum class H2Fragmentation(val label: String, val coreName: String, val description: String) {
        ON("On", "on", "Fragment TLS handshake to evade DPI"),
        OFF("Off", "off", "Standard TLS handshake"),
    }

    private enum class LogTab(val label: String) {
        ALL("All"),
        APP("App"),
        CORE("Core"),
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
        val label: String,
        val description: String,
    ) {
        AUTO(
            CoreConfig.CHAIN_OUTER_AUTO,
            "Auto",
            "Try MASQUE, then WireGuard, then WoW — remembers what works",
        ),
        MASQUE("masque", "MASQUE", "HTTP/3, falling back to HTTP/2 with TLS fragmentation"),
        WIREGUARD("wireguard", "WireGuard", "Single WARP tunnel; blocked on some carriers"),
        WOW("gool", "WoW", "WARP on WARP — slowest, for the most filtered networks"),
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
        const val CHAIN_ARMED_DEFAULT = true

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
