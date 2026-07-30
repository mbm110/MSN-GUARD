package studio.cluvex.aethery

import android.animation.ValueAnimator
import android.app.Activity
import android.app.Dialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
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
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowManager
import android.window.OnBackInvokedCallback
import android.window.OnBackInvokedDispatcher
import android.view.animation.DecelerateInterpolator
import android.view.animation.LinearInterpolator
import android.view.animation.PathInterpolator
import android.widget.FrameLayout
import android.widget.EditText
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import com.google.android.material.color.DynamicColors
import java.io.File
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import kotlin.math.min
import kotlin.math.roundToInt

class MainActivity : Activity() {
    private lateinit var connectionControl: ConnectionControl
    private lateinit var connectionTitle: TextView
    private lateinit var connectionDetail: TextView
    private lateinit var connectionLatency: TextView
    private lateinit var latencyGraph: LatencyGraphView
    private lateinit var ipAddressLabel: TextView
    private lateinit var ipAddressValue: TextView
    private lateinit var ipAddressCard: LinearLayout
    private lateinit var ipRefreshIcon: RetryView
    private lateinit var modeSelector: LinearLayout
    private lateinit var modeValue: TextView
    private lateinit var connectionTypeValue: TextView
    private lateinit var logSelector: LinearLayout
    private lateinit var perfSelector: LinearLayout
    private lateinit var scannerSelector: LinearLayout
    private lateinit var scanValue: TextView
    private lateinit var mainRoot: FrameLayout
    private lateinit var pageHost: FrameLayout
    private lateinit var appUpdater: AppUpdater
    private var predictiveBackCallback: Any? = null
    private var selectedProtocol = Protocol.MASQUE
    private var pendingConfig: String? = null
    private var visualState = ConnectionControl.State.DISCONNECTED
    private var receiverRegistered = false
    private var autoPingRunning = false
    private val autoPingHandler = Handler(Looper.getMainLooper())
    private val autoPingRunnable = object : Runnable {
        override fun run() {
            if (isTunnelActive() && autoPingRunning) {
                pingConnection()
                autoPingHandler.postDelayed(this, 5000L)
            }
        }
    }
    private var showingSettings = false
    private var showingLogs = false
    private var showingScanner = false
    private var showingMode = false
    private var settingsPage: View? = null
    private var tunnelControlsPage: View? = null
    private var zeroTrustPage: View? = null
    private var zeroTrustControlButton: TextView? = null
    private var logsPage: View? = null
    private var scannerPage: View? = null
    private var modePage: View? = null
    private var splitTunnelPage: View? = null
    private var splitTunnelAppsPage: View? = null
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
    private var ipRequest = 0
    @Volatile private var ipRefreshInFlight = false
    @Volatile private var ipRefreshPending = false
    private var ipRefreshAnimator: ValueAnimator? = null
    private val statusHandler = Handler(Looper.getMainLooper())
    private val statusPoll = object : Runnable {
        override fun run() {
            renderStatus()
            statusHandler.postDelayed(this, STATUS_POLL_MS)
        }
    }
    private val CANVAS by lazy { dynamicColor(android.R.color.system_neutral1_900, FALLBACK_CANVAS) }
    private val SURFACE by lazy { dynamicColor(android.R.color.system_neutral1_800, FALLBACK_SURFACE) }
    private val SURFACE_VARIANT by lazy { dynamicColor(android.R.color.system_neutral2_800, FALLBACK_SURFACE_VARIANT) }
    private val INK by lazy { dynamicColor(android.R.color.system_neutral1_50, FALLBACK_INK) }
    private val MUTED by lazy { dynamicColor(android.R.color.system_neutral2_300, FALLBACK_MUTED) }
    private val DIVIDER by lazy { dynamicColor(android.R.color.system_neutral2_600, FALLBACK_DIVIDER) }
    private val primary by lazy { dynamicColor(android.R.color.system_accent1_300, FALLBACK_PRIMARY) }
    private val primaryContainer by lazy { dynamicColor(android.R.color.system_accent1_800, FALLBACK_PRIMARY_CONTAINER) }
    private val connected = 0xFF22C55E.toInt()
    private val connectedContainer = 0xFF052E16.toInt()
    private val motionInterpolator = PathInterpolator(0.2f, 0f, 0f, 1f)

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.hasExtra(AetherVpnService.EXTRA_TRAFFIC_TX)) {
                trafficTx = intent.getLongExtra(AetherVpnService.EXTRA_TRAFFIC_TX, 0)
                trafficRx = intent.getLongExtra(AetherVpnService.EXTRA_TRAFFIC_RX, 0)
                trafficSpeedTx = intent.getLongExtra(AetherVpnService.EXTRA_TRAFFIC_SPEED_TX, 0)
                trafficSpeedRx = intent.getLongExtra(AetherVpnService.EXTRA_TRAFFIC_SPEED_RX, 0)
                trafficMonthTx = intent.getLongExtra(AetherVpnService.EXTRA_TRAFFIC_MONTH_TX, 0)
                trafficMonthRx = intent.getLongExtra(AetherVpnService.EXTRA_TRAFFIC_MONTH_RX, 0)
                renderTrafficMonitor()
                return
            }
            when (intent.getStringExtra(AetherVpnService.EXTRA_STATUS)) {
                AetherVpnService.STATUS_CONNECTING -> showConnecting(intent.getStringExtra(AetherVpnService.EXTRA_DETAIL))
                AetherVpnService.STATUS_STARTING -> showStarting()
                AetherVpnService.STATUS_SCANNING -> showScanning()
                AetherVpnService.STATUS_CONNECTED -> showConnected()
                AetherVpnService.STATUS_FAILED -> showFailure(intent.getStringExtra(AetherVpnService.EXTRA_DETAIL))
                AetherVpnService.STATUS_DISCONNECTED -> showDisconnected()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        DynamicColors.applyToActivityIfAvailable(this)
        super.onCreate(savedInstanceState)
        configureSystemBars()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            OnBackInvokedCallback { handleBack() }.also { callback ->
                predictiveBackCallback = callback
                onBackInvokedDispatcher.registerOnBackInvokedCallback(
                    OnBackInvokedDispatcher.PRIORITY_DEFAULT,
                    callback,
                )
            }
        }
        requestNotificationPermission()
        appUpdater = AppUpdater(this)

        connectionControl = ConnectionControl(this, primary, primaryContainer, connected, connectedContainer).apply {
            setOnClickListener { toggleTunnel() }
        }
        connectionTitle = label(textSize = 20f, color = INK, style = TypefaceStyle.MEDIUM).apply {
            gravity = Gravity.CENTER
        }
        connectionDetail = label(textSize = 14f, color = MUTED).apply { gravity = Gravity.CENTER }
        connectionLatency = label("Latency unavailable", 13f, MUTED).apply {
            gravity = Gravity.CENTER
            contentDescription = "Ping connection"
            isClickable = true
            isFocusable = true
            setOnClickListener { pingConnection() }
        }
        latencyGraph = LatencyGraphView(this).apply {
            isClickable = true
            isFocusable = true
            setOnClickListener { pingConnection() }
        }
        ipAddressLabel = label("PUBLIC IP", 12f, MUTED, TypefaceStyle.MEDIUM).apply {
            letterSpacing = 0.1f
        }
        ipAddressValue = label("Checking…", 16f, INK, TypefaceStyle.MEDIUM, singleLine = true)
        ipAddressCard = createIpAddressCard()
        selectedProtocol = Protocol.MASQUE
        modeValue = label(selectedProtocol.label, 16f, INK, TypefaceStyle.MEDIUM)
        modeSelector = createModeSelector()
        connectionTypeValue = label(connectionType().label, 16f, INK, TypefaceStyle.MEDIUM)
        logSelector = createLogSelector()
        perfSelector = createPerfSelector()
        scanValue = label(scanSummary(), 14f, INK, TypefaceStyle.MEDIUM)
        scannerSelector = createScannerSelector()

        mainRoot = FrameLayout(this).apply { setBackgroundColor(CANVAS) }
        val header = createHeader()
        mainRoot.addView(header, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply {
            leftMargin = dp(24)
            rightMargin = dp(24)
            topMargin = dp(16)
        })
        mainRoot.setOnApplyWindowInsetsListener { _, insets ->
            (header.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(16)
                header.layoutParams = this
            }
            insets
        }
        mainRoot.addView(createConnectionConsole(), FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            Gravity.CENTER,
        ).apply {
            leftMargin = dp(24)
            rightMargin = dp(24)
            topMargin = dp(17)
        })
        mainRoot.addView(label("AETHER CORE", 12f, MUTED).apply {
            letterSpacing = 0.12f
            gravity = Gravity.CENTER
        }, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            Gravity.BOTTOM,
        ).apply { bottomMargin = dp(24) })
        pageHost = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            addView(mainRoot, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            ))
        }
        setContentView(pageHost)
        showOpeningOverlay()
        refreshPublicIp()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(AetherVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(statusReceiver, filter)
        }
        receiverRegistered = true
        statusPoll.run()
    }

    override fun onStop() {
        statusHandler.removeCallbacks(statusPoll)
        if (receiverRegistered) {
            unregisterReceiver(statusReceiver)
            receiverRegistered = false
        }
        super.onStop()
    }

    override fun onDestroy() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            (predictiveBackCallback as? OnBackInvokedCallback)?.let {
                onBackInvokedDispatcher.unregisterOnBackInvokedCallback(it)
            }
        }
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        renderStatus()
        appUpdater.resumeInstallIfPermitted()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
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
            setImageResource(R.drawable.aethery_splash_logo)
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
                            .withEndAction { pageHost.removeView(overlay) }
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
        latencyGraph.setLabel("Pinging\u2026")
        Thread {
            val result = runCatching {
                val startedAt = System.nanoTime()
                val connection = openTunnelConnection(PING_URL)
                try {
                    connection.connectTimeout = PING_TIMEOUT_MS
                    connection.readTimeout = PING_TIMEOUT_MS
                    connection.requestMethod = "GET"
                    connection.instanceFollowRedirects = false
                    check(connection.responseCode in 200..399) { "HTTP ${connection.responseCode}" }
                    val ms = (System.nanoTime() - startedAt) / 1_000_000
                    "${ms} ms" to ms.toFloat()
                } finally {
                    connection.disconnect()
                }
            }.getOrElse { "Ping unavailable" to null }
            runOnUiThread {
                pingInFlight = false
                if (request == latencyRequest && isTunnelActive()) {
                    latencyGraph.setLabel(result.first)
                    result.second?.let {
                        latencyGraph.addPoint(it)
                        if (visualState == ConnectionControl.State.DEGRADED) showConnected(restored = true)
                    } ?: showDegraded()
                    updateNotificationHealth(ping = result.first)
                }
            }
        }.start()
    }

    private fun createHeader(): LinearLayout = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        addView(ImageView(this@MainActivity).apply {
            setImageResource(R.drawable.aethery_logo)
            contentDescription = getString(R.string.app_name)
            scaleType = ScaleType.CENTER_INSIDE
            adjustViewBounds = true
            scaleX = 1.20f
            scaleY = 1.20f
        }, LinearLayout.LayoutParams(dp(36), dp(40)))
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
        }, LinearLayout.LayoutParams(dp(48), dp(48)))
    }

    private fun createConnectionConsole(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER_HORIZONTAL
        addView(connectionTitle, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ))
        addView(connectionDetail, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(6) })
        addView(connectionControl, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(16) })
        addView(latencyGraph, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(64),
        ).apply { topMargin = dp(6) })
        addView(ipAddressCard, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(64),
        ).apply { topMargin = dp(16) })
        addView(modeSelector, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(64),
        ).apply { topMargin = dp(16) })
        addView(scannerSelector, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(64),
        ).apply { topMargin = dp(12) })
        addView(LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(logSelector, LinearLayout.LayoutParams(0, dp(64), 1f).apply { rightMargin = dp(6) })
            addView(perfSelector, LinearLayout.LayoutParams(0, dp(64), 1f).apply { leftMargin = dp(6) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(12) })
    }

    private fun createIpAddressCard(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(20), 0, dp(18), 0)
        background = roundedBackground(SURFACE_VARIANT, 20, DIVIDER)
        contentDescription = "Public IP address"
        isClickable = true
        isFocusable = true
        setOnClickListener { refreshPublicIp() }
        val labels = LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.VERTICAL
            addView(ipAddressLabel)
            addView(ipAddressValue, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
        }
        addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        ipRefreshIcon = RetryView(this@MainActivity, INK)
        addView(ipRefreshIcon, LinearLayout.LayoutParams(dp(24), dp(24)))
    }

    private fun refreshPublicIp() {
        if (ipRefreshInFlight) {
            ipRefreshPending = true
            return
        }
        ipRefreshInFlight = true
        val request = ++ipRequest
        startIpRefreshAnimation()
        ipAddressLabel.text = if (isTunnelActive()) "VPN IP" else "PUBLIC IP"
        ipAddressValue.text = "Checking…"
        Thread {
            val result = runCatching {
                repeat(IP_FETCH_ATTEMPTS) { attempt ->
                    runCatching { fetchPublicIp() }.getOrNull()?.let { return@runCatching it }
                    if (attempt + 1 < IP_FETCH_ATTEMPTS) Thread.sleep(IP_RETRY_DELAY_MS)
                }
                error("IP unavailable")
            }
            runOnUiThread {
                ipRefreshInFlight = false
                if (ipRefreshPending) {
                    ipRefreshPending = false
                    refreshPublicIp()
                    return@runOnUiThread
                }
                if (request != ipRequest) return@runOnUiThread
                finishIpRefreshAnimation()
                val (ip, country) = result.getOrElse { "IP unavailable" to "" }
                ipAddressLabel.text = when {
                    ip == "IP unavailable" -> "PUBLIC IP"
                    isTunnelActive() -> "VPN IP"
                    else -> "PUBLIC IP"
                }
                val flag = countryFlag(country)
                ipAddressValue.text = listOf(flag, ip).filter(String::isNotBlank).joinToString(" ")
                ipAddressCard.contentDescription = "${ipAddressLabel.text}: ${ipAddressValue.text}"
                if (isTunnelActive() && ip != "IP unavailable") updateNotificationHealth(ip = ip)
                ipAddressValue.alpha = 0f
                ipAddressValue.translationY = dp(4).toFloat()
                ipAddressValue.animate().alpha(1f).translationY(0f)
                    .setDuration(220).setInterpolator(motionInterpolator).start()
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
                    return ip to values["loc"].orEmpty()
                } finally {
                    connection.disconnect()
                }
            } catch (error: Throwable) {
                failure = error
            }
        }
        throw failure ?: IllegalStateException("IP unavailable")
    }

    private fun startIpRefreshAnimation() {
        ipRefreshAnimator?.cancel()
        ipAddressCard.animate().cancel()
        ipAddressValue.animate().cancel()
        ipAddressValue.alpha = 0.6f
        ipRefreshIcon.rotation = 0f
        ipRefreshAnimator = ValueAnimator.ofFloat(0f, 360f).apply {
            duration = 900L
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            addUpdateListener { animation ->
                ipRefreshIcon.rotation = animation.animatedValue as Float
                val pulse = if (animation.animatedFraction < 0.5f) animation.animatedFraction else 1f - animation.animatedFraction
                ipAddressCard.alpha = 0.9f + pulse * 0.1f
            }
            start()
        }
    }

    private fun finishIpRefreshAnimation() {
        ipRefreshAnimator?.cancel()
        ipRefreshAnimator = null
        ipRefreshIcon.rotation = 0f
        ipAddressCard.alpha = 1f
        ipAddressCard.scaleX = 1f
        ipAddressCard.scaleY = 1f
    }

    private fun countryFlag(country: String): String {
        if (country.length != 2 || country.any { !it.isLetter() }) return ""
        return country.uppercase().map { char -> String(Character.toChars(0x1F1E6 + char.code - 'A'.code)) }.joinToString("")
    }

    private fun openTunnelConnection(url: String): HttpURLConnection =
        if (connectionType() == ConnectionType.PROXY && NativeCore.isRunning()) {
            URL(url).openConnection(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort())))
        } else {
            URL(url).openConnection()
        } as HttpURLConnection

    private fun updateNotificationHealth(ip: String? = null, ping: String? = null) {
        if (!NativeCore.isRunning()) return
        startService(Intent(this, AetherVpnService::class.java)
            .setAction(AetherVpnService.ACTION_NOTIFICATION_HEALTH)
            .apply {
                ip?.let { putExtra(AetherVpnService.EXTRA_NOTIFICATION_IP, it) }
                ping?.let { putExtra(AetherVpnService.EXTRA_NOTIFICATION_PING, it) }
            })
    }

    private fun createModeSelector(): LinearLayout = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        orientation = LinearLayout.HORIZONTAL
        setPadding(dp(20), 0, dp(18), 0)
        background = roundedBackground(SURFACE_VARIANT, 20, DIVIDER)
        contentDescription = "Connection mode, ${selectedProtocol.label}"
        isClickable = true
        isFocusable = true
        setOnClickListener { openModeScreen() }

        addView(label("MODE", 12f, MUTED).apply { letterSpacing = 0.1f })
        addView(modeValue, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            leftMargin = dp(16)
        })
        addView(ChevronView(this@MainActivity, INK), LinearLayout.LayoutParams(dp(24), dp(24)))
    }

    private fun createLogSelector(): LinearLayout = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        orientation = LinearLayout.HORIZONTAL
        setPadding(dp(20), 0, dp(18), 0)
        background = roundedBackground(SURFACE_VARIANT, 20, DIVIDER)
        contentDescription = "View connection log"
        isClickable = true
        isFocusable = true
        setOnClickListener { openLogsScreen() }

        addView(label("LOG", 12f, MUTED).apply { letterSpacing = 0.1f })
        addView(label("Events", 16f, INK, TypefaceStyle.MEDIUM, singleLine = true), LinearLayout.LayoutParams(
            0,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            1f,
        ).apply { leftMargin = dp(16) })
        addView(ChevronView(this@MainActivity, INK), LinearLayout.LayoutParams(dp(24), dp(24)))
    }

    private fun createPerfSelector(): LinearLayout = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        orientation = LinearLayout.HORIZONTAL
        setPadding(dp(20), 0, dp(18), 0)
        background = roundedBackground(SURFACE_VARIANT, 20, DIVIDER)
        contentDescription = "Performance profile, ${perfProfile().label}"
        isClickable = true
        isFocusable = true
        setOnClickListener { choosePerfProfile() }

        addView(label("PERF", 12f, MUTED).apply { letterSpacing = 0.1f })
        addView(label(perfProfile().label, 16f, INK, TypefaceStyle.MEDIUM, singleLine = true), LinearLayout.LayoutParams(
            0,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            1f,
        ).apply { leftMargin = dp(16) })
        addView(ChevronView(this@MainActivity, INK), LinearLayout.LayoutParams(dp(24), dp(24)))
    }

    private fun createScannerSelector(): LinearLayout = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        orientation = LinearLayout.HORIZONTAL
        setPadding(dp(20), 0, dp(18), 0)
        background = roundedBackground(SURFACE_VARIANT, 20, DIVIDER)
        contentDescription = "Scanner options, ${scanSummary()}"
        isClickable = true
        isFocusable = true
        setOnClickListener { openScannerScreen() }

        addView(label("SCAN", 12f, MUTED).apply { letterSpacing = 0.08f })
        addView(scanValue.apply {
            (scanValue.layoutParams as? LinearLayout.LayoutParams)?.let {
                it.leftMargin = dp(16)
                scanValue.layoutParams = it
            }
            textSize = 16f
            setSingleLine(true)
            ellipsize = android.text.TextUtils.TruncateAt.END
        }, LinearLayout.LayoutParams(
            0,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            1f,
        ).apply { leftMargin = dp(16) })
        addView(ChevronView(this@MainActivity, INK), LinearLayout.LayoutParams(dp(24), dp(24)))
    }

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
            addView(label("Logs", 22f, INK, TypefaceStyle.MEDIUM))
        }
        content.addView(header)
        content.addView(label("Aether and VPN events", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(16) })
        val logLevelRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val currentLogLevel = logLevel()
        LogLevel.entries.forEach { level ->
            val isActive = level == currentLogLevel
            val chip = label(level.label, 14f, if (isActive) primaryContainer else INK, TypefaceStyle.MEDIUM).apply {
                gravity = Gravity.CENTER
                setPadding(dp(15), dp(8), dp(15), dp(8))
                background = roundedBackground(if (isActive) primary else SURFACE_VARIANT, 14, if (isActive) primary else DIVIDER)
                isClickable = true
                isFocusable = true
                setOnClickListener {
                    preferences().edit().putString(LOG_LEVEL, level.coreName).apply()
                    for (i in 0 until logLevelRow.childCount) {
                        val child = logLevelRow.getChildAt(i) as TextView
                        val childLevel = LogLevel.entries[i]
                        val selected = childLevel == level
                        child.setTextColor(if (selected) primaryContainer else INK)
                        child.background = roundedBackground(if (selected) primary else SURFACE_VARIANT, 12, if (selected) primary else DIVIDER)
                    }
                }
            }
            logLevelRow.addView(chip, LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f,
            ).apply { rightMargin = dp(4) })
        }
        content.addView(logLevelRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(0); rightMargin = dp(0); bottomMargin = dp(12) })
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
        val events = label(textSize = 13f, color = INK).apply {
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        var followLatest = true
        val scroll = ScrollView(this).apply {
            addView(events)
            setOnScrollChangeListener { _, _, scrollY, _, _ ->
                val contentHeight = getChildAt(0)?.height ?: 0
                followLatest = scrollY >= contentHeight - height - dp(8)
            }
        }
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
        var renderedLogs: String? = null
        val refresh = object : Runnable {
            override fun run() {
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

    private fun animatePageOpen(page: View) {
        page.alpha = 0f
        page.translationY = dp(24).toFloat()
        page.scaleX = 0.92f
        page.scaleY = 0.92f

        val behind = if (pageHost.childCount > 1) pageHost.getChildAt(pageHost.childCount - 2) else mainRoot
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
        page.animate()
            .alpha(0f)
            .translationY(dp(24).toFloat())
            .scaleX(0.92f)
            .scaleY(0.92f)
            .setDuration(LOG_CLOSE_ANIMATION_MS)
            .setInterpolator(motionInterpolator)
            .withEndAction {
                if (page.parent == pageHost) pageHost.removeView(page)
                onEnd()
            }
            .start()

        val behind = if (pageHost.childCount > 1) pageHost.getChildAt(pageHost.childCount - 2) else mainRoot
        behind.animate()
            .alpha(1f)
            .scaleX(1f)
            .scaleY(1f)
            .setDuration(LOG_CLOSE_ANIMATION_MS)
            .setInterpolator(motionInterpolator)
            .start()
    }

    private fun staggerListItems(container: ViewGroup) {
        for (i in 0 until container.childCount) {
            val child = container.getChildAt(i)
            child.alpha = 0f
            child.translationY = dp(12).toFloat()
            child.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(PAGE_ANIMATION_MS)
                .setStartDelay(80L + i * 32L)
                .setInterpolator(motionInterpolator)
                .start()
        }
    }

    private fun connectionLogText(tab: LogTab = LogTab.ALL): String {
        val appEvents = ConnectionLog.snapshot()
        val coreEvents = NativeCore.lastLog().lineSequence().filter(String::isNotBlank).toList()
        val events = when (tab) {
            LogTab.ALL -> appEvents + coreEvents
            LogTab.APP -> appEvents
            LogTab.CORE -> coreEvents
        }
        return events.joinToString("\n").ifBlank { "No connection events yet" }
    }

    private fun openScannerScreen(animate: Boolean = true) {
        if (visualState == ConnectionControl.State.CONNECTING ||
            visualState == ConnectionControl.State.CONNECTED ||
            NativeCore.isRunning()
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
                    scanValue.text = scanSummary()
                    scannerSelector.contentDescription = "Scanner options, ${scanSummary()}"
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
                scanValue.text = scanSummary()
                scannerSelector.contentDescription = "Scanner options, ${scanSummary()}"
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
                scanValue.text = scanSummary()
                scannerSelector.contentDescription = "Scanner options, ${scanSummary()}"
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
        val indicator = label("SELECTED", 11f, primary, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
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
        val indicator = label("SELECTED", 11f, primary, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
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
        val indicator = label("SELECTED", 11f, primary, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
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
        val indicator = label("SELECTED", 11f, primary, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
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

    private fun showConnectionTypeSheet() {
        if (visualState == ConnectionControl.State.CONNECTING ||
            visualState == ConnectionControl.State.CONNECTED ||
            NativeCore.isRunning()
        ) return

        val dialog = Dialog(this).apply {
            requestWindowFeature(Window.FEATURE_NO_TITLE)
            setCanceledOnTouchOutside(true)
        }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(label("Connection type", 22f, INK, TypefaceStyle.MEDIUM))
        sheet.addView(label("Choose device-wide VPN or local SOCKS5 proxy", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(4); bottomMargin = dp(20) })
        ConnectionType.entries.forEachIndexed { index, type ->
            sheet.addView(createConnectionTypeOption(type, dialog), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(76),
            ).apply { if (index > 0) topMargin = dp(10) })
        }
        val container = FrameLayout(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ))
        }
        dialog.setContentView(container)
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    private fun createConnectionTypeOption(type: ConnectionType, dialog: Dialog): LinearLayout {
        val selected = type == connectionType()
        return LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            background = roundedBackground(
                if (selected) primaryContainer else SURFACE_VARIANT,
                18,
                if (selected) primary else SURFACE_VARIANT,
            )
            contentDescription = "Use ${type.label} connection type"
            isClickable = true
            isFocusable = true
            setOnClickListener {
                preferences().edit().putString(CONNECTION_TYPE, type.name).apply()
                connectionTypeValue.text = type.label
                dialog.dismiss()
                if (showingSettings) openSettingsScreen(animate = false)
            }
            val texts = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
            texts.addView(label(type.label, 16f, INK, TypefaceStyle.MEDIUM))
            texts.addView(label(type.description, 13f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
            addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            if (selected) addView(label("CURRENT", 11f, primary, TypefaceStyle.MEDIUM).apply {
                letterSpacing = 0.08f
            })
        }
    }

    private fun openModeScreen() {
        if (visualState == ConnectionControl.State.CONNECTING ||
            visualState == ConnectionControl.State.CONNECTED ||
            NativeCore.isRunning()
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

        content.addView(label("Choose how Aethery connects", 14f, MUTED), LinearLayout.LayoutParams(
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
                if (selected) primaryContainer else SURFACE_VARIANT,
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
            if (selected) addView(label("CURRENT", 11f, primary, TypefaceStyle.MEDIUM).apply {
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
        content.addView(label("CONNECTION TYPE", 12f, MUTED).apply { letterSpacing = 0.1f })
        content.addView(createSettingsButton("${connectionType().label} ›") { showConnectionTypeSheet() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(56),
        ).apply { topMargin = dp(8) })

        content.addView(label("KILL SWITCH", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(24) })
        lateinit var killSwitchRow: LinearLayout
        killSwitchRow = createToggleRow("Kill switch", "Block all traffic if the tunnel drops", killSwitchEnabled()) {
            preferences().edit().putBoolean(KILL_SWITCH, it).apply()
        }
        content.addView(killSwitchRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(72),
        ).apply { topMargin = dp(8) })

        content.addView(label("LOCAL NETWORK", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(24) })
        val lanShareRow = createToggleRow(
            "Internet LAN connection",
            "Expose SOCKS5 to devices on this Wi-Fi network in Proxy mode",
            lanSharingEnabled(),
        ) {
            preferences().edit().putBoolean(LAN_SHARING, it).apply()
        }
        content.addView(lanShareRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(72),
        ).apply { topMargin = dp(8) })

        content.addView(label("TRAFFIC", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(24) })
        content.addView(createSettingsButton("Traffic monitor ›") { openTrafficMonitorScreen() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(52),
        ).apply { topMargin = dp(10) })

        content.addView(label("CORE SOCKS PORT", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(24) })
        val portField = EditText(this).apply {
            setText(socksPort().toString())
            setTextColor(INK)
            setHintTextColor(MUTED)
            textSize = 16f
            inputType = InputType.TYPE_CLASS_NUMBER
            setSingleLine(true)
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), 0, dp(12), 0)
            background = roundedBackground(SURFACE_VARIANT, 16, SURFACE_VARIANT)
            contentDescription = "Core SOCKS port"
        }
        content.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(portField, LinearLayout.LayoutParams(0, dp(56), 1f))
            addView(createSettingsButton("Apply", backgroundOverride = primary, textColorOverride = primaryContainer) {
                applySocksPort(portField)
            }, LinearLayout.LayoutParams(
                dp(96),
                dp(56),
            ).apply { leftMargin = dp(10) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        content.addView(label("Used by Aether's local SOCKS listener; Android VPN/TUN routes do not use this port.", 12f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(6) })

        content.addView(label("NATIVE SPLIT TUNNELING", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(24) })
        content.addView(createSettingsButton("${splitTunnelSummary()} ›") { openSplitTunnelScreen() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(52),
        ).apply { topMargin = dp(10) })
        content.addView(label("CONNECTION ADVANCED", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(28) })
        content.addView(createSettingsButton("Tunnel controls ›") { openTunnelControlsScreen() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(52),
        ).apply { topMargin = dp(10) })

        content.addView(label("Version ${appVersion()}", 14f, MUTED).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, dp(32), 0, 0)
        })
        content.addView(createSettingsButton("Check for updates") {
            appUpdater.checkForUpdate()
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(56),
        ).apply { topMargin = dp(12) })
        content.addView(createSettingsButton("Aethery on Zeth Git", R.drawable.ic_forgejo) {
            openLink("https://git.diastom.xyz/ZethRise/Aethery")
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(56),
        ).apply { topMargin = dp(10) })

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
        content.addView(label("Applied on your next connection", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(24) })
        fun addControl(text: String, action: () -> Unit): TextView = createSettingsButton(text, onClick = action).also { button ->
            content.addView(button, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(56),
            ).apply { topMargin = dp(10) })
        }
        content.addView(label("CONNECTION SHAPING", 12f, MUTED).apply { letterSpacing = 0.1f })
        addControl("Obfuscation · ${obfuscationProfile().label} ›") { chooseObfuscation() }
        addControl("Advanced obfuscation · ${advancedObfuscationSummary()} ›") { editAdvancedObfuscation() }
        lateinit var retryButton: TextView
        retryButton = addControl("WireGuard retries · ${if (retryObfuscationProfiles()) "On" else "Off"}") {
            preferences().edit().putBoolean(RETRY_OBFUSCATION, !retryObfuscationProfiles()).apply()
            updateTunnelControlButton(retryButton, "WireGuard retries · ${if (retryObfuscationProfiles()) "On" else "Off"}")
        }
        content.addView(label("ROUTING", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(28) })
        addControl("Manual endpoint · ${manualEndpoint() ?: "Automatic"} ›") { editManualEndpoint() }
        addControl("Gateway cache · ${defaultEndpointDiscovery().label} ›") { manageGatewayCache() }
        content.addView(label("TROUBLESHOOTING", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(28) })
        addControl("TLS fingerprint · ${tlsCurvePreset().label} ›") { chooseTlsCurvePreset() }
        lateinit var verificationButton: TextView
        verificationButton = addControl("WireGuard verification · ${if (wireGuardDataCheck()) "Strict" else "Fast"} ›") {
            preferences().edit().putBoolean(WIREGUARD_DATA_CHECK, !wireGuardDataCheck()).apply()
            updateTunnelControlButton(verificationButton, "WireGuard verification · ${if (wireGuardDataCheck()) "Strict" else "Fast"} ›")
        }
        content.addView(label("AETHER 1.5", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(28) })
        addControl("DNS resolvers · ${dnsSummary()} ›") { editDnsServers() }
        addControl("Destination routing · ${routingSummary()} ›") { editRoutingRules() }
        zeroTrustControlButton = addControl("Zero Trust · ${zeroTrustSummary()} ›") { openZeroTrustScreen() }
        content.addView(label("ANTI-DPI", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(28) })
        addControl("TLS fragmentation · ${if (h2Fragmentation() == H2Fragmentation.ON) "On" else "Off"} ›") {
            chooseH2Fragmentation()
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

    private fun updateTunnelControlButton(button: TextView, value: String) {
        button.animate().cancel()
        button.animate().alpha(0f).scaleX(0.97f).scaleY(0.97f).setDuration(80)
            .withEndAction {
                button.text = value
                button.animate().alpha(1f).scaleX(1f).scaleY(1f)
                    .setDuration(160).setInterpolator(DecelerateInterpolator()).start()
            }
            .start()
    }

    private fun closeTunnelControlsScreen(animate: Boolean = true) {
        val page = tunnelControlsPage ?: return
        tunnelControlsPage = null
        zeroTrustControlButton = null
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

    private fun chooseObfuscation() {
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
            val indicator = label("SELECTED", 11f, primary, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
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

    private fun chooseTlsCurvePreset() = showChoiceSheet(
        title = "TLS fingerprint",
        subtitle = "Choose TLS curve ordering for QUIC connections",
        options = TlsCurvePreset.entries.toList(),
        selected = tlsCurvePreset(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit().putString(TLS_CURVE_PRESET, chosen.coreName).apply()
    }

    private fun choosePerfProfile() = showChoiceSheet(
        title = "Performance",
        subtitle = "Scale scan concurrency and buffers to match your hardware",
        options = PerfProfile.entries.toList(),
        selected = perfProfile(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit().putString(PERF_PROFILE, chosen.coreName).apply()
        (perfSelector.getChildAt(1) as? TextView)?.text = chosen.label
    }

    private fun chooseH2Fragmentation() = showChoiceSheet(
        title = "TLS fragmentation",
        subtitle = "Fragment the TLS ClientHello to look like ordinary HTTPS traffic",
        options = H2Fragmentation.entries.toList(),
        selected = h2Fragmentation(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit().putString(H2_FRAGMENTATION, chosen.coreName).apply()
    }

    private fun chooseLogLevel() = showChoiceSheet(
        title = "Log level",
        subtitle = "Control verbosity of Aether core logs",
        options = LogLevel.entries.toList(),
        selected = logLevel(),
        label = { it.label },
        description = { it.description },
    ) { chosen ->
        preferences().edit().putString(LOG_LEVEL, chosen.coreName).apply()
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

    private fun editDnsServers() {
        val field = settingsField(
            preferences().getString(DNS_SERVERS, "").orEmpty(),
            "1.1.1.1, 9.9.9.9",
        )
        showTextSettingsSheet(
            "DNS resolvers",
            "IP addresses, optionally with ports. Blank uses Cloudflare defaults.",
            listOf("RESOLVERS" to field),
        ) { values ->
            preferences().edit().putString(DNS_SERVERS, values[0]).apply()
        }
    }

    private fun editRoutingRules() {
        val block = settingsField(
            preferences().getString(ROUTE_BLOCK, "").orEmpty(),
            "ads.example\nkeyword:tracker\nport:25",
            multiline = true,
        ).apply { maxLines = 5 }
        val direct = settingsField(
            preferences().getString(ROUTE_DIRECT, "").orEmpty(),
            "private\nexample.com\n8.6.112.0/24",
            multiline = true,
        ).apply { maxLines = 5 }
        showTextSettingsSheet(
            "Destination routing",
            "Proxy mode only. Add a CIDR directly, such as 8.6.112.0/24.",
            listOf("BLOCK" to block, "BYPASS TUNNEL / CIDR" to direct),
            validator = { values ->
                values.mapIndexedNotNull { index, rules -> invalidCidrRule(rules)?.let { index to it } }.firstOrNull()
            },
        ) { values ->
            preferences().edit()
                .putString(ROUTE_BLOCK, values[0])
                .putString(ROUTE_DIRECT, values[1])
                .apply()
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

    private fun invalidCidrRule(rules: String): String? = rules.lineSequence()
        .map(String::trim)
        .firstOrNull { rule ->
            val value = when {
                rule.startsWith("cidr:", ignoreCase = true) -> rule.substringAfter(':').trim()
                rule.startsWith("ip:", ignoreCase = true) -> rule.substringAfter(':').trim()
                rule.startsWith("regex:", ignoreCase = true) || rule.startsWith("regexp:", ignoreCase = true) -> return@firstOrNull false
                else -> rule
            }
            if ('/' !in value) return@firstOrNull false
            val (address, prefix) = value.split('/', limit = 2)
            if (!address.matches(Regex("[0-9A-Fa-f:.]+"))) return@firstOrNull true
            val bytes = runCatching { InetAddress.getByName(address).address.size }.getOrNull() ?: return@firstOrNull true
            prefix.toIntOrNull()?.let { it !in 0..if (bytes == 4) 32 else 128 } ?: true
        }
        ?.let { "Invalid CIDR: $it" }

    private fun openZeroTrustScreen() {
        zeroTrustPage?.let(pageHost::removeView)
        val team = settingsField(preferences().getString(ZERO_TRUST_TEAM, "").orEmpty(), "team name")
        val email = settingsField(preferences().getString(ZERO_TRUST_EMAIL, "").orEmpty(), "you@example.com")
        val code = settingsField("", "email code")
        val clientId = settingsField(preferences().getString(ZERO_TRUST_CLIENT_ID, "").orEmpty(), "service token client ID")
        val clientSecret = settingsField(preferences().getString(ZERO_TRUST_CLIENT_SECRET, "").orEmpty(), "service token secret", secure = true)
        val token = settingsField(preferences().getString(ZERO_TRUST_TOKEN, "").orEmpty(), "Access JWT", secure = true)
        val status = label("", 13f, MUTED)
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
        content.addView(LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { closeZeroTrustScreen() }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(label("Zero Trust", 22f, INK, TypefaceStyle.MEDIUM))
        })
        content.addView(label("Use email OTP, a service token, or an existing Access JWT.", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(12) })
        listOf(
            "TEAM" to team,
            "EMAIL" to email,
            "ONE-TIME CODE" to code,
            "SERVICE CLIENT ID" to clientId,
            "SERVICE SECRET" to clientSecret,
            "ACCESS JWT" to token,
        ).forEach { (name, field) ->
            content.addView(label(name, 11f, MUTED).apply { letterSpacing = 0.08f }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(10); bottomMargin = dp(6) })
            content.addView(field, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)))
        }
        content.addView(createToggleRow(
            "Gateway filtering",
            "Route HTTP/S through the organization gateway in Proxy mode",
            preferences().getBoolean(ZERO_TRUST_GATEWAY, false),
        ) { preferences().edit().putBoolean(ZERO_TRUST_GATEWAY, it).apply() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(72),
        ).apply { topMargin = dp(14) })
        content.addView(status, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(12) })
        val authButtons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        authButtons.addView(createSettingsButton("Send code") {
            preferences().edit()
                .putString(ZERO_TRUST_TEAM, team.text.toString().trim())
                .putString(ZERO_TRUST_EMAIL, email.text.toString().trim())
                .apply()
            status.text = "Requesting code\u2026"
            Thread {
                val result = runCatching { NativeCore.requestEmailCode(team.text.toString(), email.text.toString()) }
                runOnUiThread {
                    status.setTextColor(if (result.isSuccess) connected else ERROR)
                    status.text = result.fold({ "Code sent. Check your email." }, { it.message ?: "Could not send code" })
                }
            }.start()
        }, LinearLayout.LayoutParams(0, dp(52), 1f))
        authButtons.addView(createSettingsButton("Verify") {
            status.text = "Verifying\u2026"
            Thread {
                val result = runCatching { NativeCore.confirmEmailCode(code.text.toString()) }
                runOnUiThread {
                    result.onSuccess {
                        token.setText(it)
                        preferences().edit().putString(ZERO_TRUST_TOKEN, it).apply()
                    }
                    status.setTextColor(if (result.isSuccess) connected else ERROR)
                    status.text = result.fold({ "Verified. Access token saved." }, { it.message ?: "Code rejected" })
                }
            }.start()
        }, LinearLayout.LayoutParams(0, dp(52), 1f).apply { leftMargin = dp(10) })
        content.addView(authButtons, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)).apply { topMargin = dp(12) })
        val saveButtons = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        saveButtons.addView(createSettingsButton("Clear") {
            preferences().edit()
                .remove(ZERO_TRUST_TEAM)
                .remove(ZERO_TRUST_EMAIL)
                .remove(ZERO_TRUST_CLIENT_ID)
                .remove(ZERO_TRUST_CLIENT_SECRET)
                .remove(ZERO_TRUST_TOKEN)
                .remove(ZERO_TRUST_GATEWAY)
                .apply()
            zeroTrustControlButton?.text = "Zero Trust · ${zeroTrustSummary()} ›"
            closeZeroTrustScreen()
        }, LinearLayout.LayoutParams(0, dp(52), 1f))
        saveButtons.addView(createSettingsButton("Save", backgroundOverride = primary, textColorOverride = primaryContainer) {
            if (team.text.toString().isBlank()) {
                team.error = "Team is required"
                return@createSettingsButton
            }
            preferences().edit()
                .putString(ZERO_TRUST_TEAM, team.text.toString().trim())
                .putString(ZERO_TRUST_EMAIL, email.text.toString().trim())
                .putString(ZERO_TRUST_CLIENT_ID, clientId.text.toString().trim())
                .putString(ZERO_TRUST_CLIENT_SECRET, clientSecret.text.toString().trim())
                .putString(ZERO_TRUST_TOKEN, token.text.toString().trim())
                .apply()
            zeroTrustControlButton?.text = "Zero Trust · ${zeroTrustSummary()} ›"
            closeZeroTrustScreen()
        }, LinearLayout.LayoutParams(0, dp(52), 1f).apply { leftMargin = dp(10) })
        content.addView(saveButtons, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)).apply {
            topMargin = dp(10)
            bottomMargin = dp(8)
        })
        scroll.addView(content)
        page.addView(scroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ))
        page.setOnApplyWindowInsetsListener { _, insets ->
            content.setPadding(dp(24), insets.systemWindowInsetTop + dp(16), dp(24), insets.systemWindowInsetBottom + dp(24))
            insets
        }
        zeroTrustPage = page
        pageHost.addView(page)
        page.requestApplyInsets()
        animatePageOpen(page)
    }

    private fun closeZeroTrustScreen() {
        zeroTrustPage?.let { animatePageClose(it) { zeroTrustPage = null } }
    }

    private fun <T> showChoiceSheet(
        title: String,
        subtitle: String,
        options: List<T>,
        selected: T,
        label: (T) -> String,
        description: (T) -> String,
        onSelected: (T) -> Unit,
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
        ).apply { leftMargin = dp(48); topMargin = dp(-4); bottomMargin = dp(20) })
        val rows = mutableMapOf<T, SelectionOption>()
        options.forEachIndexed { index, item ->
            val optionTitle = label(label(item), 16f, INK, TypefaceStyle.MEDIUM)
            val indicator = label("SELECTED", 11f, primary, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
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
                    onSelected(item)
                    rows.forEach { (value, option) -> setSelectionState(option, value == item, animate = true) }
                }
            }
            val option = SelectionOption(row, optionTitle, indicator, 18)
            rows[item] = option
            setSelectionState(option, item == selected, animate = false)
            sheet.addView(row, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(72)).apply {
                topMargin = if (index == 0) 0 else dp(8)
            })
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
        settingsPage?.let { animatePageClose(it) { settingsPage = null } }
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
        content.addView(label("Traffic carried by Aethery. Per-app attribution is not available from encrypted tunnel counters.", 14f, MUTED), LinearLayout.LayoutParams(
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
            setPadding(dp(20), dp(16), dp(20), dp(16))
            background = roundedBackground(SURFACE_VARIANT, 20, DIVIDER)
            addView(label(title, 12f, MUTED, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.1f })
            addView(value, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(6) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(84),
        ).apply { bottomMargin = dp(12) })
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
        val page = FrameLayout(this).apply {
            setBackgroundColor(CANVAS)
            isClickable = true
        }
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(createHeaderBackButton { closeSplitTunnelScreen() }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(label("Split tunneling", 22f, INK, TypefaceStyle.MEDIUM))
        }
        content.addView(header)
        content.addView(label("Choose which apps use Aethery. Changes apply next connection.", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(20) })
        content.addView(label("MODE", 12f, MUTED).apply { letterSpacing = 0.1f })
        val modeOptions = mutableMapOf<SplitTunnelSettings.Mode, SelectionOption>()
        SplitTunnelSettings.Mode.entries.forEachIndexed { index, mode ->
            val option = createSplitModeOption(mode, settings.mode()) { chosen ->
                modeOptions.forEach { (m, opt) -> setSelectionState(opt, m == chosen, animate = true) }
                settings.save(chosen, selected)
                if (chosen == SplitTunnelSettings.Mode.ALL) {
                    closeSplitTunnelScreen()
                    openSettingsScreen(animate = false)
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
            addView(label("Scanning installed apps…", 14f, MUTED).apply {
                gravity = Gravity.CENTER
                setPadding(0, dp(16), 0, 0)
            })
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
                if (checked) primaryContainer else SURFACE_VARIANT,
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
                settings.save(mode, selected)
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
        val indicator = label("SELECTED", 11f, primary, TypefaceStyle.MEDIUM).apply { letterSpacing = 0.08f }
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
            if (selected) primaryContainer else SURFACE_VARIANT,
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
        splitTunnelPage?.let { animatePageClose(it) { splitTunnelPage = null } }
    }

    private fun closeSplitTunnelAppsScreen() {
        splitTunnelAppsPage?.let { animatePageClose(it) { splitTunnelAppsPage = null } }
    }

    private fun loadUserApps(onLoaded: (List<ApplicationInfo>) -> Unit) {
        cachedUserApps?.let(onLoaded) ?: Thread {
            val apps = installedUserApps()
            cachedUserApps = apps
            runOnUiThread { onLoaded(apps) }
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
            zeroTrustPage != null -> closeZeroTrustScreen()
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
        modeSelector.contentDescription = "Connection mode, ${protocol.label}"
        scanValue.text = scanSummary()
        scannerSelector.contentDescription = "Scanner options, ${scanSummary()}"
        modeValue.animate().cancel()
        modeValue.animate().alpha(0f).scaleX(0.96f).scaleY(0.96f)
            .setDuration(80)
            .setInterpolator(DecelerateInterpolator())
            .withEndAction {
                modeValue.text = protocol.label
                modeValue.animate().alpha(1f).scaleX(1f).scaleY(1f)
                    .setDuration(160)
                    .setInterpolator(DecelerateInterpolator())
                    .start()
            }
            .start()
    }

    private fun toggleTunnel() {
        if (NativeCore.isRunning()) {
            startService(Intent(this, AetherVpnService::class.java).setAction(AetherVpnService.ACTION_DISCONNECT))
            showDisconnected("Disconnecting")
            return
        }

        val config = configJson()
        if (connectionType() == ConnectionType.PROXY) {
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
        showConnecting()
        startForegroundService(Intent(this, AetherVpnService::class.java)
            .setAction(AetherVpnService.ACTION_CONNECT)
            .putExtra(AetherVpnService.EXTRA_CONFIG, config)
            .putExtra(AetherVpnService.EXTRA_VPN_MODE, connectionType() == ConnectionType.VPN))
    }

    private fun configJson(): String = CoreConfig.json(this, selectedProtocol.coreName)

    private fun renderStatus() {
        if (!NativeCore.isRunning() && isTunnelActive()) {
            NativeCore.lastError().takeIf(String::isNotBlank)?.let(::showFailure) ?: showDisconnected("Tunnel stopped unexpectedly")
        }
    }

    private fun showConnecting(detail: String? = null) {
        showConnectionProgress("Connecting", detail ?: "Starting ${selectedProtocol.label} tunnel")
    }

    private fun showStarting() {
        showConnectionProgress("Starting", "Preparing ${selectedProtocol.label} tunnel")
    }

    private fun showScanning() {
        showConnectionProgress("Scanning", "Finding the best MASQUE gateway")
    }

    private fun showConnectionProgress(title: String, detail: String) {
        latencyRequest++
        connectionLatency.text = "Latency unavailable"
        visualState = ConnectionControl.State.CONNECTING
        connectionControl.state = visualState
        connectionTitle.setTextColor(primary)
        connectionTitle.text = title
        connectionDetail.text = detail
        setModeEnabled(false)
    }

    private fun showConnected(restored: Boolean = false) {
        visualState = ConnectionControl.State.CONNECTED
        connectionControl.state = visualState
        connectionTitle.setTextColor(connected)
        connectionTitle.text = "Connected"
        connectionDetail.text = if (restored) "${selectedProtocol.label} tunnel recovered" else "${selectedProtocol.label} tunnel is active"
        latencyGraph.setLabel("Pinging\u2026")
        setModeEnabled(false)
        if (!restored) {
            pingConnection()
            startAutoPing()
            refreshPublicIp()
        }
    }

    private fun showDegraded() {
        if (!isTunnelActive()) return
        visualState = ConnectionControl.State.DEGRADED
        connectionControl.state = visualState
        connectionTitle.setTextColor(0xFFFFD180.toInt())
        connectionTitle.text = "Connection degraded"
        connectionDetail.text = "Tunnel is active; HTTP health check failed"
        latencyGraph.setLabel("Ping unavailable")
    }

    private fun showFailure(detail: String? = null) {
        latencyRequest++
        connectionLatency.text = "Latency unavailable"
        visualState = ConnectionControl.State.FAILED
        connectionControl.state = visualState
        connectionTitle.setTextColor(ERROR)
        connectionTitle.text = "Connection failed"
        connectionDetail.text = detail ?: "Check the server and try again"
        setModeEnabled(true)
    }

    private fun showDisconnected(detail: String = "Tap the circle to connect") {
        latencyRequest++
        stopAutoPing()
        latencyGraph.reset()
        visualState = ConnectionControl.State.DISCONNECTED
        connectionControl.state = visualState
        connectionTitle.setTextColor(INK)
        connectionTitle.text = "Not connected"
        connectionDetail.text = detail
        setModeEnabled(true)
        refreshPublicIp()
    }

    private fun setModeEnabled(enabled: Boolean) {
        modeSelector.isEnabled = enabled
        modeSelector.alpha = if (enabled) 1f else DISABLED_ALPHA
        scannerSelector.isEnabled = enabled
        scannerSelector.alpha = if (enabled) 1f else DISABLED_ALPHA
    }

    private fun isTunnelActive(): Boolean = visualState == ConnectionControl.State.CONNECTED ||
        visualState == ConnectionControl.State.DEGRADED

    private fun configureSystemBars() {
        window.statusBarColor = CANVAS
        window.navigationBarColor = CANVAS
        window.decorView.systemUiVisibility = 0
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
        onClick: () -> Unit,
    ): TextView = label(text, 15f, textColorOverride ?: INK, TypefaceStyle.MEDIUM).apply {
        gravity = Gravity.CENTER
        setPadding(dp(18), 0, dp(18), 0)
        background = roundedBackground(backgroundOverride ?: SURFACE_VARIANT, 16, backgroundOverride ?: SURFACE_VARIANT)
        isClickable = true
        isFocusable = true
        contentDescription = text
        icon?.let {
            setCompoundDrawablesRelativeWithIntrinsicBounds(it, 0, 0, 0)
            compoundDrawablePadding = dp(12)
            compoundDrawablesRelative[0]?.setTint(textColorOverride ?: primary)
            gravity = Gravity.CENTER_VERTICAL
        }
        setOnClickListener { onClick() }
    }

    private fun openLink(url: String) {
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }


    private fun connectionType(): ConnectionType = preferences()
        .getString(CONNECTION_TYPE, ConnectionType.VPN.name)
        ?.let { name -> ConnectionType.entries.firstOrNull { it.name == name } }
        ?: ConnectionType.VPN

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

    private fun lanSharingEnabled(): Boolean = preferences().getBoolean(LAN_SHARING, false)

    private fun createToggleRow(title: String, subtitle: String, checked: Boolean, onToggle: (Boolean) -> Unit): LinearLayout {
        val texts = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(label(title, 16f, INK, TypefaceStyle.MEDIUM))
            addView(label(subtitle, 13f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
        }
        var isOn = checked
        val thumbInset = dp(3)
        val track = LinearLayout(this).apply {
            val trackWidth = dp(48)
            val trackHeight = dp(28)
            layoutParams = LinearLayout.LayoutParams(trackWidth, trackHeight)
            background = roundedBackground(if (isOn) primary else SURFACE_VARIANT, 14, if (isOn) primary else DIVIDER)
            gravity = Gravity.CENTER_VERTICAL
            isClickable = true
            isFocusable = true
            val thumbSize = dp(22)
            val thumb = View(this@MainActivity).apply {
                layoutParams = LinearLayout.LayoutParams(thumbSize, thumbSize)
                background = roundedBackground(Color.WHITE, 11, Color.WHITE)
                translationX = if (isOn) (trackWidth - thumbSize - thumbInset).toFloat() else thumbInset.toFloat()
            }
            addView(thumb)
            setOnClickListener {
                isOn = !isOn
                onToggle(isOn)
                val targetX = if (isOn) (trackWidth - thumbSize - thumbInset).toFloat() else thumbInset.toFloat()
                thumb.animate()
                    .translationX(targetX)
                    .setDuration(160)
                    .setInterpolator(PathInterpolator(0.2f, 0f, 0f, 1f))
                    .start()
                background = roundedBackground(if (isOn) primary else SURFACE_VARIANT, 14, if (isOn) primary else DIVIDER)
            }
        }
        return LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            background = roundedBackground(SURFACE_VARIANT, 18, DIVIDER)
            addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(track)
        }
    }

    private fun logLevel(): LogLevel = preferences()
        .getString(LOG_LEVEL, LogLevel.INFO.coreName)
        ?.let { name -> LogLevel.entries.firstOrNull { it.coreName == name } }
        ?: LogLevel.INFO

    private fun perfProfile(): PerfProfile = preferences()
        .getString(PERF_PROFILE, PerfProfile.AUTO.coreName)
        ?.let { name -> PerfProfile.entries.firstOrNull { it.coreName == name } }
        ?: PerfProfile.AUTO

    private fun h2Fragmentation(): H2Fragmentation = preferences()
        .getString(H2_FRAGMENTATION, H2Fragmentation.OFF.coreName)
        ?.let { name -> H2Fragmentation.entries.firstOrNull { it.coreName == name } }
        ?: H2Fragmentation.OFF

    private fun dnsSummary(): String =
        preferences().getString(DNS_SERVERS, "")?.takeIf { it.isNotBlank() } ?: "Automatic"

    private fun routingSummary(): String =
        if (
            preferences().getString(ROUTE_BLOCK, "").isNullOrBlank() &&
            preferences().getString(ROUTE_DIRECT, "").isNullOrBlank()
        ) "Off" else "Custom"

    private fun zeroTrustSummary(): String =
        preferences().getString(ZERO_TRUST_TEAM, "")?.takeIf { it.isNotBlank() } ?: "Off"

    private fun socksPort(): Int = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getInt(DEFAULT_SOCKS_PORT, DEFAULT_SOCKS_PORT_VALUE)

    private fun splitTunnelSummary(): String {
        val settings = SplitTunnelSettings(this)
        val count = settings.packages().size
        return when (settings.mode()) {
            SplitTunnelSettings.Mode.ALL -> "All apps use Aethery"
            SplitTunnelSettings.Mode.INCLUDE -> "Only $count selected app${if (count == 1) "" else "s"}"
            SplitTunnelSettings.Mode.EXCLUDE -> "Exclude $count selected app${if (count == 1) "" else "s"}"
        }
    }

    private fun applySocksPort(field: EditText) {
        val port = field.text.toString().toIntOrNull()
        if (port == null || port !in 1..65535) {
            field.error = "Enter a port from 1 to 65535"
            return
        }
        getSharedPreferences(SETTINGS, MODE_PRIVATE).edit().putInt(DEFAULT_SOCKS_PORT, port).apply()
        field.error = null
        field.clearFocus()
    }

    private enum class Protocol(
        val label: String,
        val coreName: String,
        val description: String,
        val androidAvailable: Boolean = true,
    ) {
        MASQUE("MASQUE", "masque", "HTTP/3 tunnel"),
        WIREGUARD("WireGuard", "wireguard", "WireGuard tunnel"),
        WARP_IN_WARP("WARP-on-WARP", "gool", "Double-layer tunnel"),
    }

    private enum class ConnectionType(val label: String, val description: String) {
        VPN("VPN", "Routes device traffic through Android VPN"),
        PROXY("Proxy", "Starts local SOCKS5 at 127.0.0.1:${DEFAULT_SOCKS_PORT_VALUE}"),
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
        H3("HTTP/3", "h3", "QUIC; best on healthy UDP networks"),
        H2("HTTP/2", "h2", "TCP; use when UDP or QUIC is blocked"),
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
        const val LOG_REFRESH_MS = 750L
        const val STATUS_POLL_MS = 2_000L
        const val PAGE_ANIMATION_MS = 220L
        const val LOG_CLOSE_ANIMATION_MS = 160L
        const val PING_URL = "https://www.google.com/generate_204"
        const val PING_TIMEOUT_MS = 5_000
        val IP_INFO_URLS = arrayOf(
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://one.one.one.one/cdn-cgi/trace",
            "https://1.1.1.1/cdn-cgi/trace",
            "https://api64.ipify.org",
            "https://api.ipify.org",
        )
        val IP_ADDRESS = Regex("^[0-9A-Fa-f:.]+$")
        const val IP_TIMEOUT_MS = 5_000
        const val IP_FETCH_ATTEMPTS = 3
        const val IP_RETRY_DELAY_MS = 300L
        const val SETTINGS = "settings"
        const val CONNECTION_TYPE = "connection_type"
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
        const val LAN_SHARING = "lan_sharing"
        const val LOG_LEVEL = "log_level"
        const val PERF_PROFILE = "perf_profile"
        const val H2_FRAGMENTATION = "h2_fragmentation"
        const val DNS_SERVERS = "dns_servers"
        const val ROUTE_BLOCK = "route_block"
        const val ROUTE_DIRECT = "route_direct"
        const val ZERO_TRUST_TEAM = "zero_trust_team"
        const val ZERO_TRUST_EMAIL = "zero_trust_email"
        const val ZERO_TRUST_CLIENT_ID = "zero_trust_client_id"
        const val ZERO_TRUST_CLIENT_SECRET = "zero_trust_client_secret"
        const val ZERO_TRUST_TOKEN = "zero_trust_token"
        const val ZERO_TRUST_GATEWAY = "zero_trust_gateway"
        const val DEFAULT_SOCKS_PORT = "default_socks_port"
        const val DEFAULT_SOCKS_PORT_VALUE = 1819
        const val FALLBACK_CANVAS = 0xFF101411.toInt()
        const val FALLBACK_SURFACE = 0xFF171C18.toInt()
        const val FALLBACK_SURFACE_VARIANT = 0xFF222A24.toInt()
        const val FALLBACK_INK = 0xFFE8F1EA.toInt()
        const val FALLBACK_MUTED = 0xFFB9C6BB.toInt()
        const val FALLBACK_DIVIDER = 0xFF3B473E.toInt()
        const val FALLBACK_PRIMARY = 0xFFA4D8BB.toInt()
        const val FALLBACK_PRIMARY_CONTAINER = 0xFF1F4030.toInt()
        const val ERROR = 0xFFFFB4AB.toInt()
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

private class RetryView(context: Context, color: Int) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        strokeWidth = resources.displayMetrics.density * 1.8f
        this.color = color
    }

    override fun onDraw(canvas: Canvas) {
        val d = resources.displayMetrics.density
        val center = width / 2f
        val radius = d * 6f
        canvas.drawArc(center - radius, center - radius, center + radius, center + radius, -50f, 285f, false, paint)
        canvas.drawLine(center + radius - d, center - radius, center + radius, center - radius, paint)
        canvas.drawLine(center + radius, center - radius, center + radius, center - radius + d * 4f, paint)
    }
}

private class ConnectionControl(
    context: Context,
    private val primary: Int,
    private val primaryContainer: Int,
    private val connected: Int,
    private val connectedContainer: Int,
) : View(context) {
    enum class State { DISCONNECTED, CONNECTING, CONNECTED, DEGRADED, FAILED }

    var state: State = State.DISCONNECTED
        set(value) {
            field = value
            contentDescription = when (value) {
                State.DISCONNECTED, State.FAILED -> "Connect"
                State.CONNECTING -> "Connecting"
                State.CONNECTED, State.DEGRADED -> "Disconnect"
            }
            if (value == State.CONNECTING || value == State.CONNECTED || value == State.DEGRADED) startConnectingAnimation() else stopConnectingAnimation()
            animate().cancel()
            animate().scaleX(0.9f).scaleY(0.9f).setDuration(90).withEndAction {
                animate().scaleX(1f).scaleY(1f).setDuration(180).start()
            }.start()
            invalidate()
        }

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val arcBounds = RectF()
    private val density = resources.displayMetrics.density
    private var progress = 0f
    private var pulse = 0f
    private var connectingAnimator: ValueAnimator? = null

    init {
        isClickable = true
        isFocusable = true
        contentDescription = "Connect"
        setLayerType(View.LAYER_TYPE_SOFTWARE, null)
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val desired = dp(238)
        setMeasuredDimension(resolveSize(desired, widthMeasureSpec), resolveSize(desired, heightMeasureSpec))
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val centerX = width / 2f
        val centerY = height / 2f
        val radius = dp(95).toFloat() + if (state == State.CONNECTING) dp(3) * pulse else 0f
        val palette = when (state) {
            State.DISCONNECTED, State.CONNECTING -> Palette(primaryContainer, primary)
            State.CONNECTED -> Palette(CONNECTED_BRIGHT_CONTAINER, CONNECTED_BRIGHT)
            State.DEGRADED -> Palette(DEGRADED_CONTAINER, DEGRADED)
            State.FAILED -> Palette(ERROR_CONTAINER, ERROR)
        }

        paint.style = Paint.Style.FILL
        paint.color = palette.container
        val active = state == State.CONNECTED || state == State.DEGRADED
        val shadowAlpha = if (active) 0x88 else 0x44
        val shadowColor = (shadowAlpha shl 24) or (if (active) palette.accent and 0xFFFFFF else 0x000000)
        paint.setShadowLayer(dp(if (active) 18 else 12).toFloat(), 0f, 0f, shadowColor)
        canvas.drawCircle(centerX, centerY, radius, paint)
        paint.clearShadowLayer()

        paint.style = Paint.Style.STROKE
        paint.strokeWidth = dp(if (state == State.DISCONNECTED) 1 else 2).toFloat()
        paint.color = palette.accent
        canvas.drawCircle(centerX, centerY, radius, paint)

        val iconRadius = dp(31).toFloat()
        arcBounds.set(centerX - iconRadius, centerY - iconRadius, centerX + iconRadius, centerY + iconRadius)
        paint.strokeWidth = dp(3).toFloat()
        paint.strokeCap = Paint.Cap.ROUND
        canvas.drawArc(arcBounds, 330f, 240f, false, paint)
        canvas.drawLine(centerX, centerY - dp(34), centerX, centerY - dp(8), paint)
        paint.strokeCap = Paint.Cap.BUTT

        if (state == State.CONNECTING) {
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = dp(3).toFloat()
            canvas.drawArc(
                RectF(
                    centerX - radius - dp(7),
                    centerY - radius - dp(7),
                    centerX + radius + dp(7),
                    centerY + radius + dp(7),
                ),
                progress * 360f,
                78f + pulse * 42f,
                false,
                paint,
            )
        } else if (state == State.CONNECTED || state == State.DEGRADED) {
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = dp(2 + (pulse * 2f).roundToInt()).toFloat()
            canvas.drawCircle(centerX, centerY, radius + dp(5) + pulse * dp(5), paint)
        }


    }

    override fun onTouchEvent(event: MotionEvent): Boolean = when (event.actionMasked) {
        MotionEvent.ACTION_DOWN -> {
            animate().scaleX(0.97f).scaleY(0.97f).setDuration(90).start()
            true
        }
        MotionEvent.ACTION_UP -> {
            animate().scaleX(1f).scaleY(1f).setDuration(180).start()
            performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
            performClick()
            true
        }
        MotionEvent.ACTION_CANCEL -> {
            animate().scaleX(1f).scaleY(1f).setDuration(180).start()
            true
        }
        else -> super.onTouchEvent(event)
    }

    override fun performClick(): Boolean {
        super.performClick()
        return true
    }

    override fun onDetachedFromWindow() {
        stopConnectingAnimation()
        super.onDetachedFromWindow()
    }

    private fun startConnectingAnimation() {
        if (connectingAnimator != null) return
        connectingAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = if (state == State.CONNECTED || state == State.DEGRADED) 1_600 else 1_050
            repeatCount = ValueAnimator.INFINITE
            addUpdateListener {
                progress = it.animatedFraction
                pulse = if (progress < 0.5f) progress * 2f else (1f - progress) * 2f
                invalidate()
            }
            start()
        }
    }

    private fun stopConnectingAnimation() {
        connectingAnimator?.cancel()
        connectingAnimator = null
        progress = 0f
        pulse = 0f
    }

    private fun dp(value: Int): Int = (value * density).roundToInt()

    private fun preferences() = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    private data class Palette(val container: Int, val accent: Int)

    private companion object {
        const val ERROR = 0xFFFFB4AB.toInt()
        const val ERROR_CONTAINER = 0xFF4A1E1C.toInt()
        const val CONNECTED_BRIGHT = 0xFF8FFFB5.toInt()
        const val CONNECTED_BRIGHT_CONTAINER = 0xFF176B3B.toInt()
        const val DEGRADED = 0xFFFFD180.toInt()
        const val DEGRADED_CONTAINER = 0xFF5A4300.toInt()
    }
}

private class LatencyGraphView(context: Context) : View(context) {
    private val maxPoints = 20
    private val points = mutableListOf<Float>()
    private var currentLabel = "Latency unavailable"
    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = resources.displayMetrics.density * 2f
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        color = 0xFFA4D8BB.toInt()
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = 0x30A4D8BB.toInt()
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFFE8F1EA.toInt()
        textSize = resources.displayMetrics.density * 13f
        typeface = android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL)
    }
    private val mutedPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFFB9C6BB.toInt()
        textSize = resources.displayMetrics.density * 11f
    }
    private val density = resources.displayMetrics.density
    private val path = android.graphics.Path()
    private var graphOffset = 0f
    private var graphAnimator: ValueAnimator? = null

    fun addPoint(ms: Float) {
        points.add(ms)
        if (points.size > maxPoints) points.removeAt(0)
        currentLabel = "${ms.toInt()} ms"
        animateGraph()
    }

    fun setLabel(text: String) {
        currentLabel = text
        invalidate()
    }

    private fun animateGraph() {
        graphAnimator?.cancel()
        graphAnimator = ValueAnimator.ofFloat(0f, -density * 3f, 0f).apply {
            duration = 280
            interpolator = DecelerateInterpolator()
            addUpdateListener {
                graphOffset = it.animatedValue as Float
                invalidate()
            }
            start()
        }
    }

    fun reset() {
        points.clear()
        currentLabel = "Latency unavailable"
        graphAnimator?.cancel()
        graphAnimator = null
        graphOffset = 0f
        invalidate()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val desiredW = resolveSize((180 * density).toInt(), widthMeasureSpec)
        val desiredH = resolveSize((56 * density).toInt(), heightMeasureSpec)
        setMeasuredDimension(desiredW, desiredH)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        val padX = density * 4f
        val padTop = density * 20f
        val padBottom = density * 4f
        val graphH = h - padTop - padBottom

        textPaint.textAlign = Paint.Align.CENTER
        canvas.drawText(currentLabel, w / 2f, padTop - density * 2f, textPaint)

        if (points.isEmpty()) return

        canvas.save()
        canvas.translate(0f, graphOffset)

        val maxVal = points.max().coerceAtLeast(10f)
        val stepX = (w - padX * 2) / (maxPoints - 1).coerceAtLeast(1)

        if (points.size == 1) {
            val x = padX
            val y = padTop + graphH * (1f - points[0] / maxVal)
            canvas.drawCircle(x, y, density * 3f, linePaint.apply { style = Paint.Style.FILL })
            linePaint.style = Paint.Style.STROKE
            canvas.restore()
            return
        }

        path.reset()
        for (i in points.indices) {
            val x = padX + i * stepX
            val y = padTop + graphH * (1f - points[i] / maxVal)
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        canvas.drawPath(path, linePaint)

        val fillPath = android.graphics.Path(path)
        val lastX = padX + (points.size - 1) * stepX
        fillPath.lineTo(lastX, padTop + graphH)
        fillPath.lineTo(padX, padTop + graphH)
        fillPath.close()
        canvas.drawPath(fillPath, fillPaint)
        canvas.restore()
    }

    override fun onDetachedFromWindow() {
        graphAnimator?.cancel()
        super.onDetachedFromWindow()
    }
}
