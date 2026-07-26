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
import android.view.animation.DecelerateInterpolator
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
import java.net.URL
import kotlin.math.min
import kotlin.math.roundToInt

class MainActivity : Activity() {
    private lateinit var connectionControl: ConnectionControl
    private lateinit var connectionTitle: TextView
    private lateinit var connectionDetail: TextView
    private lateinit var connectionLatency: TextView
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
    private var selectedProtocol = Protocol.MASQUE
    private var pendingConfig: String? = null
    private var visualState = ConnectionControl.State.DISCONNECTED
    private var receiverRegistered = false
    private var showingSettings = false
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
    @Volatile private var cachedUserApps: List<ApplicationInfo>? = null
    private var latencyRequest = 0
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
            when (intent.getStringExtra(AetherVpnService.EXTRA_STATUS)) {
                AetherVpnService.STATUS_CONNECTING -> showConnecting()
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
            topMargin = -dp(12)
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

    private fun pingConnection() {
        if (visualState != ConnectionControl.State.CONNECTED) return
        val request = ++latencyRequest
        connectionLatency.text = "Pinging…"
        Thread {
            val result = runCatching {
                val startedAt = System.nanoTime()
                val connection = URL(PING_URL).openConnection() as HttpURLConnection
                try {
                    connection.connectTimeout = PING_TIMEOUT_MS
                    connection.readTimeout = PING_TIMEOUT_MS
                    connection.requestMethod = "GET"
                    connection.instanceFollowRedirects = false
                    check(connection.responseCode in 200..399) { "HTTP ${connection.responseCode}" }
                    "${(System.nanoTime() - startedAt) / 1_000_000} ms"
                } finally {
                    connection.disconnect()
                }
            }.getOrElse { "Ping unavailable" }
            runOnUiThread {
                if (request == latencyRequest && visualState == ConnectionControl.State.CONNECTED) {
                    connectionLatency.text = result
                }
            }
        }.start()
    }

    private fun createHeader(): LinearLayout = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        val titles = LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.VERTICAL
            addView(ImageView(this@MainActivity).apply {
                setImageResource(R.drawable.aethery_logo)
                contentDescription = getString(R.string.app_name)
                scaleType = ScaleType.CENTER_INSIDE
                adjustViewBounds = true
            }, LinearLayout.LayoutParams(dp(36), dp(40)))
            addView(label("Private connection", 14f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
        }
        addView(titles, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
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
        addView(connectionControl)
        addView(connectionTitle, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(24) })
        addView(connectionDetail, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(6) })
        addView(connectionLatency, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(8) })
        addView(modeSelector, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(64),
        ).apply { topMargin = dp(32) })
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
        addView(ChevronView(this@MainActivity, MUTED), LinearLayout.LayoutParams(dp(24), dp(24)))
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
        addView(ChevronView(this@MainActivity, MUTED), LinearLayout.LayoutParams(dp(24), dp(24)))
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
        addView(ChevronView(this@MainActivity, MUTED), LinearLayout.LayoutParams(dp(24), dp(24)))
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
        addView(ChevronView(this@MainActivity, MUTED), LinearLayout.LayoutParams(dp(24), dp(24)))
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
            ).apply { rightMargin = dp(6) })
        }
        content.addView(logLevelRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(10); rightMargin = dp(10); bottomMargin = dp(12) })
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
                val updatedLogs = connectionLogText()
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

    private fun connectionLogText(): String {
        val events = ConnectionLog.snapshot() + NativeCore.lastLog().lineSequence().filter(String::isNotBlank)
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
            addView(createHeaderBackButton { closeScannerScreen() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label("Scanner options", 22f, INK, TypefaceStyle.MEDIUM).apply {
                setPadding(dp(4), 0, 0, 0)
            })
        }
        content.addView(header, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(8) })

        content.addView(label("Choose Aether's endpoint-discovery budget and address families", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(4); bottomMargin = dp(24) })

        val options = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val discoveryOptions = mutableMapOf<EndpointDiscovery, SelectionOption>()
        val transportOptions = mutableMapOf<MasqueTransport, SelectionOption>()
        val modeOptions = mutableMapOf<ScanMode, SelectionOption>()
        val targetOptions = mutableMapOf<ScanTarget, SelectionOption>()

        options.addView(label("MASQUE GATEWAY DISCOVERY", 12f, MUTED).apply { letterSpacing = 0.1f })
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
        ))

        page.setOnApplyWindowInsetsListener { _, insets ->
            content.setPadding(dp(24), insets.systemWindowInsetTop + dp(16), dp(24), insets.systemWindowInsetBottom + dp(24))
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
            addView(createHeaderBackButton { closeSettingsScreen() }, LinearLayout.LayoutParams(dp(48), dp(48)))
            addView(label("Settings", 22f, INK, TypefaceStyle.MEDIUM).apply {
                setPadding(dp(4), 0, 0, 0)
            })
        }
        content.addView(header, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(16) })

        content.addView(label("CONNECTION TYPE", 12f, MUTED).apply { letterSpacing = 0.1f })
        content.addView(createSettingsButton("${connectionType().label} ›") { showConnectionTypeSheet() }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(56),
        ).apply { topMargin = dp(8) })

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
        content.addView(createSettingsButton("Aethery on GitHub", R.drawable.ic_github) {
            openLink("https://github.com/ZethRise/Aethery")
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(56),
        ).apply { topMargin = dp(10) })

        scroll.addView(content)
        page.addView(scroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ))

        page.setOnApplyWindowInsetsListener { _, insets ->
            content.setPadding(dp(24), insets.systemWindowInsetTop + dp(16), dp(24), insets.systemWindowInsetBottom + dp(24))
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
        if (visualState == ConnectionControl.State.CONNECTING || NativeCore.isRunning()) return
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
        when {
            splitTunnelAppsPage != null -> closeSplitTunnelAppsScreen()
            splitTunnelPage != null -> closeSplitTunnelScreen()
            tunnelControlsPage != null -> closeTunnelControlsScreen()
            showingLogs -> closeLogsScreen()
            showingScanner -> closeScannerScreen()
            showingMode -> closeModeScreen()
            showingSettings -> closeSettingsScreen()
            else -> super.onBackPressed()
        }
    }

    private fun updateConnectionMode(protocol: Protocol) {
        if (selectedProtocol == protocol) return
        selectedProtocol = protocol
        modeSelector.contentDescription = "Connection mode, ${protocol.label}"
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

    private fun configJson(): String = org.json.JSONObject().apply {
        put("config_path", File(filesDir, "aether.toml").absolutePath)
        put("protocol", selectedProtocol.coreName)
        put("listen", "127.0.0.1:${socksPort()}")
        put("scan_mode", defaultScanMode().coreName)
        put("ip_scan", defaultScan().coreName)
        put("endpoint_cache_path", File(filesDir, "masque-gateway-cache.json").absolutePath)
        put("endpoint_discovery", defaultEndpointDiscovery().coreName)
        put("masque_transport", defaultMasqueTransport().coreName)
        putOpt("forced_peer", manualEndpoint())
        put("obfuscation_profile", obfuscationProfile().coreName)
        put("retry_obfuscation_profiles", retryObfuscationProfiles())
        put("tls_curve_preset", tlsCurvePreset().coreName)
        put("wireguard_data_check", wireGuardDataCheck())
        put("log_level", logLevel().coreName)
        put("perf_profile", perfProfile().coreName)
        if (h2Fragmentation() == H2Fragmentation.ON) put("h2_fragmentation", true)
    }.toString()

    private fun renderStatus() {
        if (!NativeCore.isRunning() && visualState == ConnectionControl.State.CONNECTED) showDisconnected()
    }

    private fun showConnecting() {
        showConnectionProgress("Connecting", "Starting ${selectedProtocol.label} tunnel")
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

    private fun showConnected() {
        visualState = ConnectionControl.State.CONNECTED
        connectionControl.state = visualState
        connectionTitle.setTextColor(connected)
        connectionTitle.text = "Connected"
        connectionDetail.text = "${selectedProtocol.label} tunnel is active"
        connectionLatency.text = "Tap to measure latency"
        setModeEnabled(false)
        pingConnection()
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
        connectionLatency.text = "Latency unavailable"
        visualState = ConnectionControl.State.DISCONNECTED
        connectionControl.state = visualState
        connectionTitle.setTextColor(INK)
        connectionTitle.text = "Not connected"
        connectionDetail.text = detail
        setModeEnabled(true)
    }

    private fun setModeEnabled(enabled: Boolean) {
        modeSelector.isEnabled = enabled
        modeSelector.alpha = if (enabled) 1f else DISABLED_ALPHA
        scannerSelector.isEnabled = enabled
        scannerSelector.alpha = if (enabled) 1f else DISABLED_ALPHA
    }

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

    private fun scanSummary(): String = "${defaultScan().label} · ${defaultScanMode().label} · ${defaultMasqueTransport().label}"

    private fun preferences() = getSharedPreferences(SETTINGS, MODE_PRIVATE)

    private fun obfuscationProfile(): ObfuscationProfile = preferences()
        .getString(OBFUSCATION_PROFILE, ObfuscationProfile.BALANCED.coreName)
        ?.let { name -> ObfuscationProfile.entries.firstOrNull { it.coreName == name } }
        ?: ObfuscationProfile.BALANCED

    private fun manualEndpoint(): String? = preferences().getString(MANUAL_ENDPOINT, null)?.takeIf(String::isNotBlank)

    private fun retryObfuscationProfiles(): Boolean = preferences().getBoolean(RETRY_OBFUSCATION, true)

    private fun tlsCurvePreset(): TlsCurvePreset = preferences()
        .getString(TLS_CURVE_PRESET, TlsCurvePreset.CHROME.coreName)
        ?.let { name -> TlsCurvePreset.entries.firstOrNull { it.coreName == name } }
        ?: TlsCurvePreset.CHROME

    private fun wireGuardDataCheck(): Boolean = preferences().getBoolean(WIREGUARD_DATA_CHECK, true)

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
        const val SETTINGS = "settings"
        const val CONNECTION_TYPE = "connection_type"
        const val DEFAULT_SCAN = "default_scan"
        const val DEFAULT_SCAN_MODE = "default_scan_mode"
        const val ENDPOINT_DISCOVERY = "endpoint_discovery"
        const val DEFAULT_MASQUE_TRANSPORT = "default_masque_transport"
        const val OBFUSCATION_PROFILE = "obfuscation_profile"
        const val MANUAL_ENDPOINT = "manual_endpoint"
        const val RETRY_OBFUSCATION = "retry_obfuscation_profiles"
        const val TLS_CURVE_PRESET = "tls_curve_preset"
        const val WIREGUARD_DATA_CHECK = "wireguard_data_check"
        const val LOG_LEVEL = "log_level"
        const val PERF_PROFILE = "perf_profile"
        const val H2_FRAGMENTATION = "h2_fragmentation"
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
        this.color = color
    }

    override fun onDraw(canvas: Canvas) {
        val middleX = width / 2f
        val middleY = height / 2f - resources.displayMetrics.density
        val arm = resources.displayMetrics.density * 4f
        canvas.drawLine(middleX - arm, middleY - arm / 2, middleX, middleY + arm / 2, paint)
        canvas.drawLine(middleX, middleY + arm / 2, middleX + arm, middleY - arm / 2, paint)
    }
}

private class ConnectionControl(
    context: Context,
    private val primary: Int,
    private val primaryContainer: Int,
    private val connected: Int,
    private val connectedContainer: Int,
) : View(context) {
    enum class State { DISCONNECTED, CONNECTING, CONNECTED, FAILED }

    var state: State = State.DISCONNECTED
        set(value) {
            field = value
            contentDescription = when (value) {
                State.DISCONNECTED, State.FAILED -> "Connect"
                State.CONNECTING -> "Connecting"
                State.CONNECTED -> "Disconnect"
            }
            if (value == State.CONNECTING || value == State.CONNECTED) startConnectingAnimation() else stopConnectingAnimation()
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
        val desired = dp(196)
        setMeasuredDimension(resolveSize(desired, widthMeasureSpec), resolveSize(desired, heightMeasureSpec))
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val centerX = width / 2f
        val centerY = height / 2f
        val radius = dp(78).toFloat() + if (state == State.CONNECTING) dp(3) * pulse else 0f
        val palette = when (state) {
            State.DISCONNECTED, State.CONNECTING -> Palette(primaryContainer, primary)
            State.CONNECTED -> Palette(CONNECTED_BRIGHT_CONTAINER, CONNECTED_BRIGHT)
            State.FAILED -> Palette(ERROR_CONTAINER, ERROR)
        }

        paint.style = Paint.Style.FILL
        paint.color = palette.container
        val shadowAlpha = if (state == State.CONNECTED) 0x88 else 0x44
        val shadowColor = (shadowAlpha shl 24) or (if (state == State.CONNECTED) palette.accent and 0xFFFFFF else 0x000000)
        paint.setShadowLayer(dp(if (state == State.CONNECTED) 18 else 12).toFloat(), 0f, 0f, shadowColor)
        canvas.drawCircle(centerX, centerY, radius, paint)
        paint.clearShadowLayer()

        paint.style = Paint.Style.STROKE
        paint.strokeWidth = dp(if (state == State.DISCONNECTED) 1 else 2).toFloat()
        paint.color = palette.accent
        canvas.drawCircle(centerX, centerY, radius, paint)

        val iconRadius = dp(25).toFloat()
        arcBounds.set(centerX - iconRadius, centerY - iconRadius, centerX + iconRadius, centerY + iconRadius)
        paint.strokeWidth = dp(3).toFloat()
        paint.strokeCap = Paint.Cap.ROUND
        canvas.drawArc(arcBounds, 330f, 240f, false, paint)
        canvas.drawLine(centerX, centerY - dp(28), centerX, centerY - dp(6), paint)
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
        } else if (state == State.CONNECTED) {
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
            duration = if (state == State.CONNECTED) 1_600 else 1_050
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
    }
}
