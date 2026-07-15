package studio.cluvex.aethery

import android.animation.ValueAnimator
import android.app.Activity
import android.app.Dialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
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
import android.widget.FrameLayout
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import kotlin.math.min
import kotlin.math.roundToInt

class MainActivity : Activity() {
    private lateinit var connectionControl: ConnectionControl
    private lateinit var connectionTitle: TextView
    private lateinit var connectionDetail: TextView
    private lateinit var modeSelector: LinearLayout
    private lateinit var modeValue: TextView
    private lateinit var logSelector: LinearLayout
    private lateinit var scannerSelector: LinearLayout
    private lateinit var scanValue: TextView
    private lateinit var mainRoot: FrameLayout
    private lateinit var pageHost: FrameLayout
    private var selectedProtocol = Protocol.MASQUE
    private var pendingConfig: String? = null
    private var visualState = ConnectionControl.State.DISCONNECTED
    private var receiverRegistered = false
    private var showingSettings = false
    private var settingsPage: View? = null

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.getStringExtra(AetherVpnService.EXTRA_STATUS)) {
                AetherVpnService.STATUS_CONNECTING -> showConnecting()
                AetherVpnService.STATUS_CONNECTED -> showConnected()
                AetherVpnService.STATUS_FAILED -> showFailure(intent.getStringExtra(AetherVpnService.EXTRA_DETAIL))
                AetherVpnService.STATUS_DISCONNECTED -> showDisconnected()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        configureSystemBars()

        connectionControl = ConnectionControl(this).apply { setOnClickListener { toggleTunnel() } }
        connectionTitle = label(textSize = 20f, color = INK, style = TypefaceStyle.MEDIUM).apply {
            gravity = Gravity.CENTER
        }
        connectionDetail = label(textSize = 14f, color = MUTED).apply { gravity = Gravity.CENTER }
        selectedProtocol = defaultProtocol()
        modeValue = label(selectedProtocol.label, 16f, INK, TypefaceStyle.MEDIUM)
        modeSelector = createModeSelector()
        logSelector = createLogSelector()
        scanValue = label(defaultScan().label, 14f, INK, TypefaceStyle.MEDIUM)
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
    }

    override fun onStop() {
        if (receiverRegistered) {
            unregisterReceiver(statusReceiver)
            receiverRegistered = false
        }
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        renderStatus()
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

    private fun createHeader(): LinearLayout = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        val titles = LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.VERTICAL
            addView(label("Aethery", 22f, INK, TypefaceStyle.MEDIUM))
            addView(label("Private connection", 14f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
        }
        addView(titles, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        addView(label("⚙", 28f, INK).apply {
            gravity = Gravity.CENTER
            contentDescription = "Settings"
            isClickable = true
            isFocusable = true
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
        addView(modeSelector, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(64),
        ).apply { topMargin = dp(32) })
        val diagnostics = LinearLayout(this@MainActivity).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            addView(logSelector, LinearLayout.LayoutParams(
                0,
                dp(56),
                0.42f,
            ))
            addView(scannerSelector, LinearLayout.LayoutParams(
                0,
                dp(56),
                0.58f,
            ).apply { leftMargin = dp(10) })
        }
        addView(diagnostics, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(56),
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
        setOnClickListener { showModeSheet() }

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
        background = roundedBackground(SURFACE_VARIANT, 18, DIVIDER)
        contentDescription = "View connection log"
        isClickable = true
        isFocusable = true
        setOnClickListener { showLogSheet() }

        addView(label("LOG", 12f, MUTED).apply { letterSpacing = 0.1f })
        addView(label("Events", 14f, INK, TypefaceStyle.MEDIUM), LinearLayout.LayoutParams(
            0,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            1f,
        ).apply { leftMargin = dp(16) })
        addView(ChevronView(this@MainActivity, MUTED), LinearLayout.LayoutParams(dp(24), dp(24)))
    }

    private fun createScannerSelector(): LinearLayout = LinearLayout(this).apply {
        gravity = Gravity.CENTER_VERTICAL
        orientation = LinearLayout.HORIZONTAL
        setPadding(dp(16), 0, dp(14), 0)
        background = roundedBackground(SURFACE_VARIANT, 18, DIVIDER)
        contentDescription = "Scanner options, ${defaultScan().label}"
        isClickable = true
        isFocusable = true
        setOnClickListener { showScannerSheet() }

        addView(label("SCANNER", 12f, MUTED).apply { letterSpacing = 0.08f })
        addView(scanValue, LinearLayout.LayoutParams(
            0,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            1f,
        ).apply { leftMargin = dp(10) })
        addView(ChevronView(this@MainActivity, MUTED), LinearLayout.LayoutParams(dp(20), dp(20)))
    }

    private fun showLogSheet() {
        val dialog = Dialog(this).apply {
            requestWindowFeature(Window.FEATURE_NO_TITLE)
            setCanceledOnTouchOutside(true)
        }
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            background = roundedBackground(SURFACE, 28, SURFACE)
        }
        sheet.addView(label("Connection log", 22f, INK, TypefaceStyle.MEDIUM))
        sheet.addView(label("Latest tunnel events", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(4); bottomMargin = dp(16) })

        val events = label(textSize = 13f, color = INK).apply {
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        val scroll = ScrollView(this).apply { addView(events) }
        sheet.addView(scroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(300),
        ))

        val container = FrameLayout(this).apply {
            setPadding(dp(16), 0, dp(16), dp(16))
            addView(sheet, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ))
        }
        dialog.setContentView(container)
        val refreshHandler = Handler(Looper.getMainLooper())
        val refresh = object : Runnable {
            override fun run() {
                events.text = connectionLogText()
                scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
                if (dialog.isShowing) refreshHandler.postDelayed(this, LOG_REFRESH_MS)
            }
        }
        dialog.setOnShowListener { refresh.run() }
        dialog.setOnDismissListener { refreshHandler.removeCallbacks(refresh) }
        dialog.show()
        dialog.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setDimAmount(0.62f)
            setLayout(WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.WRAP_CONTENT)
            setGravity(Gravity.BOTTOM)
        }
    }

    private fun connectionLogText(): String {
        val events = ConnectionLog.snapshot() + NativeCore.lastLog().lineSequence().filter(String::isNotBlank)
        return events.joinToString("\n").ifBlank { "No connection events yet" }
    }

    private fun showScannerSheet() {
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
        sheet.addView(label("Scanner options", 22f, INK, TypefaceStyle.MEDIUM))
        sheet.addView(label("Choose address families for endpoint discovery", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(4); bottomMargin = dp(20) })
        ScanTarget.entries.forEachIndexed { index, target ->
            sheet.addView(createScannerOption(target, dialog), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(68),
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

    private fun createScannerOption(target: ScanTarget, dialog: Dialog): LinearLayout {
        val selected = target == defaultScan()
        return LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            background = roundedBackground(
                if (selected) PRIMARY_CONTAINER else SURFACE_VARIANT,
                18,
                if (selected) PRIMARY else SURFACE_VARIANT,
            )
            contentDescription = "Scan ${target.label} endpoints"
            isClickable = true
            isFocusable = true
            setOnClickListener {
                getSharedPreferences(SETTINGS, MODE_PRIVATE).edit().putString(DEFAULT_SCAN, target.coreName).apply()
                scanValue.text = target.label
                scannerSelector.contentDescription = "Scanner options, ${target.label}"
                dialog.dismiss()
            }
            val labels = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
            labels.addView(label(target.label, 16f, INK, TypefaceStyle.MEDIUM))
            labels.addView(label(target.description, 13f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
            addView(labels, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            if (selected) addView(label("SELECTED", 11f, PRIMARY, TypefaceStyle.MEDIUM).apply {
                letterSpacing = 0.08f
            })
        }
    }

    private fun showModeSheet() {
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
        sheet.addView(label("Connection mode", 22f, INK, TypefaceStyle.MEDIUM))
        sheet.addView(label("Choose how Aethery connects", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(4); bottomMargin = dp(20) })
        Protocol.entries.forEachIndexed { index, protocol ->
            sheet.addView(createModeOption(protocol, dialog), LinearLayout.LayoutParams(
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

    private fun showSettingsPage() {
        showingSettings = true
        val page = FrameLayout(this).apply { setBackgroundColor(CANVAS) }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), 0, dp(24), dp(24))
        }
        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(label("‹", 40f, INK).apply {
                gravity = Gravity.CENTER
                contentDescription = "Back"
                isClickable = true
                isFocusable = true
                setOnClickListener { showMainPage() }
            }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(label("Settings", 22f, INK, TypefaceStyle.MEDIUM), LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f,
            ))
        }
        content.addView(header)
        content.addView(label("Version ${appVersion()}", 14f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(48); topMargin = dp(-8); bottomMargin = dp(36) })
        content.addView(label("DEFAULT PROTOCOL", 12f, MUTED).apply { letterSpacing = 0.1f })
        Protocol.entries.forEachIndexed { index, protocol ->
            content.addView(createDefaultProtocolOption(protocol), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(76),
            ).apply { topMargin = if (index == 0) dp(16) else dp(12) })
        }
        content.addView(label("CORE SOCKS PORT", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(28) })
        val portField = EditText(this).apply {
            setText(socksPort().toString())
            setTextColor(INK)
            setHintTextColor(MUTED)
            textSize = 16f
            inputType = InputType.TYPE_CLASS_NUMBER
            setSingleLine(true)
            setSelectAllOnFocus(false)
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), 0, dp(12), 0)
            background = roundedBackground(SURFACE_VARIANT, 16, SURFACE_VARIANT)
            contentDescription = "Core SOCKS port"
        }
        val portRow = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            addView(portField, LinearLayout.LayoutParams(0, dp(52), 1f))
            addView(createSettingsButton("Apply") { applySocksPort(portField) }, LinearLayout.LayoutParams(
                dp(92),
                dp(52),
            ).apply { leftMargin = dp(10) })
        }
        content.addView(portRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })
        content.addView(label("Used by Aether's local SOCKS listener; Android VPN/TUN routes do not use this port.", 12f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(6) })
        page.addView(content, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply {
            leftMargin = dp(24)
            rightMargin = dp(24)
            topMargin = dp(16)
        })
        page.setOnApplyWindowInsetsListener { _, insets ->
            (content.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(16)
                content.layoutParams = this
            }
            insets
        }
        setContentView(page)
    }

    private fun showMainPage() {
        showingSettings = false
        setContentView(mainRoot)
    }

    private fun openSettingsScreen(animate: Boolean = true) {
        showingSettings = true
        settingsPage?.let(pageHost::removeView)

        val page = FrameLayout(this).apply { setBackgroundColor(CANVAS) }
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(label("‹", 40f, INK).apply {
                gravity = Gravity.START or Gravity.CENTER_VERTICAL
                contentDescription = "Back"
                isClickable = true
                isFocusable = true
                setOnClickListener { closeSettingsScreen() }
            }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(label("Settings", 22f, INK, TypefaceStyle.MEDIUM))
        }
        content.addView(header)
        content.addView(label("DEFAULT PROTOCOL", 12f, MUTED).apply { letterSpacing = 0.1f })
        Protocol.entries.forEachIndexed { index, protocol ->
            content.addView(createDefaultProtocolOption(protocol), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(76),
            ).apply { topMargin = if (index == 0) dp(16) else dp(12) })
        }
        content.addView(label("CORE SOCKS PORT", 12f, MUTED).apply { letterSpacing = 0.1f }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(28) })
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
            addView(portField, LinearLayout.LayoutParams(0, dp(52), 1f))
            addView(createSettingsButton("Apply") { applySocksPort(portField) }, LinearLayout.LayoutParams(
                dp(92),
                dp(52),
            ).apply { leftMargin = dp(10) })
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(10) })
        content.addView(label("Used by Aether's local SOCKS listener; Android VPN/TUN routes do not use this port.", 12f, MUTED), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(6) })
        page.addView(content, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply {
            leftMargin = dp(24)
            rightMargin = dp(24)
            topMargin = dp(16)
        })

        val footer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(label("Version ${appVersion()}", 14f, MUTED))
            addView(createSettingsButton("Check for updates") {
                openLink("https://github.com/ZethRise/Aethery/releases/latest")
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(52),
            ).apply { topMargin = dp(12) })
            addView(createSettingsButton("Aethery on GitHub", R.drawable.ic_github) {
                openLink("https://github.com/ZethRise/Aethery")
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(52),
            ).apply { topMargin = dp(10) })
        }
        page.addView(footer, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
            Gravity.BOTTOM,
        ).apply {
            leftMargin = dp(24)
            rightMargin = dp(24)
            bottomMargin = dp(24)
        })
        page.setOnApplyWindowInsetsListener { _, insets ->
            (content.layoutParams as FrameLayout.LayoutParams).apply {
                topMargin = insets.systemWindowInsetTop + dp(16)
                content.layoutParams = this
            }
            (footer.layoutParams as FrameLayout.LayoutParams).apply {
                bottomMargin = insets.systemWindowInsetBottom + dp(24)
                footer.layoutParams = this
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
            page.alpha = 0f
            page.translationX = dp(32).toFloat()
            mainRoot.animate().alpha(0.65f).translationX(-dp(12).toFloat())
                .setDuration(PAGE_ANIMATION_MS).setInterpolator(DecelerateInterpolator()).start()
            page.animate().alpha(1f).translationX(0f)
                .setDuration(PAGE_ANIMATION_MS).setInterpolator(DecelerateInterpolator()).start()
        }
    }

    private fun closeSettingsScreen() {
        showingSettings = false
        val page = settingsPage ?: return
        page.animate().alpha(0f).translationX(dp(32).toFloat())
            .setDuration(PAGE_ANIMATION_MS).setInterpolator(DecelerateInterpolator())
            .withEndAction {
                pageHost.removeView(page)
                settingsPage = null
            }.start()
        mainRoot.animate().alpha(1f).translationX(0f)
            .setDuration(PAGE_ANIMATION_MS).setInterpolator(DecelerateInterpolator()).start()
    }

    override fun onBackPressed() {
        if (showingSettings) closeSettingsScreen() else super.onBackPressed()
    }

    private fun createDefaultProtocolOption(protocol: Protocol): LinearLayout {
        val selected = protocol == defaultProtocol()
        return LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            background = roundedBackground(
                if (selected) PRIMARY_CONTAINER else SURFACE_VARIANT,
                18,
                if (selected) PRIMARY else SURFACE_VARIANT,
            )
            isClickable = true
            isFocusable = true
            contentDescription = "Set ${protocol.label} as default"
            setOnClickListener {
                getSharedPreferences(SETTINGS, MODE_PRIVATE).edit().putString(DEFAULT_PROTOCOL, protocol.coreName).apply()
                selectedProtocol = protocol
                modeValue.text = protocol.label
                modeSelector.contentDescription = "Connection mode, ${protocol.label}"
                openSettingsScreen(animate = false)
            }
            addView(label(protocol.label, 16f, INK, TypefaceStyle.MEDIUM), LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f,
            ))
            if (selected) addView(label("DEFAULT", 11f, PRIMARY, TypefaceStyle.MEDIUM).apply {
                letterSpacing = 0.08f
            })
        }
    }

    private fun createModeOption(protocol: Protocol, dialog: Dialog): LinearLayout {
        val selected = protocol == selectedProtocol
        return LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(18), 0, dp(18), 0)
            background = roundedBackground(
                if (selected) PRIMARY_CONTAINER else SURFACE_VARIANT,
                18,
                if (selected) PRIMARY else SURFACE_VARIANT,
            )
            contentDescription = "Use ${protocol.label} mode"
            isClickable = protocol.androidAvailable
            isFocusable = protocol.androidAvailable
            alpha = if (protocol.androidAvailable) 1f else DISABLED_ALPHA
            setOnClickListener {
                if (!protocol.androidAvailable) return@setOnClickListener
                selectedProtocol = protocol
                modeValue.text = protocol.label
                modeSelector.contentDescription = "Connection mode, ${protocol.label}"
                dialog.dismiss()
            }
            val texts = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL }
            texts.addView(label(protocol.label, 16f, INK, TypefaceStyle.MEDIUM))
            texts.addView(label(protocol.description, 13f, MUTED), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
            addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            if (selected) addView(label("CURRENT", 11f, PRIMARY, TypefaceStyle.MEDIUM).apply {
                letterSpacing = 0.08f
            }) else if (!protocol.androidAvailable) addView(label("DESKTOP ONLY", 11f, MUTED, TypefaceStyle.MEDIUM).apply {
                letterSpacing = 0.08f
            })
        }
    }

    private fun toggleTunnel() {
        if (NativeCore.isRunning()) {
            startService(Intent(this, AetherVpnService::class.java).setAction(AetherVpnService.ACTION_DISCONNECT))
            showDisconnected("Disconnecting")
            return
        }

        val config = configJson()
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
            .putExtra(AetherVpnService.EXTRA_CONFIG, config))
    }

    private fun configJson(): String = org.json.JSONObject().apply {
        put("config_path", File(filesDir, "aether.toml").absolutePath)
        put("protocol", selectedProtocol.coreName)
        put("listen", "127.0.0.1:${socksPort()}")
        put("scan_mode", "balanced")
        put("ip_scan", defaultScan().coreName)
    }.toString()

    private fun renderStatus() {
        if (!NativeCore.isRunning() && visualState == ConnectionControl.State.CONNECTED) showDisconnected()
    }

    private fun showConnecting() {
        visualState = ConnectionControl.State.CONNECTING
        connectionControl.state = visualState
        connectionTitle.setTextColor(PRIMARY)
        connectionTitle.text = "Connecting"
        connectionDetail.text = "Starting ${selectedProtocol.label} tunnel"
        setModeEnabled(false)
    }

    private fun showConnected() {
        visualState = ConnectionControl.State.CONNECTED
        connectionControl.state = visualState
        connectionTitle.setTextColor(CONNECTED)
        connectionTitle.text = "Connected"
        connectionDetail.text = "${selectedProtocol.label} tunnel is active"
        setModeEnabled(false)
    }

    private fun showFailure(detail: String? = null) {
        visualState = ConnectionControl.State.FAILED
        connectionControl.state = visualState
        connectionTitle.setTextColor(ERROR)
        connectionTitle.text = "Connection failed"
        connectionDetail.text = detail ?: "Check the server and try again"
        setModeEnabled(true)
    }

    private fun showDisconnected(detail: String = "Tap the circle to connect") {
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

    private fun label(
        text: String = "",
        textSize: Float,
        color: Int,
        style: TypefaceStyle = TypefaceStyle.REGULAR,
    ): TextView = TextView(this).apply {
        this.text = text
        this.textSize = textSize
        setTextColor(color)
        typeface = when (style) {
            TypefaceStyle.REGULAR -> android.graphics.Typeface.create("sans", android.graphics.Typeface.NORMAL)
            TypefaceStyle.MEDIUM -> android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL)
        }
    }

    private fun roundedBackground(fill: Int, radius: Int, stroke: Int): GradientDrawable =
        GradientDrawable().apply {
            setColor(fill)
            cornerRadius = dp(radius).toFloat()
            setStroke(dp(1), stroke)
        }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    private fun appVersion(): String =
        packageManager.getPackageInfo(packageName, 0).versionName ?: "Unknown"

    private fun createSettingsButton(
        text: String,
        icon: Int? = null,
        onClick: () -> Unit,
    ): TextView = label(text, 15f, INK, TypefaceStyle.MEDIUM).apply {
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(18), 0, dp(18), 0)
        background = roundedBackground(SURFACE_VARIANT, 16, SURFACE_VARIANT)
        isClickable = true
        isFocusable = true
        contentDescription = text
        icon?.let {
            setCompoundDrawablesRelativeWithIntrinsicBounds(it, 0, 0, 0)
            compoundDrawablePadding = dp(12)
            compoundDrawablesRelative[0]?.setTint(PRIMARY)
        }
        setOnClickListener { onClick() }
    }

    private fun openLink(url: String) {
        runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }

    private fun defaultProtocol(): Protocol {
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE).getString(DEFAULT_PROTOCOL, Protocol.MASQUE.coreName)
        return Protocol.entries.firstOrNull { it.coreName == name } ?: Protocol.MASQUE
    }

    private fun defaultScan(): ScanTarget {
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE).getString(DEFAULT_SCAN, ScanTarget.IPV4.coreName)
        return ScanTarget.entries.firstOrNull { it.coreName == name } ?: ScanTarget.IPV4
    }

    private fun socksPort(): Int = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getInt(DEFAULT_SOCKS_PORT, DEFAULT_SOCKS_PORT_VALUE)

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

    private enum class ScanTarget(
        val label: String,
        val coreName: String,
        val description: String,
    ) {
        IPV4("IPv4", "v4", "Scan IPv4 endpoints only"),
        IPV6("IPv6", "v6", "Scan IPv6 endpoints only"),
        BOTH("Both", "both", "Scan IPv4 and IPv6 endpoints"),
    }

    private enum class TypefaceStyle { REGULAR, MEDIUM }

    private companion object {
        const val VPN_REQUEST = 100
        const val LOG_REFRESH_MS = 750L
        const val PAGE_ANIMATION_MS = 220L
        const val SETTINGS = "settings"
        const val DEFAULT_PROTOCOL = "default_protocol"
        const val DEFAULT_SCAN = "default_scan"
        const val DEFAULT_SOCKS_PORT = "default_socks_port"
        const val DEFAULT_SOCKS_PORT_VALUE = 1819
        const val CANVAS = 0xFF101411.toInt()
        const val SURFACE = 0xFF171C18.toInt()
        const val SURFACE_VARIANT = 0xFF222A24.toInt()
        const val INK = 0xFFE8F1EA.toInt()
        const val MUTED = 0xFFB9C6BB.toInt()
        const val DIVIDER = 0xFF3B473E.toInt()
        const val PRIMARY = 0xFFA4D8BB.toInt()
        const val PRIMARY_CONTAINER = 0xFF1F4030.toInt()
        const val CONNECTED = 0xFF67D89C.toInt()
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

private class ConnectionControl(context: Context) : View(context) {
    enum class State { DISCONNECTED, CONNECTING, CONNECTED, FAILED }

    var state: State = State.DISCONNECTED
        set(value) {
            field = value
            contentDescription = when (value) {
                State.DISCONNECTED, State.FAILED -> "Connect"
                State.CONNECTING -> "Connecting"
                State.CONNECTED -> "Disconnect"
            }
            if (value == State.CONNECTING) startConnectingAnimation() else stopConnectingAnimation()
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
        val desired = dp(176)
        setMeasuredDimension(resolveSize(desired, widthMeasureSpec), resolveSize(desired, heightMeasureSpec))
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val size = min(width, height).toFloat()
        val centerX = width / 2f
        val centerY = height / 2f
        val radius = size / 2f - dp(10) + if (state == State.CONNECTING) dp(3) * pulse else 0f
        val palette = when (state) {
            State.DISCONNECTED, State.CONNECTING -> Palette(PRIMARY_CONTAINER, PRIMARY)
            State.CONNECTED -> Palette(CONNECTED_CONTAINER, CONNECTED)
            State.FAILED -> Palette(ERROR_CONTAINER, ERROR)
        }

        paint.style = Paint.Style.FILL
        paint.color = palette.container
        paint.setShadowLayer(dp(12).toFloat(), 0f, dp(5).toFloat(), 0x44000000)
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
        canvas.drawArc(arcBounds, 42f, 276f, false, paint)
        canvas.drawLine(centerX, centerY - dp(33), centerX, centerY - dp(3), paint)
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
            duration = 1_050
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

    private data class Palette(val container: Int, val accent: Int)

    private companion object {
        const val PRIMARY = 0xFFA4D8BB.toInt()
        const val PRIMARY_CONTAINER = 0xFF1F4030.toInt()
        const val CONNECTED = 0xFF67D89C.toInt()
        const val CONNECTED_CONTAINER = 0xFF123B27.toInt()
        const val ERROR = 0xFFFFB4AB.toInt()
        const val ERROR_CONTAINER = 0xFF4A1E1C.toInt()
    }
}
