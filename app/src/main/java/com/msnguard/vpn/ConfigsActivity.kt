package com.msnguard.vpn

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import kotlin.math.roundToInt

/**
 * The user-config screen: list, paste, edit.
 *
 * A separate activity rather than another page inside MainActivity. MainActivity
 * is already 4,800 lines with eleven in-place pages sharing one back-stack flag
 * per page; adding a twelfth with its own sub-editor would compound that. The
 * cost is that this file re-declares small view helpers, which is why they live
 * in ConfigsUi.kt where both can reach them.
 *
 * Result contract: finishes with RESULT_OK whenever the store changed, so the
 * caller repaints its card without having to diff anything.
 */
class ConfigsActivity : Activity() {

    private val palette by lazy { AppAppearance.load(this) }
    private val handler = Handler(Looper.getMainLooper())

    private lateinit var root: FrameLayout
    private lateinit var listHost: LinearLayout
    private lateinit var emptyState: LinearLayout
    private lateinit var countLabel: TextView

    private var profiles = mutableListOf<ConfigProfile>()
    /** id → row, so a ping result can repaint one row without a full rebuild. */
    private val rows = mutableMapOf<String, ConfigRowView>()
    private var dirty = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setBackgroundDrawableResource(android.R.color.transparent)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
        )
        root = FrameLayout(this).apply { setBackgroundColor(palette.canvas) }
        setContentView(root)
        buildListPage()
        reload()
        // Sweep on open, the same as the reference client: the numbers a user
        // stares at while choosing must be from this session, not last week.
        sweepPings()
    }

    override fun finish() {
        setResult(if (dirty) RESULT_OK else RESULT_CANCELED)
        super.finish()
    }

    // ------------------------------------------------------------------ list

    private fun buildListPage() {
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(backButton { finish() }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(text("My configs", 22f, palette.ink, medium = true), LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f,
            ))
            countLabel = text("", 12f, palette.muted, medium = true)
            addView(countLabel, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { rightMargin = dp(6) })
        }
        content.addView(header)

        content.addView(
            text(
                "Paste a VLESS, VMess, Trojan, Shadowsocks or Hysteria2 link and " +
                    "MSN-GUARD works out the rest. Everything else stays on our tuned defaults.",
                13.5f,
                palette.muted,
            ),
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = dp(48); topMargin = dp(-6); bottomMargin = dp(16) },
        )

        // Two primary actions, side by side. Paste is first and wider: it is the
        // path that will be used ninety-nine times out of a hundred.
        val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        actions.addView(
            primaryButton("Paste from clipboard") { pasteFromClipboard() },
            LinearLayout.LayoutParams(0, dp(48), 2f),
        )
        actions.addView(
            secondaryButton("Ping all") { sweepPings() },
            LinearLayout.LayoutParams(0, dp(48), 1f).apply { leftMargin = dp(8) },
        )
        content.addView(actions, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ))

        content.addView(
            secondaryButton("Add manually") { openEditor(null) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(46)).apply {
                topMargin = dp(8)
            },
        )

        emptyState = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(20), dp(44), dp(20), dp(20))
            addView(text("No configs yet", 16f, palette.ink, medium = true))
            addView(
                text(
                    "Copy a link from your provider, then tap Paste from clipboard.",
                    13f,
                    palette.muted,
                ).apply { gravity = Gravity.CENTER },
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = dp(6) },
            )
        }
        content.addView(emptyState)

        listHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val scroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
            addView(listHost)
        }
        content.addView(scroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            0,
            1f,
        ).apply { topMargin = dp(14) })

        root.addView(content, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ).apply {
            leftMargin = dp(20)
            rightMargin = dp(20)
        })
        applyInsets(content)
    }

    /** Rebuild the rows from the store. */
    private fun reload() {
        profiles = ConfigStore.all(this).toMutableList()
        val activeId = ConfigStore.activeId(this)
        rows.clear()
        listHost.removeAllViews()
        countLabel.text = if (profiles.isEmpty()) "" else "${profiles.size}"
        emptyState.visibility = if (profiles.isEmpty()) View.VISIBLE else View.GONE

        profiles.forEachIndexed { index, profile ->
            val row = ConfigRowView(
                this,
                palette,
                onTap = { activate(profile) },
                onEdit = { openEditor(profile) },
                onDelete = { confirmDelete(profile) },
                onLongPress = { copyToClipboard(profile) },
            )
            row.render(profile, profile.id == activeId, !XrayConfigBuilder.isSupported(profile))
            rows[profile.id] = row
            listHost.addView(row, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = if (index == 0) 0 else dp(8) })
        }
    }

    private fun activate(profile: ConfigProfile) {
        if (!XrayConfigBuilder.isSupported(profile)) {
            toast("${profile.kind.label} needs a core we do not ship yet")
            return
        }
        val problem = profile.validate()
        if (problem != null) {
            toast(problem)
            openEditor(profile)
            return
        }
        ConfigStore.setActive(this, profile.id)
        dirty = true
        reload()
        toast("${profile.displayName()} selected")
    }

    private fun confirmDelete(profile: ConfigProfile) {
        // No dialog: the row is gone and the toast offers the undo. A modal for
        // every delete makes clearing a stale subscription of thirty entries a
        // sixty-tap chore.
        val removed = profile
        ConfigStore.remove(this, profile.id)
        dirty = true
        reload()
        toast("Deleted ${removed.displayName()}")
    }

    /** Put the profile back on the clipboard as a shareable link. */
    private fun copyToClipboard(profile: ConfigProfile) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        if (clipboard == null) {
            toast("Clipboard unavailable")
            return
        }
        clipboard.setPrimaryClip(
            android.content.ClipData.newPlainText("config", ConfigParser.toUri(profile)),
        )
        toast("Link copied")
    }

    /**
     * Read the clipboard, parse everything in it, report honestly.
     *
     * Android 10+ only hands the clipboard to a focused app, which this is —
     * called from a button tap. A null clip therefore means the clipboard really
     * is empty, not that we were blocked.
     */
    private fun pasteFromClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val raw = clipboard?.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(this)
            ?.toString()
            .orEmpty()
        if (raw.isBlank()) {
            toast("Clipboard is empty")
            return
        }
        val batch = ConfigParser.parseMany(raw)
        if (batch.profiles.isEmpty()) {
            toast("Nothing recognisable in the clipboard")
            return
        }
        ConfigStore.addAll(this, batch.profiles)
        // First config ever added becomes the active one: the user pasted it in
        // order to use it, and making them tap it again teaches nothing.
        if (ConfigStore.activeId(this) == null) {
            batch.profiles.firstOrNull { XrayConfigBuilder.isSupported(it) }
                ?.let { ConfigStore.setActive(this, it.id) }
        }
        dirty = true
        reload()
        val message = buildString {
            append("Added ${batch.profiles.size}")
            if (batch.failures.isNotEmpty()) append(", skipped ${batch.failures.size} unreadable")
        }
        toast(message)
        sweepPings()
    }

    /** Measure every profile, painting each result as it arrives. */
    private fun sweepPings() {
        if (profiles.isEmpty()) return
        ConfigPinger.invalidate()
        val activeId = ConfigStore.activeId(this)
        profiles.forEach { rows[it.id]?.setMeasuring() }
        ConfigPinger.pingAll(
            profiles,
            post = { block -> handler.post(block) },
            onEach = { id, ms ->
                ConfigStore.recordPing(this, id, ms)
                val profile = profiles.firstOrNull { it.id == id } ?: return@pingAll
                profile.lastPingMs = ms
                rows[id]?.render(profile, id == activeId, !XrayConfigBuilder.isSupported(profile))
                dirty = true
            },
        )
    }

    // ---------------------------------------------------------------- editor

    /**
     * The full field editor — the pencil from the reference screenshot.
     *
     * Every field the reference exposes is here, including `finalMask` and
     * `Cipher Suites`, because a power user's config is worthless if one of its
     * fields cannot be corrected. This is the ONLY screen in the app with this
     * density, and it is behind a per-row pencil, so the ordinary user never
     * meets it.
     *
     * [existing] null means a new manual entry.
     */
    private fun openEditor(existing: ConfigProfile?) {
        val editing = existing ?: ConfigProfile.blank(ConfigProfile.Kind.VLESS)
        val page = FrameLayout(this).apply {
            setBackgroundColor(palette.canvas)
            isClickable = true
        }
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        val fields = mutableMapOf<String, EditText>()
        fun field(
            key: String,
            labelText: String,
            value: String,
            multiline: Boolean = false,
            numeric: Boolean = false,
        ) {
            content.addView(
                text(labelText, 11f, palette.muted).apply { letterSpacing = 0.06f },
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = dp(12); bottomMargin = dp(5) },
            )
            val input = EditText(this).apply {
                setText(value)
                setTextColor(palette.ink)
                setHintTextColor(palette.faint)
                textSize = 14.5f
                inputType = when {
                    numeric -> InputType.TYPE_CLASS_NUMBER
                    multiline -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
                    else -> InputType.TYPE_CLASS_TEXT
                }
                setSingleLine(!multiline)
                if (multiline) {
                    maxLines = 6
                    gravity = Gravity.TOP
                }
                setPadding(dp(16), dp(12), dp(16), dp(12))
                background = Sculpt.sculptedBackground(
                    resources.displayMetrics.density,
                    palette.surfaceVariant,
                    14,
                    stroke = palette.divider,
                )
                typeface = if (multiline) {
                    Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
                } else {
                    Typeface.create("sans", Typeface.NORMAL)
                }
            }
            fields[key] = input
            content.addView(input, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                if (multiline) dp(108) else dp(50),
            ))
        }

        val header = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            addView(backButton { root.removeView(page) }, LinearLayout.LayoutParams(dp(48), dp(56)))
            addView(
                text(editing.kind.label, 22f, palette.ink, medium = true),
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
            )
        }
        content.addView(header)

        // Protocol first, and changeable: a manual entry has to be able to say
        // what it is, and a mis-detected paste has to be fixable.
        var kind = editing.kind
        lateinit var kindRow: OrbitSettingsRow
        kindRow = OrbitSettingsRow(this, palette, "Protocol", kind.label) {
            showKindPicker(kind) { chosen ->
                kind = chosen
                kindRow.setValue(chosen.label)
            }
        }
        content.addView(kindRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(4) })

        field("remarks", "remarks", editing.remarks)
        field("server", "address", editing.server)
        field("port", "port", editing.port, numeric = true)
        field("credential", editing.kind.credentialLabel, editing.credential)
        field("encryption", "encryption", editing.encryption)
        field("flow", "flow", editing.flow)
        field("network", "network  (tcp · ws · grpc · httpupgrade · h2)", editing.network)
        field("host", "host header / authority", editing.host)
        field("path", "path / serviceName", editing.path)
        field("finalMask", "finalMask   raw JSON: { FinalMaskObject }", editing.finalMask, multiline = true)
        field("security", "security  (none · tls · reality)", editing.security)
        field("sni", "SNI", editing.sni)
        field("fingerprint", "fingerprint  (chrome · firefox · safari · unsafe)", editing.fingerprint)
        field("alpn", "ALPN", editing.alpn)

        var allowInsecure = editing.allowInsecure
        val insecureRow = OrbitToggleRow(
            this,
            palette,
            "allowInsecure",
            "Accept a certificate that does not verify",
            allowInsecure,
        ) { allowInsecure = it }
        content.addView(insecureRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(12) })

        field("publicKey", "REALITY publicKey", editing.publicKey)
        field("shortId", "REALITY shortId", editing.shortId)
        field("spiderX", "REALITY spiderX", editing.spiderX)
        field("cipherSuites", "Cipher Suites", editing.cipherSuites, multiline = true)
        field("echConfigList", "echConfigList", editing.echConfigList)
        field("pinnedPeerName", "Verify peer certificate by name", editing.pinnedPeerName)
        field("certFingerprint", "Certificate fingerprint (SHA-256)", editing.certFingerprint)

        content.addView(
            primaryButton("Save") {
                fun value(key: String) = fields[key]?.text?.toString()?.trim().orEmpty()
                val updated = editing.copy(kind = kind).apply {
                    remarks = value("remarks")
                    server = value("server")
                    port = value("port")
                    credential = value("credential")
                    encryption = value("encryption")
                    flow = value("flow")
                    network = value("network").ifBlank { "tcp" }
                    host = value("host")
                    path = value("path")
                    security = value("security")
                    sni = value("sni")
                    fingerprint = value("fingerprint")
                    alpn = value("alpn")
                    this.allowInsecure = allowInsecure
                    publicKey = value("publicKey")
                    shortId = value("shortId")
                    spiderX = value("spiderX")
                    finalMask = value("finalMask")
                    cipherSuites = value("cipherSuites")
                    echConfigList = value("echConfigList")
                    pinnedPeerName = value("pinnedPeerName")
                    certFingerprint = value("certFingerprint")
                    // A saved edit invalidates the old measurement: the user may
                    // have just changed the address.
                    lastPingMs = if (server == editing.server && port == editing.port) {
                        editing.lastPingMs
                    } else {
                        ConfigProfile.PING_UNKNOWN
                    }
                }
                val problem = updated.validate()
                if (problem != null) {
                    toast(problem)
                    return@primaryButton
                }
                ConfigStore.upsert(this, updated)
                dirty = true
                root.removeView(page)
                reload()
                ConfigPinger.ping(
                    updated,
                    post = { block -> handler.post(block) },
                ) { ms ->
                    ConfigStore.recordPing(this, updated.id, ms)
                    updated.lastPingMs = ms
                    rows[updated.id]?.render(
                        updated,
                        updated.id == ConfigStore.activeId(this),
                        !XrayConfigBuilder.isSupported(updated),
                    )
                }
            },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(50)).apply {
                topMargin = dp(20)
                bottomMargin = dp(28)
            },
        )

        val scroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
            addView(content)
        }
        page.addView(scroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ).apply { leftMargin = dp(20); rightMargin = dp(20) })
        root.addView(page)
        applyInsets(scroll)
    }

    private fun showKindPicker(current: ConfigProfile.Kind, onPick: (ConfigProfile.Kind) -> Unit) {
        val sheet = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(20))
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density, palette.surface, 24,
                stroke = palette.divider,
            )
        }
        val dialog = android.app.Dialog(this).apply {
            requestWindowFeature(android.view.Window.FEATURE_NO_TITLE)
        }
        sheet.addView(text("Protocol", 18f, palette.ink, medium = true))
        ConfigProfile.Kind.entries.forEach { entry ->
            sheet.addView(
                OrbitSettingsRow(
                    this,
                    palette,
                    entry.label,
                    if (entry == current) "current" else null,
                ) {
                    onPick(entry)
                    dialog.dismiss()
                },
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = dp(8) },
            )
        }
        dialog.setContentView(sheet)
        dialog.window?.apply {
            setBackgroundDrawableResource(android.R.color.transparent)
            setLayout(
                (resources.displayMetrics.widthPixels * 0.9f).toInt(),
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }
        dialog.show()
    }

    // --------------------------------------------------------------- helpers

    /**
     * Pad for the status and navigation bars.
     *
     * FLAG_LAYOUT_NO_LIMITS is set so the canvas colour reaches the screen
     * edges; without this the header would sit under the clock.
     */
    private fun applyInsets(target: View) {
        target.setOnApplyWindowInsetsListener { view, insets ->
            view.setPadding(
                view.paddingLeft,
                insets.systemWindowInsetTop + dp(8),
                view.paddingRight,
                insets.systemWindowInsetBottom + dp(8),
            )
            insets
        }
        target.requestApplyInsets()
    }

    private fun text(
        value: String,
        size: Float,
        color: Int,
        medium: Boolean = false,
    ): TextView = TextView(this).apply {
        this.text = value
        textSize = size
        setTextColor(color)
        typeface = if (medium) {
            Typeface.create("sans-serif-medium", Typeface.NORMAL)
        } else {
            Typeface.create("sans", Typeface.NORMAL)
        }
    }

    private fun primaryButton(caption: String, onClick: () -> Unit): TextView =
        text(caption, 15f, palette.primaryContainer, medium = true).apply {
            gravity = Gravity.CENTER
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density, palette.primary, 16,
                accent = Sculpt.lighten(palette.primary, 0.3f),
            )
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick() }
        }

    private fun secondaryButton(caption: String, onClick: () -> Unit): TextView =
        text(caption, 14f, palette.ink, medium = true).apply {
            gravity = Gravity.CENTER
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density, palette.surfaceVariant, 16,
                stroke = palette.divider,
            )
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick() }
        }

    private fun backButton(onClick: () -> Unit): TextView =
        text("‹", 30f, palette.ink, medium = true).apply {
            gravity = Gravity.CENTER
            isClickable = true
            isFocusable = true
            contentDescription = "Back"
            setOnClickListener { onClick() }
        }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    companion object {
        fun intent(context: Context): Intent = Intent(context, ConfigsActivity::class.java)
    }
}
