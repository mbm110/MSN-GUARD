package com.msnguard.vpn

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.text.TextUtils
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * Exit-node card: flag, IP readout, location line, live trace.
 *
 * The IP text is monospace with a fixed max width so a 39-character IPv6
 * literal cannot push the card taller or shove the transport rail off screen.
 * Shortening is delegated to [IpFormatter]; this view only picks a font step.
 *
 * The trailing graphic is a [SparkLineView] — a 1.6dp green polyline with a soft
 * fill, as in the approved mock. It used to be [MicroBarsView], which drew thick
 * columns and looked nothing like the preview.
 */
class ExitNodeCard(
    context: Context,
    private val palette: AppAppearance.Palette,
    onClick: () -> Unit,
) : LinearLayout(context) {

    private val flagView: TextView
    private val keyView: TextView
    private val ipView: TextView
    private val locView: TextView
    private val spark: SparkLineView

    private fun px(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    private fun text(
        value: String,
        size: Float,
        color: Int,
        medium: Boolean = false,
        mono: Boolean = false,
        spacing: Float = 0f,
    ): TextView = TextView(context).apply {
        text = value
        textSize = size
        setTextColor(color)
        letterSpacing = spacing
        typeface = when {
            mono -> Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
            medium -> Typeface.create("sans-serif-medium", Typeface.NORMAL)
            else -> Typeface.create("sans", Typeface.NORMAL)
        }
    }

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        val fill = Sculpt.blend(palette.surface, palette.ink, 0.03f)
        background = Sculpt.sculptedRipple(
            resources.displayMetrics.density, fill, 22, palette.primary,
            accent = Sculpt.withAlpha(palette.ink, 0.09f),
        )
        setPadding(px(13), px(11), px(15), px(11))
        isClickable = true
        isFocusable = true
        setOnClickListener {
            performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
            onClick()
        }

        // Flag sits in its own sculpted tile so an emoji-less device still shows
        // a visible slot rather than a hole in the layout.
        flagView = text("\uD83C\uDF10", 19f, palette.ink).apply {
            gravity = Gravity.CENTER
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density,
                Sculpt.darken(palette.surface, 0.12f),
                14,
                Sculpt.withAlpha(palette.ink, 0.10f),
            )
        }
        addView(flagView, LayoutParams(px(42), px(42)))

        val column = LinearLayout(context).apply { orientation = VERTICAL }
        keyView = text("EXIT NODE", 8.5f, Sculpt.withAlpha(palette.faint, 0.95f), medium = true, spacing = 0.14f)
        ipView = text("not tunnelled", 15f, palette.ink, medium = true, mono = true).apply {
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.END
        }
        locView = text("tap to refresh", 10.5f, Sculpt.withAlpha(palette.faint, 0.9f))
        column.addView(keyView)
        column.addView(ipView, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = px(2) })
        column.addView(locView, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = px(1) })
        addView(column, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            leftMargin = px(12)
        })

        spark = SparkLineView(context, palette.mint).apply { seed() }
        addView(spark, LayoutParams(px(52), px(24)))
    }

    /**
     * @param address raw address as reported by the trace endpoint; may be v4 or v6
     * @param countryCode two-letter code, or null/blank when unknown
     * @param tunnelled true when the tunnel is up, which changes the caption
     */
    fun render(
        address: String,
        countryCode: String?,
        tunnelled: Boolean,
        measuring: Boolean = false,
    ) {
        keyView.text = if (tunnelled) "EXIT NODE" else "YOUR IP"
        if (address.isBlank() || address == UNAVAILABLE) {
            // On the native path the exit address comes from the core, measured
            // inside the tunnel, and arrives a second or two after connect. Saying
            // "unavailable, tap to retry" there invites the user to retry
            // something that is simply not finished — and tapping cannot speed it
            // up, because this process has no route into the tunnel.
            if (measuring) {
                ipView.text = MEASURING
                ipView.textSize = 13f
                locView.text = "reading from inside the tunnel"
                flagView.text = "\uD83C\uDF10"
                contentDescription = "Measuring the tunnel exit address"
                return
            }
            ipView.text = UNAVAILABLE
            ipView.textSize = 15f
            locView.text = "tap to retry"
            flagView.text = "\uD83C\uDF10"
            contentDescription = "IP unavailable, tap to retry"
            return
        }
        val fit = IpFormatter.fit(address)
        ipView.text = fit.text
        ipView.textSize = when (fit.step) {
            IpFormatter.Step.V4 -> 15f
            IpFormatter.Step.V6 -> 12.5f
            IpFormatter.Step.V6_LONG -> 11f
        }
        flagView.text = IpFormatter.flag(countryCode)
        val country = countryCode?.trim()?.uppercase().orEmpty()
        // Country only — city was explicitly not wanted, and the trace endpoint
        // does not return one anyway.
        locView.text = when {
            country.isNotEmpty() && tunnelled -> "$country · tunnelled"
            country.isNotEmpty() -> country
            tunnelled -> "tunnelled"
            else -> "not tunnelled"
        }
        // Accessibility reads the full address; the visual is the shortened one.
        contentDescription = "${keyView.text}: ${fit.full}${if (country.isNotEmpty()) ", $country" else ""}"
    }

    fun pushSample(value: Float) = spark.push(value)

    fun resetSpark() = spark.reset()

    private companion object {
        const val UNAVAILABLE = "IP unavailable"
        const val MEASURING = "measuring…"
    }
}

/**
 * Bottom action bar: LOG / SPLIT / SCAN MODE.
 *
 * Each entry is a sculpted pill with a vector glyph above its caption, and each
 * one sinks on press (the inner shadow moves to the top edge) rather than only
 * flashing a ripple.
 */
class OrbitActionBar(
    context: Context,
    private val palette: AppAppearance.Palette,
    entries: List<Entry>,
) : LinearLayout(context) {

    data class Entry(val caption: String, val glyph: Glyph, val onClick: () -> Unit)

    enum class Glyph { LOG, SPLIT, SCAN }

    private fun px(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    init {
        orientation = HORIZONTAL
        val density = resources.displayMetrics.density
        val fill = Sculpt.blend(palette.surface, palette.ink, 0.025f)
        entries.forEachIndexed { index, entry ->
            val cell = object : FrameLayout(context) {
                override fun setPressed(pressed: Boolean) {
                    super.setPressed(pressed)
                    background = Sculpt.sculptedBackground(
                        density,
                        if (pressed) Sculpt.darken(fill, 0.10f) else fill,
                        18,
                        accent = Sculpt.withAlpha(
                            if (pressed) palette.primary else palette.ink,
                            if (pressed) 0.35f else 0.085f,
                        ),
                        pressed = pressed,
                    )
                }
            }.apply {
                background = Sculpt.sculptedBackground(
                    density, fill, 18,
                    accent = Sculpt.withAlpha(palette.ink, 0.085f),
                )
                isClickable = true
                isFocusable = true
                contentDescription = entry.caption
                setOnClickListener {
                    performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
                    entry.onClick()
                }
            }
            val stack = LinearLayout(context).apply {
                orientation = VERTICAL
                gravity = Gravity.CENTER
            }
            stack.addView(GlyphView(context, entry.glyph, palette.muted), LayoutParams(px(19), px(19)))
            stack.addView(TextView(context).apply {
                text = entry.caption
                textSize = 8.5f
                setTextColor(Sculpt.withAlpha(palette.muted, 0.95f))
                letterSpacing = 0.11f
                typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
                setSingleLine(true)
                ellipsize = TextUtils.TruncateAt.END
                gravity = Gravity.CENTER
            }, LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = px(5) })
            cell.addView(stack, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER,
            ))
            addView(cell, LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f).apply {
                leftMargin = if (index == 0) 0 else px(9)
            })
        }
    }
}

/**
 * The over-WARP button: a full-width chained-shield card.
 *
 * A separate control rather than a fifth cell on the transport rail, because it
 * is not a fifth transport — it wraps the selected transport in a WARP tunnel. It
 * is therefore only meaningful on the two transports that can be wrapped
 * (PSIPHON and TOR), and is shown disabled on MASQUE / WireGuard / WoW rather
 * than hidden, so the feature stays discoverable and its precondition is obvious.
 *
 * The inner transport's name is set from outside via [setInner], because which
 * one is being wrapped depends on the rail's selection and this view has no
 * business knowing the transport list.
 *
 * Dimmed and outlined when off, lit with the violet accent and a "CHAINED" badge
 * when armed.
 */
class ChainModeCard(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val onToggle: (Boolean) -> Unit,
) : LinearLayout(context) {

    private val titleView: TextView
    private val subtitleView: TextView
    private val badgeView: TextView
    private val icon: ChainGlyphView
    private var armed = false
    /** Why the card is unavailable, shown in place of the normal subtitle. */
    private var unavailableReason: String? = null

    /** The transport being wrapped, for every string this card shows. */
    private var innerName: String = "PSIPHON"

    /**
     * Whether the chain can apply to the selected transport at all.
     *
     * Separate from [unavailableReason] because "cannot be changed right now" and
     * "does not apply to this transport" are different facts and were being
     * conflated. Connected-on-Psiphon is not applicable=false — the chain is
     * actively carrying traffic — it is merely locked, so the card must still show
     * CHAINED rather than N/A.
     */
    private var applicable = false
    /**
     * How the outer transport is chosen, as words for the armed subtitle.
     *
     * Set from settings, not here: the card shows the choice, the settings row makes
     * it. Keeping the string rather than the enum keeps this view free of any
     * knowledge of the transports themselves.
     */
    private var outerSummary: String = "auto transport"

    private fun px(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        // Vertical padding only pads within the fixed height the parent gives this
        // card, which matches the action bar's dp(56). Do not add height here.
        setPadding(px(13), px(6), px(14), px(6))
        isClickable = true
        isFocusable = true
        setOnClickListener {
            // A disabled card must not toggle. isEnabled=false already blocks the
            // click on most devices, but a focus-based tap (TV remote, keyboard)
            // can still deliver one, and silently flipping state there would leave
            // the card and the config disagreeing.
            if (!isEnabled) return@setOnClickListener
            performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
            setArmed(!armed)
            onToggle(armed)
        }

        icon = ChainGlyphView(context, palette.violet)
        addView(icon, LayoutParams(px(34), px(34)))

        val column = LinearLayout(context).apply { orientation = VERTICAL }
        titleView = TextView(context).apply {
            text = "PSIPHON OVER WARP"
            textSize = 11f
            letterSpacing = 0.1f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            setSingleLine(true)
        }
        subtitleView = TextView(context).apply {
            textSize = 9.5f
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.END
        }
        column.addView(titleView)
        column.addView(subtitleView, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = px(1) })
        addView(column, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            leftMargin = px(11)
        })

        badgeView = TextView(context).apply {
            textSize = 8.5f
            letterSpacing = 0.12f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            setPadding(px(9), px(4), px(9), px(4))
        }
        addView(badgeView, LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ))

        setArmed(false)
    }

    /**
     * Marks the card unavailable and says why in the subtitle.
     *
     * @param reason shown instead of the usual subtitle; null means available.
     * @param applicable whether the chain applies to the selected transport at all.
     *   Defaults to `reason == null` so existing single-argument calls keep their
     *   old meaning. Pass true with a non-null reason for "applies, but locked" —
     *   which is what being connected on Psiphon is.
     */
    fun setUnavailable(reason: String?, applicable: Boolean = reason == null) {
        unavailableReason = reason
        this.applicable = applicable
        isEnabled = reason == null
        setArmed(armed)
    }

    /**
     * Names the transport this card wraps, e.g. "PSIPHON" or "TOR".
     *
     * Drives the title, the armed subtitle and the accessibility text together, so
     * a card reading "PSIPHON OVER WARP" can never appear while the rail has Tor
     * selected. Repaints immediately for the same reason [setOuterSummary] does.
     */
    fun setInner(name: String) {
        innerName = name.uppercase()
        titleView.text = "$innerName OVER WARP"
        setArmed(armed)
    }

    /**
     * The inner transport as prose: "Psiphon", "Tor".
     *
     * [innerName] is stored upper-cased for the title, which is shouting in a
     * sentence, so it is title-cased here rather than at every use site.
     */
    private fun innerLabel(): String =
        innerName.take(1) + innerName.drop(1).lowercase()

    /** Description of what the chain does, shown when armed. */
    private fun armedSubtitle(): String = "armed · ${innerLabel()} inside WARP, $outerSummary"

    /**
     * Says how the outer transport is chosen, e.g. "auto transport" or "via WoW".
     *
     * Repaints immediately so the card cannot disagree with the settings row that
     * just changed it.
     */
    fun setOuterSummary(summary: String) {
        outerSummary = summary
        setArmed(armed)
    }

    /** Paints the armed/disarmed look. Does not notify [onToggle]. */
    fun setArmed(value: Boolean) {
        armed = value
        val available = unavailableReason == null
        // Lit means "the chain is on and it applies here" — NOT "the card is
        // interactive". Those were the same expression, so a live chained tunnel
        // (locked while connected) went dark and showed N/A, claiming the feature
        // did not apply while it was carrying every packet.
        val lit = value && applicable
        val density = resources.displayMetrics.density
        val fill = if (lit) {
            Sculpt.blend(palette.surface, palette.violet, 0.16f)
        } else {
            Sculpt.blend(palette.surface, palette.ink, 0.02f)
        }
        background = Sculpt.sculptedRipple(
            density, fill, 18, palette.violet,
            accent = Sculpt.withAlpha(
                if (lit) palette.violet else palette.ink,
                if (lit) 0.45f else 0.085f,
            ),
        )
        titleView.setTextColor(if (lit) palette.ink else palette.muted)
        // What it changes, not a speed claim. Chaining measured slower than either
        // layer alone on a clean network (0.23s vs 0.32s latency, same protocol
        // both sides), but on a filtered carrier Psiphon alone is pushed onto
        // domain-fronted CDN paths whose latency is far worse — so inside WARP it
        // can be the faster of the two. "Slower" was true of the lab and wrong in
        // the field, so the label states the effect that always holds.
        subtitleView.text = unavailableReason ?: if (value) {
            armedSubtitle()
        } else {
            "for when neither exit IP is accepted"
        }
        subtitleView.setTextColor(Sculpt.withAlpha(palette.faint, 0.95f))
        badgeView.text = when {
            // N/A means "does not apply to this transport", so it must not appear
            // merely because the card is locked. While connected on Psiphon the
            // chain is live, and the badge has to keep saying so.
            !applicable -> "N/A"
            value -> "CHAINED"
            else -> "OFF"
        }
        badgeView.setTextColor(if (lit) palette.violet else palette.faint)
        badgeView.background = Sculpt.sculptedBackground(
            density,
            if (lit) Sculpt.withAlpha(palette.violet, 0.16f) else Sculpt.darken(palette.surface, 0.16f),
            999,
            Sculpt.withAlpha(if (lit) palette.violet else palette.ink, if (lit) 0.4f else 0.10f),
        )
        icon.setLinked(lit)
        val label = innerLabel()
        contentDescription = when {
            // Mirrors the badge exactly: N/A only when the chain does not apply.
            !applicable -> "$label over WARP unavailable: $unavailableReason"
            value && !available -> "$label over WARP is armed, $unavailableReason"
            value -> "$label over WARP is armed"
            else -> "$label over WARP is off"
        }
    }

    fun isArmed(): Boolean = armed

    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        alpha = if (enabled) 1f else 0.45f
    }
}

/** Two interlocking links — one tunnel inside another, drawn rather than shipped. */
private class ChainGlyphView(
    context: Context,
    private val accent: Int,
) : View(context) {

    private var linked = false

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }

    fun setLinked(value: Boolean) {
        linked = value
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val d = resources.displayMetrics.density
        paint.strokeWidth = 1.9f * d
        paint.color = if (linked) accent else Sculpt.withAlpha(accent, 0.45f)
        val w = width.toFloat()
        val h = height.toFloat()
        val r = w * 0.19f
        // Upper-left link and lower-right link, overlapping in the middle: the
        // visual shorthand for one tunnel carried inside another.
        canvas.drawCircle(w * 0.38f, h * 0.38f, r, paint)
        canvas.drawCircle(w * 0.62f, h * 0.62f, r, paint)
    }
}

/** Tiny vector glyphs drawn in code — three shapes is not worth three XML assets. */
private class GlyphView(
    context: Context,
    private val glyph: OrbitActionBar.Glyph,
    private val color: Int,
) : View(context) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        color = this@GlyphView.color
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val d = resources.displayMetrics.density
        paint.strokeWidth = 1.7f * d
        val w = width.toFloat()
        val h = height.toFloat()
        when (glyph) {
            OrbitActionBar.Glyph.LOG -> {
                // Three stacked lines, the last one short.
                val xs = w * 0.16f
                val xe = w * 0.84f
                canvas.drawLine(xs, h * 0.28f, xe, h * 0.28f, paint)
                canvas.drawLine(xs, h * 0.52f, xe, h * 0.52f, paint)
                canvas.drawLine(xs, h * 0.76f, w * 0.58f, h * 0.76f, paint)
            }
            OrbitActionBar.Glyph.SPLIT -> {
                // A trunk that forks: one stem, two branches.
                canvas.drawLine(w * 0.5f, h * 0.86f, w * 0.5f, h * 0.52f, paint)
                canvas.drawLine(w * 0.5f, h * 0.52f, w * 0.2f, h * 0.2f, paint)
                canvas.drawLine(w * 0.5f, h * 0.52f, w * 0.8f, h * 0.2f, paint)
            }
            OrbitActionBar.Glyph.SCAN -> {
                // Radar: two arcs plus a dot.
                paint.style = Paint.Style.STROKE
                val cx = w * 0.5f
                val cy = h * 0.72f
                canvas.drawArc(cx - w * 0.34f, cy - h * 0.34f, cx + w * 0.34f, cy + h * 0.34f, 200f, 140f, false, paint)
                canvas.drawArc(cx - w * 0.16f, cy - h * 0.16f, cx + w * 0.16f, cy + h * 0.16f, 200f, 140f, false, paint)
                paint.style = Paint.Style.FILL
                canvas.drawCircle(cx, cy, 1.5f * d, paint)
                paint.style = Paint.Style.STROKE
            }
        }
    }
}
