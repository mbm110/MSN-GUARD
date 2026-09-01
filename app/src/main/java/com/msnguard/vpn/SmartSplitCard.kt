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
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * Smart Split card: the SHARD-transport twin of [ChainModeCard].
 *
 * Sits in the same slot on the home screen and is the same dp(56) height, because
 * the two are mutually exclusive by construction — the chain card applies to
 * Psiphon and Tor, this one only to SHARD, so exactly one of them is ever
 * applicable and the layout never grows.
 *
 * ## What it does not show
 *
 * The measured fragment profile. The app decides between a patient and a stubborn
 * fragmenter by probing the carrier, and naming that in the UI would be asking the
 * user to have an opinion about a fact — see [SmartSplit] for why it is a
 * measurement and not a preference. The subtitle says whether a measurement exists
 * for this network, never which way it went.
 */
class SmartSplitCard(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val onToggle: (Boolean) -> Unit,
) : LinearLayout(context) {

    private val titleView: TextView
    private val subtitleView: TextView
    private val badgeView: TextView
    private val icon: SplitGlyphView
    private var enabledState = false

    /** Why the card cannot be used, shown in place of the normal subtitle. */
    private var unavailableReason: String? = null

    /** Whether Smart Split applies to the selected transport at all. */
    private var applicable = false

    /**
     * What the measurement says, in the user's terms — never the profile name.
     *
     * Kept as a string rather than the enum for the same reason [ChainModeCard]
     * keeps [ChainModeCard.setOuterSummary]'s: the view shows a decision it does
     * not make, and holding the enum here would invite it to start reasoning about
     * fragmenters.
     */
    private var tuningSummary: String = ""

    private fun px(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(px(13), px(6), px(14), px(6))
        isClickable = true
        isFocusable = true
        setOnClickListener {
            // Same guard as the chain card: a focus-based tap (TV remote, keyboard)
            // is delivered even when isEnabled is false, and flipping state there
            // would leave the card and the next config disagreeing.
            if (!isEnabled) return@setOnClickListener
            performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
            setSplitEnabled(!enabledState)
            onToggle(enabledState)
        }

        icon = SplitGlyphView(context, palette.mint)
        addView(icon, LayoutParams(px(34), px(34)))

        val column = LinearLayout(context).apply { orientation = VERTICAL }
        titleView = TextView(context).apply {
            text = "SMART SPLIT"
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
        column.addView(
            subtitleView,
            LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = px(1) }
        )
        addView(
            column,
            LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                leftMargin = px(11)
            }
        )

        badgeView = TextView(context).apply {
            textSize = 8.5f
            letterSpacing = 0.12f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            setPadding(px(9), px(4), px(9), px(4))
        }
        addView(
            badgeView,
            LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        )

        setSplitEnabled(false)
    }

    /**
     * Marks the card unavailable and says why.
     *
     * @param reason shown instead of the usual subtitle; null means available.
     * @param applicable whether Smart Split applies to the selected transport.
     *   Defaults to `reason == null`, so "locked while connected" (a non-null
     *   reason with applicable=true) still shows ON rather than dropping to N/A —
     *   the same distinction [ChainModeCard.setUnavailable] draws, for the same
     *   reason: while connected the split is carrying traffic.
     */
    fun setUnavailable(reason: String?, applicable: Boolean = reason == null) {
        unavailableReason = reason
        this.applicable = applicable
        isEnabled = reason == null
        setSplitEnabled(enabledState)
    }

    /** Sets the tuning line, e.g. "tuned for this network". Repaints immediately. */
    fun setTuningSummary(summary: String) {
        tuningSummary = summary
        setSplitEnabled(enabledState)
    }

    /** Paints the on/off look. Does not notify [onToggle]. */
    fun setSplitEnabled(value: Boolean) {
        enabledState = value
        val lit = value && applicable
        val density = resources.displayMetrics.density
        val fill = if (lit) {
            Sculpt.blend(palette.surface, palette.mint, 0.16f)
        } else {
            Sculpt.blend(palette.surface, palette.ink, 0.02f)
        }
        background = Sculpt.sculptedRipple(
            density, fill, 18, palette.mint,
            accent = Sculpt.withAlpha(
                if (lit) palette.mint else palette.ink,
                if (lit) 0.45f else 0.085f,
            ),
        )
        titleView.setTextColor(if (lit) palette.ink else palette.muted)
        // States the effect, not the mechanism. "Iranian sites direct, blocked
        // sites through the node" is the whole feature in one line, and it stays
        // true whichever fragment profile the probe settles on.
        subtitleView.text = unavailableReason ?: when {
            !value -> "everything through the node"
            tuningSummary.isNotEmpty() -> "local sites direct · $tuningSummary"
            else -> "local sites direct, blocked sites via node"
        }
        // `muted`, not `faint`. Measured on both palettes rather than eyeballed:
        // faint@0.95 on the lit mint fill is 2.68:1 on Midnight and 4.49:1 on
        // Porcelain — one clear fail and one miss. `muted` measures 6.00:1 and
        // 5.46:1 lit, 8.10:1 and 6.29:1 unlit, so all four states clear 4.5:1.
        subtitleView.setTextColor(palette.muted)
        badgeView.text = when {
            !applicable -> "N/A"
            value -> "ON"
            else -> "OFF"
        }
        badgeView.setTextColor(if (lit) palette.mintText else palette.faint)
        badgeView.background = Sculpt.sculptedBackground(
            density,
            // 0.10 mint, not 0.16: the pill sits on the card's own mint tint, so the
            // two washes stack. At 0.16 the ON label measures 4.27:1 on Porcelain;
            // at 0.10 it is 4.53:1 there and 6.64:1 on Midnight. The border carries
            // the emphasis instead, where contrast is not a legibility question.
            if (lit) Sculpt.withAlpha(palette.mint, 0.10f) else Sculpt.recess(palette.surface, 0.16f),
            999,
            Sculpt.withAlpha(if (lit) palette.mint else palette.ink, if (lit) 0.4f else 0.10f),
        )
        icon.setActive(lit)
        contentDescription = when {
            !applicable -> "Smart Split unavailable: $unavailableReason"
            value && unavailableReason != null -> "Smart Split is on, $unavailableReason"
            value -> "Smart Split is on"
            else -> "Smart Split is off"
        }
    }

    fun isSplitEnabled(): Boolean = enabledState

    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        alpha = if (enabled) 1f else 0.45f
    }
}

/**
 * One path that forks into two — traffic taking two routes out of one tunnel.
 *
 * Deliberately not the action bar's SPLIT glyph: that one is a symmetrical Y and
 * means per-app split tunnelling, a different feature that is also in this app.
 * This one's branches are asymmetric, and only the lit branch gets the dot.
 */
private class SplitGlyphView(
    context: Context,
    private val accent: Int,
) : View(context) {

    private var active = false

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }

    fun setActive(value: Boolean) {
        active = value
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val d = resources.displayMetrics.density
        paint.strokeWidth = 1.9f * d
        paint.color = if (active) accent else Sculpt.withAlpha(accent, 0.45f)
        val w = width.toFloat()
        val h = height.toFloat()
        // Stem up the middle, then two branches leaving at different angles.
        paint.style = Paint.Style.STROKE
        canvas.drawLine(w * 0.5f, h * 0.84f, w * 0.5f, h * 0.5f, paint)
        canvas.drawLine(w * 0.5f, h * 0.5f, w * 0.24f, h * 0.24f, paint)
        canvas.drawLine(w * 0.5f, h * 0.5f, w * 0.78f, h * 0.34f, paint)
        if (active) {
            // A dot on each branch end: both routes are live, which is the point.
            paint.style = Paint.Style.FILL
            canvas.drawCircle(w * 0.24f, h * 0.24f, 1.6f * d, paint)
            canvas.drawCircle(w * 0.78f, h * 0.34f, 1.6f * d, paint)
            paint.style = Paint.Style.STROKE
        }
    }
}
