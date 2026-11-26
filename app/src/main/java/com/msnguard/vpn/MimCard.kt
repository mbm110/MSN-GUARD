package com.msnguard.vpn

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.text.TextUtils
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * Masque-over-Masque card: the MASQUE-transport twin of [ChainModeCard].
 *
 * Sits in the same slot on the home screen and is the same dp(56) height.
 * Exactly one of the three slot occupants is ever visible: the chain card on
 * Psiphon/Tor, Smart Split on SHARD, this one on MASQUE — the transport the
 * user selected decides, so the layout never grows.
 *
 * Upstream Aether v2.0.0 calls this masque-in-masque: the outer hop is dialled
 * from the carrier network, the inner hop is dialled *through* the outer one,
 * so the edge only ever sees the outer hop's exit address — the same shape as
 * Psiphon/Tor over WARP, with MASQUE in both positions.
 *
 * Defaults to OFF: two stacked MASQUE handshakes are measurably slower than
 * one, and plain MASQUE is the configuration most networks need. The user
 * arms it for the networks where one layer is not enough.
 */
class MimCard(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val onToggle: (Boolean) -> Unit,
) : LinearLayout(context) {

    private val titleView: TextView
    private val subtitleView: TextView
    private val badgeView: TextView
    private val icon: MimGlyphView
    private var armed = false

    /** Why the card cannot be used, shown in place of the normal subtitle. */
    private var unavailableReason: String? = null

    /** Whether masque-over-masque applies to the selected transport at all. */
    private var applicable = false

    private fun px(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(px(13), px(6), px(14), px(6))
        isClickable = true
        isFocusable = true
        setOnClickListener {
            // Same guard as the chain card: a focus-based tap (TV remote,
            // keyboard) is delivered even when isEnabled is false, and flipping
            // state there would leave the card and the next config disagreeing.
            if (!isEnabled) return@setOnClickListener
            performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
            setArmed(!armed)
            onToggle(armed)
        }

        icon = MimGlyphView(context, palette.violet)
        addView(icon, LayoutParams(px(34), px(34)))

        val column = LinearLayout(context).apply { orientation = VERTICAL }
        titleView = TextView(context).apply {
            text = Strings.t("MASQUE OVER MASQUE")
            textSize = 11f
            letterSpacing = if (AppLanguage.current() == "fa") 0f else spacing(0.1f)
            typeface = Typefaces.medium(context)
            if (AppLanguage.current() != "en") {
                setLineSpacing(0f, Typefaces.lineHeightMult())
            }
            setSingleLine(true)
            // RTL ROW RULE: the card title pins to the START edge.
            gravity = Gravity.START
            textAlignment = android.view.View.TEXT_ALIGNMENT_VIEW_START
        }
        subtitleView = TextView(context).apply {
            textSize = 9.5f
            if (AppLanguage.current() != "en") {
                setLineSpacing(0f, Typefaces.lineHeightMult())
            }
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.END
            // RTL ROW RULE: the subtitle sits under the START-pinned title.
            gravity = Gravity.START
            textAlignment = android.view.View.TEXT_ALIGNMENT_VIEW_START
        }
        column.addView(titleView)
        column.addView(
            subtitleView,
            LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = if (AppLanguage.current() == "en") px(1) else px(4) }
        )
        addView(
            column,
            LayoutParams(0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                // RTL ROW RULE (3.4.25): start/end margins flip with the locale.
                marginStart = px(11)
                if (AppLanguage.current() != "en") marginEnd = px(14)
            }
        )

        badgeView = TextView(context).apply {
            textSize = 8.5f
            letterSpacing = if (AppLanguage.current() == "fa") 0f else spacing(0.12f)
            typeface = Typefaces.medium(context)
            gravity = Gravity.CENTER
            val localized = AppLanguage.current() != "en"
            setPadding(
                px(if (localized) 10 else 9),
                px(if (localized) 6 else 4),
                px(if (localized) 10 else 9),
                px(if (localized) 6 else 4),
            )
        }
        addView(
            badgeView,
            LayoutParams(
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        )

        setArmed(false)
    }

    /**
     * Marks the card unavailable and says why.
     *
     * @param reason shown instead of the usual subtitle; null means available.
     * @param applicable whether the feature applies to the selected transport.
     *   Defaults to `reason == null` so "locked while connected" (a non-null
     *   reason with applicable=true) still shows CHAINED rather than N/A —
     *   while connected the double hop is carrying traffic.
     */
    fun setUnavailable(reason: String?, applicable: Boolean = reason == null) {
        unavailableReason = reason
        this.applicable = applicable
        isEnabled = reason == null
        setArmed(armed)
    }

    /** Paints the armed/disarmed look. Does not notify [onToggle]. */
    fun setArmed(value: Boolean) {
        armed = value
        // Lit means "on and it applies here" — NOT "interactive". Same
        // distinction as the chain card's, for the same reason: a live
        // masque-over-masque session is locked but carrying every packet.
        val lit = value && applicable
        val density = resources.displayMetrics.density
        val fill = if (lit) {
            Sculpt.blend(palette.surface, palette.violet, 0.16f)
        } else {
            Sculpt.blend(palette.surface, palette.ink, 0.02f)
        }
        // v2.0.0: the frame is a fixed neon-violet accent whether lit or not —
        // the same constant border as the other occupants of this slot.
        background = Sculpt.sculptedRipple(
            density, fill, 18, palette.violet,
            accent = Sculpt.withAlpha(palette.neonViolet, 0.55f),
        )
        titleView.setTextColor(if (lit) palette.ink else palette.muted)
        // States the effect for the user, not the mechanism: the outer hop is
        // what the network sees, which is the entire point of the second hop.
        subtitleView.text = unavailableReason ?: if (value) {
            Strings.t("two hops — the network sees the outer one")
        } else {
            Strings.t("chain a second masque hop inside the first")
        }
        // `muted` for the same measured-contrast reason as SmartSplitCard.
        subtitleView.setTextColor(palette.muted)
        badgeView.text = when {
            !applicable -> Strings.t("N/A")
            value -> Strings.t("CHAINED")
            else -> Strings.t("OFF")
        }
        badgeView.setTextColor(if (lit) palette.violetText else palette.faint)
        badgeView.background = Sculpt.sculptedBackground(
            density,
            if (lit) Sculpt.withAlpha(palette.violet, 0.16f) else Sculpt.recess(palette.surface, 0.16f),
            999,
            Sculpt.withAlpha(if (lit) palette.violet else palette.ink, if (lit) 0.4f else 0.10f),
        )
        icon.setLinked(lit)
        contentDescription = when {
            !applicable -> "Masque over Masque unavailable: $unavailableReason"
            value && unavailableReason != null -> "Masque over Masque is on, $unavailableReason"
            value -> "Masque over Masque is on"
            else -> "Masque over Masque is off"
        }
    }

    fun isArmed(): Boolean = armed

    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        alpha = if (enabled) 1f else 0.45f
    }
}

/**
 * Two interlocking rounded links — the chain glyph, in MASQUE's violet.
 *
 * The same drawing ChainModeCard uses for "one tunnel inside another";
 * masque-over-masque is exactly that shape with both tunnels MASQUE.
 */
private class MimGlyphView(
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
        canvas.drawCircle(w * 0.38f, h * 0.38f, r, paint)
        canvas.drawCircle(w * 0.62f, h * 0.62f, r, paint)
    }
}

/** Neon letter-spacing scatters Persian's joined letters — clamp for Persian. */
private fun spacing(v: Float): Float = if (AppLanguage.current() != "en") 0f else v
