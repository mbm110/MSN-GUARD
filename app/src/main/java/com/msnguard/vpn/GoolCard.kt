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
 * Gool-over-MASQUE card: the WoW-transport occupant of the slot
 * [ChainModeCard] fills on Psiphon/Tor, [MimCard] on MASQUE and
 * [SmartSplitCard] on SHARD.
 *
 * Exactly one of the four slot occupants is ever visible — the transport the
 * user selected decides, so the layout never grows.
 *
 * Upstream Aether v2.3.0: gool carries the wireguard WARP identity inside the
 * masque tunnel and registers it THROUGH that tunnel, so the exit address is
 * foreign rather than local. The card's OFF state is `--gool-classic` —
 * wireguard in wireguard, the plain (local) warp exit every MSN WoW build
 * shipped before this.
 *
 * Defaults to OFF (3.2.43): the classic carrier is the state WoW always
 * connected with; the armed direction is opt-in. The user's explicit ON is
 * remembered and never quietly disarmed.
 */
class GoolCard(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val onToggle: (Boolean) -> Unit,
) : LinearLayout(context) {

    private val titleView: TextView
    private val subtitleView: TextView
    private val badgeView: TextView
    private val icon: GoolGlyphView
    private var armed = false

    /** Why the card cannot be used, shown in place of the normal subtitle. */
    private var unavailableReason: String? = null

    /** Whether gool-over-masque applies to the selected transport at all. */
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

        icon = GoolGlyphView(context, palette.violet)
        addView(icon, LayoutParams(px(34), px(34)))

        val column = LinearLayout(context).apply { orientation = VERTICAL }
        titleView = TextView(context).apply {
            text = Strings.t("GOOL OVER MASQUE")
            textSize = 11f
            letterSpacing = spacing(0.1f)
            typeface = Typefaces.medium(context)
            if (AppLanguage.current() != "en") {
                setLineSpacing(0f, Typefaces.lineHeightMult())
            }
            setSingleLine(true)
        }
        subtitleView = TextView(context).apply {
            textSize = 9.5f
            if (AppLanguage.current() != "en") {
                setLineSpacing(0f, Typefaces.lineHeightMult())
            }
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.END
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
                leftMargin = px(11)
                if (AppLanguage.current() != "en") rightMargin = px(14)
            }
        )

        badgeView = TextView(context).apply {
            textSize = 8.5f
            letterSpacing = spacing(0.12f)
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
     *   while connected the masque-carried wireguard is carrying traffic.
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
        // distinction as the chain card's: a live gool-over-masque session is
        // locked but carrying every packet.
        val lit = value && applicable
        val density = resources.displayMetrics.density
        val fill = if (lit) {
            Sculpt.blend(palette.surface, palette.violet, 0.16f)
        } else {
            Sculpt.blend(palette.surface, palette.ink, 0.02f)
        }
        // Same fixed neon-violet accent as the other occupants of this slot.
        background = Sculpt.sculptedRipple(
            density, fill, 18, palette.violet,
            accent = Sculpt.withAlpha(palette.neonViolet, 0.55f),
        )
        titleView.setTextColor(if (lit) palette.ink else palette.muted)
        // States the effect for the user, not the mechanism: the foreign exit
        // is the entire point of the masque carrier.
        subtitleView.text = unavailableReason ?: if (value) {
            Strings.t("foreign exit — the identity registers through the tunnel")
        } else {
            Strings.t("classic: wireguard in wireguard, a local exit")
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
            !applicable -> "Gool over Masque unavailable: $unavailableReason"
            value && unavailableReason != null -> "Gool over Masque is on, $unavailableReason"
            value -> "Gool over Masque is on"
            else -> "Gool over Masque is off"
        }
    }

    fun isArmed(): Boolean = armed

    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        alpha = if (enabled) 1f else 0.45f
    }
}

/**
 * Two interlocking rounded links — the chain glyph, in the slot's violet.
 *
 * The same drawing [ChainModeCard] and [MimCard] use for "one tunnel inside
 * another"; gool-over-masque is exactly that shape, wireguard inside masque.
 */
private class GoolGlyphView(
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
