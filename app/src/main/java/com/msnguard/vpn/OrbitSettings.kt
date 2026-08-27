package com.msnguard.vpn

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.animation.PathInterpolator
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * Settings-screen building blocks in the Orbit visual language.
 *
 * The home screen got sculpted glass; the settings pages were still flat
 * rectangles. Rather than restyle every one of the six sub-screens by hand,
 * these three components replace the shared primitives, so Tunnel controls,
 * Theme, Traffic monitor, Split tunneling and Scan Mode all inherit the new
 * look from one place.
 */

/**
 * A section label with a neon tick to its left.
 *
 * The tick is the cheapest way to make a bare uppercase caption read as a
 * deliberate divider rather than stray text, and it ties the settings pages
 * back to the dial's accent colour.
 */
class OrbitSectionHeader(
    context: Context,
    palette: AppAppearance.Palette,
    text: String,
) : LinearLayout(context) {

    private val density = resources.displayMetrics.density

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL

        addView(TickView(context, palette.primary), LayoutParams(dp(3), dp(13)).apply {
            rightMargin = dp(9)
        })
        addView(TextView(context).apply {
            this.text = text
            textSize = 11.5f
            setTextColor(palette.muted)
            letterSpacing = 0.14f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        })
    }

    private fun dp(value: Int): Int = (value * density).roundToInt()

    /** A rounded 3dp bar with a soft glow; drawn rather than a drawable so the
     *  glow radius can scale with density. */
    private class TickView(context: Context, private val color: Int) : View(context) {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val density = resources.displayMetrics.density

        init {
            setLayerType(LAYER_TYPE_SOFTWARE, null)
        }

        override fun onDraw(canvas: Canvas) {
            paint.color = color
            paint.setShadowLayer(3f * density, 0f, 0f, Sculpt.withAlpha(color, 0.75f))
            val radius = width / 2f
            canvas.drawRoundRect(0f, 0f, width.toFloat(), height.toFloat(), radius, radius, paint)
            paint.clearShadowLayer()
        }
    }
}

/**
 * A sculpted settings row: optional leading glyph, title, optional trailing
 * value, chevron.
 *
 * Replaces the flat `createSettingsButton` rectangle. The value is a separate,
 * dimmer text view on the right instead of being appended to the title with
 * " · ", so long values (a manual endpoint, a theme name) truncate on their own
 * without pushing the title off-screen.
 */
class OrbitSettingsRow(
    context: Context,
    private val palette: AppAppearance.Palette,
    title: String,
    value: String? = null,
    private val destructive: Boolean = false,
    iconRes: Int? = null,
    onClick: () -> Unit,
) : LinearLayout(context) {

    private val density = resources.displayMetrics.density
    private val titleView: TextView
    private val valueView: TextView

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(16), dp(13), dp(14), dp(13))
        isClickable = true
        isFocusable = true

        val accent = if (destructive) DESTRUCTIVE else palette.primary
        background = Sculpt.sculptedBackground(
            density,
            palette.surfaceVariant,
            16,
            stroke = palette.divider,
        )

        iconRes?.let { res ->
            addView(android.widget.ImageView(context).apply {
                setImageResource(res)
                setColorFilter(accent)
            }, LayoutParams(dp(19), dp(19)).apply { rightMargin = dp(13) })
        }

        titleView = TextView(context).apply {
            text = title
            textSize = 15f
            setTextColor(if (destructive) DESTRUCTIVE else palette.ink)
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            setSingleLine(true)
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        addView(titleView, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

        valueView = TextView(context).apply {
            text = value.orEmpty()
            textSize = 13.5f
            setTextColor(Sculpt.withAlpha(palette.muted, 0.95f))
            setSingleLine(true)
            ellipsize = android.text.TextUtils.TruncateAt.END
            visibility = if (value.isNullOrBlank()) GONE else VISIBLE
        }
        // The value gets at most half the row: past that the title starts
        // truncating, and the title is what the user is scanning for.
        addView(valueView, LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = dp(10) })

        addView(ChevronGlyph(context, Sculpt.withAlpha(palette.muted, 0.8f)), LayoutParams(dp(18), dp(18)).apply {
            leftMargin = dp(6)
        })

        contentDescription = listOfNotNull(title, value).joinToString(", ")
        setOnClickListener { onClick() }
    }

    /** Presses sink inward: the highlight and shadow swap places. */
    override fun setPressed(pressed: Boolean) {
        super.setPressed(pressed)
        background = Sculpt.sculptedBackground(
            density,
            if (pressed) Sculpt.lighten(palette.surfaceVariant, 0.06f) else palette.surfaceVariant,
            16,
            stroke = if (pressed) Sculpt.withAlpha(palette.primary, 0.55f) else palette.divider,
            pressed = pressed,
        )
    }

    override fun onFocusChanged(gainFocus: Boolean, direction: Int, rect: android.graphics.Rect?) {
        super.onFocusChanged(gainFocus, direction, rect)
        background = Sculpt.sculptedBackground(
            density,
            palette.surfaceVariant,
            16,
            stroke = if (gainFocus) palette.primary else palette.divider,
            strokeWidth = if (gainFocus) 2 else 1,
        )
    }

    fun setValue(value: String?) {
        valueView.text = value.orEmpty()
        valueView.visibility = if (value.isNullOrBlank()) GONE else VISIBLE
        contentDescription = listOfNotNull(titleView.text?.toString(), value).joinToString(", ")
    }

    fun setTitle(title: String) {
        titleView.text = title
        contentDescription = listOfNotNull(title, valueView.text?.toString()?.takeIf { it.isNotBlank() })
            .joinToString(", ")
    }

    /**
     * Grey the row out and stop it accepting taps.
     *
     * A disabled row still says what it *would* control, which is why the title
     * stays put and only the colours fade: hiding the row instead would leave the
     * user wondering where a setting went, and leaving it tappable would open a
     * sheet whose choice has no effect.
     */
    fun setAvailable(available: Boolean) {
        if (isEnabled == available) return
        isEnabled = available
        isClickable = available
        isFocusable = available
        alpha = if (available) 1f else 0.42f
    }

    private fun dp(value: Int): Int = (value * density).roundToInt()

    private companion object {
        val DESTRUCTIVE = 0xFFFF6B7F.toInt()
    }
}

/** A chevron drawn with two strokes; avoids shipping another vector asset. */
private class ChevronGlyph(context: Context, private val color: Int) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    private val density = resources.displayMetrics.density

    override fun onDraw(canvas: Canvas) {
        paint.color = color
        paint.strokeWidth = 1.6f * density
        val cx = width / 2f - density
        val cy = height / 2f
        val arm = 3.6f * density
        canvas.drawLine(cx - arm / 2, cy - arm, cx + arm / 2, cy, paint)
        canvas.drawLine(cx + arm / 2, cy, cx - arm / 2, cy + arm, paint)
    }
}

/**
 * A sculpted toggle row with a neon track.
 *
 * The old toggle was a grey pill with a white dot. This one lights the track
 * with the accent colour and gives the thumb a shadow, so "on" reads at a
 * glance in a dark room, which is the condition this app is actually used in.
 */
class OrbitToggleRow(
    context: Context,
    private val palette: AppAppearance.Palette,
    title: String,
    subtitle: String,
    checked: Boolean,
    private val onToggle: (Boolean) -> Unit,
) : LinearLayout(context) {

    private val density = resources.displayMetrics.density
    private var isOn = checked
    private val track: View
    private val thumb: View
    private val subtitleView: TextView
    private val trackWidth = dp(46)
    private val trackHeight = dp(27)
    private val thumbSize = dp(21)
    private val thumbInset = dp(3)

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(16), dp(12), dp(14), dp(12))
        background = Sculpt.sculptedBackground(density, palette.surfaceVariant, 16, stroke = palette.divider)

        subtitleView = TextView(context).apply {
            text = subtitle
            textSize = 12.5f
            setTextColor(Sculpt.withAlpha(palette.muted, 0.95f))
        }
        val texts = LinearLayout(context).apply {
            orientation = VERTICAL
            addView(TextView(context).apply {
                text = title
                textSize = 15f
                setTextColor(palette.ink)
                typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            })
            addView(subtitleView, LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(2) })
        }
        addView(texts, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

        thumb = View(context).apply {
            layoutParams = LayoutParams(thumbSize, thumbSize)
            translationX = restingThumbX()
        }
        track = LinearLayout(context).apply {
            layoutParams = LayoutParams(trackWidth, trackHeight)
            gravity = Gravity.CENTER_VERTICAL
            isClickable = true
            isFocusable = true
            addView(thumb)
            setOnClickListener { toggle() }
        }
        addView(track, LayoutParams(trackWidth, trackHeight).apply { leftMargin = dp(12) })

        renderSwitch()
        // Tapping anywhere on the row toggles it. A 27dp track is a small target
        // on a 6" phone, and the whole row already looks tappable.
        isClickable = true
        isFocusable = true
        setOnClickListener { toggle() }
        updateDescription(title)
    }

    private fun toggle() {
        isOn = !isOn
        onToggle(isOn)
        thumb.animate()
            .translationX(restingThumbX())
            .setDuration(170)
            .setInterpolator(PathInterpolator(0.2f, 0f, 0f, 1f))
            .start()
        renderSwitch()
    }

    private fun restingThumbX(): Float =
        if (isOn) (trackWidth - thumbSize - thumbInset).toFloat() else thumbInset.toFloat()

    private fun renderSwitch() {
        track.background = Sculpt.sculptedBackground(
            density,
            if (isOn) palette.primary else Sculpt.withAlpha(palette.canvas, 0.85f),
            999,
            stroke = if (isOn) Sculpt.lighten(palette.primary, 0.25f) else palette.divider,
            accent = if (isOn) Sculpt.lighten(palette.primary, 0.45f) else null,
            pressed = !isOn,
        )
        thumb.background = Sculpt.sculptedBackground(
            density,
            if (isOn) 0xFFFFFFFF.toInt() else Sculpt.lighten(palette.muted, 0.15f),
            999,
            accent = if (isOn) 0xFFFFFFFF.toInt() else null,
        )
    }

    private fun updateDescription(title: String) {
        contentDescription = "$title, ${if (isOn) "on" else "off"}"
        track.contentDescription = contentDescription
    }

    /**
     * Grey the row out and stop it toggling.
     *
     * Same reasoning as [OrbitSettingsRow.setAvailable]: a switch whose state has
     * no effect is worse than a visibly disabled one, because the user has no way
     * to tell that flipping it did nothing.
     */
    fun setAvailable(available: Boolean) {
        if (isEnabled == available) return
        isEnabled = available
        isClickable = available
        isFocusable = available
        track.isClickable = available
        track.isFocusable = available
        alpha = if (available) 1f else 0.42f
    }

    /** Repaint to [value] without invoking the toggle callback. */
    fun setChecked(value: Boolean) {
        if (isOn == value) return
        isOn = value
        thumb.translationX = restingThumbX()
        renderSwitch()
    }

    /**
     * Replace the subtitle after construction.
     *
     * LAN sharing needs this: the row's subtitle carries the actual address the
     * user has to type on the other device, and that address is only known once
     * the proxy is listening. A static subtitle would either be a lie or would
     * force the address into a second row.
     */
    fun setSubtitle(text: String) {
        subtitleView.text = text
    }

    private fun dp(value: Int): Int = (value * density).roundToInt()
}
