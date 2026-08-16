package com.msnguard.vpn

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Typeface
import android.text.TextUtils
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.View
import android.view.ViewGroup
import android.view.animation.OvershootInterpolator
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * Reusable Orbit surfaces. Everything here is deliberately view-based and hand
 * built: the app ships no Compose runtime and no Material components, and a 49MB
 * APK is already mostly native libraries.
 */

private fun Context.px(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

private fun Context.orbitLabel(
    text: String,
    size: Float,
    color: Int,
    medium: Boolean = false,
    mono: Boolean = false,
    spacing: Float = 0f,
): TextView = TextView(this).apply {
    this.text = text
    textSize = size
    setTextColor(color)
    letterSpacing = spacing
    typeface = when {
        mono -> Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
        medium -> Typeface.create("sans-serif-medium", Typeface.NORMAL)
        else -> Typeface.create("sans", Typeface.NORMAL)
    }
}

/**
 * One at-a-glance counter with a sparkline floor.
 *
 * Each tile owns its own accent — mint for DOWN, violet for UP, amber for SPEED,
 * exactly as the approved mock. All three used to share `palette.primary`, which
 * is why every bar row looked identical and flat. The caption takes the accent
 * too, and the bars fade from the accent to a neighbouring hue across the row.
 */
class MetricTile(
    context: Context,
    private val palette: AppAppearance.Palette,
    keyText: String,
    private val accent: Int,
    private val accentSecondary: Int = accent,
    onClick: () -> Unit,
) : LinearLayout(context) {

    private val valueView: TextView
    private val unitView: TextView
    private val bars: MicroBarsView

    init {
        orientation = VERTICAL
        val fill = Sculpt.blend(palette.surface, palette.ink, 0.03f)
        background = Sculpt.sculptedRipple(
            resources.displayMetrics.density, fill, 20, accent,
            accent = Sculpt.withAlpha(accent, 0.18f),
        )
        setPadding(context.px(13), context.px(11), context.px(13), 0)
        isClickable = true
        isFocusable = true
        setOnClickListener { onClick() }

        // Caption in the tile's own accent: the mock coloured .k per tile.
        addView(context.orbitLabel(keyText, 8.5f, Sculpt.withAlpha(accent, 0.92f), medium = true, spacing = 0.13f))

        val row = LinearLayout(context).apply {
            orientation = HORIZONTAL
            gravity = Gravity.BOTTOM
        }
        valueView = context.orbitLabel("0", 21f, palette.ink, medium = true, mono = true)
        unitView = context.orbitLabel("B", 9f, Sculpt.withAlpha(palette.faint, 0.95f), medium = true, spacing = 0.08f)
        row.addView(valueView)
        row.addView(unitView, LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = context.px(3); bottomMargin = context.px(3) })
        addView(row, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = context.px(1) })

        bars = MicroBarsView(context, accent, accentSecondary).apply { seed() }
        addView(bars, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            context.px(16),
        ).apply { topMargin = context.px(5); bottomMargin = context.px(9) })
    }

    /** [value] is pre-scaled for display; [unit] is its suffix, e.g. "GB". */
    fun setValue(value: String, unit: String) {
        valueView.text = value
        unitView.text = unit
    }

    fun push(sample: Float) = bars.push(sample)

    fun resetBars() = bars.reset()

    fun dim(active: Boolean) {
        alpha = if (active) 1f else 0.55f
    }
}

/**
 * Segmented transport picker with a lit thumb that slides between cells.
 *
 * The thumb is a sibling view positioned by translationX rather than a
 * background on the selected cell, so the movement is animatable and the cells
 * stay dumb text views. Each cell now also gets its own sculpted press state —
 * tapping WireGuard on the home screen used to give no visual feedback at all
 * because the cells were bare TextViews with no background.
 */
class TransportRail(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val labels: List<String>,
    private val onPick: (Int) -> Unit,
) : FrameLayout(context) {

    private val thumb: View
    private val cells = mutableListOf<TextView>()
    private var selectedIndex = 0
    private var thumbAnimator: ValueAnimator? = null

    /** Width of one segment, derived from the padded content box. */
    private val cellWidth: Float
        get() {
            val inner = width - paddingLeft - paddingRight
            if (inner <= 0) return 0f
            return inner.toFloat() / labels.size.coerceAtLeast(1)
        }

    init {
        val fill = Sculpt.darken(palette.surface, 0.30f)
        background = Sculpt.recessedBackground(resources.displayMetrics.density, fill, 999)
        setPadding(context.px(5), context.px(5), context.px(5), context.px(5))

        thumb = View(context).apply {
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density,
                Sculpt.blend(palette.surface, palette.primary, 0.16f),
                999,
                Sculpt.withAlpha(palette.primary, 0.45f),
            )
        }
        // No margins here: the FrameLayout padding already insets children. The
        // previous version added another 5dp on three sides on top of the
        // padding, which is why the lit thumb sat short and offset from the cell
        // it was supposed to be under.
        addView(thumb, LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT))

        val row = LinearLayout(context).apply { orientation = LinearLayout.HORIZONTAL }
        labels.forEachIndexed { index, text ->
            val cell = object : TextView(context) {
                // Pressing a rail cell sinks it, the same as every other button.
                override fun setPressed(pressed: Boolean) {
                    super.setPressed(pressed)
                    background = if (pressed) {
                        Sculpt.sculptedBackground(
                            resources.displayMetrics.density,
                            Sculpt.darken(palette.surface, 0.18f),
                            999,
                            pressed = true,
                        )
                    } else {
                        null
                    }
                }
            }.apply {
                this.text = text
                textSize = 10.5f
                setTextColor(palette.faint)
                letterSpacing = 0.05f
                typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
                gravity = Gravity.CENTER
                setSingleLine(true)
                ellipsize = TextUtils.TruncateAt.END
                isClickable = true
                isFocusable = true
                setOnClickListener {
                    if (!isEnabled) return@setOnClickListener
                    performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
                    select(index, animate = true)
                    onPick(index)
                }
            }
            cells.add(cell)
            row.addView(cell, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f))
        }
        addView(row, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ))
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        val width = cellWidth.roundToInt()
        if (width <= 0) return
        thumb.layoutParams = (thumb.layoutParams as LayoutParams).apply { this.width = width }
        thumb.requestLayout()
        thumb.translationX = selectedIndex * cellWidth
    }

    fun select(index: Int, animate: Boolean) {
        if (index !in labels.indices) return
        selectedIndex = index
        cells.forEachIndexed { i, cell ->
            cell.setTextColor(if (i == index) palette.ink else palette.faint)
        }
        val slot = cellWidth
        if (slot <= 0f) return
        val target = index * slot
        thumbAnimator?.cancel()
        if (!animate) {
            thumb.translationX = target
            return
        }
        thumbAnimator = ValueAnimator.ofFloat(thumb.translationX, target).apply {
            duration = 330
            interpolator = OvershootInterpolator(1.1f)
            addUpdateListener { thumb.translationX = it.animatedValue as Float }
            start()
        }
    }

    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        alpha = if (enabled) 1f else 0.5f
        cells.forEach { it.isEnabled = enabled }
    }

    override fun onDetachedFromWindow() {
        thumbAnimator?.cancel()
        thumbAnimator = null
        super.onDetachedFromWindow()
    }
}
