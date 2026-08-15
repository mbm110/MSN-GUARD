package studio.cluvex.aethery

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.content.res.ColorStateList
import android.view.View
import kotlin.math.roundToInt

/**
 * Shared drawing helpers for the Orbit visual language.
 *
 * The whole point of this file is that a "sculpted" control is not one colour —
 * it is four layers: a specular highlight near the top-left, a body gradient,
 * a one-pixel light line on the top edge, and an inner shadow at the bottom.
 * Reproducing that inline at every call site is how the old UI ended up flat,
 * so every surface in the app now goes through [sculptedBackground].
 */
object Sculpt {

    /** Alpha-blend [overlay] onto [base]. Used to fake translucency on opaque views. */
    fun blend(base: Int, overlay: Int, alpha: Float): Int {
        val a = alpha.coerceIn(0f, 1f)
        val r = ((Color.red(base) * (1 - a)) + (Color.red(overlay) * a)).roundToInt()
        val g = ((Color.green(base) * (1 - a)) + (Color.green(overlay) * a)).roundToInt()
        val b = ((Color.blue(base) * (1 - a)) + (Color.blue(overlay) * a)).roundToInt()
        return Color.rgb(r, g, b)
    }

    fun withAlpha(color: Int, alpha: Float): Int =
        Color.argb((alpha.coerceIn(0f, 1f) * 255).roundToInt(), Color.red(color), Color.green(color), Color.blue(color))

    /** Lift a colour towards white — the highlight edge of a bevel. */
    fun lighten(color: Int, amount: Float): Int = blend(color, Color.WHITE, amount)

    /** Push a colour towards black — the shadow edge of a bevel. */
    fun darken(color: Int, amount: Float): Int = blend(color, Color.BLACK, amount)

    /**
     * The standard MSN-GUARD raised surface: vertical body gradient, hairline
     * top highlight, hairline outline. [radius] is in dp.
     *
     * [stroke] overrides the auto-derived outline (used by the settings rows,
     * which want the palette's divider rather than a lightened fill).
     * [accent] is a stronger outline used for lit/active states and wins over
     * [stroke]. [pressed] inverts the gradient so the surface reads as recessed
     * without the caller having to switch functions mid-expression.
     */
    fun sculptedBackground(
        density: Float,
        fill: Int,
        radius: Int,
        accent: Int? = null,
        stroke: Int? = null,
        strokeWidth: Int = 1,
        pressed: Boolean = false,
    ): GradientDrawable = GradientDrawable(
        GradientDrawable.Orientation.TOP_BOTTOM,
        if (pressed) {
            intArrayOf(darken(fill, 0.12f), darken(fill, 0.04f), fill)
        } else {
            intArrayOf(lighten(fill, 0.075f), fill, darken(fill, 0.06f))
        },
    ).apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = radius * density
        setStroke(
            (strokeWidth * 1.4f * density).roundToInt().coerceAtLeast(1),
            accent ?: stroke ?: lighten(fill, 0.16f),
        )
    }

    /** Same as [sculptedBackground] but pressed: gradient inverted so it reads as recessed. */
    fun recessedBackground(
        density: Float,
        fill: Int,
        radius: Int,
        accent: Int? = null,
    ): GradientDrawable = GradientDrawable(
        GradientDrawable.Orientation.TOP_BOTTOM,
        intArrayOf(darken(fill, 0.12f), darken(fill, 0.04f), fill),
    ).apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = radius * density
        setStroke((1.4f * density).roundToInt(), accent ?: lighten(fill, 0.10f))
    }

    /**
     * Wrap a sculpted surface in a ripple so touch feedback survives.
     *
     * The old flat buttons relied on selectableItemBackground, which draws
     * nothing on top of a custom GradientDrawable on some OEM skins. An explicit
     * RippleDrawable with a mask always draws.
     */
    fun sculptedRipple(
        density: Float,
        fill: Int,
        radius: Int,
        rippleColor: Int,
        accent: Int? = null,
    ): RippleDrawable {
        val mask = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = radius * density
            setColor(Color.WHITE)
        }
        return RippleDrawable(
            ColorStateList.valueOf(withAlpha(rippleColor, 0.22f)),
            sculptedBackground(density, fill, radius, accent),
            mask,
        )
    }
}

/**
 * Small sparkline drawn along the bottom edge of a metric tile.
 *
 * Deliberately dumb: it keeps at most [maxBars] samples and rescales to the
 * largest one, so a tile that has never seen traffic draws a flat floor instead
 * of dividing by zero.
 */
class MicroBarsView(
    context: Context,
    private var barColor: Int,
) : View(context) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val density = resources.displayMetrics.density
    private val samples = ArrayDeque<Float>()
    private val maxBars = 9

    fun setColor(color: Int) {
        barColor = color
        invalidate()
    }

    fun push(value: Float) {
        samples.addLast(value.coerceAtLeast(0f))
        while (samples.size > maxBars) samples.removeFirst()
        invalidate()
    }

    fun seed() {
        if (samples.isNotEmpty()) return
        repeat(maxBars) { samples.addLast(0f) }
        invalidate()
    }

    fun reset() {
        samples.clear()
        seed()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (samples.isEmpty()) return
        val peak = samples.maxOrNull() ?: 0f
        val gap = 1.6f * density
        val slot = (width - gap * (maxBars - 1)) / maxBars
        if (slot <= 0f) return
        val radius = 1f * density
        samples.forEachIndexed { index, value ->
            // A zero peak means "no traffic yet": draw a 12% stub, never NaN.
            val ratio = if (peak <= 0f) 0.12f else (0.12f + 0.88f * (value / peak))
            val barHeight = height * ratio
            val left = index * (slot + gap)
            paint.shader = LinearGradient(
                0f, height - barHeight, 0f, height.toFloat(),
                Sculpt.withAlpha(barColor, 0.85f), Sculpt.withAlpha(barColor, 0.12f),
                Shader.TileMode.CLAMP,
            )
            canvas.drawRoundRect(
                RectF(left, height - barHeight, left + slot, height.toFloat()),
                radius, radius, paint,
            )
        }
        paint.shader = null
    }
}
