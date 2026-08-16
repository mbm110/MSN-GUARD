package com.msnguard.vpn

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorFilter
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PixelFormat
import android.graphics.RadialGradient
import android.graphics.Rect
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.graphics.drawable.StateListDrawable
import android.content.res.ColorStateList
import android.os.SystemClock
import android.view.View
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * Shared drawing helpers for the Orbit visual language.
 *
 * A "sculpted" control is not one colour — it is four layers, exactly as the
 * approved mock described them:
 *   1. a specular highlight near the top-left (convex glass),
 *   2. a body gradient,
 *   3. a one-pixel light line along the top edge,
 *   4. an inner shadow at the bottom that creates depth.
 * Pressing inverts 3 and 4 so the surface genuinely sinks instead of only
 * shrinking.
 *
 * The old implementation faked this with a plain [GradientDrawable], which can
 * only do a linear body gradient — no radial specular, no inner shadow. That is
 * why the shipped buttons looked flat next to the HTML preview. [GlassDrawable]
 * below draws all four layers, and every surface in the app goes through it.
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

    /** Linear interpolation between two colours, alpha included. */
    fun mix(from: Int, to: Int, t: Float): Int {
        val f = t.coerceIn(0f, 1f)
        fun channel(a: Int, b: Int) = (a + (b - a) * f).roundToInt().coerceIn(0, 255)
        return Color.argb(
            channel(Color.alpha(from), Color.alpha(to)),
            channel(Color.red(from), Color.red(to)),
            channel(Color.green(from), Color.green(to)),
            channel(Color.blue(from), Color.blue(to)),
        )
    }

    /**
     * The standard MSN-GUARD raised glass surface. [radius] is in dp.
     *
     * [accent] is a lit outline used for active states and wins over [stroke].
     * [pressed] forces the recessed lighting for callers that manage their own
     * state; everyone else gets a state list, so any clickable view using this
     * background genuinely sinks on touch instead of only scaling.
     */
    fun sculptedBackground(
        density: Float,
        fill: Int,
        radius: Int,
        accent: Int? = null,
        stroke: Int? = null,
        strokeWidth: Int = 1,
        pressed: Boolean = false,
    ): Drawable {
        val outline = accent ?: stroke ?: withAlpha(Color.WHITE, 0.11f)
        fun layer(down: Boolean) = GlassDrawable(
            density = density,
            fill = fill,
            radiusDp = radius.toFloat(),
            stroke = outline,
            strokeWidthDp = strokeWidth * 1.1f,
            pressed = down,
            glow = accent,
        )
        if (pressed) return layer(true)
        // StateListDrawable, not a bare GlassDrawable: this is what gives every
        // button in the app the "press = sink inwards" behaviour for free. Views
        // that are not clickable simply never enter state_pressed and always
        // render the raised layer.
        return StateListDrawable().apply {
            setEnterFadeDuration(0)
            setExitFadeDuration(140)
            addState(intArrayOf(android.R.attr.state_pressed), layer(true))
            addState(intArrayOf(), layer(false))
        }
    }

    /** A recessed well: the inverse lighting, used for the transport rail track. */
    fun recessedBackground(
        density: Float,
        fill: Int,
        radius: Int,
        accent: Int? = null,
    ): Drawable = GlassDrawable(
        density = density,
        fill = fill,
        radiusDp = radius.toFloat(),
        stroke = accent ?: withAlpha(Color.WHITE, 0.08f),
        strokeWidthDp = 1.1f,
        pressed = true,
    )

    /**
     * Wrap a sculpted surface in a ripple so touch feedback survives.
     *
     * selectableItemBackground draws nothing over a custom drawable on some OEM
     * skins, so the ripple is explicit and always has a mask.
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
            ColorStateList.valueOf(withAlpha(rippleColor, 0.20f)),
            sculptedBackground(density, fill, radius, accent),
            mask,
        )
    }
}

/**
 * The four-layer glass surface from the approved mock, drawn by hand.
 *
 * Layer order matches CSS paint order in the preview:
 *   body gradient → radial specular → inner bottom shadow → bevel stroke.
 * [pressed] swaps the vertical lighting and moves the inner shadow to the top,
 * which is what makes a press read as "sunk in" rather than "faded".
 */
class GlassDrawable(
    private val density: Float,
    private val fill: Int,
    private val radiusDp: Float,
    private val stroke: Int,
    private val strokeWidthDp: Float = 1.1f,
    private val pressed: Boolean = false,
    private val glow: Int? = null,
) : Drawable() {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val rect = RectF()
    private val clip = Path()

    override fun draw(canvas: Canvas) {
        val b = bounds
        if (b.width() <= 0 || b.height() <= 0) return
        val strokeWidth = (strokeWidthDp * density).coerceAtLeast(1f)
        val inset = strokeWidth / 2f
        rect.set(b.left + inset, b.top + inset, b.right - inset, b.bottom - inset)
        // A pill radius (999dp in the mock) has to clamp to half the height or
        // drawRoundRect produces a lens shape on short views.
        val radius = (radiusDp * density).coerceAtMost(minOf(rect.width(), rect.height()) / 2f)

        // 1. body gradient
        paint.style = Paint.Style.FILL
        paint.shader = LinearGradient(
            0f, rect.top, 0f, rect.bottom,
            if (pressed) {
                intArrayOf(Sculpt.darken(fill, 0.22f), Sculpt.darken(fill, 0.06f), fill)
            } else {
                intArrayOf(Sculpt.lighten(fill, 0.09f), fill, Sculpt.darken(fill, 0.09f))
            },
            floatArrayOf(0f, 0.55f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawRoundRect(rect, radius, radius, paint)

        // 2. specular highlight, top-left — the "convex glass" cue
        if (!pressed) {
            paint.shader = RadialGradient(
                rect.left + rect.width() * 0.30f,
                rect.top,
                maxOf(rect.width(), rect.height()) * 0.95f,
                intArrayOf(Sculpt.withAlpha(Color.WHITE, 0.13f), Sculpt.withAlpha(Color.WHITE, 0f)),
                floatArrayOf(0f, 1f),
                Shader.TileMode.CLAMP,
            )
            canvas.drawRoundRect(rect, radius, radius, paint)
        }

        // 3. inner shadow — bottom when raised, top when pressed
        val shadowStops = if (pressed) {
            intArrayOf(Sculpt.withAlpha(Color.BLACK, 0.45f), Sculpt.withAlpha(Color.BLACK, 0f))
        } else {
            intArrayOf(Sculpt.withAlpha(Color.BLACK, 0f), Sculpt.withAlpha(Color.BLACK, 0.30f))
        }
        paint.shader = LinearGradient(
            0f, rect.top, 0f, rect.bottom,
            shadowStops,
            if (pressed) floatArrayOf(0f, 0.45f) else floatArrayOf(0.55f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawRoundRect(rect, radius, radius, paint)
        paint.shader = null

        // 4. bevel: one-pixel light line on the top edge, fading down the sides
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = strokeWidth
        paint.shader = LinearGradient(
            0f, rect.top, 0f, rect.bottom,
            intArrayOf(
                Sculpt.withAlpha(Color.WHITE, if (pressed) 0.05f else 0.22f),
                Sculpt.withAlpha(Color.WHITE, 0.04f),
            ),
            floatArrayOf(0f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawRoundRect(rect, radius, radius, paint)
        paint.shader = null

        // outline / lit accent ring
        paint.color = stroke
        canvas.drawRoundRect(rect, radius, radius, paint)

        // a lit control also gets a soft outer bloom, like the mock's box-shadow
        glow?.let { color ->
            if (Color.alpha(color) < 40) return@let
            clip.reset()
            paint.color = Sculpt.withAlpha(color, 0.22f)
            paint.strokeWidth = strokeWidth * 2.4f
            canvas.drawRoundRect(rect, radius, radius, paint)
        }
    }

    override fun setAlpha(alpha: Int) = Unit

    override fun setColorFilter(colorFilter: ColorFilter?) = Unit

    @Deprecated("Deprecated in Drawable", ReplaceWith("PixelFormat.TRANSLUCENT"))
    override fun getOpacity(): Int = PixelFormat.TRANSLUCENT

    override fun getPadding(padding: Rect): Boolean = false
}

/**
 * Sparkline floor for a metric tile.
 *
 * Two changes over the flat version: each bar is coloured by interpolating
 * between two accents across the row (so a tile reads as a gradient, the way the
 * preview did) and the amplitude also drives brightness, so a quiet tile is dim
 * and a busy one glows.
 */
class MicroBarsView(
    context: Context,
    private var barColor: Int,
    private var barColorAlt: Int = barColor,
) : View(context) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val density = resources.displayMetrics.density
    private val samples = ArrayDeque<Float>()
    private val maxBars = 11

    fun setColors(primary: Int, secondary: Int = primary) {
        barColor = primary
        barColorAlt = secondary
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
        val gap = 1.8f * density
        val slot = (width - gap * (maxBars - 1)) / maxBars
        if (slot <= 0f) return
        val radius = 1.2f * density
        samples.forEachIndexed { index, value ->
            // A zero peak means "no traffic yet": draw a 10% stub, never NaN.
            val ratio = if (peak <= 0f) 0.10f else (0.10f + 0.90f * (value / peak))
            val barHeight = height * ratio
            val left = index * (slot + gap)
            // Colour walks across the row, and quiet bars stay dim.
            val hue = Sculpt.mix(barColor, barColorAlt, index / (maxBars - 1f))
            val top = Sculpt.withAlpha(hue, 0.35f + 0.60f * ratio)
            val bottom = Sculpt.withAlpha(hue, 0.06f)
            paint.shader = LinearGradient(
                0f, height - barHeight, 0f, height.toFloat(),
                top, bottom,
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

/**
 * The thin green trace next to the exit-node IP.
 *
 * The preview drew a stroked polyline with a soft fill underneath; the shipped
 * build reused [MicroBarsView], which is why it looked like fat columns. This is
 * that polyline: 1.6dp stroke, rounded joins, gradient fill to transparent.
 */
class SparkLineView(
    context: Context,
    private var lineColor: Int,
) : View(context) {

    private val stroke = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val density = resources.displayMetrics.density
    private val path = Path()
    private val fillPath = Path()
    private val samples = ArrayDeque<Float>()
    private val maxPoints = 14

    fun setColor(color: Int) {
        lineColor = color
        invalidate()
    }

    fun push(value: Float) {
        samples.addLast(value.coerceIn(0f, 1f))
        while (samples.size > maxPoints) samples.removeFirst()
        invalidate()
    }

    /** A gentle resting wave so the card never shows an empty box. */
    fun seed() {
        samples.clear()
        repeat(maxPoints) { index ->
            samples.addLast((0.35f + 0.2f * sin(index * 0.9f)).coerceIn(0f, 1f))
        }
        invalidate()
    }

    fun reset() = seed()

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (samples.size < 2 || width <= 0 || height <= 0) return
        val inset = 2f * density
        val usableH = height - inset * 2
        val step = width.toFloat() / (samples.size - 1)
        path.reset()
        samples.forEachIndexed { index, value ->
            val x = index * step
            val y = inset + usableH * (1f - value)
            if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        fillPath.set(path)
        fillPath.lineTo(width.toFloat(), height.toFloat())
        fillPath.lineTo(0f, height.toFloat())
        fillPath.close()
        fillPaint.shader = LinearGradient(
            0f, 0f, 0f, height.toFloat(),
            Sculpt.withAlpha(lineColor, 0.26f), Sculpt.withAlpha(lineColor, 0f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawPath(fillPath, fillPaint)
        stroke.strokeWidth = 1.6f * density
        stroke.shader = LinearGradient(
            0f, 0f, width.toFloat(), 0f,
            Sculpt.withAlpha(lineColor, 0.55f), lineColor,
            Shader.TileMode.CLAMP,
        )
        canvas.drawPath(path, stroke)
        stroke.shader = null
        fillPaint.shader = null
    }
}

/**
 * The strip that closes the home screen under LOG / SPLIT / SCAN.
 *
 * That area used to be dead space. It now carries a slow horizon wave in the
 * accent colour plus the build signature. Deliberately cheap: it only animates
 * while attached AND lit, one path of 48 points, ~20fps, no bitmaps, no blur.
 */
class OrbitFooterWave(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val caption: String,
) : View(context) {

    private val wave = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    private val text = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL)
        letterSpacing = 0.18f
    }
    private val density = resources.displayMetrics.density
    private val path = Path()
    private var lit = false
    private var running = false

    private val ticker = object : Runnable {
        override fun run() {
            if (!running) return
            invalidate()
            postDelayed(this, 50L)
        }
    }

    fun setLit(value: Boolean) {
        if (lit == value) return
        lit = value
        syncTicker()
        invalidate()
    }

    private fun syncTicker() {
        val shouldRun = lit && isAttachedToWindow
        if (shouldRun == running) return
        running = shouldRun
        removeCallbacks(ticker)
        if (running) post(ticker)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        syncTicker()
    }

    override fun onDetachedFromWindow() {
        running = false
        removeCallbacks(ticker)
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (width <= 0 || height <= 0) return
        val accent = if (lit) palette.connected else palette.faint
        val phase = if (lit) (SystemClock.uptimeMillis() % 4_000L) / 4_000f * (2f * Math.PI.toFloat()) else 0f
        val midY = height * 0.42f
        val amplitude = (if (lit) 5.5f else 2.2f) * density
        path.reset()
        val points = 48
        for (i in 0..points) {
            val t = i / points.toFloat()
            val x = width * t
            // Two summed sines: one long swell, one short ripple. Envelope fades
            // both ends so the trace melts into the background instead of
            // stopping at a hard edge.
            val envelope = sin(t * Math.PI.toFloat())
            val y = midY + amplitude * envelope *
                (sin(t * 6.2f + phase) * 0.7f + sin(t * 13f - phase * 1.6f) * 0.3f)
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        wave.strokeWidth = 1.5f * density
        wave.shader = LinearGradient(
            0f, 0f, width.toFloat(), 0f,
            intArrayOf(
                Sculpt.withAlpha(accent, 0f),
                Sculpt.withAlpha(accent, if (lit) 0.85f else 0.35f),
                Sculpt.withAlpha(accent, 0f),
            ),
            floatArrayOf(0f, 0.5f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawPath(path, wave)
        wave.shader = null

        text.textSize = 8.5f * density
        text.color = Sculpt.withAlpha(palette.faint, if (lit) 0.95f else 0.7f)
        canvas.drawText(caption, width / 2f, height * 0.92f, text)
    }
}
