package studio.cluvex.aethery

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.SweepGradient
import android.graphics.Typeface
import android.text.TextPaint
import android.view.HapticFeedbackConstants
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * The Orbit dial: the one control that matters on the main screen.
 *
 * Layers, outermost first:
 *  1. breathing halo (connected only)
 *  2. two ripple rings that expand and fade (connected only)
 *  3. static thin ring + slowly rotating dashed ring
 *  4. 60 gauge ticks that light up green as the tunnel comes up
 *  5. progress arc — sweeps while connecting, settles at ~85% when connected
 *  6. the glass core: radial specular highlight, body gradient, bevel edge,
 *     inner bottom shadow, and a moving sheen band
 *  7. contents: shield + "TAP TO CONNECT" when down, session timer when up
 *
 * The shield/label and the timer are mutually exclusive by design — that was an
 * explicit product decision, not an oversight. When the tunnel is up the timer
 * takes the centre; the shield would be redundant next to a green halo.
 */
class OrbitDialView(
    context: Context,
    private var palette: AppAppearance.Palette,
) : View(context) {

    enum class State { DISCONNECTED, CONNECTING, CONNECTED, DEGRADED, FAILED }

    var state: State = State.DISCONNECTED
        set(value) {
            val previous = field
            field = value
            contentDescription = when (value) {
                State.DISCONNECTED, State.FAILED -> "Connect"
                State.CONNECTING -> "Connecting"
                State.CONNECTED, State.DEGRADED -> "Disconnect"
            }
            if (value == State.CONNECTED || value == State.DEGRADED) {
                if (previous != State.CONNECTED && previous != State.DEGRADED) tickReveal = 0f
                animateTickReveal()
            } else {
                tickReveal = 0f
            }
            if (value == State.CONNECTING || value == State.CONNECTED || value == State.DEGRADED) {
                startLoop()
            } else {
                stopLoop()
            }
            invalidate()
        }

    /** Session uptime text drawn inside the core. Empty hides it. */
    var timerText: String = ""
        set(value) {
            if (field == value) return
            field = value
            invalidate()
        }

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val textPaint = TextPaint(Paint.ANTI_ALIAS_FLAG)
    private val density = resources.displayMetrics.density
    private val bounds = RectF()

    private var loopFraction = 0f
    private var pulse = 0f
    private var tickReveal = 0f
    private var loopAnimator: ValueAnimator? = null
    private var tickAnimator: ValueAnimator? = null

    private val monoTypeface: Typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
    private val labelTypeface: Typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)

    init {
        isClickable = true
        isFocusable = true
        isFocusableInTouchMode = false
        contentDescription = "Connect"
        // Shadow layers and sweep gradients need software rendering to be exact
        // on older GPUs; the view is small and repaints at most 60fps.
        setLayerType(LAYER_TYPE_SOFTWARE, null)
    }

    fun applyPalette(next: AppAppearance.Palette) {
        palette = next
        invalidate()
    }

    private fun accentFor(state: State): Int = when (state) {
        State.DISCONNECTED -> palette.muted
        State.CONNECTING -> AMBER
        State.CONNECTED -> palette.connected
        State.DEGRADED -> AMBER
        State.FAILED -> ERROR
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val desired = dp(266)
        setMeasuredDimension(resolveSize(desired, widthMeasureSpec), resolveSize(desired, heightMeasureSpec))
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width / 2f
        val cy = height / 2f
        val outer = (min(width, height) / 2f) - dp(2)
        val accent = accentFor(state)
        val active = state == State.CONNECTED || state == State.DEGRADED

        if (active) {
            drawHalo(canvas, cx, cy, outer, accent)
            drawRipples(canvas, cx, cy, outer, accent)
        }
        drawRings(canvas, cx, cy, outer)
        drawTicks(canvas, cx, cy, outer, accent)
        drawArc(canvas, cx, cy, outer, accent)
        drawCore(canvas, cx, cy, outer, accent, active)
        drawContents(canvas, cx, cy, accent, active)
    }

    private fun drawHalo(canvas: Canvas, cx: Float, cy: Float, outer: Float, accent: Int) {
        val radius = outer + dp(20) + pulse * dp(4)
        paint.style = Paint.Style.FILL
        paint.shader = RadialGradient(
            cx, cy, radius,
            intArrayOf(
                Sculpt.withAlpha(accent, 0.001f),
                Sculpt.withAlpha(accent, 0.16f + pulse * 0.07f),
                Sculpt.withAlpha(accent, 0f),
            ),
            floatArrayOf(0.62f, 0.84f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawCircle(cx, cy, radius, paint)
        paint.shader = null
    }

    private fun drawRipples(canvas: Canvas, cx: Float, cy: Float, outer: Float, accent: Int) {
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 1.5f * density
        // Two rings, half a cycle apart, expanding 1.0 -> 1.3 and fading out.
        for (offset in listOf(0f, 0.5f)) {
            val phase = (loopFraction + offset) % 1f
            paint.color = Sculpt.withAlpha(accent, 0.42f * (1f - phase))
            canvas.drawCircle(cx, cy, outer * (1f + phase * 0.30f), paint)
        }
    }

    private fun drawRings(canvas: Canvas, cx: Float, cy: Float, outer: Float) {
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 1f * density
        paint.color = Sculpt.withAlpha(palette.ink, 0.06f)
        canvas.drawCircle(cx, cy, outer, paint)

        // Slowly rotating dashed ring. Drawn as short arc segments rather than a
        // DashPathEffect so the rotation is exact and cheap.
        val inner = outer - dp(20)
        paint.color = Sculpt.withAlpha(palette.ink, 0.075f)
        bounds.set(cx - inner, cy - inner, cx + inner, cy + inner)
        val spin = loopFraction * 12f
        var angle = spin
        while (angle < 360f + spin) {
            canvas.drawArc(bounds, angle, 4.5f, false, paint)
            angle += 11f
        }
    }

    private fun drawTicks(canvas: Canvas, cx: Float, cy: Float, outer: Float, accent: Int) {
        val litCount = when (state) {
            State.CONNECTED, State.DEGRADED -> (TICK_COUNT * 0.73f * tickReveal).roundToInt()
            else -> 0
        }
        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND
        for (i in 0 until TICK_COUNT) {
            val major = i % 5 == 0
            val length = if (major) dp(10).toFloat() else dp(7).toFloat()
            // -90° so tick 0 sits at the top and the gauge fills clockwise.
            val rad = Math.toRadians((i * (360.0 / TICK_COUNT)) - 90.0)
            val cosA = cos(rad).toFloat()
            val sinA = sin(rad).toFloat()
            val startR = outer - length
            val lit = i < litCount
            val sweeping = state == State.CONNECTING && ((i + (loopFraction * TICK_COUNT).toInt()) % 3 == 0)
            paint.strokeWidth = if (lit || sweeping) 1.8f * density else 1.5f * density
            paint.color = when {
                lit -> Sculpt.withAlpha(accent, 0.95f)
                sweeping -> Sculpt.withAlpha(AMBER, 0.8f)
                else -> Sculpt.withAlpha(palette.ink, 0.11f)
            }
            canvas.drawLine(
                cx + cosA * startR, cy + sinA * startR,
                cx + cosA * outer, cy + sinA * outer,
                paint,
            )
        }
        paint.strokeCap = Paint.Cap.BUTT
    }

    private fun drawArc(canvas: Canvas, cx: Float, cy: Float, outer: Float, accent: Int) {
        val r = outer - dp(6)
        bounds.set(cx - r, cy - r, cx + r, cy + r)
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 2.5f * density
        paint.strokeCap = Paint.Cap.ROUND

        paint.color = Sculpt.withAlpha(palette.ink, 0.07f)
        canvas.drawArc(bounds, 0f, 360f, false, paint)

        val sweep = when (state) {
            State.CONNECTED, State.DEGRADED -> 306f
            State.CONNECTING -> 90f + pulse * 150f
            else -> 0f
        }
        if (sweep <= 0f) {
            paint.strokeCap = Paint.Cap.BUTT
            return
        }
        val start = if (state == State.CONNECTING) loopFraction * 360f - 90f else -90f
        paint.shader = SweepGradient(
            cx, cy,
            intArrayOf(accent, Sculpt.lighten(accent, 0.3f), accent),
            floatArrayOf(0f, 0.5f, 1f),
        )
        canvas.drawArc(bounds, start, sweep, false, paint)
        paint.shader = null
        paint.strokeCap = Paint.Cap.BUTT
    }

    private fun drawCore(canvas: Canvas, cx: Float, cy: Float, outer: Float, accent: Int, active: Boolean) {
        val r = outer * CORE_RATIO
        val base = Sculpt.blend(palette.surface, palette.ink, 0.045f)

        // Drop shadow under the glass. Green-tinted when the tunnel is up.
        paint.style = Paint.Style.FILL
        paint.color = base
        val shadowColor = if (active) Sculpt.withAlpha(accent, 0.42f) else Sculpt.withAlpha(Color.BLACK, 0.6f)
        paint.setShadowLayer(dp(if (active) 26 else 18).toFloat(), 0f, dp(6).toFloat(), shadowColor)
        canvas.drawCircle(cx, cy, r, paint)
        paint.clearShadowLayer()

        // Body gradient, top-left lit.
        paint.shader = LinearGradient(
            cx - r, cy - r, cx + r * 0.6f, cy + r,
            intArrayOf(Sculpt.lighten(base, 0.10f), base, Sculpt.darken(base, 0.14f)),
            floatArrayOf(0f, 0.46f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawCircle(cx, cy, r, paint)
        paint.shader = null

        // Specular highlight near the top-left — this is what sells "glass".
        paint.shader = RadialGradient(
            cx - r * 0.34f, cy - r * 0.42f, r * 0.95f,
            intArrayOf(Sculpt.withAlpha(Color.WHITE, 0.17f), Sculpt.withAlpha(Color.WHITE, 0f)),
            floatArrayOf(0f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawCircle(cx, cy, r, paint)
        paint.shader = null

        // Moving sheen band, connected only. Clipped to the core circle.
        if (active) {
            val save = canvas.save()
            val clip = android.graphics.Path().apply { addCircle(cx, cy, r, android.graphics.Path.Direction.CW) }
            canvas.clipPath(clip)
            val travel = -1.4f + 2.8f * ((loopFraction * 0.6f) % 1f)
            val bandX = cx + travel * r
            paint.shader = LinearGradient(
                bandX - r * 0.30f, cy - r, bandX + r * 0.30f, cy + r,
                intArrayOf(
                    Sculpt.withAlpha(Color.WHITE, 0f),
                    Sculpt.withAlpha(Color.WHITE, 0.085f),
                    Sculpt.withAlpha(Color.WHITE, 0f),
                ),
                floatArrayOf(0f, 0.5f, 1f),
                Shader.TileMode.CLAMP,
            )
            canvas.drawCircle(cx, cy, r, paint)
            paint.shader = null
            canvas.restoreToCount(save)
        }

        // Bevel edge: brighter at the top, and an accent ring when active.
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 1.4f * density
        paint.shader = LinearGradient(
            cx, cy - r, cx, cy + r,
            intArrayOf(Sculpt.withAlpha(Color.WHITE, 0.24f), Sculpt.withAlpha(Color.WHITE, 0.05f)),
            floatArrayOf(0f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawCircle(cx, cy, r, paint)
        paint.shader = null
        if (active) {
            paint.strokeWidth = 1.2f * density
            paint.color = Sculpt.withAlpha(accent, 0.38f)
            canvas.drawCircle(cx, cy, r - dp(1), paint)
        }
        if (isFocused) {
            paint.strokeWidth = 2f * density
            paint.color = accent
            canvas.drawCircle(cx, cy, r + dp(7), paint)
        }
    }

    private fun drawContents(canvas: Canvas, cx: Float, cy: Float, accent: Int, active: Boolean) {
        if (active && timerText.isNotEmpty()) {
            textPaint.typeface = monoTypeface
            textPaint.textAlign = Paint.Align.CENTER
            textPaint.textSize = 27f * density
            textPaint.color = Sculpt.lighten(accent, 0.55f)
            textPaint.setShadowLayer(dp(14).toFloat(), 0f, 0f, Sculpt.withAlpha(accent, 0.5f))
            canvas.drawText(timerText, cx, cy + 8f * density, textPaint)
            textPaint.clearShadowLayer()

            textPaint.typeface = labelTypeface
            textPaint.textSize = 9f * density
            textPaint.letterSpacing = 0.19f
            textPaint.color = Sculpt.withAlpha(palette.muted, 0.85f)
            canvas.drawText("SESSION", cx, cy + 28f * density, textPaint)
            textPaint.letterSpacing = 0f
            return
        }

        // Shield glyph + call to action.
        val shieldTop = cy - dp(30).toFloat()
        val shieldW = dp(30).toFloat()
        val shieldH = dp(34).toFloat()
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 2f * density
        paint.strokeJoin = Paint.Join.ROUND
        paint.color = when (state) {
            State.CONNECTING -> AMBER
            State.FAILED -> ERROR
            else -> Sculpt.withAlpha(palette.muted, 0.9f)
        }
        val path = android.graphics.Path().apply {
            moveTo(cx, shieldTop)
            lineTo(cx + shieldW / 2f, shieldTop + shieldH * 0.13f)
            lineTo(cx + shieldW / 2f, shieldTop + shieldH * 0.52f)
            cubicTo(
                cx + shieldW / 2f, shieldTop + shieldH * 0.82f,
                cx + shieldW * 0.22f, shieldTop + shieldH * 0.97f,
                cx, shieldTop + shieldH,
            )
            cubicTo(
                cx - shieldW * 0.22f, shieldTop + shieldH * 0.97f,
                cx - shieldW / 2f, shieldTop + shieldH * 0.82f,
                cx - shieldW / 2f, shieldTop + shieldH * 0.52f,
            )
            lineTo(cx - shieldW / 2f, shieldTop + shieldH * 0.13f)
            close()
        }
        canvas.drawPath(path, paint)
        paint.strokeJoin = Paint.Join.MITER

        textPaint.typeface = labelTypeface
        textPaint.textAlign = Paint.Align.CENTER
        textPaint.textSize = 10.5f * density
        textPaint.letterSpacing = 0.19f
        textPaint.color = when (state) {
            State.CONNECTING -> AMBER
            State.FAILED -> ERROR
            else -> Sculpt.withAlpha(palette.muted, 0.85f)
        }
        val cta = when (state) {
            State.CONNECTING -> "CONNECTING"
            State.FAILED -> "RETRY"
            else -> "TAP TO CONNECT"
        }
        canvas.drawText(cta, cx, cy + dp(26).toFloat(), textPaint)
        textPaint.letterSpacing = 0f
    }

    override fun onTouchEvent(event: MotionEvent): Boolean = when (event.actionMasked) {
        MotionEvent.ACTION_DOWN -> {
            animate().scaleX(0.955f).scaleY(0.955f).setDuration(110).start()
            true
        }
        MotionEvent.ACTION_UP -> {
            animate().scaleX(1f).scaleY(1f).setDuration(190).start()
            performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
            performClick()
            true
        }
        MotionEvent.ACTION_CANCEL -> {
            animate().scaleX(1f).scaleY(1f).setDuration(190).start()
            true
        }
        else -> super.onTouchEvent(event)
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        if (keyCode == KeyEvent.KEYCODE_DPAD_CENTER || keyCode == KeyEvent.KEYCODE_ENTER) {
            performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
            performClick()
            return true
        }
        return super.onKeyDown(keyCode, event)
    }

    override fun performClick(): Boolean {
        super.performClick()
        return true
    }

    override fun onFocusChanged(gainFocus: Boolean, direction: Int, previouslyFocusedRect: android.graphics.Rect?) {
        super.onFocusChanged(gainFocus, direction, previouslyFocusedRect)
        invalidate()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        // A view can be detached mid-connection (screen off, config change) and
        // reattached still CONNECTED. Without this the halo and sheen stay frozen.
        if (state == State.CONNECTING || state == State.CONNECTED || state == State.DEGRADED) startLoop()
    }

    override fun onDetachedFromWindow() {
        stopLoop()
        tickAnimator?.cancel()
        tickAnimator = null
        super.onDetachedFromWindow()
    }

    private fun startLoop() {
        if (loopAnimator != null) return
        loopAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = if (state == State.CONNECTING) 1_150 else 3_600
            repeatCount = ValueAnimator.INFINITE
            interpolator = null
            addUpdateListener {
                loopFraction = it.animatedFraction
                pulse = if (loopFraction < 0.5f) loopFraction * 2f else (1f - loopFraction) * 2f
                invalidate()
            }
            start()
        }
    }

    private fun stopLoop() {
        loopAnimator?.cancel()
        loopAnimator = null
        loopFraction = 0f
        pulse = 0f
    }

    private fun animateTickReveal() {
        tickAnimator?.cancel()
        tickAnimator = ValueAnimator.ofFloat(tickReveal, 1f).apply {
            duration = 900
            addUpdateListener {
                tickReveal = it.animatedValue as Float
                invalidate()
            }
            start()
        }
    }

    private fun dp(value: Int): Int = (value * density).roundToInt()

    private fun min(a: Int, b: Int): Int = if (a < b) a else b

    private companion object {
        const val TICK_COUNT = 60
        const val CORE_RATIO = 0.745f
        val AMBER = 0xFFFFC46B.toInt()
        val ERROR = 0xFFFF6B7F.toInt()
    }
}
