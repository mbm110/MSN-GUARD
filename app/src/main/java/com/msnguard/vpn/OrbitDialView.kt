package com.msnguard.vpn

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
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
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * The Orbit dial: the one control that matters on the main screen.
 *
 * Layers, outermost first — same list as the approved mock:
 *  1. breathing halo (connected only)
 *  2. two ripple rings that expand and fade (connected only)
 *  3. static hairline ring + slowly rotating dashed ring
 *  4. 60 gauge ticks, every fifth longer, lighting green as the tunnel comes up
 *  5. progress arc — sweeps while connecting, settles at ~85% when connected
 *  6. the glass core: radial specular, body gradient, bevel edge, inner bottom
 *     shadow, and a sheen band that crosses every ~5s
 *  7. contents: shield + "TAP TO CONNECT" when down, session timer when up
 *
 * GEOMETRY, and why it matters: the halo and the ripples grow *beyond* the ring.
 * The first Orbit build sized the ring to the full view, so the pulse expanded
 * outside the view's own bounds and the parent clipped it — the dial looked like
 * it was bursting out of an invisible box, and the bottom of the glow was simply
 * missing. Every radius is now derived from [RING_RATIO] of the half-extent, so
 * the biggest thing this view ever draws (ripple at 1.30x, halo at ring+22dp)
 * still lands inside the measured square. Nothing is clipped, and the heartbeat
 * scales inside its own frame.
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

    /**
     * Connect progress, 0..100, or -1 for "no measurable progress".
     *
     * Only drawn in [State.CONNECTING], and only when non-negative: a transport
     * that cannot report real progress shows the spinner alone rather than a
     * fabricated number. See MsnGuardVpnService.EXTRA_PROGRESS.
     */
    var progressPercent: Int = -1
        set(value) {
            if (field == value) return
            field = value
            invalidate()
        }

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val textPaint = TextPaint(Paint.ANTI_ALIAS_FLAG)
    private val density = resources.displayMetrics.density
    private val bounds = RectF()
    private val corePath = Path()

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
        // on older GPUs; the view is small and repaints at most 20fps.
        setLayerType(LAYER_TYPE_SOFTWARE, null)
    }

    fun applyPalette(next: AppAppearance.Palette) {
        palette = next
        invalidate()
    }

    private fun accentFor(state: State): Int = when (state) {
        State.DISCONNECTED -> palette.muted
        State.CONNECTING -> palette.amber
        State.CONNECTED -> palette.connected
        State.DEGRADED -> palette.amber
        State.FAILED -> palette.danger
    }

    /**
     * Uniform shrink factor for the whole dial, bleed included.
     *
     * The console asks for this when its natural height would overflow the
     * viewport: shrinking the dial is how the screen stops scrolling. Because
     * the factor scales the measured box AND the ring together, the ratio
     * between them is untouched, so the halo and ripples keep exactly the
     * proportional room they have at 1.0 and cannot be cropped by shrinking.
     */
    var sizeScale: Float = 1f
        set(value) {
            val clamped = value.coerceIn(MIN_SIZE_SCALE, 1f)
            if (field != clamped) {
                field = clamped
                requestLayout()
            }
        }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        // The measured box is the RING plus [BLEED_DP], not the ring alone.
        //
        // This is the actual cause of the dial having been cropped on all four
        // sides, and clipChildren=false on the ancestors could never have fixed
        // it: this view runs with LAYER_TYPE_SOFTWARE, so Android allocates an
        // offscreen bitmap exactly the size of the VIEW and every pixel outside
        // it is discarded before any parent gets a say. The halo reaches
        // HALO_OUTSET+HALO_PULSE past the ring and a ripple reaches
        // ring*RIPPLE_GROWTH past it, in every direction — with a box of exactly
        // 2*ring all of that got shaved flat.
        //
        // So the canvas is always ring + bleed, and BLEED_DP is derived from
        // those two reaches rather than guessed. Shrinking goes through
        // [sizeScale], which scales box and ring by the same factor, so the
        // bleed can never be squeezed out from under the glow.
        val desired = dp(((RING_DP + BLEED_DP) * 2 * sizeScale).roundToInt())
        val size = resolveSize(desired, widthMeasureSpec)
            .coerceAtMost(resolveSize(desired, heightMeasureSpec))
        // Always square: a non-square canvas would put the ring off-centre.
        setMeasuredDimension(size, size)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width / 2f
        val cy = height / 2f
        val half = minOf(width, height) / 2f
        // The ring is RING_DP scaled by [sizeScale], and the view was measured
        // (RING_DP + BLEED_DP) * sizeScale, so the glow always has its full
        // proportional room.
        //
        // The second term is the safety net: if a parent hands this view LESS
        // than it asked for (a narrow screen, an exact-size spec), the ring
        // shrinks to the largest value that still leaves the bleed intact rather
        // than letting the outer layers get shaved. Never remove it — it is the
        // difference between a smaller dial and a cropped one.
        val ring = minOf(
            dp(RING_DP) * sizeScale,
            half * RING_DP / (RING_DP + BLEED_DP).toFloat(),
        )
        // Every inner offset below is authored against RING_DP, so they follow
        // the ring by this factor instead of staying at a fixed dp and throwing
        // the proportions off whenever the dial shrinks.
        val geo = ring / dp(RING_DP)
        val accent = accentFor(state)
        val active = state == State.CONNECTED || state == State.DEGRADED

        if (active) {
            drawHalo(canvas, cx, cy, ring, accent, geo)
            drawRipples(canvas, cx, cy, ring, accent)
        }
        drawRings(canvas, cx, cy, ring, geo)
        drawTicks(canvas, cx, cy, ring, accent, geo)
        drawArc(canvas, cx, cy, ring, accent, geo)
        drawCore(canvas, cx, cy, ring, accent, active)
        drawContents(canvas, cx, cy, ring, accent, active, geo)
    }

    /**
     * Soft breathing bloom just outside the ring.
     *
     * Not clamped to the view any more: the mock's halo is `inset:-24px` on the
     * dial box, so it is *meant* to spill past the ring. Clamping it was what
     * flattened the glow on the bottom edge.
     */
    private fun drawHalo(canvas: Canvas, cx: Float, cy: Float, ring: Float, accent: Int, geo: Float) {
        val radius = ring + dp(HALO_OUTSET_DP) * geo + pulse * dp(HALO_PULSE_DP) * geo
        paint.style = Paint.Style.FILL
        paint.shader = RadialGradient(
            cx, cy, radius,
            intArrayOf(
                Sculpt.withAlpha(accent, 0.001f),
                Sculpt.withAlpha(accent, 0.15f + pulse * 0.07f),
                Sculpt.withAlpha(accent, 0f),
            ),
            floatArrayOf(0.60f, 0.86f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawCircle(cx, cy, radius, paint)
        paint.shader = null
    }

    /** Two rings, half a cycle apart, expanding 1.0 → 1.30 and fading out. */
    private fun drawRipples(canvas: Canvas, cx: Float, cy: Float, ring: Float, accent: Int) {
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 1.5f * density
        for (offset in listOf(0f, 0.5f)) {
            val phase = (loopFraction + offset) % 1f
            paint.color = Sculpt.withAlpha(accent, 0.40f * (1f - phase))
            canvas.drawCircle(cx, cy, ring * (1f + phase * RIPPLE_GROWTH), paint)
        }
    }

    private fun drawRings(canvas: Canvas, cx: Float, cy: Float, ring: Float, geo: Float) {
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 1f * density
        paint.color = Sculpt.withAlpha(palette.ink, 0.055f)
        canvas.drawCircle(cx, cy, ring, paint)

        // Slowly rotating dashed ring, drawn as short arcs rather than a
        // DashPathEffect so the rotation is exact and cheap.
        val inner = ring - dp(20) * geo
        paint.color = Sculpt.withAlpha(palette.ink, 0.07f)
        bounds.set(cx - inner, cy - inner, cx + inner, cy + inner)
        val spin = loopFraction * 12f
        var angle = spin
        while (angle < 360f + spin) {
            canvas.drawArc(bounds, angle, 4.5f, false, paint)
            angle += 11f
        }
    }

    /**
     * The gauge, matching the mock tick-for-tick.
     *
     * The mock has 60 identical ticks (1.5px x 7px), lights the first 44 when
     * connected, and paints every third tick amber while connecting. The previous
     * Kotlin version invented long "major" ticks every fifth position and a
     * 3-tick chasing comet, which is why it read as busier and less clean than
     * the preview.
     */
    private fun drawTicks(canvas: Canvas, cx: Float, cy: Float, ring: Float, accent: Int, geo: Float) {
        val litCount = when (state) {
            State.CONNECTED, State.DEGRADED -> (TICK_LIT * tickReveal).roundToInt()
            else -> 0
        }
        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND
        val length = dp(7) * geo
        for (i in 0 until TICK_COUNT) {
            // -90° so tick 0 sits at the top and the gauge fills clockwise.
            val rad = Math.toRadians((i * (360.0 / TICK_COUNT)) - 90.0)
            val cosA = cos(rad).toFloat()
            val sinA = sin(rad).toFloat()
            val startR = ring - length
            val lit = i < litCount
            // Every third tick glows amber while connecting — the mock's `.sw`
            // class — and the whole set breathes with the loop instead of a comet
            // running around the rim.
            val sweeping = state == State.CONNECTING && i % 3 == 0
            paint.strokeWidth = 1.5f * density
            when {
                lit -> {
                    paint.color = Sculpt.withAlpha(accent, 0.95f)
                    paint.setShadowLayer(3f * density, 0f, 0f, Sculpt.withAlpha(accent, 0.8f))
                }
                sweeping -> {
                    val breath = 0.45f + pulse * 0.5f
                    paint.color = Sculpt.withAlpha(palette.amber, breath)
                    paint.setShadowLayer(3f * density, 0f, 0f, Sculpt.withAlpha(palette.amber, 0.75f))
                }
                else -> {
                    paint.color = Sculpt.withAlpha(palette.ink, 0.11f)
                    paint.clearShadowLayer()
                }
            }
            canvas.drawLine(
                cx + cosA * startR, cy + sinA * startR,
                cx + cosA * ring, cy + sinA * ring,
                paint,
            )
        }
        paint.clearShadowLayer()
        paint.strokeCap = Paint.Cap.BUTT
    }

    private fun drawArc(canvas: Canvas, cx: Float, cy: Float, ring: Float, accent: Int, geo: Float) {
        val r = ring - dp(13) * geo
        bounds.set(cx - r, cy - r, cx + r, cy + r)
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 2.5f * density
        paint.strokeCap = Paint.Cap.ROUND

        paint.color = Sculpt.withAlpha(palette.ink, 0.06f)
        canvas.drawArc(bounds, 0f, 360f, false, paint)

        val sweep = when (state) {
            // 798 - 110 of a 798 dasharray in the mock ≈ 86% of the circle.
            State.CONNECTED, State.DEGRADED -> 310f
            State.CONNECTING -> 80f + pulse * 140f
            else -> 0f
        }
        if (sweep <= 0f) {
            paint.strokeCap = Paint.Cap.BUTT
            return
        }
        val start = if (state == State.CONNECTING) loopFraction * 360f - 90f else -90f
        paint.shader = SweepGradient(
            cx, cy,
            intArrayOf(palette.connected, palette.mint, palette.connected),
            floatArrayOf(0f, 0.5f, 1f),
        ).takeIf { state == State.CONNECTED || state == State.DEGRADED }
            ?: SweepGradient(
                cx, cy,
                intArrayOf(accent, Sculpt.lighten(accent, 0.35f), accent),
                floatArrayOf(0f, 0.5f, 1f),
            )
        canvas.drawArc(bounds, start, sweep, false, paint)
        paint.shader = null
        paint.strokeCap = Paint.Cap.BUTT
    }

    private fun drawCore(canvas: Canvas, cx: Float, cy: Float, ring: Float, accent: Int, active: Boolean) {
        val r = ring * CORE_RATIO
        val base = Sculpt.blend(palette.surface, palette.ink, 0.035f)

        // Drop shadow under the glass; accent-tinted when the tunnel is up.
        paint.style = Paint.Style.FILL
        paint.color = base
        val shadowColor = if (active) Sculpt.withAlpha(accent, 0.38f) else Sculpt.withAlpha(Color.BLACK, 0.65f)
        paint.setShadowLayer(dp(if (active) 22 else 16).toFloat(), 0f, dp(6).toFloat(), shadowColor)
        canvas.drawCircle(cx, cy, r, paint)
        paint.clearShadowLayer()

        // Body gradient, lit from the top-left.
        paint.shader = LinearGradient(
            cx - r, cy - r, cx + r * 0.6f, cy + r,
            intArrayOf(Sculpt.lighten(base, 0.11f), base, Sculpt.darken(base, 0.16f)),
            floatArrayOf(0f, 0.46f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawCircle(cx, cy, r, paint)
        paint.shader = null

        // Specular highlight near the top-left — this is what sells "glass".
        paint.shader = RadialGradient(
            cx - r * 0.34f, cy - r * 0.42f, r * 0.95f,
            intArrayOf(Sculpt.withAlpha(Color.WHITE, 0.16f), Sculpt.withAlpha(Color.WHITE, 0f)),
            floatArrayOf(0f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawCircle(cx, cy, r, paint)
        paint.shader = null

        // Sheen band crossing the glass, connected only. Clipped to the circle.
        if (active) {
            val save = canvas.save()
            corePath.reset()
            corePath.addCircle(cx, cy, r, Path.Direction.CW)
            canvas.clipPath(corePath)
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

        // Inner bottom shadow: the fourth sculpt layer, inside the glass.
        paint.shader = RadialGradient(
            cx, cy + r * 0.62f, r * 0.95f,
            intArrayOf(Sculpt.withAlpha(Color.BLACK, 0.30f), Sculpt.withAlpha(Color.BLACK, 0f)),
            floatArrayOf(0f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawCircle(cx, cy, r, paint)
        paint.shader = null

        // Bevel edge: brighter at the top; accent ring when active.
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
            paint.color = Sculpt.withAlpha(accent, 0.36f)
            canvas.drawCircle(cx, cy, r - dp(1), paint)
        }
        if (isFocused) {
            paint.strokeWidth = 2f * density
            paint.color = accent
            canvas.drawCircle(cx, cy, r + dp(6), paint)
        }
    }

    private fun drawContents(
        canvas: Canvas,
        cx: Float,
        cy: Float,
        ring: Float,
        accent: Int,
        active: Boolean,
        geo: Float,
    ) {
        if (active && timerText.isNotEmpty()) {
            textPaint.typeface = monoTypeface
            textPaint.textAlign = Paint.Align.CENTER
            textPaint.textSize = 26f * density * geo
            textPaint.color = Sculpt.lighten(accent, 0.55f)
            textPaint.setShadowLayer(dp(14) * geo, 0f, 0f, Sculpt.withAlpha(accent, 0.5f))
            canvas.drawText(timerText, cx, cy + 7f * density * geo, textPaint)
            textPaint.clearShadowLayer()

            textPaint.typeface = labelTypeface
            textPaint.textSize = 9f * density * geo
            textPaint.letterSpacing = 0.19f
            textPaint.color = Sculpt.withAlpha(palette.faint, 0.95f)
            canvas.drawText("SESSION", cx, cy + 27f * density * geo, textPaint)
            textPaint.letterSpacing = 0f
            return
        }

        // Shield glyph + call to action.
        val shieldTop = cy - dp(30) * geo
        val shieldW = dp(30) * geo
        val shieldH = dp(34) * geo
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 2f * density
        paint.strokeJoin = Paint.Join.ROUND
        paint.color = when (state) {
            State.CONNECTING -> palette.amber
            State.FAILED -> palette.danger
            else -> Sculpt.withAlpha(palette.muted, 0.9f)
        }
        // While a connect is measurably progressing, the percentage replaces the
        // shield glyph: the spinner already says "working", so the number is the
        // only new information. Transports that cannot measure progress keep the
        // glyph — no fabricated figure (see progressPercent).
        if (state == State.CONNECTING && progressPercent >= 0) {
            textPaint.typeface = monoTypeface
            textPaint.textAlign = Paint.Align.CENTER
            textPaint.textSize = 22f * density * geo
            textPaint.color = palette.amber
            canvas.drawText("$progressPercent%", cx, cy - dp(4) * geo, textPaint)
            textPaint.typeface = labelTypeface
            textPaint.textSize = 9f * density * geo
            textPaint.letterSpacing = 0.19f
            textPaint.color = Sculpt.withAlpha(palette.faint, 0.95f)
            canvas.drawText("PROGRESS", cx, cy + dp(12) * geo, textPaint)
            textPaint.letterSpacing = 0f

            textPaint.typeface = labelTypeface
            textPaint.textAlign = Paint.Align.CENTER
            textPaint.textSize = 10.5f * density * geo
            textPaint.letterSpacing = 0.19f
            textPaint.color = palette.amber
            canvas.drawText("CONNECTING", cx, cy + dp(26) * geo, textPaint)
            textPaint.letterSpacing = 0f
            return
        }
        val path = Path().apply {
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
        // The tick inside the shield, as in the mock.
        paint.strokeWidth = 1.7f * density
        canvas.drawPath(Path().apply {
            moveTo(cx - shieldW * 0.15f, shieldTop + shieldH * 0.50f)
            lineTo(cx - shieldW * 0.02f, shieldTop + shieldH * 0.63f)
            lineTo(cx + shieldW * 0.20f, shieldTop + shieldH * 0.36f)
        }, paint)
        paint.strokeJoin = Paint.Join.MITER

        textPaint.typeface = labelTypeface
        textPaint.textAlign = Paint.Align.CENTER
        textPaint.textSize = 10.5f * density * geo
        textPaint.letterSpacing = 0.19f
        textPaint.color = when (state) {
            State.CONNECTING -> palette.amber
            State.FAILED -> palette.danger
            else -> Sculpt.withAlpha(palette.faint, 0.95f)
        }
        val cta = when (state) {
            State.CONNECTING -> "CONNECTING"
            State.FAILED -> "RETRY"
            else -> "TAP TO CONNECT"
        }
        canvas.drawText(cta, cx, cy + dp(26) * geo, textPaint)
        textPaint.letterSpacing = 0f
    }

    override fun onTouchEvent(event: MotionEvent): Boolean = when (event.actionMasked) {
        MotionEvent.ACTION_DOWN -> {
            animate().scaleX(0.965f).scaleY(0.965f).setDuration(110).start()
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
        // A view can be detached mid-connection (screen off, returning from
        // Recents) and reattached still CONNECTED. Without this the halo and
        // sheen stay frozen.
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
            duration = if (state == State.CONNECTING) 1_150 else 4_400
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

    companion object {
        const val TICK_COUNT = 60
        /** Ticks lit when connected — 44 of 60, as in the mock. */
        const val TICK_LIT = 44
        /** How far a ripple grows past the ring (mock: scale(1) → scale(1.32)). */
        const val RIPPLE_GROWTH = 0.32f
        /**
         * Ring radius in dp.
         *
         * The mock drew a 266dp box (r = 133dp). That made the whole console
         * 840dp tall on a 1080x2400 phone, ~70dp more than the viewport, so the
         * main screen scrolled and part of the action bar sat below the fold.
         * 112dp is the largest ring that lets the full column fit without
         * scrolling while keeping the dial the dominant element on the screen.
         */
        const val RING_DP = 112
        /** How far past the ring the halo's outer edge sits, at rest. */
        const val HALO_OUTSET_DP = 24
        /** Extra reach the halo gains at the top of its breath. */
        const val HALO_PULSE_DP = 7
        /**
         * Slack so a feathered edge or a stroke's outer half never lands on the
         * last row of pixels. 4dp covers the ripple's 1.5px stroke and the
         * tick shadow at any density.
         */
        const val BLEED_MARGIN_DP = 4
        /**
         * Extra radius the view is measured with, beyond the ring, so the layers
         * that deliberately paint outside the ring have canvas to land on.
         *
         * DERIVED, not hand-tuned: this used to be a magic 46 that had to be
         * re-checked by hand every time the ring changed, and getting it wrong is
         * exactly what shaved the glow flat on all four sides. Now it is computed
         * from the two things that actually paint outside the ring —
         *
         *   - a ripple, reaching ring * RIPPLE_GROWTH past the ring
         *   - the halo, reaching HALO_OUTSET + HALO_PULSE past the ring
         *
         * — so changing RING_DP alone can never crop the dial again.
         */
        val BLEED_DP: Int = ceil(
            maxOf(RING_DP * RIPPLE_GROWTH, (HALO_OUTSET_DP + HALO_PULSE_DP).toFloat())
        ).toInt() + BLEED_MARGIN_DP
        /**
         * Floor for [sizeScale]. Below this the dial stops reading as the primary
         * control, so a screen too short even for the shrunk dial is allowed to
         * scroll instead — scrolling is recoverable, an unreachable connect
         * button is not.
         */
        const val MIN_SIZE_SCALE = 0.78f
        /** Core radius as a fraction of the ring: 99dp core / 133dp ring. */
        const val CORE_RATIO = 0.744f
    }
}
