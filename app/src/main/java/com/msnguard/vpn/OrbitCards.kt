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
    fun render(address: String, countryCode: String?, tunnelled: Boolean) {
        keyView.text = if (tunnelled) "EXIT NODE" else "YOUR IP"
        if (address.isBlank() || address == UNAVAILABLE) {
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
