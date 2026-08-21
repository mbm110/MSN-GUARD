package com.msnguard.vpn

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.view.View
import kotlin.math.max
import kotlin.math.roundToInt

/**
 * Minimal stacked bar chart for traffic history.
 *
 * Hand-drawn rather than pulled from a charting library, for the same reason the
 * rest of this UI is: the app has no XML layouts and no chart dependency, and a
 * download/upload bar per bucket is ~40 lines of `drawRoundRect`. A library would
 * add a few hundred KB to an APK that users in Iran download over a throttled
 * link.
 *
 * Down and up are stacked in one column rather than drawn side by side: at 24
 * buckets across a phone's width each bar is only a few dp wide, and two adjacent
 * slivers are unreadable while a stack still shows the ratio.
 */
@SuppressLint("ViewConstructor")
class OrbitBarChartView(
    context: Context,
    private val palette: AppAppearance.Palette,
) : View(context) {

    // Download uses the mint accent, upload the violet one — the same pairing the
    // home-screen metric tiles already use for down/up, so the colours mean the
    // same thing on both screens.
    private val downPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = palette.mint }
    private val upPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = palette.violet }
    private val emptyPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = palette.divider }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = palette.muted
        textSize = 9f * context.resources.displayMetrics.density
        typeface = android.graphics.Typeface.create("sans", android.graphics.Typeface.NORMAL)
    }

    private var buckets: List<TrafficHistory.Bucket> = emptyList()
    private val rect = RectF()

    /**
     * Every Nth bucket gets a text label. Labelling all 24 hours overlaps at phone
     * width; every 4th hour and every other day stays legible.
     */
    var labelEvery: Int = 4
        set(value) {
            field = value.coerceAtLeast(1)
            invalidate()
        }

    fun setBuckets(value: List<TrafficHistory.Bucket>) {
        buckets = value
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (buckets.isEmpty()) return

        val density = resources.displayMetrics.density
        val labelHeight = labelPaint.textSize + 4f * density
        val plotHeight = height - labelHeight
        if (plotHeight <= 0f) return

        val gap = 2f * density
        val slot = width.toFloat() / buckets.size
        val barWidth = max(slot - gap, 1.5f * density)
        val radius = (barWidth / 2f).coerceAtMost(3f * density)

        // Scale to the tallest bucket, not to a fixed ceiling: traffic spans orders
        // of magnitude between an idle hour and a video call, and a fixed ceiling
        // flattens every real chart into the bottom of the frame. The trade-off is
        // that bar heights are only comparable WITHIN one chart, which is why the
        // absolute total is printed underneath by the caller.
        val peak = buckets.maxOf { it.total }.coerceAtLeast(1L).toFloat()

        buckets.forEachIndexed { index, bucket ->
            val left = index * slot + (slot - barWidth) / 2f
            val right = left + barWidth

            if (bucket.total == 0L) {
                // A hairline for an idle bucket, so the axis still reads as a
                // continuous timeline instead of having holes in it.
                val top = plotHeight - 1f * density
                rect.set(left, top, right, plotHeight)
                canvas.drawRoundRect(rect, radius, radius, emptyPaint)
            } else {
                val totalHeight = (bucket.total / peak) * plotHeight
                val downHeight = if (bucket.total == 0L) 0f
                else (bucket.rx.toFloat() / bucket.total) * totalHeight

                // Download at the bottom (it dominates), upload stacked above.
                rect.set(left, plotHeight - downHeight, right, plotHeight)
                canvas.drawRoundRect(rect, radius, radius, downPaint)
                if (bucket.tx > 0L) {
                    rect.set(left, plotHeight - totalHeight, right, plotHeight - downHeight)
                    canvas.drawRoundRect(rect, radius, radius, upPaint)
                }
            }

            if (index % labelEvery == 0) {
                val textWidth = labelPaint.measureText(bucket.label)
                canvas.drawText(
                    bucket.label,
                    (left + barWidth / 2f) - textWidth / 2f,
                    height - 2f * density,
                    labelPaint,
                )
            }
        }
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = MeasureSpec.getSize(widthMeasureSpec)
        val height = when (MeasureSpec.getMode(heightMeasureSpec)) {
            MeasureSpec.EXACTLY -> MeasureSpec.getSize(heightMeasureSpec)
            else -> (96 * resources.displayMetrics.density).roundToInt()
        }
        setMeasuredDimension(width, height)
    }
}
