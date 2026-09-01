package com.msnguard.vpn

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
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
    /**
     * The readable sibling of [accent], used for the key label only.
     *
     * Defaults to [accent] so the dark palette and any existing call site are
     * unchanged; the light palette passes a darkened value.
     */
    private val accentText: Int = accent,
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
        // accentText, not accent: this is 8.5sp bold lettering, the strictest
        // contrast case in the app. On the light palette the vivid accent sits at
        // 3.4:1 (fine for the bars below, not for letters); accentText is 6:1.
        // The sparkline keeps `accent`, which is where the colour identity lives.
        addView(context.orbitLabel(keyText, 8.5f, Sculpt.withAlpha(accentText, 0.92f), medium = true, spacing = 0.13f))

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
 * The thumb is a sibling view positioned by translation rather than a background
 * on the selected cell, so the movement is animatable and the cells stay dumb
 * text views. Each cell also gets its own sculpted press state — tapping
 * WireGuard used to give no visual feedback at all because the cells were bare
 * TextViews with no background.
 *
 * ## Why it grids instead of staying one row
 *
 * At five transports the row was already tight; SHARD made six, and six cells of
 * 10.5sp across a phone's width truncates every label to about four characters
 * ("WIRE…", "PSIP…"). A picker whose labels cannot be read is not a picker.
 *
 * So the rail lays out as a grid of [perRow] columns and as many rows as that
 * needs, and the thumb moves in both axes. With six entries at the default of
 * three per row that is two rows of three — each cell twice as wide as before,
 * so nothing is ellipsised, and the control still reads as one object rather
 * than two separate pickers.
 *
 * The caller passes labels only; the grid shape is derived. [rowCount] is public
 * so the screen can size the view without duplicating the arithmetic.
 */
class TransportRail(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val labels: List<String>,
    private val perRow: Int = 3,
    private val onPick: (Int) -> Unit,
) : FrameLayout(context) {

    private val thumb: View
    private val cells = mutableListOf<TextView>()
    private var selectedIndex = 0
    private var thumbAnimator: ValueAnimator? = null

    /** Hairline separators between cells. See [onDraw]. */
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = context.resources.displayMetrics.density * 0.75f
        color = Sculpt.withAlpha(palette.faint, 0.22f)
    }

    /** How many rows the labels need at [perRow] columns. */
    val rowCount: Int = if (labels.isEmpty()) {
        1
    } else {
        (labels.size + perRow - 1) / perRow
    }

    /** Columns actually laid out. Never more than there are labels. */
    private val columns: Int = perRow.coerceAtMost(labels.size.coerceAtLeast(1))

    /** Width of one cell, derived from the padded content box. */
    private val cellWidth: Float
        get() {
            val inner = width - paddingLeft - paddingRight
            if (inner <= 0) return 0f
            return inner.toFloat() / columns
        }

    /** Height of one cell. Rows are equal-weighted, so this is just a division. */
    private val cellHeight: Float
        get() {
            val inner = height - paddingTop - paddingBottom
            if (inner <= 0) return 0f
            return inner.toFloat() / rowCount
        }

    init {
        val fill = Sculpt.recess(palette.surface, 0.30f)
        // 24dp rather than the pill radius: a two-row control with a 999 radius
        // reads as a lozenge with dead corners. Kept at 999 when there is only one
        // row, so nothing about the single-row look changes.
        val radius = if (rowCount > 1) 24 else 999
        background = Sculpt.recessedBackground(resources.displayMetrics.density, fill, radius)
        setPadding(context.px(5), context.px(5), context.px(5), context.px(5))
        // ViewGroups skip onDraw by default; the separators are drawn there.
        setWillNotDraw(false)

        thumb = View(context).apply {
            background = Sculpt.sculptedBackground(
                resources.displayMetrics.density,
                Sculpt.blend(palette.surface, palette.primary, 0.16f),
                if (rowCount > 1) 20 else 999,
                Sculpt.withAlpha(palette.primary, 0.45f),
            )
        }
        // No margins here: the FrameLayout padding already insets children. An
        // earlier version added another 5dp on three sides on top of the padding,
        // which is why the lit thumb sat short of the cell it was under.
        addView(thumb, LayoutParams(0, 0))

        val grid = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        labels.indices.step(columns).forEach { start ->
            val row = LinearLayout(context).apply { orientation = LinearLayout.HORIZONTAL }
            for (index in start until (start + columns)) {
                if (index >= labels.size) {
                    // Short last row: a weighted spacer, so the cells that do exist
                    // keep the same width as every other row's instead of stretching
                    // to fill and leaving the thumb the wrong size under them.
                    row.addView(
                        View(context),
                        LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f),
                    )
                    continue
                }
                val cell = object : TextView(context) {
                    override fun setPressed(pressed: Boolean) {
                        super.setPressed(pressed)
                        background = if (pressed) {
                            Sculpt.sculptedBackground(
                                resources.displayMetrics.density,
                                Sculpt.recess(palette.surface, 0.18f),
                                if (rowCount > 1) 20 else 999,
                                pressed = true,
                            )
                        } else {
                            null
                        }
                    }
                }.apply {
                    this.text = labels[index]
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
                row.addView(
                    cell,
                    LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f),
                )
            }
            grid.addView(
                row,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f),
            )
        }
        addView(grid, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        ))
    }

    /**
     * Sizes the thumb here, before children are measured — not in
     * [onSizeChanged].
     *
     * onSizeChanged runs *during* a layout pass, and a requestLayout() issued from
     * inside one is swallowed: the thumb kept its initial 0×0 and stayed invisible
     * until some later, unrelated pass happened to remeasure it. That is why the
     * default selection had no frame around it on a cold start while tapping any
     * cell made one appear — the tap's pressed-state background change was the
     * unrelated pass. Setting the size before super.onMeasure() means the thumb is
     * measured correctly on the very first pass.
     */
    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val innerWidth = MeasureSpec.getSize(widthMeasureSpec) - paddingLeft - paddingRight
        val innerHeight = MeasureSpec.getSize(heightMeasureSpec) - paddingTop - paddingBottom
        if (innerWidth > 0 && innerHeight > 0) {
            val cw = (innerWidth.toFloat() / columns).roundToInt()
            val ch = (innerHeight.toFloat() / rowCount).roundToInt()
            val params = thumb.layoutParams
            if (params.width != cw || params.height != ch) {
                params.width = cw
                params.height = ch
            }
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec)
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (cellWidth <= 0f || cellHeight <= 0f) return
        thumb.translationX = (selectedIndex % columns) * cellWidth
        thumb.translationY = (selectedIndex / columns) * cellHeight
    }

    /**
     * Hairlines between the cells.
     *
     * Drawn before children (so the lit thumb and the labels sit on top of them)
     * and inset from the control's own edges, which is what makes six labels in one
     * recessed box read as a grid rather than a word soup. Inner edges only —
     * a line flush against the rounded border would clip against it.
     */
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cw = cellWidth
        val ch = cellHeight
        if (cw <= 0f || ch <= 0f) return
        val inset = ch * 0.22f
        val insetX = cw * 0.18f
        for (column in 1 until columns) {
            val x = paddingLeft + column * cw
            canvas.drawLine(x, paddingTop + inset, x, (height - paddingBottom) - inset, gridPaint)
        }
        for (row in 1 until rowCount) {
            val y = paddingTop + row * ch
            canvas.drawLine(paddingLeft + insetX, y, (width - paddingRight) - insetX, y, gridPaint)
        }
    }

    fun select(index: Int, animate: Boolean) {
        if (index !in labels.indices) return
        selectedIndex = index
        cells.forEachIndexed { i, cell ->
            cell.setTextColor(if (i == index) palette.ink else palette.faint)
        }
        val slotX = cellWidth
        val slotY = cellHeight
        if (slotX <= 0f || slotY <= 0f) return
        val targetX = (index % columns) * slotX
        val targetY = (index / columns) * slotY
        thumbAnimator?.cancel()
        if (!animate) {
            thumb.translationX = targetX
            thumb.translationY = targetY
            return
        }
        val fromX = thumb.translationX
        val fromY = thumb.translationY
        thumbAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 330
            interpolator = OvershootInterpolator(1.1f)
            addUpdateListener {
                val t = it.animatedValue as Float
                thumb.translationX = fromX + (targetX - fromX) * t
                thumb.translationY = fromY + (targetY - fromY) * t
            }
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
