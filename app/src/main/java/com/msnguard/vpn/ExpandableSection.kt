package com.msnguard.vpn

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.transition.AutoTransition
import android.transition.TransitionManager
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.animation.PathInterpolator
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.roundToInt

/**
 * An expandable settings section in the Orbit visual language.
 *
 * Wraps [OrbitSectionHeader]'s neon-tick + uppercase caption with a chevron and
 * a collapsible body, so the settings page stops being a two-screen-long
 * unstructured list. Sections are independent — any number can be open at once —
 * because collapsing one to reveal another costs a scroll you cannot undo
 * mid-tap, and a single-open accordion makes comparing two sections impossible.
 *
 * Pure programmatic Views, matching everything else in this package: the app
 * ships no layout XML, and adding it for one screen would split the styling
 * story in two. Dark-card styling, toggles and subtitles are untouched — this
 * only owns the header and the visibility of the body it is given.
 *
 * Usage, the same place a `sectionLabel(...)` used to go:
 *
 * ```
 * content.addView(expandableSection(Strings.t("PROTECTION")) { body ->
 *     body.addView(killSwitchRow)
 *     body.addView(autoReconnectRow)
 * })
 * ```
 */
class ExpandableSection(
    context: Context,
    private val palette: AppAppearance.Palette,
    title: String,
    /** Drawn expanded on first show. Protection is the section a first-time
     *  user actually needs to see; the rest stay shut until they are looked for. */
    initiallyExpanded: Boolean = false,
    /** Notified after every toggle. Used by the settings page to re-fit its
     *  entrance animation window to the new content height. */
    private val onExpansionChanged: ((expanded: Boolean) -> Unit)? = null,
    private val body: (LinearLayout) -> Unit,
) : LinearLayout(context) {

    private var sectionTitle: String = title
    private val density = resources.displayMetrics.density

    private val content: LinearLayout
    private val chevron: ChevronView
    private var expanded = initiallyExpanded

    init {
        orientation = VERTICAL

        content = LinearLayout(context).apply {
            orientation = VERTICAL
            // A GONE body measures zero, so a fast double-tap that out-runs the
            // transition cannot leave a gap where rows were about to appear.
            visibility = if (initiallyExpanded) VISIBLE else GONE
        }

        val header = HeaderRow(context, palette, title).apply {
            isClickable = true
            isFocusable = true
            contentDescription = "$sectionTitle ${if (expanded) "باز" else "بسته"} — برای تغییر، ضربه بزنید"
        }
        chevron = header.chevronView()
        chevron.rotation = if (initiallyExpanded) 180f else 0f
        header.setOnClickListener { toggle() }

        addView(header, LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        addView(content, LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(8)
        })

        body(content)
    }

    /** Flips [expanded] and animates both the body height and the chevron. */
    fun toggle() {
        // beginDelayedTransition has to capture the parent *before* the
        // visibility change, or there is no snapshot to animate from. The parent
        // is null while the section is still detached, and toggling then would
        // leave the body in a state the transition never captured — so it is
        // skipped and the body simply arrives at its final visibility.
        val parent = parent as? ViewGroup
        expanded = !expanded
        if (parent != null) {
            TransitionManager.beginDelayedTransition(parent, AutoTransition().apply {
                // Matching the chevron's own curve makes the two animations read
                // as one gesture rather than two speeds layered on top of each other.
                interpolator = PathInterpolator(0.2f, 0f, 0f, 1f)
                duration = 220
            })
        }
        content.visibility = if (expanded) VISIBLE else GONE
        chevron.animate()
            .rotation(if (expanded) 180f else 0f)
            .setDuration(220)
            .setInterpolator(PathInterpolator(0.2f, 0f, 0f, 1f))
            .start()
        contentDescription = "$sectionTitle ${if (expanded) "باز" else "بسته"} — برای تغییر، ضربه بزنید"
        onExpansionChanged?.invoke(expanded)
    }

    /** Force a state without animating — used when restoring a saved state. */
    fun setExpanded(value: Boolean, animate: Boolean = true) {
        if (expanded == value) return
        if (animate) toggle() else {
            expanded = value
            content.visibility = if (value) VISIBLE else GONE
            chevron.rotation = if (value) 180f else 0f
        }
    }

    fun isExpanded(): Boolean = expanded

    /**
     * Hand the caller the body so it can add rows to it after construction.
     *
     * Rows are added in [body] for the common case, but the Psiphon section's
     * availability depends on live state that is resolved after the page is
     * built, so it needs a handle.
     */
    fun body(block: LinearLayout.() -> Unit) = content.block()

    private fun dp(value: Int): Int = (value * density).roundToInt()

    /**
     * The clickable header: neon tick, uppercase caption, trailing chevron.
     *
     * Layout mirrors [OrbitSectionHeader] exactly. The caption gets weight 1 so
     * the chevron is pinned to the far right without a second container — one
     * weight-less LinearLayout cheaper in the view tree.
     */
    private inner class HeaderRow(
        context: Context,
        palette: AppAppearance.Palette,
        text: String,
    ) : LinearLayout(context) {

        private val chevron: ChevronView = ChevronView(context, palette.neonBlue)

        init {
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            // Left/right inset equal to the rows' horizontal padding so the tick
            // and the rows' own left edge line up; vertical padding is smaller
            // because a header is a divider, not a full tappable surface.
            setPadding(dp(16), dp(10), dp(14), dp(10))

            addView(TickView(context, palette.neonBlue), LayoutParams(dp(3), dp(13)).apply {
                rightMargin = dp(9)
            })
            addView(TextView(context).apply {
                this.text = text
                val english = AppLanguage.current() == "en"
                textSize = if (english) 11.5f else 15.5f
                setTextColor(
                    if (english) {
                        palette.muted
                    } else if (AppAppearance.isDark(palette.muted)) {
                        Sculpt.blend(palette.muted, palette.neonBlue, 0.55f)
                    } else {
                        palette.muted
                    }
                )
                letterSpacing = if (english) 0.14f else 0f
                typeface = if (english) {
                    Typeface.create("sans-serif-medium", Typeface.NORMAL)
                } else {
                    Typefaces.bold(context)
                }
                if (!english) setLineSpacing(0f, Typefaces.lineHeightMult())
                isSingleLine = true
            }, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(chevron, LayoutParams(dp(18), dp(18)).apply { leftMargin = dp(8) })
        }

        fun chevronView(): ChevronView = chevron

        private fun dp(value: Int): Int = (value * density).roundToInt()
    }

    /**
     * The cyan chevron that rotates as the section opens and closes.
     *
     * Rotation is applied to the View, not redrawn in onDraw: rotating the drawn
     * path instead would force a redraw per frame, and the view clips to its own
     * bounds, so a 180° rotation of a symmetric chevron lands on the same pixels.
     */
    private inner class ChevronView(context: Context, private val color: Int) : View(context) {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeCap = Paint.Cap.ROUND
        }
        private val density = resources.displayMetrics.density

        init {
            // The glow is a shadow layer, and shadow layers need software.
            setLayerType(View.LAYER_TYPE_SOFTWARE, null)
        }

        override fun onDraw(canvas: Canvas) {
            paint.color = color
            paint.strokeWidth = 1.9f * density
            paint.setShadowLayer(2.5f * density, 0f, 0f, Sculpt.withAlpha(color, 0.55f))
            val cx = width / 2f
            val cy = height / 2f
            val arm = 3.6f * density
            canvas.drawLine(cx - arm, cy + arm, cx, cy - arm, paint)
            canvas.drawLine(cx, cy - arm, cx + arm, cy + arm, paint)
            paint.clearShadowLayer()
        }
    }

    /**
     * A rounded 3dp bar with a soft glow. Drawn rather than a drawable so the
     * glow radius scales with density. Identical to OrbitSectionHeader's own
     * tick, kept duplicated rather than shared so the two can diverge if a
     * section header ever needs a different accent.
     */
    private inner class TickView(context: Context, private val color: Int) : View(context) {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val density = resources.displayMetrics.density

        init {
            setLayerType(View.LAYER_TYPE_SOFTWARE, null)
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
