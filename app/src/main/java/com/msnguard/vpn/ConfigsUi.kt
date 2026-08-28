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
 * Views for the user-config feature.
 *
 * Kept out of MainActivity deliberately: that file is already 4,800 lines and
 * every view in here is also used by [ConfigsActivity], which is a separate
 * activity and cannot reach MainActivity's private helpers.
 */

private fun Context.cfgLabel(
    text: String,
    size: Float,
    color: Int,
    medium: Boolean = false,
    mono: Boolean = false,
): TextView = TextView(this).apply {
    this.text = text
    textSize = size
    setTextColor(color)
    typeface = when {
        mono -> Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
        medium -> Typeface.create("sans-serif-medium", Typeface.NORMAL)
        else -> Typeface.create("sans", Typeface.NORMAL)
    }
}

/** Formats a stored ping value for display, with its colour. */
object PingFormat {
    /** Green for a good reading, red for a dead one, grey for never measured. */
    fun text(ms: Int): String = when (ms) {
        ConfigProfile.PING_UNKNOWN -> "—"
        ConfigProfile.PING_FAILED -> "-1"
        else -> "$ms ms"
    }

    fun color(ms: Int, palette: AppAppearance.Palette): Int = when (ms) {
        ConfigProfile.PING_UNKNOWN -> Sculpt.withAlpha(palette.faint, 0.9f)
        ConfigProfile.PING_FAILED -> palette.danger
        // Amber above 800ms: still usable, but the user should know before they
        // blame the app for being slow.
        in 801..Int.MAX_VALUE -> palette.amber
        else -> palette.connected
    }
}

/**
 * The home-screen entry point for user configs.
 *
 * A full-width card in the main console, NOT a settings row and NOT a tab. The
 * requirement was that this feature be the visible difference from other
 * clients, so it sits in the first screen's flow at the same weight as the
 * transport rail: one tap from launch, with the active config's name, protocol
 * and latency legible without opening anything.
 *
 * Empty state carries the instruction ("Paste a v2ray link") rather than a bare
 * "None", because a card that only says "None" teaches the user nothing about
 * what it wants.
 */
class ConfigCard(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val onOpen: () -> Unit,
) : LinearLayout(context) {

    private val titleView: TextView
    private val detailView: TextView
    private val pingView: TextView
    private val icon: ConfigGlyphView

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(cdp(13), cdp(6), cdp(14), cdp(6))
        isClickable = true
        isFocusable = true
        background = Sculpt.sculptedBackground(
            resources.displayMetrics.density,
            Sculpt.blend(palette.surface, palette.ink, 0.03f),
            18,
            accent = Sculpt.withAlpha(palette.amber, 0.22f),
        )
        setOnClickListener {
            performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
            onOpen()
        }

        icon = ConfigGlyphView(context, palette.amber)
        addView(icon, LayoutParams(cdp(30), cdp(30)))

        val stack = LinearLayout(context).apply { orientation = VERTICAL }
        titleView = context.cfgLabel("MY CONFIGS", 13.5f, palette.ink, medium = true).apply {
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.END
        }
        detailView = context.cfgLabel("Paste a v2ray link to add one", 11.5f, palette.muted).apply {
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.END
        }
        stack.addView(titleView)
        stack.addView(detailView, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = cdp(2) })
        addView(stack, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            leftMargin = cdp(11)
        })

        pingView = context.cfgLabel("", 12f, palette.connected, medium = true, mono = true)
        addView(pingView, LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = cdp(8) })
    }

    /**
     * Repaint from the store.
     *
     * [total] is shown even when a config is active, because "3 saved" is the
     * only affordance telling the user the list has more in it.
     */
    fun render(active: ConfigProfile?, total: Int) {
        if (active == null) {
            titleView.text = "MY CONFIGS"
            detailView.text = if (total == 0) {
                "Paste a v2ray link to add one"
            } else {
                "$total saved · tap to choose one"
            }
            pingView.text = ""
            return
        }
        titleView.text = active.displayName()
        detailView.text = buildString {
            append(active.summary())
            if (total > 1) append("  ·  $total saved")
        }
        pingView.text = PingFormat.text(active.lastPingMs)
        pingView.setTextColor(PingFormat.color(active.lastPingMs, palette))
    }

    private fun cdp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()
}

/**
 * One row in the config list — the layout from the reference screenshot.
 *
 *   line 1  name (wraps to 2 lines)                    [pencil] [trash]
 *   line 2  188.114.97.6 : 443
 *   line 3  VLESS / ws / tls                              122 ms
 *
 * The name is allowed two lines because real config names are long
 * (`@Channel | 443 | f29bd2`) and truncating them to one line makes a list of
 * configs from the same channel indistinguishable.
 */
class ConfigRowView(
    context: Context,
    private val palette: AppAppearance.Palette,
    private val onTap: () -> Unit,
    private val onEdit: () -> Unit,
    private val onDelete: () -> Unit,
    private val onLongPress: () -> Unit = {},
) : LinearLayout(context) {

    private val nameView: TextView
    private val addressView: TextView
    private val summaryView: TextView
    private val pingView: TextView
    private val activeBadge: TextView

    init {
        orientation = VERTICAL
        setPadding(cdp(16), cdp(13), cdp(12), cdp(13))
        isClickable = true
        isFocusable = true
        background = Sculpt.sculptedBackground(
            resources.displayMetrics.density,
            palette.surfaceVariant,
            16,
            stroke = palette.divider,
        )
        setOnClickListener {
            performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
            onTap()
        }
        // Long press copies the config back out as a link. There is no visible
        // share button because the row already carries two icons and a third
        // would crowd a name that needs the width more.
        setOnLongClickListener {
            performHapticFeedback(HapticFeedbackConstants.LONG_PRESS)
            onLongPress()
            true
        }
        val head = LinearLayout(context).apply { orientation = HORIZONTAL }
        nameView = context.cfgLabel("", 15f, palette.ink, medium = true).apply {
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
        }
        head.addView(nameView, LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

        // 40dp touch targets on 18dp glyphs: the icons sit next to each other and
        // next to the row's own click handler, so anything smaller makes deleting
        // a config a coin flip against selecting it.
        head.addView(iconButton(PencilGlyph(context, palette.muted), "Edit", onEdit), LayoutParams(cdp(40), cdp(40)))
        head.addView(iconButton(TrashGlyph(context, palette.muted), "Delete", onDelete), LayoutParams(cdp(40), cdp(40)))
        addView(head, LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

        // ---- line 2: address
        addressView = context.cfgLabel("", 12.5f, palette.muted, mono = true).apply {
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.MIDDLE
        }
        addView(addressView, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = cdp(5) })

        // ---- line 3: amber protocol summary, green ping
        val foot = LinearLayout(context).apply {
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        summaryView = context.cfgLabel("", 12f, palette.amber, medium = true)
        foot.addView(summaryView)
        activeBadge = context.cfgLabel("ACTIVE", 9.5f, palette.primary, medium = true).apply {
            letterSpacing = 0.1f
            visibility = GONE
        }
        foot.addView(activeBadge, LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { leftMargin = cdp(8) })
        foot.addView(View(context), LayoutParams(0, 1, 1f))
        pingView = context.cfgLabel("", 12.5f, palette.connected, medium = true, mono = true)
        foot.addView(pingView)
        addView(foot, LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = cdp(6) })
    }

    private fun iconButton(glyph: View, description: String, onClick: () -> Unit): FrameLayout =
        FrameLayout(context).apply {
            isClickable = true
            isFocusable = true
            contentDescription = description
            background = Sculpt.sculptedRipple(
                resources.displayMetrics.density,
                Sculpt.withAlpha(palette.canvas, 0f),
                999,
                palette.primary,
            )
            addView(glyph, FrameLayout.LayoutParams(cdp(18), cdp(18), Gravity.CENTER))
            setOnClickListener {
                performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
                onClick()
            }
        }

    fun render(profile: ConfigProfile, isActive: Boolean, unsupported: Boolean) {
        nameView.text = profile.displayName()
        addressView.text = profile.endpoint()
        summaryView.text = if (unsupported) "${profile.summary()}  ·  not supported yet" else profile.summary()
        summaryView.setTextColor(if (unsupported) palette.danger else palette.amber)
        pingView.text = PingFormat.text(profile.lastPingMs)
        pingView.setTextColor(PingFormat.color(profile.lastPingMs, palette))
        activeBadge.visibility = if (isActive) VISIBLE else GONE
        background = Sculpt.sculptedBackground(
            resources.displayMetrics.density,
            palette.surfaceVariant,
            16,
            stroke = if (isActive) Sculpt.withAlpha(palette.primary, 0.7f) else palette.divider,
            strokeWidth = if (isActive) 2 else 1,
        )
    }

    /** Show "…" while this row's probe is in flight. */
    fun setMeasuring() {
        pingView.text = "···"
        pingView.setTextColor(Sculpt.withAlpha(palette.faint, 0.9f))
    }

    private fun cdp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()
}

/** A stack of three chevrons — the "configs" mark, drawn not shipped. */
private class ConfigGlyphView(context: Context, private val color: Int) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }

    override fun onDraw(canvas: Canvas) {
        val d = resources.displayMetrics.density
        paint.color = color
        paint.strokeWidth = 1.8f * d
        val w = width.toFloat()
        val h = height.toFloat()
        // Three nested rounded rectangles offset diagonally: a stack of cards.
        for (i in 0..2) {
            val inset = i * 3f * d
            val top = h * 0.20f + inset
            val left = w * 0.18f + inset
            val right = w * 0.82f
            val bottom = h * 0.58f + inset
            if (bottom > h) break
            canvas.drawRoundRect(left, top, right, bottom, 2.5f * d, 2.5f * d, paint)
        }
    }
}

/** The pencil from the reference screenshot: a tilted shaft with a nib. */
private class PencilGlyph(context: Context, private val color: Int) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }

    override fun onDraw(canvas: Canvas) {
        val d = resources.displayMetrics.density
        paint.color = color
        paint.strokeWidth = 1.7f * d
        val w = width.toFloat()
        val h = height.toFloat()
        // Shaft, corner to corner.
        canvas.drawLine(w * 0.24f, h * 0.76f, w * 0.74f, h * 0.26f, paint)
        // The band across the shaft, and the nib closing the tip.
        canvas.drawLine(w * 0.58f, h * 0.16f, w * 0.84f, h * 0.42f, paint)
        canvas.drawLine(w * 0.24f, h * 0.76f, w * 0.20f, h * 0.86f, paint)
        canvas.drawLine(w * 0.20f, h * 0.86f, w * 0.32f, h * 0.82f, paint)
    }
}

/** The bin with a cross on its body, matching the reference. */
private class TrashGlyph(context: Context, private val color: Int) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }

    override fun onDraw(canvas: Canvas) {
        val d = resources.displayMetrics.density
        paint.color = color
        paint.strokeWidth = 1.7f * d
        val w = width.toFloat()
        val h = height.toFloat()
        // Lid, drawn as its own bar above the body.
        canvas.drawLine(w * 0.16f, h * 0.26f, w * 0.84f, h * 0.26f, paint)
        canvas.drawLine(w * 0.38f, h * 0.26f, w * 0.42f, h * 0.14f, paint)
        canvas.drawLine(w * 0.42f, h * 0.14f, w * 0.58f, h * 0.14f, paint)
        canvas.drawLine(w * 0.58f, h * 0.14f, w * 0.62f, h * 0.26f, paint)
        // Body.
        canvas.drawLine(w * 0.24f, h * 0.26f, w * 0.30f, h * 0.86f, paint)
        canvas.drawLine(w * 0.76f, h * 0.26f, w * 0.70f, h * 0.86f, paint)
        canvas.drawLine(w * 0.30f, h * 0.86f, w * 0.70f, h * 0.86f, paint)
        // The cross on the body.
        canvas.drawLine(w * 0.42f, h * 0.46f, w * 0.58f, h * 0.68f, paint)
        canvas.drawLine(w * 0.58f, h * 0.46f, w * 0.42f, h * 0.68f, paint)
    }
}
