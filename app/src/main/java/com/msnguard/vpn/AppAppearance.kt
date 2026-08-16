package com.msnguard.vpn

import android.content.Context

/**
 * The Orbit palette — one fixed design language, no theme switcher.
 *
 * The colour picker used to offer five palettes plus a "Dynamic" mode that
 * inherited the phone's Material colours. That was removed on purpose: the
 * approved design is a specific dark-glass + neon look, and letting the OS
 * repaint it produced washed-out greys and light-mode surfaces the layout was
 * never designed for. Every value below is taken straight from the approved
 * Orbit Pro mock, so what shipped in the preview is what the app draws.
 *
 * [Palette] keeps the old field names so no call site had to change, and adds
 * the Orbit accent tokens (mint / neon / violet / amber / danger / faint) that
 * the mock used for the metric tiles, the sparkline and the dial.
 */
object AppAppearance {

    data class Palette(
        /** page background — mock `--void` */
        val canvas: Int,
        /** raised card fill */
        val surface: Int,
        /** recessed / secondary card fill */
        val surfaceVariant: Int,
        /** primary text — mock `--ink` */
        val ink: Int,
        /** secondary text — mock `--dim` */
        val muted: Int,
        /** hairline borders — mock `--line` */
        val divider: Int,
        /** the brand accent — mock `--mint` */
        val primary: Int,
        /** text drawn on top of [primary] */
        val primaryContainer: Int,
        /** the "tunnel is up" accent — mock `--neon` */
        val connected: Int,
        val connectedContainer: Int,
        /** tertiary text — mock `--faint` */
        val faint: Int,
        /** download accent — mock `--mint` */
        val mint: Int,
        /** upload accent — mock `--violet` */
        val violet: Int,
        /** in-progress / speed accent — mock `--amber` */
        val amber: Int,
        /** failure accent — mock `--danger` */
        val danger: Int,
    )

    val ORBIT = Palette(
        canvas = 0xFF04070B.toInt(),
        surface = 0xFF0B1116.toInt(),
        surfaceVariant = 0xFF111A20.toInt(),
        ink = 0xFFEAF6F3.toInt(),
        muted = 0xFF9DB0B5.toInt(),
        divider = 0xFF1C2429.toInt(),
        primary = 0xFF4FE3C1.toInt(),
        primaryContainer = 0xFF04070B.toInt(),
        connected = 0xFF5CE68F.toInt(),
        connectedContainer = 0xFF11331F.toInt(),
        faint = 0xFF5F7276.toInt(),
        mint = 0xFF4FE3C1.toInt(),
        violet = 0xFF9B8CFF.toInt(),
        amber = 0xFFFFC46B.toInt(),
        danger = 0xFFFF6B7F.toInt(),
    )

    /** Kept as a function so the old `AppAppearance.load(this)` call sites work. */
    @Suppress("UNUSED_PARAMETER")
    fun load(context: Context): Palette = ORBIT

    /** The app is dark, always. Callers use this to pick system-bar icon colour. */
    @Suppress("UNUSED_PARAMETER")
    fun isNight(context: Context): Boolean = true
}
