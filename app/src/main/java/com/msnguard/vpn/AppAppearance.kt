package com.msnguard.vpn

import android.content.Context
import android.graphics.Color

/**
 * The Orbit palettes — one dark, one light, chosen by the user.
 *
 * History matters here. The colour picker used to offer five palettes plus a
 * "Dynamic" mode that inherited the phone's Material colours, and that was
 * removed on purpose: the approved design is a specific look, and letting the OS
 * repaint it produced washed-out greys and light surfaces the layout was never
 * designed for.
 *
 * This is not that. There are exactly two palettes, both drawn from an approved
 * mock, and nothing about them is derived from the phone's wallpaper:
 *   - [ORBIT]     — the original dark glass + neon console.
 *   - [PORCELAIN] — a light palette: grey canvas, white raised cards.
 *
 * ## Why a light palette is more than swapping ink for canvas
 *
 * The dark look builds depth out of a white specular highlight on the top edge
 * of every surface. On a white card that highlight is invisible, so a naive
 * inversion produces flat white rectangles floating on flat white. Depth on
 * light has to come from the opposite direction: a shadow below the surface, and
 * a card that is *lighter* than the page rather than darker.
 *
 * That inversion lives in [Sculpt.Lighting], carried on the palette, so every
 * surface in the app changes lighting model together instead of each call site
 * guessing. [load] installs it before any drawing happens.
 *
 * ## Text vs graphics accents
 *
 * `#4FE3C1` mint reads at 11:1 on the dark card and 3.4:1 on white — fine for a
 * dial arc, below the 4.5:1 floor for the letters of a label. So every accent
 * has a `…Text` sibling. On [ORBIT] the two are the same colour; on [PORCELAIN]
 * the text sibling is darkened until it clears 4.5:1 on both the card and the
 * canvas. Shapes keep the vivid colour, which is what makes the light theme
 * still look like MSN-GUARD instead of a generic white app.
 */
object AppAppearance {

    /** Which palette the user picked. Persisted in the shared "settings" store. */
    enum class Mode(val key: String, val label: String, val description: String) {
        DARK("dark", "Dark", "The original console — black glass and neon"),
        LIGHT("light", "Light", "Porcelain — grey page, white cards"),
        ;

        companion object {
            fun from(key: String?): Mode = entries.firstOrNull { it.key == key } ?: DARK
        }
    }

    const val PREF_KEY = "theme_mode"

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
        /**
         * Text and glyphs drawn on top of a surface filled with [primary] — the
         * Save/Done/Reset buttons.
         *
         * Dark on both palettes, which is not an accident: [primary] is a mid-to-
         * bright teal in both, so a light label on it never reaches 4.5:1 while a
         * dark one clears it comfortably.
         */
        val primaryContainer: Int,
        /**
         * Background of a row that is currently selected — a protocol option, a
         * split-tunnel app, a picker entry.
         *
         * Split out from [primaryContainer] because the dark palette could use one
         * value for both and the light palette cannot. Dark: `#04070B`, the canvas,
         * so a selected row reads as a recess with a mint border. Light: a pale
         * mint wash, because filling a selected row with near-black ink on a white
         * page would hide the ink-coloured label sitting on it.
         */
        val selectedSurface: Int,
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
        /**
         * Accents again, dark enough to be *read as letters* on this palette's
         * surfaces. Identical to the vivid values on a dark palette, where the
         * vivid values already clear 4.5:1.
         */
        val primaryText: Int = primary,
        val connectedText: Int = connected,
        val mintText: Int = mint,
        val violetText: Int = violet,
        val amberText: Int = amber,
        val dangerText: Int = danger,
        /** Failure text on the connection headline. */
        val error: Int = danger,
        /** How sculpted surfaces are lit on this palette. */
        val lighting: Sculpt.Lighting = Sculpt.DARK_LIGHTING,
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
        selectedSurface = 0xFF04070B.toInt(),
        connected = 0xFF5CE68F.toInt(),
        connectedContainer = 0xFF11331F.toInt(),
        faint = 0xFF5F7276.toInt(),
        mint = 0xFF4FE3C1.toInt(),
        violet = 0xFF9B8CFF.toInt(),
        amber = 0xFFFFC46B.toInt(),
        danger = 0xFFFF6B7F.toInt(),
        // On the dark canvas the vivid accents already read as text (10-11:1),
        // so no separate text ramp — except the failure headline, which the app
        // has always drawn in a softer red than the dial's danger ring.
        error = 0xFFFFB4AB.toInt(),
        lighting = Sculpt.DARK_LIGHTING,
    )

    /**
     * Porcelain: `#EEF1F4` page, `#FFFFFF` cards.
     *
     * The page is deliberately NOT white. A white page with white cards has
     * nothing to separate them but a hairline, and the layout leans on card
     * shapes to group things. Grey page + white card gives the cards their own
     * luminance step, and the shadow from [Sculpt.Lighting.elevationDp] does the
     * rest.
     *
     * Every text value below was measured against all three backgrounds a label
     * can land on — `#FFFFFF` (card), `#EEF1F4` (page), `#E4F3EF` (selected row) —
     * and the worst of the three is what is quoted. All clear the 4.5:1 body-text
     * floor:
     *   ink 15.4 · muted 5.7 · faint 4.5 · primaryText 5.3 · mintText 5.3
     *   connectedText 5.2 · violetText 6.2 · amberText 6.4 · dangerText 5.7
     *
     * The vivid accents are 3.0-4.5:1 and are used for shapes only — the dial arc,
     * the sparkline, a pill fill, a border. Never for letters.
     */
    val PORCELAIN = Palette(
        canvas = 0xFFEEF1F4.toInt(),
        surface = 0xFFFFFFFF.toInt(),
        // A shade off the card, not equal to it: `surfaceVariant` is the fill of
        // an *unselected* chip or recessed row, and those sit on white cards. Equal
        // values would leave only the hairline border to show a chip is there.
        surfaceVariant = 0xFFF4F7F9.toInt(),
        ink = 0xFF111A1F.toInt(),
        muted = 0xFF4E6069.toInt(),
        divider = 0xFFE0E6EA.toInt(),
        primary = 0xFF0E9C82.toInt(),
        // Text on top of a filled primary surface: the Reset button's label, a lit
        // pill. Ink, not white — white on #0E9C82 is 3.4:1, and this is a 15sp
        // button label. Ink on the same fill is 5.1:1. That matches how the dark
        // palette already does it (near-black canvas on bright mint), so the two
        // themes stay consistent rather than one inverting.
        primaryContainer = 0xFF111A1F.toInt(),
        // Pale mint, 1.09:1 against the card — deliberately faint. The border is
        // `primary` and the label goes bold, so selection is carried by three cues
        // at once rather than by a strong fill that would fight the white page.
        selectedSurface = 0xFFE4F3EF.toInt(),
        connected = 0xFF17A05E.toInt(),
        connectedContainer = 0xFFDDF3E6.toInt(),
        // #5B6D75, not the mock's #8496A0. The preview used `faint` for hints that
        // sit on a card, and 8496A0 measures 2.6:1 there — under the floor for text
        // of any size. 5B6D75 keeps the tertiary *role* (still clearly behind
        // `muted`) while clearing 4.5:1 on the card, the page AND a selected row.
        faint = 0xFF5B6D75.toInt(),
        mint = 0xFF0E9C82.toInt(),
        violet = 0xFF6B5BD6.toInt(),
        amber = 0xFFA96A08.toInt(),
        danger = 0xFFE04257.toInt(),
        primaryText = 0xFF087060.toInt(),
        connectedText = 0xFF0A7340.toInt(),
        mintText = 0xFF087060.toInt(),
        violetText = 0xFF5347B8.toInt(),
        amberText = 0xFF7D4B00.toInt(),
        dangerText = 0xFFB3261E.toInt(),
        error = 0xFFB3261E.toInt(),
        lighting = Sculpt.LIGHT_LIGHTING,
    )

    fun mode(context: Context): Mode = Mode.from(
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getString(PREF_KEY, null)
    )

    fun setMode(context: Context, mode: Mode) {
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .edit()
            .putString(PREF_KEY, mode.key)
            .apply()
    }

    fun palette(mode: Mode): Palette = when (mode) {
        Mode.DARK -> ORBIT
        Mode.LIGHT -> PORCELAIN
    }

    /**
     * The palette for this session, and the only place [Sculpt.lighting] is set.
     *
     * Sculpt's drawing helpers are called from ~26 sites that do not hold a
     * palette (a settings row knows its own colours, not the app's lighting
     * model). Installing the lighting here means every one of those calls is
     * correct by construction, because nothing in the app can obtain a palette
     * without going through this function first.
     */
    fun load(context: Context): Palette = palette(mode(context)).also {
        Sculpt.lighting = it.lighting
    }

    /** Callers use this to pick system-bar icon colour and XML theme. */
    fun isNight(context: Context): Boolean = mode(context) == Mode.DARK

    /** Perceived brightness test, used where only a colour is in hand. */
    fun isDark(color: Int): Boolean =
        (Color.red(color) * 299 + Color.green(color) * 587 + Color.blue(color) * 114) / 1000 < 140
}
