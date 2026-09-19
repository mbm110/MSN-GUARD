package com.msnguard.vpn

import android.content.Context
import android.graphics.Typeface
import androidx.core.content.res.ResourcesCompat

/**
 * Offline UI fonts, picked by the active language.
 *
 * Persian renders in Vazirmatn (Regular/Bold/ExtraBold) so the joined letters
 * and diacritics are crisp without any network fetch; Chinese renders in a
 * subset of Noto Sans SC (Regular/Medium/Bold) covering GB2312 level-1+2 plus
 * every string the app itself ships. English keeps the system sans family.
 *
 * [Typeface.create] is NOT used here: it would fall back to the default family
 * for these names. The instances are held in fields — a file read per label
 * would be measurable on the settings screen, which builds ~60 rows.
 */
object Typefaces {

    @Volatile private var regular: Typeface? = null
    @Volatile private var medium: Typeface? = null
    @Volatile private var semiBold: Typeface? = null
    @Volatile private var bold: Typeface? = null
    @Volatile private var extraBold: Typeface? = null
    @Volatile private var mono: Typeface? = null

    /** The regular-weight label font for the active language. */
    fun regular(ctx: Context): Typeface {
        val lang = AppLanguage.current()
        return when (lang) {
            "fa" -> cached(ctx, R.font.vazirmatn_regular) { regular }
            "zh" -> cached(ctx, R.font.noto_sc_regular) { regular }
            else -> Typeface.create("sans", Typeface.NORMAL)
        }
    }

    /** Medium — the console's default label weight. */
    fun medium(ctx: Context): Typeface {
        val lang = AppLanguage.current()
        return when (lang) {
            "fa" -> cached(ctx, R.font.vazirmatn_medium) { medium }
            "zh" -> cached(ctx, R.font.noto_sc_medium) { medium }
            else -> Typeface.create("sans-serif-medium", Typeface.NORMAL)
        }
    }

    /**
     * Between medium and bold — the weight WhiteAesther's Persian UI is set in.
     *
     * Persian has no bold-on-light contrast tradition to lean on: heavy weights
     * close the counters that distinguish ع from غ and ک from گ, so a heading
     * that reads as "strong" in Latin reads as "blocked in" here. SemiBold keeps
     * the emphasis without sealing the letterforms.
     */
    fun semiBold(ctx: Context): Typeface {
        val lang = AppLanguage.current()
        return when (lang) {
            "fa" -> cached(ctx, R.font.vazirmatn_semibold) { semiBold }
            "zh" -> cached(ctx, R.font.noto_sc_bold) { semiBold }
            else -> Typeface.create("sans-serif-medium", Typeface.NORMAL)
        }
    }

    /** Bold — section headers and strong values. */
    fun bold(ctx: Context): Typeface {
        val lang = AppLanguage.current()
        return when (lang) {
            "fa" -> cached(ctx, R.font.vazirmatn_bold) { bold }
            "zh" -> cached(ctx, R.font.noto_sc_bold) { bold }
            else -> Typeface.create("sans-serif-medium", Typeface.BOLD)
        }
    }

    /**
     * The connection status headline. Vazirmatn's ExtraBold gives Persian the
     * same visual punch the console's medium-weight Latin headline has.
     */
    fun extraBold(ctx: Context): Typeface {
        val lang = AppLanguage.current()
        return when (lang) {
            "fa" -> cached(ctx, R.font.vazirmatn_extrabold) { extraBold }
            "zh" -> cached(ctx, R.font.noto_sc_bold) { extraBold }
            else -> Typeface.create("sans-serif-medium", Typeface.BOLD)
        }
    }

    /** Monospace digits stay the system mono in every language. */
    fun mono(ctx: Context): Typeface =
        mono ?: Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL).also { mono = it }

    /**
     * Persian needs more leading than the console's tight default: diacritics
     * and letter dots clip at 1.0. Chinese keeps the compact system leading so
     * localized rows do not squeeze the connection dial.
     *
     * Multipliers below 1.0 (approved for fa/zh, v1.8.7): the localized fonts
     * carry big vertical metrics (Vazirmatn 1.71×, Noto SC 1.45× vs Latin's
     * ~1.17×), so even the "unmultiplied" line was taller than the English
     * one. Compressing below 1.0 cuts into that slack, not into glyphs:
     * Vazirmatn at 0.80 keeps ≈1.37× of headroom, Noto SC at 0.85 keeps
     * ≈1.23× — both still comfortable for diacritics, and the reclaimed
     * height is what lets the connection dial sit at the English size.
     */
    fun lineHeightMult(): Float = when (AppLanguage.current()) {
        "fa" -> 0.80f
        "zh" -> 0.85f
        else -> 1.0f
    }

    private inline fun cached(ctx: Context, res: Int, field: () -> Typeface?): Typeface {
        field()?.let { return it }
        synchronized(this) {
            field()?.let { return it }
            return runCatching { ResourcesCompat.getFont(ctx, res)!! }
                .getOrElse { Typeface.create("sans", Typeface.NORMAL) }
        }
    }
}
