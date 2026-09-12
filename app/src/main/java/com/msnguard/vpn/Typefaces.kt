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
            "fa" -> cached(ctx, R.font.vazirmatn_bold) { medium }
            "zh" -> cached(ctx, R.font.noto_sc_medium) { medium }
            else -> Typeface.create("sans-serif-medium", Typeface.NORMAL)
        }
    }

    /** Bold — section headers and strong values. */
    fun bold(ctx: Context): Typeface {
        val lang = AppLanguage.current()
        return when (lang) {
            "fa" -> cached(ctx, R.font.vazirmatn_extrabold) { bold }
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
     */
    fun lineHeightMult(): Float = when (AppLanguage.current()) {
        "fa" -> 1.5f
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
