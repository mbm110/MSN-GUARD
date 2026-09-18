package com.msnguard.vpn

import android.content.Context
import com.msnguard.vpn.profiled

/**
 * The app's UI language: English, Persian, Chinese.
 *
 * Chosen once, on first launch, by a one-time picker; after that the row in
 * Settings owns it. An install that has not answered yet keeps following the
 * OS locale (fa/zh) so nobody's UI flips languages on the update that
 * introduced the picker.
 */
object AppLanguage {

    /** Preference key. Values: "en", "fa", "zh". */
    const val PREF = "app_language"

    /** Preference key recording that the user has already picked a language once. */
    const val PREF_CHOSEN = "language_chosen"

    /** The language codes the UI itself is translated into. */
    val SUPPORTED = listOf("en", "fa", "zh")

    /**
     * The active language code, never blank.
     *
     * Resolved lazily per call rather than cached in a field, so changing
     * the preference takes effect without any invalidation wiring; the
     * cost is one SharedPreferences read, which Android already keeps in
     * memory after the first load.
     *
     * Two cases:
     * - The user has picked once ([PREF_CHOSEN], or an explicit value in
     *   [PREF] from an earlier version's Settings row). That value is law.
     * - Nobody has picked anything yet: an existing install updating to the
     *   version that introduced the picker. It keeps following the device
     *   locale, exactly as before, until the picker is answered — once, on
     *   the first launch — and from then on the stored choice owns it.
     *
     * "system" never round-trips: [set] always writes a concrete code, and
     * the Settings row offers only the three.
     */
    fun current(context: Context? = null): String {
        val ctx = context ?: appContext ?: return "en"
        val prefs = ctx.profiled()
        val stored = prefs.getString(PREF, null)
        // An explicit stored code together with a recorded pick means the choice is made.
        if (stored in SUPPORTED && prefs.getBoolean(PREF_CHOSEN, false)) return stored!!
        return when {
            stored in SUPPORTED -> stored!!         // pre-picker Settings choice
            else -> fromSystem(ctx)                 // not picked yet: keep the locale
        }
    }

    /** Map the device locale to a supported language, English as fallback. */
    private fun fromSystem(context: Context): String {
        val tag = context.resources.configuration.locales[0]?.language ?: "en"
        return if (tag in SUPPORTED) tag else "en"
    }

    /** True once the user has picked a language with the one-time picker. */
    fun hasChosen(context: Context): Boolean =
        context.profiled()
            .getBoolean(PREF_CHOSEN, false)

    /**
     * Record the user's language choice.
     *
     * `commit()`, not `apply()`: the caller follows this with `recreate()`, which
     * destroys and rebuilds the activity immediately. An async write that loses
     * the race leaves the rebuilt activity reading no choice at all — the
     * language picker shows again, and the user cannot get into the app.
     */
    fun set(context: Context, code: String) {
        context.profiled()
            .edit().putString(PREF, code).putBoolean(PREF_CHOSEN, true).commit()
    }

    /** Holds the application context so t() works from the service too. */
    @Volatile
    var appContext: Context? = null

    /** Picker label for a code, e.g. "فارسی" for fa. */
    fun label(code: String): String = when (code) {
        "fa" -> "فارسی"
        "zh" -> "中文"
        else -> "English"
    }
}
