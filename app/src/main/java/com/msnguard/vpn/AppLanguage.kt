package com.msnguard.vpn

import android.content.Context

/**
 * The app's UI language: English (default), Persian, Chinese.
 *
 * A single preference, read once per [current] call — cheap enough for a
 * t() lookup on every label, since the whole table is already in memory as
 * object literals.
 *
 * "system" means: follow the OS locale when it is fa or zh, English
 * otherwise. That is the default, so a fresh install never switches
 * languages on the user unasked.
 */
object AppLanguage {

    /** Preference key. Values: "system", "en", "fa", "zh". */
    const val PREF = "app_language"

    /** The language codes the UI itself is translated into. */
    val SUPPORTED = listOf("en", "fa", "zh")

    /**
     * The active language code, never blank.
     *
     * Resolved lazily per call rather than cached in a field, so changing
     * the preference takes effect without any invalidation wiring; the
     * cost is one SharedPreferences read, which Android already keeps in
     * memory after the first load.
     */
    fun current(context: Context? = null): String {
        val ctx = context ?: appContext ?: return "en"
        val stored = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getString(PREF, null) ?: return fromSystem(ctx)
        return if (stored in SUPPORTED) stored else fromSystem(ctx)
    }

    /** Map the device locale to a supported language, English as fallback. */
    private fun fromSystem(context: Context): String {
        val tag = context.resources.configuration.locales[0]?.language ?: "en"
        return if (tag in SUPPORTED) tag else "en"
    }

    fun set(context: Context, code: String) {
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .edit().putString(PREF, code).apply()
    }

    /** Holds the application context so t() works from the service too. */
    @Volatile
    var appContext: Context? = null

    /** Picker label for a code, e.g. "فارسی" for fa. */
    fun label(code: String): String = when (code) {
        "system" -> Strings.t("Follow system")
        "fa" -> "فارسی"
        "zh" -> "中文"
        else -> "English"
    }
}
