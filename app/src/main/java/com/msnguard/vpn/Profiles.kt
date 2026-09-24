package com.msnguard.vpn

import android.content.Context
import android.content.SharedPreferences
import com.msnguard.vpn.profiled

/**
 * User profiles: four independent settings configurations in one install.
 *
 * ## Why the key-level approach
 *
 * The app reads and writes [SETTINGS_FILE] in 43 places across 14 files, all of
 * them through `getSharedPreferences("settings", …)` with a literal key. Every
 * one of those reads and writes is routed through [profiled] here, which
 * translates a logical key (`kill_switch`) into a per-profile physical key
 * (`p1_kill_switch`). The caller never sees the prefix; the app sees four
 * independent preference spaces inside one file.
 *
 * The alternative — a separate file per profile — was rejected. Files have to
 * be renamed in 43 sites AND in [SettingsBackup], whose export walks the file
 * list literally. Prefixing is invisible to both, and it degrades honestly: an
 * old key without a prefix is read as Profile A, so an upgrade keeps every
 * setting the user already has instead of resetting them.
 *
 * ## What is NOT profiled
 *
 * Learned state stays global. [SettingsBackup.TRANSIENT_KEYS] — the last exit
 * IP, the winning transport, ETags and node counts — is a measurement of *this
 * device on this carrier*, and it would be wrong for Profile B to inherit
 * Profile A's measurement of a network it never saw. The same applies to
 * traffic counters and to the profile choice itself, which must survive.
 *
 * [KEYS_NOT_PROFILED] lists those keys explicitly: it is read by [SettingsBackup]
 * so a backup still carries the real choices and still drops the measurements.
 */
object Profiles {

    /** The SharedPreferences file everything lives in. */
    const val SETTINGS_FILE = "settings"

    /** The key holding the currently-active profile, 0-based. NOT profiled. */
    const val ACTIVE_PROFILE = "active_profile"

    /** How many profiles exist. Fixed at four; the names are fixed too. */
    const val COUNT = 4

    /**
     * The four names, in order. Fixed rather than user-editable: a free-form
     * name is a third thing to back up, to validate, and to explain in a
     * support message, and the user asked for A–D.
     */
    val NAMES = arrayOf("Profile A", "Profile B", "Profile C", "Profile D")

    /**
     * Keys that must stay global regardless of profile.
     *
     * Learned state, counters, and the profile choice itself. Kept here rather
     * than in [SettingsBackup] because the decision is about *what a key means*,
     * and the backup only needs to know it in order to keep doing what it does
     * for every other key.
     */
    /**
     * Preference keys that must stay global regardless of profile.
     *
     * Learned state, counters, the profile choice itself, and the UI's own
     * language: a language switch is not a per-transport setting, and making it
     * one would mean a user who picks فارسی in Profile A sees English in
     * Profile B.
     */
    val KEYS_NOT_PROFILED = setOf(
        ACTIVE_PROFILE,
        AppLanguage.PREF,
        AppLanguage.PREF_CHOSEN,
        // Traffic and usage counters: a record of what happened, not a choice.
        "rx_total", "tx_total", "month_start", "traffic_stats",
        // Learned state — see SettingsBackup.TRANSIENT_KEYS. Named in both
        // places deliberately: this list governs key routing, that one governs
        // what a backup may carry. Overlapping on purpose, not by accident.
        "last_ip", "last_exit_region",
        "shard_etag", "shard_last_check", "shard_last_count", "shard_last_paths",
        "policy_etag", "policy_last_check",
        "smart_split_etag", "smart_split_last_check",
        "psiphon_available_regions",
        "psiphon_winning_strategy", "psiphon_winning_strategy_shape",
        "psiphon_winning_strategy_chained", "psiphon_winning_strategy_chained_shape",
        "chain_outer_index", "plain_working_transport",
        "tor_winning_mode", "tor_winning_mode_chained",
        "auto_scan_done",
        // UI state, not a setting: which settings sections the user left open.
        // Tied to the screen, not to a tunnel configuration.
    ) + (0..32).map { "section_open_$it" }.toSet() + SettingsBackup.TRANSIENT_KEYS

    /** Prefixes of keys that must stay global, for keys not known in advance. */
    val PREFIXES_NOT_PROFILED = listOf("smart_split_profile_")

    /** The profile currently in effect, 0-based. Never throws, never returns > 3. */
    fun active(context: Context): Int {
        val p = context.getSharedPreferences(SETTINGS_FILE, Context.MODE_PRIVATE)
            .getInt(ACTIVE_PROFILE, 0)
        return if (p in 0 until COUNT) p else 0
    }

    /** Name of the active profile, for display. */
    fun activeName(context: Context): String = NAMES[active(context)]

    /**
     * Remaps every profiled key in [SETTINGS_FILE] so [index] becomes the active
     * profile, and returns the number of keys that moved.
     *
     * A switch is not a restore: it must not drop anything, and it must be
     * visible before the next connect. So the move is committed synchronously,
     * and the caller recreates the activity so no row keeps showing the profile
     * the user just left.
     *
     * Returns 0 when the target is already active, which the caller uses to
     * skip the recreate.
     *
     * ## Upgrade migration
     *
     * An install from before this feature holds bare keys (`kill_switch`), with
     * no prefix at all. Those belong to Profile A — the first profile anyone
     * has. Prefixing them on the *first ever switch* is what keeps an existing
     * user's settings: without it, reading `p0_kill_switch` after the round trip
     * finds nothing and silently resets the row to its default.
     */
    fun switch(context: Context, index: Int): Int {
        if (index !in 0 until COUNT) return 0
        if (active(context) == index) return 0
        val prefs = context.getSharedPreferences(SETTINGS_FILE, Context.MODE_PRIVATE)
        val snapshot = prefs.all
        val editor = prefs.edit()

        // One pass. A key is either already prefixed (p2_kill_switch) — in which
        // case stripProfile returns its logical name — or bare (kill_switch), in
        // which case stripProfile returns null and the key IS its own logical
        // name. Both end up rewritten to the target profile's prefix.
        //
        // The bare case is the upgrade path: an install from before this feature
        // holds unprefixed keys, and they belong to whatever profile is active.
        // Sending them to the target on the first switch is what keeps an
        // existing user's settings — reading p0_kill_switch after the round trip
        // would otherwise find nothing and silently reset the row.
        var moved = 0
        snapshot.forEach { (key, value) ->
            if (!isProfiled(key)) return@forEach
            val bare = stripProfile(key) ?: key
            editor.remove(key)
            editor.putValue(profiledKey(index, bare), value)
            moved++
        }
        editor.putInt(ACTIVE_PROFILE, index).commit()
        return moved
    }

    /**
     * The physical key a logical key is stored under in the active profile.
     */
    private fun profiledKey(profile: Int, key: String): String = "p${profile}_$key"

    /**
     * The logical key behind a physical one, or null for un-profiled keys.
     *
     * Visible to the file, not just [switch]: [ProfiledPrefs.getAll] exposes
     * logical keys and has to invert the prefix.
     */
    fun stripProfile(key: String): String? {
        if (key.length < 3 || key[0] != 'p' || !key[1].isDigit()) return null
        return key.substring(2)
    }

    /** True if a key carries per-profile state. */
    fun isProfiled(key: String): Boolean =
        key !in KEYS_NOT_PROFILED && !PREFIXES_NOT_PROFILED.any(key::startsWith)

    /**
     * Physical key for [key] in the active profile.
     *
     * Reads a bare key as the active profile's: an install from before profiles
     * existed holds unprefixed keys, and they belong to whatever profile the user
     * is on. This is what makes the upgrade transparent — every row keeps its
     * value without a migration having to run first.
     */
    fun key(context: Context, key: String): String {
        if (!isProfiled(key)) return key
        return profiledKey(active(context), key)
    }

    /**
     * Prefix every bare profiled key with the active profile's prefix, once.
     *
     * Called from onCreate. The fallback in [key] makes this optional, not
     * load-bearing — but leaving bare keys in place means [switch] has to handle
     * two shapes of the same logical key forever, and the fallback silently
     * moves a setting when the user never asked it to move. Doing it up front
     * means there is one shape, and [switch] is a pure relabel.
     *
     * Also strips the profile prefix from keys that turned out to be global —
     * the language keys were profiled in 2.0.8/2.0.9 and are not any more. A user
     * who picked a language in those builds has `p0_app_language` on disk; leaving
     * it there would make the picker prompt again on this upgrade, and the
     * language row in Settings would read nothing.
     */
    fun migrateIfNeeded(context: Context): Int {
        val prefs = context.getSharedPreferences(SETTINGS_FILE, Context.MODE_PRIVATE)
        val prefix = profiledKey(active(context), "")
        var changed = 0
        val editor = prefs.edit()

        // Bare profiled keys -> the active profile's prefix.
        prefs.all.entries.filter { (key, _) ->
            isProfiled(key) && stripProfile(key) == null
        }.forEach { (key, value) ->
            editor.remove(key)
            editor.putValue(prefix + key, value)
            changed++
        }

        // Prefixed keys that are now global -> bare. isProfiled is the current
        // truth, so a key it rejects is global no matter what shape it is in.
        prefs.all.entries.filter { (key, _) ->
            !isProfiled(key) && stripProfile(key) != null
        }.forEach { (key, value) ->
            val bare = stripProfile(key)!!
            if (!prefs.all.keys.contains(bare)) {
                editor.remove(key)
                editor.putValue(bare, value)
                changed++
            }
        }

        if (changed > 0) editor.commit()
        return changed
    }

    /**
     * Clear every profiled key in every profile.
     *
     * Used by "Reset to defaults": the user asked for a clean install's
     * behaviour, and a clean install has no Profile B either. Global keys are
     * untouched — the counters are usage records, and the learned state is
     * cleared separately by [SettingsBackup.resetToDefaults] for the same
     * reason it clears shard_health.
     */
    fun resetAllProfiles(context: Context) {
        val prefs = context.getSharedPreferences(SETTINGS_FILE, Context.MODE_PRIVATE)
        val editor = prefs.edit()
        prefs.all.keys.forEach { key ->
            if (isProfiled(key) || stripProfile(key) != null) editor.remove(key)
        }
        editor.remove(ACTIVE_PROFILE).commit()
    }

    /** How many profiled keys profile [index] holds. For the reset confirmation. */
    fun profiledKeyCount(context: Context, index: Int): Int {
        val prefs = context.getSharedPreferences(SETTINGS_FILE, Context.MODE_PRIVATE)
        return prefs.all.keys.count { key -> isProfiled(key) && stripProfile(key) != null }
    }
}

/**
 * The preferences of the active profile.
 *
 * Every settings read and write in the app goes through this: it turns
 * `prefs.getBoolean("kill_switch")` into a read of the active profile's key.
 * Nothing else in the app has to know profiles exist.
 *
 * Callers that need the editor (`edit()`) get one that prefixes on write too.
 */
fun Context.profiled(): SharedPreferences = ProfiledPrefs(this)

/**
 * A [SharedPreferences] whose keys are translated to the active profile's.
 *
 * Delegates every read to the underlying settings file under a rewritten key,
 * and writes through to an editor that rewrites in the same direction. The
 * interface is implemented fully enough for this app's use; [edit] returns the
 * real editor, wrapped so puts are prefixed too.
 */
private class ProfiledPrefs(private val ctx: Context) : SharedPreferences {

    private val backing: SharedPreferences
        get() = ctx.getSharedPreferences(Profiles.SETTINGS_FILE, Context.MODE_PRIVATE)

    private fun k(key: String) = Profiles.key(ctx, key)

    override fun getString(key: String, defValue: String?) = backing.getString(k(key), defValue)
    override fun getStringSet(key: String, defValues: Set<String>?) = backing.getStringSet(k(key), defValues)
    override fun getInt(key: String, defValue: Int) = backing.getInt(k(key), defValue)
    override fun getLong(key: String, defValue: Long) = backing.getLong(k(key), defValue)
    override fun getFloat(key: String, defValue: Float) = backing.getFloat(k(key), defValue)
    override fun getBoolean(key: String, defValue: Boolean) = backing.getBoolean(k(key), defValue)
    override fun contains(key: String) = backing.contains(k(key))

    /**
     * An editor whose puts land in the active profile.
     *
     * Applied immediately to the same delegate so a key change mid-session is
     * not split across two profiles.
     */
    override fun edit(): SharedPreferences.Editor = ProfiledEditor(backing.edit(), this::k)

    override fun getAll(): Map<String, *> =
        backing.all.filterKeys { key -> Profiles.stripProfile(key) != null }
            .mapKeys { (key, _) -> Profiles.stripProfile(key)!! }

    override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) =
        backing.registerOnSharedPreferenceChangeListener(l)
    override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) =
        backing.unregisterOnSharedPreferenceChangeListener(l)
}

/** An editor that prefixes its keys. */
private class ProfiledEditor(
    private val real: SharedPreferences.Editor,
    private val rewrite: (String) -> String,
) : SharedPreferences.Editor {
    override fun putString(key: String, value: String?) = real.putString(rewrite(key), value)
    override fun putStringSet(key: String, values: Set<String>?) = real.putStringSet(rewrite(key), values)
    override fun putInt(key: String, value: Int) = real.putInt(rewrite(key), value)
    override fun putLong(key: String, value: Long) = real.putLong(rewrite(key), value)
    override fun putFloat(key: String, value: Float) = real.putFloat(rewrite(key), value)
    override fun putBoolean(key: String, value: Boolean) = real.putBoolean(rewrite(key), value)
    override fun remove(key: String) = real.remove(rewrite(key))
    override fun clear() = real.clear()
    override fun commit() = real.commit()
    override fun apply() = real.apply()
}

/** putValue with Any, for the bulk move in [Profiles.switch]. */
private fun SharedPreferences.Editor.putValue(key: String, value: Any?): SharedPreferences.Editor = when (value) {
    is Boolean -> putBoolean(key, value)
    is Int -> putInt(key, value)
    is Long -> putLong(key, value)
    is Float -> putFloat(key, value)
    is String -> putString(key, value)
    is Set<*> -> putStringSet(key, value.map { it.toString() }.toSet())
    else -> this
}
