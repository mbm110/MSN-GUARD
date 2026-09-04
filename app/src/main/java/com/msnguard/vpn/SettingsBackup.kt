package com.msnguard.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Export, import and factory-reset of everything the user chose in this app.
 *
 * ## What a backup is for
 *
 * The reason this exists is the field case it was asked for: the app is
 * uninstalled and reinstalled, and every choice — protocol, tunnel type, SOCKS
 * port, Psiphon country, Tor bridges, split tunnelling, anti-DPI shaping — is
 * gone with it. Android's own auto-backup cannot be relied on here: it is off
 * for many users, it is tied to a Google account this audience often does not
 * use, and it does not survive a sideloaded reinstall of a different signing
 * key. A file the user holds does.
 *
 * ## What is carried, and what is deliberately NOT
 *
 * Carried: the two preference files that hold decisions the user made:
 * `settings` and `split_tunneling`.
 *
 * Not carried, on purpose:
 *
 *  * **Learned state** ([TRANSIENT_KEYS]). Which Psiphon rung won, which outer
 *    transport last worked, the SHARD subscription's ETag and node count, the
 *    last exit IP. Every one of those is a measurement of *this device on this
 *    carrier*, not a choice. Restoring them onto a fresh install would send the
 *    first connect to a rung with no evidence behind it and, worse, look like
 *    the app remembering something it has never measured. A clean restore
 *    carries decisions and lets the memories rebuild themselves.
 *  * **`shard_health`**, for the same reason: per-node latency and failure
 *    counts measured on another install.
 *  * **`traffic_stats`**. Monthly usage is a record of what happened, not a
 *    setting, and moving it between installs would make the counter lie.
 *  * **Zero Trust credentials** (`secure_settings`). They are encrypted with an
 *    AndroidKeyStore key that is destroyed on uninstall, so the ciphertext could
 *    not be decrypted after a reinstall anyway — and exporting them decrypted
 *    would put a live secret in a file the user forwards through a chat app.
 *
 * The exported file is therefore not sensitive: it holds preferences, not
 * credentials. That is a property worth keeping — say so when the file is
 * produced rather than leaving the user to guess.
 *
 * ## Format
 *
 * One JSON object. Values are typed explicitly rather than inferred, because
 * `SharedPreferences` distinguishes Int from Long and a `StringSet` from a
 * String, and putting a Long back as an Int throws `ClassCastException` on the
 * *next read*, i.e. far from the restore that caused it.
 */
object SettingsBackup {

    /** Marker so a file from another app cannot be read as ours. */
    const val APP_MARKER = "MSN-GUARD"

    /**
     * Format revision. Bumped only for a change a previous build could not read;
     * added keys do not need it, because import ignores what it does not know.
     */
    const val FORMAT = 1

    /** Suggested filename; the version makes a folder of backups self-sorting. */
    fun suggestedFileName(version: String): String =
        "msn-guard-settings-v$version.json"

    /**
     * The preference files a backup covers, in the order they are applied.
     *
     * Spelled out here rather than referenced from `MainActivity.SETTINGS` and
     * `SplitTunnelSettings.PREFERENCES`: both live in `private companion object`s,
     * and widening their visibility for a backup routine would be the wrong
     * trade. The cost of that choice is that a rename over there is not caught
     * here by the compiler — if either file name ever changes, this list has to
     * change with it.
     */
    private const val SETTINGS_FILE = "settings"
    private const val SPLIT_TUNNEL_FILE = "split_tunneling"
    private val FILES = listOf(SETTINGS_FILE, SPLIT_TUNNEL_FILE)

    /**
     * Keys inside the settings file that are measurements, not choices.
     *
     * Kept as a prefix/exact list rather than a naming convention because these
     * keys were named before this feature existed and renaming them would
     * silently reset every existing user's learned state.
     */
    private val TRANSIENT_KEYS = setOf(
        // Exit measurement of the last session.
        "last_ip",
        "last_exit_region",
        // SHARD subscription bookkeeping — the list itself is a cache file.
        "shard_etag",
        "shard_last_check",
        "shard_last_count",
        "shard_last_paths",
        // Psiphon's advertised region list, refreshed from the network.
        "psiphon_available_regions",
        // Which rung/transport last worked, per mode. See MsnGuardVpnService's
        // winningStrategyKey() and CoreConfig.PLAIN_WORKING_TRANSPORT_PREF.
        "psiphon_winning_strategy",
        "psiphon_winning_strategy_shape",
        "psiphon_winning_strategy_chained",
        "psiphon_winning_strategy_chained_shape",
        "chain_outer_index",
        "plain_working_transport",
        "tor_winning_mode",
        "tor_winning_mode_chained",
        // "the one-time transport search already found a winner on this device".
        // A measurement of one carrier's blocking, so a restore onto a phone on a
        // different network must let the search run there instead of inheriting a
        // verdict it never made. See MainActivity.AUTO_SCAN_DONE.
        "auto_scan_done",
    )

    /**
     * Key prefixes inside the settings file that are measurements, not choices.
     *
     * Smart Split stores one entry per network (`smart_split_profile_cell:43211`,
     * `…_wifi`), so the set of keys is not knowable in advance and an exact list
     * cannot express it.
     *
     * These must not travel in a backup even though they look like settings. The
     * value is a fact about one SIM on one carrier's DPI; restoring it onto another
     * device — or the same device after a SIM change — would pin a fragment profile
     * that was never measured there, and the wrong profile means sites that do not
     * open rather than sites that are slow. `smart_split_enabled` is a real choice
     * and is deliberately NOT covered by this prefix.
     */
    private val TRANSIENT_PREFIXES = listOf("smart_split_profile_")

    /**
     * Preference files cleared by [resetToDefaults] but never exported.
     *
     * Learned data: a factory reset should forget it, a backup should not carry
     * it. `traffic_stats` is deliberately absent — see the class comment.
     */
    private val LEARNED_FILES = listOf("shard_health")

    /** Human-readable summary for the settings row: how many values a backup holds. */
    fun valueCount(context: Context): Int =
        FILES.sumOf { name -> exportable(context, name).size }

    private fun exportable(context: Context, file: String): Map<String, Any?> =
        context.getSharedPreferences(file, Context.MODE_PRIVATE).all
            .filterKeys { key -> !(file == SETTINGS_FILE && transient(key)) }

    private fun transient(key: String): Boolean =
        key in TRANSIENT_KEYS || TRANSIENT_PREFIXES.any { key.startsWith(it) }

    /**
     * The whole backup as JSON text, ready to be written to a file.
     *
     * @param version app version string, recorded for the user's benefit only —
     *   import does not check it, because a preference the user set in an older
     *   build is still the preference they set.
     */
    fun export(context: Context, version: String): String {
        val prefs = JSONObject()
        FILES.forEach { file ->
            val values = JSONObject()
            exportable(context, file).forEach { (key, value) ->
                encode(value)?.let { values.put(key, it) }
            }
            prefs.put(file, values)
        }
        return JSONObject().apply {
            put("app", APP_MARKER)
            put("format", FORMAT)
            put("version", version)
            put("created", System.currentTimeMillis())
            put("prefs", prefs)
        }.toString(2)
    }

    /** One preference value as `{"t":<type>,"v":<value>}`, or null if untranslatable. */
    private fun encode(value: Any?): JSONObject? = when (value) {
        is Boolean -> JSONObject().put("t", "b").put("v", value)
        is Int -> JSONObject().put("t", "i").put("v", value)
        is Long -> JSONObject().put("t", "l").put("v", value)
        is Float -> JSONObject().put("t", "f").put("v", value.toDouble())
        is String -> JSONObject().put("t", "s").put("v", value)
        is Set<*> -> JSONObject()
            .put("t", "ss")
            .put("v", JSONArray().apply { value.forEach { put(it.toString()) } })
        else -> null
    }

    /** What [restore] did, for a message the user can act on. */
    data class Outcome(val restored: Int, val skipped: Int, val version: String)

    /**
     * Applies a backup produced by [export].
     *
     * Throws [IllegalArgumentException] with a user-facing message on anything
     * that is not our file — a wrong pick in the system file picker is the
     * expected failure here, not a rare one.
     *
     * The target files are cleared first. A merge would leave a key the backup
     * does not contain at whatever the fresh install defaulted to, so a restore
     * would produce a state that is neither the backup nor the default — and the
     * user asked for "my settings back", which means exactly the file.
     */
    fun restore(context: Context, text: String): Outcome {
        val root = runCatching { JSONObject(text) }.getOrElse {
            throw IllegalArgumentException("This file is not a settings backup")
        }
        if (root.optString("app") != APP_MARKER) {
            throw IllegalArgumentException("This backup belongs to another app")
        }
        val format = root.optInt("format", -1)
        if (format < 1 || format > FORMAT) {
            throw IllegalArgumentException("This backup was made by a newer version")
        }
        val prefs = root.optJSONObject("prefs")
            ?: throw IllegalArgumentException("This backup carries no settings")

        var restored = 0
        var skipped = 0
        FILES.forEach { file ->
            val values = prefs.optJSONObject(file) ?: return@forEach
            val editor = context.getSharedPreferences(file, Context.MODE_PRIVATE).edit()
            editor.clear()
            values.keys().forEach { key ->
                if (file == SETTINGS_FILE && transient(key)) {
                    // A backup written by a build that exported these; drop them
                    // here too rather than trusting the file.
                    skipped++
                    return@forEach
                }
                val entry = values.optJSONObject(key)
                if (entry == null || !writeValue(editor, key, entry)) skipped++ else restored++
            }
            // commit(), not apply(): the activity is recreated immediately after
            // this returns, and it must read the restored values, not the old ones.
            editor.commit()
        }
        if (restored == 0) throw IllegalArgumentException("This backup carries no settings")
        return Outcome(restored, skipped, root.optString("version", "?"))
    }

    /** Writes one decoded value; false when the entry is malformed. */
    private fun writeValue(
        editor: android.content.SharedPreferences.Editor,
        key: String,
        entry: JSONObject,
    ): Boolean {
        if (!entry.has("v")) return false
        return when (entry.optString("t")) {
            "b" -> { editor.putBoolean(key, entry.optBoolean("v")); true }
            "i" -> { editor.putInt(key, entry.optInt("v")); true }
            "l" -> { editor.putLong(key, entry.optLong("v")); true }
            "f" -> { editor.putFloat(key, entry.optDouble("v").toFloat()); true }
            "s" -> { editor.putString(key, entry.optString("v")); true }
            "ss" -> {
                val array = entry.optJSONArray("v") ?: return false
                val set = HashSet<String>(array.length())
                for (index in 0 until array.length()) {
                    array.optString(index).takeIf { it.isNotEmpty() }?.let(set::add)
                }
                editor.putStringSet(key, set)
                true
            }
            else -> false
        }
    }

    /**
     * Back to a fresh install's behaviour.
     *
     * Clears the choice files and the learned ones, so the next connect behaves
     * exactly like the first connect after installing — that is what "default"
     * means to the person tapping it. Monthly traffic totals survive: they are a
     * record of usage, and silently zeroing someone's data counter because they
     * reset their settings would be a second, unasked-for action.
     */
    fun resetToDefaults(context: Context) {
        (FILES + LEARNED_FILES).forEach { file ->
            context.getSharedPreferences(file, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit()
        }
    }
}
