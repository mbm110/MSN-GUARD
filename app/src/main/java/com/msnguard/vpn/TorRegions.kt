package com.msnguard.vpn

import android.content.Context

/**
 * The exit countries a user may ask Tor for, and the names to show for them.
 *
 * Deliberately a sibling of [PsiphonRegions] rather than a reuse of it: the two
 * networks have completely different country sets. Psiphon's list comes from its
 * own server inventory; Tor's comes from which volunteer relays hold the Exit
 * flag right now, and that distribution is far more lopsided — a handful of
 * countries carry almost all of it.
 *
 * ## What the codes mean here
 *
 * Tor's knob is `ExitNodes {cc}` plus `StrictNodes`. This app sets
 * **`StrictNodes 0`**, which makes the choice a *preference*: tor prefers that
 * country and leaves it when it cannot build a working circuit there. That is
 * the same contract the Psiphon row advertises, and it is the reason this is
 * safe to expose — `StrictNodes 1` on a country with one exit means no
 * connection at all when that exit is down.
 *
 * Measured on this project's server against live tor 0.4.6.10, warm cache:
 *
 * | request | bootstrap | exit address | real country |
 * |---------|-----------|--------------|--------------|
 * | `{de}`  | 100% / 4s | 185.220.101.32 | DE |
 * | `{nl}`  | 100% / 4s | 192.42.116.109 | NL |
 * | `{se}`  | 100% / 4s | 193.189.100.196 | SE |
 * | `{at}`  | 100% / 4s | 109.70.100.10 | AT |
 * | `{ro}`  | 100% / 4s | 185.100.85.24 | RO |
 *
 * One earlier `{de}` run exited in SE instead, which is `StrictNodes 0` doing
 * exactly what it promises. The UI says so rather than pretending the choice is
 * a guarantee.
 *
 * ## Why the counts are in here
 *
 * They are the honest predictor of whether a choice will be honoured. Counted
 * from the Tor Project's own onionoo service (`type=relay&running=true&flag=Exit`)
 * at the time of writing: 3275 running exits across 52 countries, and the top
 * three hold more than two thirds of them. A country with four exits will fall
 * back often; the user deserves to know that before picking it, not after.
 */
object TorRegions {

    /** Preference key holding the wanted two-letter code, or [AUTO]. */
    const val REGION_PREF = "tor_exit_region"

    /** Value of [REGION_PREF] meaning "any country". */
    const val AUTO = "auto"

    /**
     * Countries with enough running exit capacity to be worth offering, with
     * their exit counts.
     *
     * The cut is at five exits. Below that a preference is honoured so rarely
     * that offering it would be a control that mostly does nothing — Greece,
     * Mexico, Estonia and Portugal each have exactly one exit, and Japan has
     * three. Countries are still reachable by tor's own choice; they are just
     * not offered as a target.
     */
    private val EXIT_COUNT = mapOf(
        "US" to 1165, "NL" to 614, "DE" to 415, "SE" to 344, "AT" to 123,
        "LU" to 93, "RO" to 70, "FR" to 67, "NO" to 54, "SG" to 35,
        "CH" to 34, "UA" to 29, "IS" to 24, "HR" to 20, "HU" to 19,
        "BG" to 17, "IT" to 15, "DK" to 15, "FI" to 12, "ZA" to 11,
        "CZ" to 10, "PL" to 9, "GB" to 7, "ES" to 6, "ID" to 6,
        "HK" to 6, "CA" to 5,
    )

    private val NAMES = mapOf(
        "AT" to "Austria",
        "BG" to "Bulgaria",
        "CA" to "Canada",
        "CH" to "Switzerland",
        "CZ" to "Czechia",
        "DE" to "Germany",
        "DK" to "Denmark",
        "ES" to "Spain",
        "FI" to "Finland",
        "FR" to "France",
        "GB" to "United Kingdom",
        "HK" to "Hong Kong",
        "HR" to "Croatia",
        "HU" to "Hungary",
        "ID" to "Indonesia",
        "IS" to "Iceland",
        "IT" to "Italy",
        "LU" to "Luxembourg",
        "NL" to "Netherlands",
        "NO" to "Norway",
        "PL" to "Poland",
        "RO" to "Romania",
        "SE" to "Sweden",
        "SG" to "Singapore",
        "UA" to "Ukraine",
        "US" to "United States",
        "ZA" to "South Africa",
    )

    /** Human name for a code, or the code itself when unknown. */
    fun name(code: String): String {
        val key = code.trim().uppercase()
        return NAMES[key] ?: key
    }

    /** Flag + name, e.g. "🇩🇪 Germany". */
    fun label(code: String): String = "${IpFormatter.flag(code)} ${name(code)}"

    /**
     * One line of context under a country in the picker.
     *
     * Says the count plainly, and warns where the count is low enough that the
     * fallback is the likely outcome. A control that explains its own limits is
     * better than one that quietly disobeys.
     */
    fun detail(code: String): String {
        val n = EXIT_COUNT[code.trim().uppercase()] ?: return "Exit capacity unknown"
        val noun = if (n == 1) "exit relay" else "exit relays"
        return if (n < 15) "$n $noun — may fall back to another country" else "$n $noun"
    }

    /** Selectable countries, ordered by name. */
    fun options(): List<String> = EXIT_COUNT.keys.sortedBy { name(it) }

    /**
     * The wanted exit country, or null for "any".
     *
     * Anything not on the offered list resolves to null rather than being passed
     * to tor: an unknown code in `ExitNodes` would leave tor with an empty
     * candidate set and every circuit would then fail for a reason that looks
     * like censorship.
     */
    fun selected(context: Context): String? {
        val stored = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getString(REGION_PREF, AUTO)
            ?.trim()
            ?.uppercase()
            .orEmpty()
        if (stored.isEmpty() || stored.equals(AUTO, ignoreCase = true)) return null
        return stored.takeIf { EXIT_COUNT.containsKey(it) }
    }
}
