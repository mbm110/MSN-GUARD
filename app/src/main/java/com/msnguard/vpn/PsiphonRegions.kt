package com.msnguard.vpn

import android.content.Context

/**
 * The egress countries a user may ask for, and the names to show for them.
 *
 * Psiphon's own `EgressRegion` is a *hard* filter, not a weighting: set it and
 * only that country's servers are candidates. That is why this list is used for a
 * single short attempt in front of the strategy ladder rather than for the whole
 * connection — see [MsnGuardVpnService.regionPhase].
 *
 * Two sources, unioned:
 *
 *  - [BUNDLED] is what the 430 embedded server entries in `assets/server_entries.txt`
 *    actually advertise, counted at build time. It exists so the picker is
 *    populated on a fresh install, before any tunnel has ever come up.
 *  - Psiphon reports the live set through `onAvailableEgressRegions` on every
 *    successful handshake. That is authoritative — the embedded list ages — so it
 *    is cached and merged on top.
 *
 * Codes with no name mapping still work: they show as the bare code, so a country
 * Psiphon adds later is selectable without an app update.
 */
object PsiphonRegions {

    /** Where the last `onAvailableEgressRegions` report is cached, comma-separated. */
    const val AVAILABLE_PREF = "psiphon_available_regions"

    /**
     * Countries present in the embedded server list, with their server counts at
     * the time of writing (DE 60, US 65, CA 65, NL 38 …). The counts are not stored
     * — they change with every server-list refresh — but they are the reason the
     * list is ordered by name rather than by size: a user picking a country cares
     * which country it is, not how many servers it has.
     */
    private val BUNDLED = mapOf(
        "AT" to "Austria",
        "AU" to "Australia",
        "BE" to "Belgium",
        "CA" to "Canada",
        "CH" to "Switzerland",
        "CZ" to "Czechia",
        "DE" to "Germany",
        "DK" to "Denmark",
        "ES" to "Spain",
        "FI" to "Finland",
        "FR" to "France",
        "GB" to "United Kingdom",
        "ID" to "Indonesia",
        "IE" to "Ireland",
        "IN" to "India",
        "IT" to "Italy",
        "JP" to "Japan",
        "NL" to "Netherlands",
        "NO" to "Norway",
        "PL" to "Poland",
        "RO" to "Romania",
        "RS" to "Serbia",
        "SE" to "Sweden",
        "SG" to "Singapore",
        "US" to "United States",
    )

    /**
     * How many of the embedded server entries each country has.
     *
     * Shown in the picker because it is the honest predictor of whether a country
     * will connect: a country with three servers is far likelier to need the
     * fallback than one with sixty. Counted from `assets/server_entries.txt`; the
     * absolute numbers drift as the list is refreshed, the ordering does not.
     */
    private val BUNDLED_COUNT = mapOf(
        "US" to 65, "CA" to 65, "DE" to 60, "NL" to 38, "GB" to 31, "FR" to 26,
        "PL" to 18, "SE" to 17, "JP" to 13, "SG" to 12, "IN" to 11, "ES" to 10,
        "IT" to 9, "AU" to 8, "DK" to 7, "FI" to 7, "RS" to 5, "NO" to 5,
        "CH" to 5, "AT" to 4, "CZ" to 4, "BE" to 3, "IE" to 3, "ID" to 3,
        "RO" to 1,
    )

    /**
     * One line of context under a country in the picker.
     *
     * Countries only Psiphon reports have no bundled count, which is not a problem
     * — it just means the count is unknown, so say nothing rather than "0 servers".
     */
    fun detail(code: String): String {
        val n = BUNDLED_COUNT[code.trim().uppercase()] ?: return "Reported available by Psiphon"
        return if (n == 1) "1 server in the bundled list" else "$n servers in the bundled list"
    }


    /**
     * Names for countries Psiphon can report but the embedded list does not carry.
     * Kept separate from [BUNDLED] so it is obvious which entries are evidence and
     * which are just labels.
     */
    private val EXTRA_NAMES = mapOf(
        "AE" to "United Arab Emirates",
        "AR" to "Argentina",
        "BG" to "Bulgaria",
        "BR" to "Brazil",
        "CL" to "Chile",
        "EE" to "Estonia",
        "GR" to "Greece",
        "HK" to "Hong Kong",
        "HU" to "Hungary",
        "IL" to "Israel",
        "IS" to "Iceland",
        "KR" to "South Korea",
        "LT" to "Lithuania",
        "LV" to "Latvia",
        "MD" to "Moldova",
        "MX" to "Mexico",
        "MY" to "Malaysia",
        "NZ" to "New Zealand",
        "PT" to "Portugal",
        "SK" to "Slovakia",
        "TR" to "Türkiye",
        "TW" to "Taiwan",
        "UA" to "Ukraine",
        "ZA" to "South Africa",
    )

    /** Human name for a two-letter code, or the code itself when unknown. */
    fun name(code: String): String {
        val key = code.trim().uppercase()
        return BUNDLED[key] ?: EXTRA_NAMES[key] ?: key
    }

    /** Flag + name, e.g. "🇩🇪 Germany". */
    fun label(code: String): String = "${IpFormatter.flag(code)} ${name(code)}"

    /**
     * Selectable countries, ordered by name.
     *
     * The bundled set is always included even if a cached report is narrower: a
     * report is a snapshot of one moment on one network, and dropping a country
     * the embedded list still carries would remove a working choice.
     */
    fun options(context: Context): List<String> {
        val cached = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getString(AVAILABLE_PREF, "")
            .orEmpty()
            .split(',')
            .map { it.trim().uppercase() }
            .filter(::isCode)
        return (BUNDLED.keys + cached).distinct().sortedBy { name(it) }
    }

    /** Cache Psiphon's live report so the picker reflects what the network offers. */
    fun remember(context: Context, codes: List<String>) {
        val clean = codes.map { it.trim().uppercase() }.filter(::isCode).distinct().sorted()
        if (clean.isEmpty()) return
        context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit()
            .putString(AVAILABLE_PREF, clean.joinToString(","))
            .apply()
    }

    /** Exactly two ASCII letters — anything else is not an egress region. */
    fun isCode(code: String): Boolean =
        code.length == 2 && code.all { it in 'A'..'Z' }
}
