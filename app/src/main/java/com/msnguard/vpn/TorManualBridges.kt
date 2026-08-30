package com.msnguard.vpn

import android.content.Context

/**
 * The user's own bridge lines, and the rules Tor actually enforces on them.
 *
 * Everything in [validate] was measured against a real `tor --verify-config`
 * rather than reasoned about, because Tor's bridge parser accepts and rejects
 * things that are not obvious from its manual:
 *
 * ```
 *   Bridge 51.222.13.177:80 <40-hex>                    valid
 *   Bridge 51.222.13.177:80                             valid  (fingerprint is optional)
 *   Bridge 51.222.13.177                                valid  (port defaults; we still ask for one)
 *   Bridge bridge.example.com:443 <40-hex>              REJECTED — "Error parsing Bridge address"
 *   Bridge 51.222.13.177:0 <40-hex>                     REJECTED — port 0
 *   Bridge 51.222.13.177:80 DEADBEEF                    REJECTED — "Key digest is wrong length"
 *   Bridge [2001:db8::1]:443 <40-hex>                   valid
 *   UseBridges 1 with no Bridge line                    REJECTED — tor refuses to start
 * ```
 *
 * The hostname rejection is the one that matters most in practice: a bridge
 * handed out over Telegram as `some.host:443` cannot be used by Tor at all, and
 * without this check the user would get "Tor could not connect" and no idea why.
 * webtunnel is the exception that proves the rule — its lines carry a
 * documentation-range placeholder IP and the real host lives in `url=`.
 *
 * Stored as one raw string, exactly as typed, and re-parsed on every use. Keeping
 * the user's text rather than a normalised form means a line this parser refuses
 * is still in the box when they reopen the editor, so they can see and fix it.
 */
internal object TorManualBridges {

    /** Raw multi-line text as the user typed it. */
    const val BRIDGES_PREF = "tor_manual_bridges"

    /**
     * Transports our bundled lyrebird can actually serve.
     *
     * Taken from lyrebird 0.8.1's `transports.Init()`, which is the build CI
     * compiles (`.github/workflows/tor-binaries.yml`): meeklite, obfs2, obfs3,
     * obfs4, scramblesuit, snowflake, webtunnel. Naming them here rather than
     * accepting anything means a typo like `obsf4` is caught in the editor
     * instead of becoming a torrc that starts and never connects.
     *
     * obfs2/obfs3/scramblesuit are registered by lyrebird but deliberately not
     * offered: both obfs2 and obfs3 are cryptographically broken and trivially
     * fingerprinted, and no bridge distributor has handed them out for years.
     */
    private val SUPPORTED = setOf("obfs4", "meek_lite", "webtunnel", "snowflake")

    /**
     * What users actually paste, mapped to what lyrebird registers.
     *
     * Tor Browser's own UI says "meek-azure" and some bridge lists say "meek";
     * lyrebird registers the transport as `meek_lite`. Rewriting the name is
     * safe because the arguments are identical — it is the same transport.
     */
    private val ALIASES = mapOf(
        "meek" to "meek_lite",
        "meek-azure" to "meek_lite",
        "meek_azure" to "meek_lite",
        "meeklite" to "meek_lite",
        "meek-lite" to "meek_lite",
    )

    /** Hard cap on lines, so a pasted wall of text cannot become a 200-bridge torrc. */
    private const val MAX_LINES = 8

    private val IPV4 = Regex("""^\d{1,3}(?:\.\d{1,3}){3}$""")
    private val IPV6_BRACKETED = Regex("""^\[[0-9a-fA-F:.]+]$""")
    private val FINGERPRINT = Regex("""^[0-9a-fA-F]{40}$""")

    /** One parsed bridge line: the text Tor gets, and the transport it needs. */
    data class Bridge(val line: String, val transport: String?)

    fun raw(context: Context): String =
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getString(BRIDGES_PREF, "")
            .orEmpty()

    fun save(context: Context, text: String) {
        val trimmed = text.trim()
        context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().apply {
            if (trimmed.isEmpty()) remove(BRIDGES_PREF) else putString(BRIDGES_PREF, trimmed)
        }.apply()
    }

    /**
     * Parse whatever is stored into bridge lines, dropping anything invalid.
     *
     * Lenient on purpose: [validate] is what refuses bad input at the editor, and
     * by the time this runs the text has already passed it. Should a bad line
     * survive an upgrade, dropping it beats writing a torrc Tor will not read —
     * one dead line out of three still leaves a working session.
     */
    fun bridges(context: Context): List<Bridge> = parse(raw(context))

    fun parse(text: String): List<Bridge> =
        text.lines()
            .map { stripKeyword(it) }
            .filter { it.isNotEmpty() }
            .take(MAX_LINES)
            .mapNotNull { line ->
                if (lineProblem(line) != null) null else Bridge(line, transportOf(line))
            }

    /** Distinct pluggable transports the stored lines need, in first-seen order. */
    fun transports(context: Context): List<String> =
        bridges(context).mapNotNull { it.transport }.distinct()

    /**
     * Null when the text is usable, otherwise the message shown under the field.
     *
     * Blank is an error here rather than "unset": this is only ever called from
     * the editor's Save, and saving an empty box while Manual bridge is the
     * pinned mode would produce a connect attempt that cannot work. Clearing is a
     * separate button.
     */
    fun validate(text: String): String? {
        val lines = text.lines().map { stripKeyword(it) }.filter { it.isNotEmpty() }
        if (lines.isEmpty()) return "Paste at least one bridge line"
        if (lines.size > MAX_LINES) return "At most $MAX_LINES bridges"
        lines.forEachIndexed { index, line ->
            lineProblem(line)?.let { problem ->
                return if (lines.size == 1) problem else "Line ${index + 1}: $problem"
            }
        }
        return null
    }

    /** What the settings row shows: "Not set", or a count and the transports. */
    fun summary(context: Context): String {
        val parsed = bridges(context)
        if (parsed.isEmpty()) return "Not set"
        val kinds = parsed.map { it.transport ?: "plain" }.distinct().joinToString(", ")
        val count = if (parsed.size == 1) "1 bridge" else "${parsed.size} bridges"
        return "$count · $kinds"
    }

    /** True when Manual bridge mode has something to work with. */
    fun isConfigured(context: Context): Boolean = bridges(context).isNotEmpty()

    // ------------------------------------------------------------------ internals

    /**
     * Drop a leading `Bridge` keyword and normalise the transport name.
     *
     * Users copy whole torrc lines out of BridgeDB mail and Telegram messages, so
     * roughly half of real pastes start with the keyword. Tor's own config parser
     * would see `Bridge Bridge obfs4 …` and fail on "Bridge" as an address.
     */
    private fun stripKeyword(rawLine: String): String {
        var line = rawLine.trim()
        if (line.startsWith("#") || line.startsWith("//")) return ""
        if (line.length > 6 && line.substring(0, 6).equals("bridge", ignoreCase = true) &&
            line[6].isWhitespace()
        ) {
            line = line.substring(7).trim()
        }
        val head = line.substringBefore(' ').lowercase()
        val alias = ALIASES[head]
        if (alias != null) {
            line = alias + line.substring(head.length)
        }
        return line
    }

    /** The transport a line names, or null for a plain `IP:PORT` bridge. */
    private fun transportOf(line: String): String? {
        val head = line.substringBefore(' ')
        return if (looksLikeAddress(head)) null else head.lowercase()
    }

    private fun looksLikeAddress(token: String): Boolean {
        val host = token.substringBeforeLast(':', missingDelimiterValue = token)
        return IPV4.matches(host) || IPV6_BRACKETED.matches(host) ||
            IPV4.matches(token) || IPV6_BRACKETED.matches(token)
    }

    /** Null when the single line is fine, otherwise the reason it is not. */
    private fun lineProblem(line: String): String? {
        val parts = line.split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (parts.isEmpty()) return "Empty bridge line"

        val transport = transportOf(line)
        if (transport != null && transport !in SUPPORTED) {
            return "Unknown transport \"$transport\" — use ${SUPPORTED.joinToString(", ")}"
        }

        val addressIndex = if (transport == null) 0 else 1
        val address = parts.getOrNull(addressIndex)
            ?: return "Add the bridge address as IP:port"
        addressProblem(address)?.let { return it }

        // The token after the address is a fingerprint when it is not a key=value
        // argument. Tor takes it or leaves it, but a truncated one is a line that
        // parses and then never connects, so it is checked here.
        val next = parts.getOrNull(addressIndex + 1)
        if (next != null && !next.contains('=') && !FINGERPRINT.matches(next)) {
            return "The fingerprint must be 40 hex characters"
        }

        // obfs4 without a cert is the single most common broken paste: the line is
        // valid to Tor, lyrebird gets no key material and every dial fails.
        if (transport == "obfs4" && parts.none { it.startsWith("cert=") }) {
            return "This obfs4 bridge is missing its cert= value"
        }
        // Same class of problem for the two URL-based transports.
        if ((transport == "webtunnel" || transport == "snowflake") &&
            parts.none { it.startsWith("url=") }
        ) {
            return "This $transport bridge is missing its url= value"
        }
        return null
    }

    private fun addressProblem(address: String): String? {
        val portText = address.substringAfterLast(':', missingDelimiterValue = "")
        val host = address.substringBeforeLast(':', missingDelimiterValue = address)
        if (portText.isEmpty() || portText.toIntOrNull() == null) {
            return "Add a port, as in ${host.ifEmpty { "1.2.3.4" }}:443"
        }
        val port = portText.toInt()
        if (port !in 1..65535) return "The port must be between 1 and 65535"
        if (IPV4.matches(host)) {
            if (host.split('.').any { (it.toIntOrNull() ?: 256) > 255 }) {
                return "\"$host\" is not a valid IPv4 address"
            }
            return null
        }
        if (IPV6_BRACKETED.matches(host)) return null
        // Tor's parser refuses hostnames outright, so this is not a style rule.
        return "Tor needs a numeric address, not \"$host\" — use IP:port, " +
            "or [IPv6]:port"
    }
}
