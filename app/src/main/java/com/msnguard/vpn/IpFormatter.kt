package com.msnguard.vpn

/**
 * Fits an IP address into a fixed-width readout without breaking the layout.
 *
 * The problem this solves: the exit-node card gives the address about 198dp.
 * In the monospace face that is roughly 29 characters at the smallest step, but
 * a full IPv6 literal is 39 (`2606:4700:0110:8a36:b4d1:2f7c:9e05:1a42`). Letting
 * it wrap pushed the card two lines taller and shoved the transport rail off
 * screen; letting it ellipsise at the tail made every address on the same /32
 * look identical.
 *
 * Three stages, cheapest first:
 *  1. [compress] — RFC 5952 canonical form: strip leading zeros per hextet and
 *     collapse the longest run of zero groups to `::`. Most real addresses fit
 *     after this alone.
 *  2. [Fit.step] — the caller drops the font size a step for v6.
 *  3. middle-elide on `:` boundaries, keeping both the prefix (which network)
 *     and the suffix (which host). Never cuts inside a hextet.
 *
 * Pure and side-effect free so it is unit-testable without an Android context.
 */
object IpFormatter {

    enum class Step { V4, V6, V6_LONG }

    data class Fit(
        val text: String,
        val step: Step,
        val isV6: Boolean,
        val full: String,
    )

    /** Budget in characters at the smallest step. Measured, not guessed. */
    const val BUDGET = 29

    fun fit(raw: String, budget: Int = BUDGET): Fit {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return Fit(trimmed, Step.V4, false, trimmed)
        if (!trimmed.contains(':')) return Fit(trimmed, Step.V4, false, trimmed)

        val compressed = compress(trimmed)
        if (compressed.length <= budget) {
            val step = if (compressed.length <= 25) Step.V6 else Step.V6_LONG
            return Fit(compressed, step, true, trimmed)
        }
        return Fit(middleElide(compressed, budget), Step.V6_LONG, true, trimmed)
    }

    /**
     * RFC 5952 §4 canonical text form.
     *
     * Returns the input lowercased and unchanged when it already contains `::`
     * or does not have the expected eight groups — being conservative here is
     * better than mangling something we do not understand, e.g. a zone id or an
     * IPv4-mapped form.
     */
    fun compress(address: String): String {
        val lower = address.lowercase()
        if (lower.contains("::")) return lower
        val groups = lower.split(':')
        if (groups.size != 8) return lower
        if (groups.any { it.isEmpty() || it.length > 4 }) return lower

        val stripped = groups.map { group ->
            val s = group.trimStart('0')
            if (s.isEmpty()) "0" else s
        }

        var bestIndex = -1
        var bestLength = 0
        var runIndex = -1
        var runLength = 0
        stripped.forEachIndexed { index, group ->
            if (group == "0") {
                if (runIndex < 0) {
                    runIndex = index
                    runLength = 1
                } else {
                    runLength++
                }
                if (runLength > bestLength) {
                    bestLength = runLength
                    bestIndex = runIndex
                }
            } else {
                runIndex = -1
                runLength = 0
            }
        }

        // RFC 5952: only collapse a run of two or more, and never a single zero.
        if (bestLength < 2) return stripped.joinToString(":")
        val head = stripped.take(bestIndex).joinToString(":")
        val tail = stripped.drop(bestIndex + bestLength).joinToString(":")
        return "$head::$tail"
    }

    /**
     * Keeps as many leading and trailing hextets as fit, joined by `…`.
     * Alternates head/tail so the two halves stay balanced.
     */
    private fun middleElide(compressed: String, budget: Int): String {
        val groups = compressed.split(':')
        if (groups.size < 3) return compressed.take(budget)
        val head = mutableListOf<String>()
        val tail = mutableListOf<String>()
        var low = 0
        var high = groups.size - 1
        while (low <= high) {
            val takeHead = head.size <= tail.size
            if (takeHead) {
                val candidate = head + groups[low]
                if (width(candidate, tail) > budget) break
                head.add(groups[low])
                low++
            } else {
                val candidate = listOf(groups[high]) + tail
                if (width(head, candidate) > budget) break
                tail.add(0, groups[high])
                high--
            }
        }
        if (head.isEmpty() && tail.isEmpty()) return compressed.take(budget)
        return head.joinToString(":") + "\u2026" + tail.joinToString(":")
    }

    /** Rendered length of `head…tail`, where `…` costs one char plus two joins. */
    private fun width(head: List<String>, tail: List<String>): Int =
        head.joinToString(":").length + tail.joinToString(":").length + 3

    /**
     * Two-letter country code to a flag emoji via regional indicators.
     *
     * Returns a globe for anything that is not exactly two ASCII letters, which
     * is deliberately strict: Cloudflare answers `loc=T1` for every Tor exit
     * ("T1" is its pseudo-code for the Tor network, measured on four different
     * exits), and `XX`/`T1`-style pseudo-codes must render as the globe rather
     * than as two nonsense letter boxes. Callers that want a real country for a
     * Tor exit must resolve the address through a geo lookup instead — see
     * [isRealCountry].
     */
    fun flag(countryCode: String?): String {
        val code = countryCode?.trim()?.uppercase() ?: return "\uD83C\uDF10"
        if (!isRealCountry(code)) return "\uD83C\uDF10"
        val base = 0x1F1E6
        val first = base + (code[0] - 'A')
        val second = base + (code[1] - 'A')
        return String(Character.toChars(first)) + String(Character.toChars(second))
    }

    /**
     * True when [code] is a country code that can actually be shown as a flag.
     *
     * Exists because "the endpoint returned a `loc` field" and "we know the exit
     * country" are different facts. Cloudflare's `cdn-cgi/trace` returns
     * `loc=T1` through Tor — verified on 85.93.218.204, 185.220.100.240,
     * 45.66.35.28 and 185.220.101.20, all `T1` — and `T1` passes a naive
     * "non-blank" check while being unmappable to a flag. Treating it as a
     * country is what left the flag as a globe forever in Tor mode while the
     * address itself was correct.
     *
     * `XX` and `T1` are the two pseudo-codes seen in the wild; the letter test
     * covers the rest by construction.
     */
    fun isRealCountry(code: String?): Boolean {
        val key = code?.trim()?.uppercase() ?: return false
        if (key.length != 2 || key.any { it !in 'A'..'Z' }) return false
        return key != "T1" && key != "XX"
    }
}
