package com.msnguard.vpn

/**
 * Rewrites every log line so a forwarded log states *what* happened without
 * stating *how* this app works.
 *
 * Why this exists
 * ---------------
 * The in-app log is the support channel: the user copies it and sends it on. In
 * that form it was also a complete description of the transport. Real lines from
 * a field log gave away the whole SHARD design:
 *
 * ```
 * ShardManager winner AL 🇦🇱 | @Raydikalx | B2CCBD | 5e4e03 in 1702ms
 * ShardSocksFront listening on 127.0.0.1:1825 → xray SOCKS 1824
 * ShardSubscription updated — 27 nodes, 108 paths
 * ```
 *
 * That names the engine, the internal port layout, the pool size, and — worst —
 * the upstream publisher whose channel the node list comes from. Anyone holding
 * one log could reproduce the transport, or get the source shut down.
 *
 * What is kept and what is coded
 * ------------------------------
 * The split is deliberate, because the log still has to be usable:
 *
 * - **Kept readable: the failure itself.** `verify timeout during the QUIC
 *   handshake`, `could not bind`, `context canceled`, timings, HTTP status codes.
 *   Those describe a symptom, not a design, and they are what makes a log worth
 *   reading at all.
 * - **Coded: identity and topology.** Subsystem names, hostnames, addresses,
 *   ports, URLs, file paths, engine name, node labels, pool counts.
 *
 * Reversible where it matters
 * ---------------------------
 * IPv4 addresses and ports are *keyed but reversible* — given a token the exact
 * address can be recovered, which is what makes a report actionable, since that
 * node can then be tested directly. Hostnames, URLs, node keys and file paths get
 * a one-way keyed digest instead: for those, knowing *whether two lines mean the
 * same host* is all a diagnosis needs, and a digest cannot be turned back into an
 * advertisement for someone's channel.
 *
 * Every token is deterministic, so the same node yields the same code all session
 * and a rotation shows up as a code that changed.
 *
 * Honest limit
 * ------------
 * The key is a constant in this file, so anyone who decompiles the APK can undo
 * it. That is not the threat being addressed. This stops a log that has been
 * *forwarded, screenshotted or pasted into a group* from being readable — which
 * is how logs actually leak.
 *
 * Cost
 * ----
 * Seven precompiled patterns and one alternation per line, inside the lock that
 * [ConnectionLog.record] already holds. Nothing allocates until a match is found.
 */
object LogRedactor {

    /** Salt for the one-way digests. Not a secret from the APK; see the class doc. */
    private const val DIGEST_KEY: Int = 0x6D5A1F3B

    /** Keystream for the reversible address encoding, one byte per octet. */
    private val ADDR_KEY = intArrayOf(0x5B, 0x9F, 0x2E, 0x71)

    /** Mask for the reversible port encoding. */
    private const val PORT_KEY = 0x1A2B

    /**
     * Not base32's alphabet and not in order, so a token does not read as an
     * encoding anyone recognises. Deliberately contains no `0` and no `1`: that is
     * what guarantees a generated token can never look like one of this app's own
     * port numbers and be rewritten twice.
     */
    private const val ALPHABET = "3QF7RJ2WXMK9YBDTNAHCLPZG5V4S8E6U"

    // --- tokens ------------------------------------------------------------

    private fun encode(value: Int, width: Int): String {
        val out = StringBuilder(width)
        var v = value
        repeat(width) {
            out.append(ALPHABET[v and 31])
            v = v ushr 5
        }
        return out.toString()
    }

    /** One-way, keyed, deterministic. FNV-1a is enough: this is not a MAC. */
    private fun digest(value: String, width: Int = 4): String {
        var h = 0x811C9DC5.toInt() xor DIGEST_KEY
        for (ch in value) {
            h = h xor ch.code
            h *= 16777619
        }
        return encode(h, width)
    }

    /** Reversible: four octets XOR the keystream, packed into seven symbols. */
    private fun addressToken(a: Int, b: Int, c: Int, d: Int): String {
        val octets = intArrayOf(a, b, c, d)
        var packed = 0
        for (i in 0..3) packed = (packed shl 8) or ((octets[i] xor ADDR_KEY[i]) and 0xFF)
        return encode(packed, 7)
    }

    /** Reversible: sixteen bits XOR the mask, packed into four symbols. */
    private fun portToken(port: Int): String = encode(port xor PORT_KEY, 4)

    /**
     * The code for one node, from its stable key rather than its label.
     *
     * The label is the leak no pattern can catch: it is free text written by the
     * publisher, and in this pool it carries a channel handle, a flag, a country
     * and a rotating hex suffix. So a node's identity is coded at the call site and
     * the label never reaches the log at all.
     */
    fun nodeTag(nodeKey: String): String = "n" + digest(nodeKey, 4)

    // --- patterns ----------------------------------------------------------

    /** Absolute paths: they reveal the package layout and the engine's file name. */
    private val PATH = Regex("""/(?:data|system|storage|sdcard|proc|vendor)/[^\s,;:)"']*""")

    /**
     * A publisher's node label, which is the worst leak in the log and the one no
     * structural rule catches — it is free text somebody else wrote.
     *
     * Both shapes seen in the live pool are pipe-separated, so a run of two or more
     * `|` fields is treated as one label and coded whole:
     *
     * ```
     * AL 🇦🇱 | @Raydikalx | B2CCBD | 5e4e03
     * 🇺🇸 | @WhiteDNS | US983|2.6MB/s|…
     * ```
     *
     * Two pipes minimum, so ordinary prose containing a single `|` is untouched.
     * Call sites now log [nodeTag] instead of a label, but this stays as the net
     * underneath: a label can also arrive second-hand inside an engine error
     * string, and one that slips through is an advertisement for someone's channel.
     *
     * Fields deliberately contain no internal spaces. An earlier version allowed
     * them and the match ran away to the left, swallowing the prose in front of the
     * label — `ShardManager winner AL … | @x | …` was coded whole, so the line lost
     * which subsystem had spoken. [FLAG] is stripped before this runs, which is what
     * leaves `AL 🇦🇱` as a single spaceless field.
     */
    private val LABEL_RUN = Regex("""[^\s|]+(?:\s*\|\s*[^\s|]+){2,}""")

    /** A bare channel handle, for labels that carry a handle and no pipes at all. */
    private val HANDLE = Regex("""@[A-Za-z0-9_]{3,}""")

    /**
     * Regional-indicator pairs — a flag names the exit country as plainly as text.
     *
     * Written as `\x{...}` code points, not as surrogate pairs. `[\uD83C][\uDDE6-…]`
     * looks equivalent and silently never matches: Java's regex engine scans the
     * input by code point, so a lone high surrogate in a character class has nothing
     * to match against. That failure was not theoretical — it left `AL 🇦🇱` in the
     * log and shifted [LABEL_RUN]'s match one field to the right.
     */
    private val FLAG = Regex("""[\x{1F1E6}-\x{1F1FF}]{2}""")

    private val URL = Regex("""https?://[^\s"',)]+""")

    /** Optional `:port`, so `address:port` is coded as one unit. */
    private val IPV4 = Regex("""\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b(?::(\d{1,5}))?""")

    /**
     * Three or more colons, so a wall-clock time (`14:24:21`, two colons) and an
     * `address:port` (one) can never match.
     */
    private val IPV6 = Regex("""\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){3,}\b""")

    /**
     * A dotted name whose last label is alphabetic. That single condition keeps
     * version strings (`1.7.10`, `26.8.28`) out while still catching asset and
     * library file names, which name the engine as loudly as a hostname does.
     */
    private val HOST = Regex("""\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b""")

    /** This app's own port block: 1819-1825 live, 21100-21199 the probe race. */
    private val OWN_PORTS = Regex("""\b(?:18(?:19|2[0-5])|211\d\d)\b""")

    /**
     * The engine's version banner, which names the engine even after its name is
     * coded: `26.8.28 (Xray, Penetrates Everything.) 3115a98 (go1.26.7 …)`. The
     * tagline, the commit and the Go version are each enough to identify it, so the
     * whole run is taken as one token — and a bare `26.8.28 started` too.
     *
     * Must run after [IPV4], or `162.159.198` would match as a version and the
     * address would stop round-tripping.
     */
    private val ENGINE_BANNER = Regex(
        """\b\d{1,3}\.\d{1,3}\.\d{1,3}\b(?:\s*\([^)]*\))?(?:\s+[0-9a-f]{7,}\b)?(?:\s*\(go[^)]*\))?"""
    )

    /**
     * Framework names that are not ours and give nothing away. Kept legible because
     * `android.permission.RECEIVE_BOOT_COMPLETED` is the entire content of a real
     * defect report — coded, that line stops being actionable.
     */
    private val KEEP_NAME = Regex("""^(?:android|androidx|java|javax|kotlin|kotlinx)\.""")

    /** Pool size and shape. Renamed rather than dropped: an empty pool is a real signal. */
    private val POOL_COUNTS = Regex("""(\d+) nodes, (\d+) paths""")
    private val ATTEMPT = Regex("""attempt (\d+) of (\d+)""")

    /**
     * Names that describe the design. One alternation, longest key first, so
     * `ShardManager/probe` wins over `ShardManager` and `xray SOCKS` over `xray`.
     */
    private val CODEBOOK = mapOf(
        // subsystems
        "ShardManager/probe" to "M7p",
        "ShardManager" to "M7",
        "ShardSubscription" to "S3",
        "ShardSocksFront" to "F2",
        "ShardRefreshJob" to "R5",
        "ShardHealth" to "H4",
        "ShardEdges" to "G8",
        "ShardExit" to "X6",
        "SmartSplit" to "Q9",
        "Smart Split" to "Q9",
        "SHARD" to "K0",
        "TorSocksFront" to "T4",
        "TorManager" to "T8",
        "Psiphon" to "P6",
        "masque gateway" to "V2g",
        "MASQUE" to "V2",
        "WireGuard" to "W1",
        "WARP" to "V3",
        "Watchdog" to "wd",
        "Tun2Socks" to "t2",
        "tun2socks" to "t2",
        // engine and its modules
        "xray SOCKS" to "u0",
        "Xray" to "E1",
        "xray" to "E1",
        "app/dispatcher" to "d2",
        "app/proxyman" to "d3",
        "app/dns" to "d1",
        "app/log" to "d6",
        "transport/internet" to "d4",
        "infra/conf/serial" to "d5",
        "core:" to "c0:",
        // method vocabulary
        "subscription" to "src",
        "seed list" to "src0",
        "udpgw" to "g7",
        "SOCKS5" to "s5",
        "SOCKS" to "s0",
        "winner" to "sel",
        "rotations" to "sw",
        "rotating" to "swap",
        "rotate" to "swap",
        "nodes" to "nd",
        "node" to "nd",
        "pool" to "pl",
        "probe" to "pb",
        "race" to "ph",
        "tunnel" to "tn",
        "geosite" to "ga",
        "geoip" to "ga",
        "geo assets" to "ga",
        // The exit-country check. Coded, or a forwarded log would state both that
        // the app tests its exits and which destination it tests them against.
        "reach check" to "rc",
        // Same subject, the v1.7.14 vocabulary. Without these a forwarded log spells
        // out the entire method in plain words: that a destination refuses the exit,
        // that a second exit exists, and that one is being shopped for.
        "exit check inconclusive" to "rc?",
        "exit check served" to "rc+",
        "exit check refused" to "rc-",
        "second exit selected" to "e2s",
        "second exit known" to "e2k",
        "no second exit answered" to "e2n",
        "no candidate for a second exit" to "e2c",
        "looking for a second exit" to "e2f",
        "second exit" to "e2",
        "exit probe could not start" to "e2x",
        "exit probe failed" to "e2e",
        "exit probe" to "e2p",
        "second leg" to "e2",
        "HTTP/3" to "z3",
        "QUIC" to "z9",
        "account" to "ac",
    )

    /**
     * Left-anchored on a word boundary, so `race` cannot match inside `traceroute`
     * and `node` cannot match inside a longer word. Not anchored on the right: some
     * keys end in `:` or `/`, where a trailing `\b` would need a word character
     * after the punctuation and the key would never match at all.
     */
    private val CODE_RE = Regex(
        """\b(?:""" +
            CODEBOOK.keys.sortedByDescending { it.length }.joinToString("|") { Regex.escape(it) } +
            ")"
    )

    // --- the pass ----------------------------------------------------------

    /**
     * Order is load-bearing. Structured values are consumed before the free-text
     * codebook can rewrite the words they are anchored to — [POOL_COUNTS] in
     * particular must run before `nodes` becomes `nd`. The address token joins its
     * port with `-` and never `.`, so [HOST] cannot then swallow a reversible
     * address token and turn it into a one-way digest.
     */
    fun redact(line: String): String {
        if (line.isEmpty()) return line
        var out = PATH.replace(line) { "f" + digest(it.value, 4) }
        // Flags first: that collapses `AL 🇦🇱` to one spaceless field, which is what
        // lets LABEL_RUN match the label without reaching back into the prose.
        out = FLAG.replace(out) { "" }
        // Then the label as one unit, before anything else splits it up.
        out = LABEL_RUN.replace(out) { "n" + digest(it.value, 4) }
        out = HANDLE.replace(out) { "p" + digest(it.value, 3) }
        out = URL.replace(out) { "u" + digest(it.value, 4) }
        out = IPV4.replace(out) { m ->
            val a = m.groupValues[1].toIntOrNull() ?: 0
            val b = m.groupValues[2].toIntOrNull() ?: 0
            val c = m.groupValues[3].toIntOrNull() ?: 0
            val d = m.groupValues[4].toIntOrNull() ?: 0
            val port = m.groupValues[5]
            // Loopback is not a secret, and keeping it legible is the difference
            // between "the front end" and "some address" when reading a log.
            val host = if (a == 127) "lo" else addressToken(a, b, c, d)
            if (port.isEmpty()) host else "$host-${portToken(port.toIntOrNull() ?: 0)}"
        }
        out = IPV6.replace(out) { "x6" + digest(it.value, 4) }
        // After IPV4, so a dotted quad is never mistaken for a version string.
        out = ENGINE_BANNER.replace(out) { "e" + digest(it.value, 4) }
        out = HOST.replace(out) { m ->
            if (KEEP_NAME.containsMatchIn(m.value)) m.value else "h" + digest(m.value, 4)
        }
        out = POOL_COUNTS.replace(out) { "c1=${it.groupValues[1]} c2=${it.groupValues[2]}" }
        out = ATTEMPT.replace(out) { "a${it.groupValues[1]}/${it.groupValues[2]}" }
        out = OWN_PORTS.replace(out) { portToken(it.value.toIntOrNull() ?: 0) }
        return CODE_RE.replace(out) { CODEBOOK[it.value] ?: it.value }
    }
}
