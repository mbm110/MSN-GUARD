package com.msnguard.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URLDecoder
import java.util.Locale

/**
 * One proxy node from the SHARD subscription, and the xray config that runs it.
 *
 * ## Where these come from
 *
 * A single subscription URL, refreshed by [ShardSubscription]. The user never
 * sees it, never pastes anything, and has no list to pick from — the whole
 * transport is one button. That is deliberate: every other app in this space
 * makes the user curate a config list, and the point of SHARD is that they do not.
 *
 * ## Why the parameters are carried verbatim
 *
 * The subscription's own `fm` (finalmask), `cs` (cipherSuites) and `fp`
 * (fingerprint) values are the entire reason this transport works on Iranian
 * carriers, and they are numerically interlocked. Measured against a real
 * ClientHello (OpenSSL 3.0.2, 536 bytes on the wire):
 *
 * ```
 *   TLS record header       5 bytes (outside the payload)
 *   payload[ 0.. 4)  handshake header
 *   payload[ 4.. 6)  client_version
 *   payload[ 6..38)  random (32)
 *   payload[38..71)  session_id (1+32)
 *   payload[71..73)  cipher-suite list length
 *   payload[73..99)  13 suites x 2 = 26
 *   payload[99..  )  extensions  <- SNI lives here
 * ```
 *
 * `lengths: ["5","94","1"]` gives `5+94 = 99`, which is exactly the end of the
 * cipher-suite list, and the trailing `"1"` re-frames every remaining byte —
 * the whole extension block, SNI included — as its own TLS record. That only
 * lands on 99 while the suite list is exactly those 13 entries, which is what
 * `cs` pins and what `fp=unsafe` (uTLS off: no GREASE, no extension shuffling,
 * no padding) keeps stable. The second rule's `109` is `(5+5) + (5+94)`, i.e.
 * the two records the first rule produced, counted with their headers.
 *
 * Change any one of those three and the other two stop meaning anything. So we
 * do not normalise, reorder, "improve" or supply defaults for them. They are
 * copied from the subscription into the config untouched, and a node whose
 * parameters we do not understand is dropped rather than guessed at.
 */
data class ShardNode(
    /** `vless` or `trojan`. */
    val protocol: String,
    /** UUID for VLESS, password for Trojan. */
    val credential: String,
    val address: String,
    val port: Int,
    /** `ws` today; kept general because the subscription may add others. */
    val network: String,
    /** `tls` or `none`. */
    val security: String,
    /** WebSocket path, already percent-decoded. */
    val path: String,
    /** The `Host` header, which is also the SNI when TLS is on. */
    val host: String,
    /** `sni` when present, else [host]. */
    val serverName: String,
    /** `fp` — practically always `unsafe`; see the class doc. */
    val fingerprint: String,
    /** `cs`, the colon-separated cipher-suite list. Empty when absent. */
    val cipherSuites: String,
    /** `fm`, a raw JSON object. Empty when absent. */
    val finalMask: String,
    /** `alpn`, comma-separated. Empty when absent. */
    val alpn: String,
    /** The `#fragment` label, decoded. Diagnostic only — never shown as-is. */
    val label: String,
) {
    /**
     * Stable identity, used as the health-memory key and for dedupe.
     *
     * Deliberately excludes [label]: the publisher rewrites those labels on every
     * rebuild (they carry a rotating hex suffix), and keying on them would throw
     * away every node's measured latency once a day for no reason.
     */
    val key: String
        get() = "$protocol|$credential|$address|$port|$network|$security|$path|$host"

    /** What the UI may show. Never the raw label, which carries other people's channel ads. */
    val displayName: String
        get() = "$address:$port"

    /**
     * Two-letter country of the exit, or empty when the publisher did not say.
     *
     * Read out of [label], which is the only place the information exists: every
     * node in this pool resolves to a Cloudflare edge, so the address tells us
     * nothing about where traffic actually leaves. Two shapes appear in the live
     * subscription and both are handled:
     *
     * ```
     *   CA 🇨🇦 | @Raydikalx | 5897B0 | 443 | 5e719c   → leading ISO code
     *   🇺🇸 | @WhiteDNS | US983|2.6MB/s|…            → flag emoji only
     * ```
     *
     * A flag emoji is two regional-indicator code points, each exactly 0x1F1E6
     * above its ASCII letter, so it decodes back to the ISO pair arithmetically.
     * Nodes labelled only with a channel handle (`@DeltaKroneckerGithub`) have no
     * country at all and yield an empty string — the caller falls back to the
     * measured exit rather than inventing one.
     */
    val countryCode: String
        get() {
            val trimmed = label.trimStart()
            // Leading ISO pair, e.g. "CA 🇨🇦 | …". Must be followed by a
            // separator so a handle like "USAvpn" cannot masquerade as one.
            if (trimmed.length >= 2 &&
                trimmed[0] in 'A'..'Z' && trimmed[1] in 'A'..'Z' &&
                (trimmed.length == 2 || trimmed[2] == ' ' || trimmed[2] == '|')
            ) {
                return trimmed.substring(0, 2)
            }
            // Otherwise the first regional-indicator pair anywhere in the label.
            var index = 0
            while (index < trimmed.length) {
                val point = trimmed.codePointAt(index)
                if (point in 0x1F1E6..0x1F1FF) {
                    val next = index + Character.charCount(point)
                    if (next < trimmed.length) {
                        val second = trimmed.codePointAt(next)
                        if (second in 0x1F1E6..0x1F1FF) {
                            return charArrayOf(
                                ('A' + (point - 0x1F1E6)),
                                ('A' + (second - 0x1F1E6)),
                            ).concatToString()
                        }
                    }
                }
                index += Character.charCount(point)
            }
            return ""
        }
}

/**
 * Parses the subscription body and renders xray configs.
 *
 * Kept separate from [ShardManager] so it can be reasoned about — and, later,
 * unit-tested — without a live process or a network.
 */
object ShardConfigs {

    private const val TAG = "ShardConfigs"

    /** Schemes we can actually run. Anything else in the file is skipped. */
    private val SUPPORTED = setOf("vless", "trojan")

    /**
     * Streams per multiplexed connection, and per XUDP connection.
     *
     * See [muxFor] for why mux is used at all and why UDP needs its own setting.
     */
    private const val MUX_CONCURRENCY = 8
    private const val XUDP_CONCURRENCY = 16

    /**
     * Parse a subscription body into nodes, in file order.
     *
     * The file is plain text, one URL per line, with `#`-prefixed metadata lines
     * (`#profile-title`, `#profile-update-interval`, a generation banner). Those
     * are skipped, not parsed: the update interval in particular is the
     * publisher's advice, and honouring it would make our refresh cadence depend
     * on a value a third party can change at will.
     *
     * Malformed lines are dropped silently rather than failing the batch. A
     * subscription is a third-party file; one bad entry must not cost the user
     * every other node in it.
     */
    fun parse(body: String): List<ShardNode> {
        val nodes = mutableListOf<ShardNode>()
        val seen = mutableSetOf<String>()
        body.lineSequence().forEach { rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEach
            val node = parseOne(line) ?: return@forEach
            // Dedupe on the way in: the pool is built from 9 upstream aggregators
            // and the same node routinely appears in several of them.
            if (seen.add(node.key)) nodes.add(node)
        }
        return nodes
    }

    private fun parseOne(line: String): ShardNode? = try {
        val scheme = line.substringBefore("://", "").lowercase(Locale.US)
        if (scheme !in SUPPORTED) return null
        val rest = line.substringAfter("://")
        val label = rest.substringAfter('#', "").let { decode(it) }
        val withoutLabel = rest.substringBefore('#')
        val credential = decode(withoutLabel.substringBefore('@', ""))
        if (credential.isEmpty()) return null
        val hostPortAndQuery = withoutLabel.substringAfter('@')
        val hostPort = hostPortAndQuery.substringBefore('?')
        val query = hostPortAndQuery.substringAfter('?', "")
        val address = hostPort.substringBeforeLast(':', "")
        val port = hostPort.substringAfterLast(':', "").toIntOrNull() ?: return null
        if (address.isEmpty() || port !in 1..65535) return null

        val params = parseQuery(query)
        val host = params["host"].orEmpty()
        val sni = params["sni"].orEmpty()
        val security = params["security"]?.lowercase(Locale.US).orEmpty().ifEmpty { "none" }
        // Only ws is implemented. A node announcing anything else is dropped
        // rather than run as ws, which would fail at the HTTP upgrade with a
        // useless error.
        val network = params["type"]?.lowercase(Locale.US).orEmpty().ifEmpty { "tcp" }
        if (network != "ws") return null

        ShardNode(
            protocol = scheme,
            credential = credential,
            address = address,
            port = port,
            network = network,
            security = security,
            path = params["path"].orEmpty().ifEmpty { "/" },
            host = host,
            // serverName falls back to host because that is what the CDN routes
            // on; an empty SNI to Cloudflare gets the default certificate and the
            // handshake fails.
            serverName = sni.ifEmpty { host },
            fingerprint = params["fp"].orEmpty(),
            cipherSuites = params["cs"].orEmpty(),
            finalMask = params["fm"].orEmpty(),
            alpn = params["alpn"].orEmpty(),
            label = label,
        )
    } catch (_: Exception) {
        // One unparseable line, not a failed refresh.
        null
    }

    /**
     * Split a query string without letting one bad pair kill the rest.
     *
     * Hand-rolled rather than `Uri.getQueryParameter` because the `fm` value is a
     * JSON object with braces, quotes and colons in it, and Android's parser is
     * fine with that but returns null for the whole query if any pair is
     * malformed. Percent-decoding is applied per value.
     */
    private fun parseQuery(query: String): Map<String, String> {
        if (query.isEmpty()) return emptyMap()
        val out = HashMap<String, String>()
        query.split('&').forEach { pair ->
            if (pair.isEmpty()) return@forEach
            val name = pair.substringBefore('=', "")
            if (name.isEmpty()) return@forEach
            out[name.lowercase(Locale.US)] = decode(pair.substringAfter('=', ""))
        }
        return out
    }

    private fun decode(value: String): String = try {
        URLDecoder.decode(value, "UTF-8")
    } catch (_: Exception) {
        value
    }

    // ------------------------------------------------------------ rendering

    /**
     * Build the outbound object for one node.
     *
     * @param tag the outbound tag routing rules will point at.
     */
    private fun outbound(node: ShardNode, tag: String, mux: Boolean = true): JSONObject {
        val settings = JSONObject()
        when (node.protocol) {
            "vless" -> settings.put(
                "vnext",
                JSONArray().put(
                    JSONObject().apply {
                        put("address", node.address)
                        put("port", node.port)
                        put(
                            "users",
                            JSONArray().put(
                                JSONObject().apply {
                                    put("id", node.credential)
                                    // "none" is the only VLESS encryption there is;
                                    // the field is still required by the parser.
                                    put("encryption", "none")
                                }
                            )
                        )
                    }
                )
            )
            "trojan" -> settings.put(
                "servers",
                JSONArray().put(
                    JSONObject().apply {
                        put("address", node.address)
                        put("port", node.port)
                        put("password", node.credential)
                    }
                )
            )
        }

        val stream = JSONObject().apply {
            put("network", node.network)
            put("security", node.security)
            // Verbatim, and only when the subscription supplied it. See the
            // ShardNode doc: these three values are numerically interlocked and
            // must not be normalised or defaulted.
            if (node.finalMask.isNotEmpty()) {
                // Parsed rather than concatenated as a string, so a malformed `fm`
                // is caught here — where the node can simply be skipped — instead
                // of making the whole config unparseable at launch.
                put("finalmask", JSONObject(node.finalMask))
            }
            if (node.security == "tls") {
                put(
                    "tlsSettings",
                    JSONObject().apply {
                        put("serverName", node.serverName)
                        if (node.fingerprint.isNotEmpty()) put("fingerprint", node.fingerprint)
                        if (node.cipherSuites.isNotEmpty()) put("cipherSuites", node.cipherSuites)
                        if (node.alpn.isNotEmpty()) {
                            put("alpn", JSONArray().apply { node.alpn.split(',').forEach { put(it.trim()) } })
                        }
                        // allowInsecure stays FALSE. These are other people's CDN
                        // hosts and the certificate is the only evidence we are
                        // talking to the host we asked for; turning verification
                        // off to raise the success rate would make every node
                        // MITM-able by the carrier, which is the exact threat this
                        // transport exists to defeat.
                        put("allowInsecure", false)
                    }
                )
            }
            put(
                "wsSettings",
                JSONObject().apply {
                    put("path", node.path)
                    // Independent "host", not headers.Host. The fork's
                    // WebSocketConfig.Build() accepts the header form but calls
                    // PrintDeprecatedFeatureWarning for it, which would put a
                    // warning line in the user's log on every single connect.
                    put("host", node.host)
                }
            )
        }

        return JSONObject().apply {
            put("tag", tag)
            put("protocol", node.protocol)
            put("settings", settings)
            put("streamSettings", stream)
            if (mux) muxFor(node)?.let { put("mux", it) }
        }
    }

    /**
     * Connection multiplexing for [node], or null when it must not be used.
     *
     * ## Why this is the single biggest speed win available here
     *
     * Without mux every TCP flow the phone opens becomes its own WebSocket over
     * its own TLS handshake to the node, and each of those handshakes is
     * deliberately slowed down by the `fm` fragmenter — the published profile
     * splits the ClientHello into ~110 one-byte TCP segments with a 1 ms delay
     * between them, so the handshake alone costs the better part of a second
     * before any request is sent. That cost is paid per flow, and a single web
     * page opens ten of them.
     *
     * Measured against the live pool with the real pinned binary (one node,
     * 10 parallel 32 KB fetches, three rounds):
     *
     * ```
     *   without mux   1096 / 1045 / 1014 ms      20 TCP connections to the node
     *   with mux       914 /  181 /  180 ms       2 TCP connections to the node
     * ```
     *
     * The first round is equal because the shared connection is still being
     * built; everything after it reuses it. On a captured session the count of
     * one-byte fragmented segments fell from 6797 to 672 for identical work,
     * which is also why this helps battery: those segments are radio wake-ups.
     *
     * Interactive latency while a bulk download is running (the case the user
     * described as "speed jumps around") improved in the same test from a
     * median of 824 ms to 117 ms, because a new request no longer has to
     * complete a fresh fragmented handshake behind the transfer.
     *
     * ## Why VLESS only
     *
     * Trojan nodes break outright. Verified three times over the whole live
     * pool: with mux enabled the three reachable Trojan nodes (indices 4, 5 and
     * 40 of the seed) failed every probe while all twenty VLESS nodes kept
     * working, and xray logged nothing — the flows simply never complete. So
     * mux is applied per protocol rather than globally.
     *
     * ## Why xudpConcurrency is not optional
     *
     * `mux.enabled` alone routes UDP through the mux too, and the fork's plain
     * UDP-over-mux path did not deliver a single DNS answer in testing
     * (12 queries, all timed out). Setting `xudpConcurrency` switches UDP to
     * XUDP, which was verified to answer 10 of 12 — better than the no-mux
     * baseline on the same node in the same minute. Since SHARD carries all DNS
     * and QUIC over SOCKS UDP, shipping mux without this would trade speed for
     * a tunnel that cannot resolve names.
     */
    private fun muxFor(node: ShardNode): JSONObject? {
        if (node.protocol != "vless") return null
        return JSONObject().apply {
            put("enabled", true)
            // 8 streams per connection: enough that a page's flows share one
            // handshake, low enough that one stalled stream cannot hold the
            // whole page. Above this xray opens a second connection anyway.
            put("concurrency", MUX_CONCURRENCY)
            put("xudpConcurrency", XUDP_CONCURRENCY)
        }
    }

    /**
     * Config for the probe phase: N nodes, N loopback SOCKS inbounds, one process.
     *
     * One process for the whole race rather than one per node, because 45
     * processes on a phone is not a plan. Each inbound is wired to exactly one
     * outbound by an `inboundTag` rule, so a request sent to port `basePort + i`
     * can only leave through node `i` — that is what makes the measurement
     * attributable.
     *
     * `blackhole` is FIRST in the outbound list, which makes it the default.
     * Anything that misses every rule is dropped instead of leaking out over the
     * carrier link and being counted as a success. Free-Configs' own health check
     * does the same thing, and for the same reason.
     */
    fun probeConfig(nodes: List<ShardNode>, basePort: Int): String {
        val inbounds = JSONArray()
        val outbounds = JSONArray().put(
            JSONObject().apply {
                put("tag", "blackhole")
                put("protocol", "blackhole")
            }
        )
        val rules = JSONArray()
        nodes.forEachIndexed { index, node ->
            val tag = "out-$index"
            inbounds.put(
                JSONObject().apply {
                    put("tag", "in-$index")
                    put("listen", "127.0.0.1")
                    put("port", basePort + index)
                    put("protocol", "socks")
                    put(
                        "settings",
                        JSONObject().apply {
                            put("auth", "noauth")
                            // UDP off on probe inbounds: the probe is one HTTP
                            // request and a UDP associate would only add sockets.
                            put("udp", false)
                        }
                    )
                }
            )
            // No mux during the race: the probe is a single short flow, so a
            // multiplexed connection would add its own setup for no benefit, and
            // the number being measured must be the node's own latency.
            outbounds.put(outbound(node, tag, mux = false))
            rules.put(
                JSONObject().apply {
                    put("type", "field")
                    put("inboundTag", JSONArray().put("in-$index"))
                    put("outboundTag", tag)
                }
            )
        }
        return JSONObject().apply {
            // "none" during the race. The probe opens and abandons dozens of
            // connections by design, and at any higher level every one of those
            // writes several lines — tens of thousands of lines of log for a
            // measurement nobody reads, on a phone.
            put("log", JSONObject().apply {
                put("loglevel", "none")
                put("access", "none")
            })
            put("inbounds", inbounds)
            put("outbounds", outbounds)
            put("routing", JSONObject().put("rules", rules))
        }.toString()
    }

    /**
     * Config for the live tunnel: one node, one SOCKS inbound, UDP enabled.
     *
     * UDP matters more here than anywhere else in this app. tun2socks sends every
     * UDP flow — DNS included, via udpgw — through this listener, so without
     * `udp: true` name resolution dies and the tunnel looks broken while being
     * perfectly healthy. Verified against the real binary: UDP ASSOCIATE is
     * granted and DNS answers come back.
     *
     * ## [listenHost]
     *
     * `127.0.0.1` normally. `0.0.0.0` only when the user turned Share over LAN on,
     * and then an HTTP inbound is added beside the SOCKS one — the same pair, on
     * the same two ports, that Psiphon and the Rust core publish, so the address
     * the Settings screen prints is correct for this transport too.
     *
     * Binding a proxy to every interface is exactly as exposed as it sounds, which
     * is why it is off by default and never inferred: the caller has to pass the
     * wildcard, and only [CoreConfig.lanSharingEnabled] makes it do so. xray has no
     * equivalent of Tor's SocksPolicy, so there is no private-range restriction
     * available here — on an untrusted Wi-Fi the whole segment can use the tunnel
     * while the switch is on.
     *
     * ## [smartSplit]
     *
     * Null — the default — is the historical behaviour: no routing rules at all,
     * `proxy` first in the outbound list and therefore the default outbound, so
     * every packet goes through the node.
     *
     * Non-null turns on Smart Split, and then this config grows a second and third
     * outbound and the rule table in [smartSplitRules]. See [SmartSplit] for why
     * the profile has to be measured rather than chosen.
     */
    fun tunnelConfig(
        node: ShardNode,
        listenHost: String,
        listenPort: Int,
        logLevel: String,
        smartSplit: SmartSplit.FragmentProfile? = null,
    ): String {
        val outbounds = JSONArray()
            .put(outbound(node, "proxy"))
            .put(
                JSONObject().apply {
                    put("tag", "blackhole")
                    put("protocol", "blackhole")
                }
            )
        if (smartSplit != null) {
            outbounds.put(fragmentedDirect(smartSplit))
                .put(JSONObject().apply {
                    put("tag", "direct-plain")
                    put("protocol", "freedom")
                })
                .put(JSONObject().apply {
                    put("tag", "dns-out")
                    put("protocol", "dns")
                    // Non-IP queries (HTTPS/SVCB records, mostly) are dropped rather
                    // than forwarded: they would be answered by whichever resolver
                    // this outbound happens to reach, and an ECH-bearing HTTPS record
                    // arriving over the wrong path is worse than no record.
                    put("settings", JSONObject().put("nonIPQuery", "drop"))
                })
        }
        return JSONObject().apply {
            put(
                "log",
                JSONObject().apply {
                    put("loglevel", logLevel)
                    // The access log is the single loudest thing in a SHARD session
                    // and it is pure cost. Measured on a 32-minute field log: 2936
                    // `accepted tcp:/udp:` lines, i.e. every DNS query and every TCP
                    // flow, each one crossing the process pipe, timestamped, appended
                    // to the log file and pushed through the ring buffer — while the
                    // 100-entry buffer meant the user could never read any of it
                    // anyway. Verified against the real binary: `access:"none"` drops
                    // them and leaves the warnings that matter.
                    if (logLevel != "info" && logLevel != "debug") put("access", "none")
                }
            )
            val inbounds = JSONArray().put(
                JSONObject().apply {
                    put("tag", "in")
                    put("listen", listenHost)
                    put("port", listenPort)
                    put("protocol", "socks")
                    put(
                        "settings",
                        JSONObject().apply {
                            put("auth", "noauth")
                            put("udp", true)
                            // Where UDP replies are sent from. Loopback whatever
                            // [listenHost] is: the datagram path is xray → this
                            // process, and a LAN client's UDP still terminates here.
                            put("ip", "127.0.0.1")
                        }
                    )
                    // Sniffing is not an optimisation here, it is the mechanism.
                    // tun2socks hands xray an IP and never a hostname, so without
                    // this every `domain:`/`geosite:` rule below is dead and 100% of
                    // traffic would take the fragmented direct path — Telegram
                    // included, which would break it.
                    //
                    // `routeOnly: true`: the sniffed name decides the route, but the
                    // original IP is still dialled. With it false xray re-resolves at
                    // the outbound, which on the node path means the node resolves
                    // the name — an extra failure mode and a DNS leak surface. Both
                    // were tested against the real binary; both route correctly, and
                    // this is the safer one.
                    if (smartSplit != null) {
                        put(
                            "sniffing",
                            JSONObject().apply {
                                put("enabled", true)
                                put("destOverride", JSONArray().put("tls").put("http"))
                                put("routeOnly", true)
                            }
                        )
                    }
                }
            )
            if (listenHost != "127.0.0.1") {
                inbounds.put(
                    JSONObject().apply {
                        put("tag", "in-http")
                        put("listen", listenHost)
                        put("port", CoreConfig.HTTP_PROXY_PORT)
                        put("protocol", "http")
                        // No settings block: the defaults are what a browser or
                        // Windows proxy field needs, and `allowTransparent` must
                        // stay off — on, xray answers absolute-form requests for
                        // hosts it was not asked to proxy.
                    }
                )
            }
            put("inbounds", inbounds)
            // Without Smart Split: no routing rules at all: with "proxy" first it is
            // the default outbound and everything goes through the node. blackhole is
            // present only so a future rule has something to point at.
            put("outbounds", outbounds)
            if (smartSplit != null) {
                put("dns", smartSplitDns())
                put("routing", JSONObject().put("rules", smartSplitRules()))
            }
        }.toString()
    }

    /**
     * The fragmented direct outbound: Serverless-for-Iran's mechanism, our config.
     *
     * Two masks, and the numbers are not adjustable knobs. `lengths: ["5","94","1"]`
     * puts the first fragment boundary at byte 99 of the ClientHello payload, which
     * is exactly the end of the cipher-suite list — see the [ShardNode] doc for the
     * byte-by-byte derivation. The second mask's `109` is the two records the first
     * mask produced, counted with their headers.
     *
     * `delays` is the one value that varies, and it is the profile: see [SmartSplit].
     *
     * `happyEyeballs` races up to 20 addresses from the A/AAAA set 300 ms apart,
     * IPv6 first. On Cloudflare-hosted destinations several edge IPs are reachable
     * while others are hijacked or throttled, and racing them avoids a bad one
     * without maintaining an IP list. The fork's defaults are 4 and 1; 20 and 2 is
     * a deliberate widening, copied from upstream because the failure it prevents
     * is common on Iranian carriers.
     */
    private fun fragmentedDirect(profile: SmartSplit.FragmentProfile): JSONObject {
        val delays = JSONArray().apply { profile.delays.forEach { put(it) } }
        val happyEyeballs = JSONObject().apply {
            put("tryDelayMs", 300)
            put("prioritizeIPv6", true)
            put("interleave", 2)
            put("maxConcurrentTry", 20)
        }
        return JSONObject().apply {
            put("tag", "direct-frag")
            put("protocol", "freedom")
            put("settings", JSONObject().put("domainStrategy", "UseIP"))
            put(
                "streamSettings",
                JSONObject().apply {
                    put(
                        "finalmask",
                        JSONObject().put(
                            "tcp",
                            JSONArray()
                                .put(fragmentMask("tlshello", listOf("5", "94", "1"), JSONArray().put("0"), "0"))
                                .put(fragmentMask("1-1", listOf("109", "1"), delays, "355"))
                        )
                    )
                    put(
                        "sockopt",
                        JSONObject().apply {
                            put("domainStrategy", "ForceIP")
                            put("happyEyeballs", happyEyeballs)
                        }
                    )
                }
            )
        }
    }

    private fun fragmentMask(
        packets: String,
        lengths: List<String>,
        delays: JSONArray,
        maxSplit: String,
    ): JSONObject = JSONObject().apply {
        put("type", "fragment")
        put(
            "settings",
            JSONObject().apply {
                put("packets", packets)
                put("lengths", JSONArray().apply { lengths.forEach { put(it) } })
                put("delays", delays)
                put("maxSplit", maxSplit)
            }
        )
    }

    /**
     * Domains that must never take the direct path, because an Iranian exit IP is
     * refused at the far end rather than blocked on the way out.
     *
     * This list is static and deliberately generous, and it cannot be replaced by a
     * health check. A sanctioned service does not fail at the TCP or TLS layer — it
     * completes the handshake and answers a valid HTTP 403, which is indistinguishable
     * from a working response to any latency- or reachability-based prober. Measured:
     * `chatgpt.com` through an Iranian-style exit connects, negotiates TLS, and
     * returns 403; `api.openai.com` returns 401, which is exactly what it returns
     * when it is working.
     *
     * A wrongly-classified host therefore does not get slower, it dies. Erring
     * towards the node is the only safe direction.
     */
    private val SANCTIONED_DOMAINS = listOf(
        "geosite:openai",
        "geosite:anthropic",
        "geosite:xai",
        "geosite:google-deepmind",
        // Gemini's own hostnames are inside `google-deepmind` and were already on
        // this list, yet the site still failed: the HTML arrived through the node
        // and then the page's RPC backend was fetched over the direct path from an
        // Iranian address, which Google refuses. Decoded from the served page, the
        // calls it cannot boot without are `geminiweb-pa`, `waa-pa` (attestation),
        // `push-pa` and `content.googleapis.com`.
        //
        // The whole `clients6` host rather than those four names: it is Google's
        // internal RPC frontend and nothing else, every surface names its endpoint
        // `<service>-pa.clients6.google.com`, and the traffic is JSON. So one
        // suffix costs almost nothing and survives Gemini renaming its endpoint —
        // which is the failure this entry exists to prevent.
        "domain:clients6.google.com",
        "full:content.googleapis.com",
        // Telegram and WhatsApp are here for a different reason: neither is
        // sanctioned, both are blocked hard enough that only the node reaches them.
        "geosite:telegram",
        "geosite:whatsapp",
    )

    /**
     * The three Google hosts that must share Gemini's exit IP — and no others.
     *
     * An earlier attempt at this used `domain:google.com`, on the theory that the
     * unit which has to be path-consistent is the whole cookie domain. That is
     * true of the cookie, but it bought consistency at an unacceptable price:
     * Gmail, Drive, Docs, Maps, Translate, Play and `dl.google.com` all moved onto
     * one node hop. Rejected on cost.
     *
     * What replaced it is measured rather than reasoned. Two facts, both checked:
     *
     * 1. **The node IPs are not the problem.** 68 nodes from the live pool were
     *    brought up one at a time on a VPS and asked for `gemini.google.com/app`:
     *    18 had a working exit, and all 18 returned HTTP 200 with the full ~831 KB
     *    page. Zero challenges. So Gemini does not refuse this pool, and no amount
     *    of node re-selection was ever going to help.
     *
     * 2. **Gemini's boot only touches three cookie-bearing `google.com` hosts.**
     *    Decoded from the served HTML: the declared `preconnect`/`dns-prefetch`
     *    set is `gemini.gstatic.com`, `lh3.googleusercontent.com`,
     *    `ogads-pa`/`waa-pa.clients6.google.com`, `www.google.com`,
     *    `www.gstatic.com`, `www.googletagmanager.com`. Of those, only
     *    `www.google.com` is under the session cookie's scope — `gstatic`,
     *    `googleusercontent` and `googletagmanager` are separate registrable
     *    domains and carry no Google session cookie, and both `clients6` names are
     *    already claimed by [SANCTIONED_DOMAINS]. `accounts.google.com` is where
     *    the session itself lives, and the `ogs.google.com/widget` endpoints are the
     *    one-Google bar, which only fetches for a signed-in user.
     *
     *    Everything else the page mentions — `one`, `myaccount`, `support`, `docs`,
     *    `drive`, `play`, `admin`, `workspace`, `notebooklm` — appears exclusively
     *    as an href in the account menu. A link that is never clicked issues no
     *    request, so it cannot contribute a second source address.
     *
     * `full:` rather than `domain:` on all three, so no subdomain is dragged in by
     * accident: `domain:google.com` was the mistake this list exists to undo, and
     * `domain:www.google.com` would still be wider than what was verified.
     *
     * Cost, stated plainly because the user has to be able to predict it: Google
     * Search itself now takes the node hop, since Search *is* `www.google.com`.
     * That is text, kilobytes a query. YouTube, Play, Gmail, Drive, Docs, Maps and
     * Photos are untouched and stay direct — none of them is one of these three
     * names, and the rule is scoped so that they cannot match.
     */
    private val GOOGLE_SESSION_HOSTS = listOf(
        "full:accounts.google.com",
        "full:www.google.com",
        "full:ogs.google.com",
    )

    /**
     * Meta's address space, for the parts of WhatsApp that carry no hostname.
     *
     * `geosite:whatsapp` alone does not fix WhatsApp, for exactly the reason
     * `geosite:telegram` alone did not fix Telegram. The chat socket is not TLS:
     * probing `g.whatsapp.net:443` returns `write:errno=104` after 0 bytes read —
     * the server never answers a ClientHello, because the protocol is Noise, not
     * TLS. So `destOverride: [tls, http]` sniffs nothing and only the web
     * origins ever match by name.
     *
     * Two blocks are needed because WhatsApp's edge is split across two providers:
     *
     * - `geoip:facebook` covers `g.whatsapp.net` (157.240.0.0/17) and the
     *   `web/static/dit/pps` hosts (57.144.0.0/14) — verified by decoding the
     *   shipped table and testing each resolved address against it.
     * - `e1..e16.whatsapp.net` live on **AWS Global Accelerator**, not on Meta's
     *   own ranges: every resolver tried, and an Iranian ECS subnet, returned one
     *   of four addresses inside `15.197.128.0/17` and `3.33.128.0/17`, both
     *   confirmed `GLOBALACCELERATOR` in Amazon's published `ip-ranges.json`.
     *   Those two prefixes are shared anycast, so unrelated services fronted by
     *   Global Accelerator also take the node. That is the deliberate trade: they
     *   keep working and merely pay an extra hop, whereas a WhatsApp edge address
     *   left on the direct path is a dead app.
     *
     * Pinning the four observed /32s instead was rejected: Global Accelerator
     * hands out per-accelerator static IPs, so a region we did not sample would
     * silently miss.
     */
    private val WHATSAPP_TRANSPORT_IPS = listOf(
        "geoip:facebook",
        "15.197.128.0/17",
        "3.33.128.0/17",
    )

    /**
     * DNS for Smart Split, and every clause is load-bearing.
     *
     * **`shard-dns` is DoH over TCP, not UDP to a resolver.** The first attempt sent
     * sanctioned names to `1.1.1.1:53` over UDP with a rule pointing that at the
     * node, and it failed: 12 queries, all timed out — UDP-over-mux is the known-weak
     * path, which is the same reason `xudpConcurrency` exists in [muxFor]. DoH over
     * TCP through the node resolves them in ~900 ms.
     *
     * **`full:challenges.cloudflare.com` in the localhost server is not optional.**
     * `hosts` maps `cloudflare-dns.com` onto it (domain-fronting the resolver, so the
     * DoH endpoint is not itself a blocked name). Without giving the bootstrap name to
     * the system resolver, DoH tries to resolve its own endpoint through itself:
     * observed as every foreign lookup timing out after 12 s with
     * `failed to retrieve response for challenges.cloudflare.com`.
     *
     * **`skipFallback: true`** on the scoped servers stops a miss from silently
     * falling through to the wrong resolver, which would put a sanctioned name's
     * lookup on the direct path.
     */
    private fun smartSplitDns(): JSONObject {
        val sanctioned = JSONArray().apply { SANCTIONED_DOMAINS.forEach { put(it) } }
        val iranian = JSONArray()
            .put("domain:ir")
            .put("geosite:category-ir")
            .put("full:challenges.cloudflare.com")
        return JSONObject().apply {
            put("queryStrategy", "UseIP")
            // A stale answer beats no answer on a carrier that drops DNS under load;
            // the alternative is a page that fails while a usable record is in hand.
            put("serveStale", true)
            put("hosts", JSONObject().put("cloudflare-dns.com", "challenges.cloudflare.com"))
            put(
                "servers",
                JSONArray()
                    .put(
                        JSONObject().apply {
                            put("tag", "shard-dns")
                            put("address", "https://1.1.1.1/dns-query")
                            put("domains", sanctioned)
                            put("skipFallback", true)
                            put("finalQuery", true)
                            put("timeoutMs", 12000)
                        }
                    )
                    .put(
                        JSONObject().apply {
                            put("address", "localhost")
                            put("domains", iranian)
                            put("skipFallback", true)
                            put("finalQuery", true)
                        }
                    )
                    .put(
                        JSONObject().apply {
                            put("tag", "doh")
                            put("address", "https://cloudflare-dns.com/dns-query")
                            put("timeoutMs", 12000)
                        }
                    )
            )
        }
    }

    /**
     * The rule table. Order IS the behaviour — every line's position was decided by
     * a failure, and the sequence was verified end to end against the real binary.
     *
     * ```
     *   www.cloudflare.com  200  -> direct-frag   (local exit)
     *   www.youtube.com     200  -> direct-frag
     *   www.instagram.com   200  -> direct-frag
     *   web.whatsapp.com    200  -> direct-frag
     *   www.aparat.com      301  -> direct-plain  (never fragmented)
     *   chatgpt.com              -> shard         (node exit)
     *   core.telegram.org   200  -> shard
     *   149.154.167.51           -> shard         via geoip, no hostname needed
     * ```
     *
     * Notable positions:
     *
     * - **DoH's own connection is fragmented** (rule 1). Otherwise the resolver's
     *   TLS session is one unfragmented handshake to a known IP and the censor
     *   closes it — the resolver would be the one thing the DPI could still see.
     * - **`geoip:telegram` is separate from `geosite:telegram`** (rules 4 and 5).
     *   MTProto dials bare IPs with no SNI, so sniffing yields nothing and the
     *   domain rule never matches. Verified: `curl` at `149.154.167.51` logged
     *   `taking detour [shard]` with the geoip rule and `[direct-frag]` without it.
     * - **Sanctioned before Iranian** (rules 4-5 before 6-7), or a sanctioned host
     *   served from an Iranian CDN would be swallowed by `geoip:ir`.
     * - **The QUIC block is scoped to TCP-fallback, and it comes AFTER the node
     *   rules** (rule 9). Foreign UDP/443 has no TCP segments to split, so QUIC
     *   walks past the fragmenter unfragmented and must be killed to force Chrome
     *   onto TCP. But SHARD deliberately forwards all UDP — that is the feature
     *   [ShardSocksFront] has that Tor does not — so this rule must never see
     *   traffic already destined for the node, or Telegram calls and games die.
     * - **`10.10.34.0/24` is the block-page host** (rule 8). Blackholing it turns
     *   "you are shown a fake page" into a clean failure, which clients retry
     *   instead of caching.
     * - **No default-deny tail.** Upstream ends with `block port 0-65535`; here the
     *   last two rules send anything unmatched to `direct-plain` instead. A phone
     *   is not a browser: a default-deny would break every app whose protocol the
     *   sniffer does not recognise, and this config is carrying the whole device.
     */
    private fun smartSplitRules(): JSONArray {
        fun rule(build: JSONObject.() -> Unit) = JSONObject().apply {
            put("type", "field")
            build()
        }
        return JSONArray()
            // 1. The DoH resolver's own TLS, back through the fragmenter.
            .put(rule {
                put("inboundTag", JSONArray().put("doh"))
                put("outboundTag", "direct-frag")
            })
            // 2. Sanctioned names' DoH lookups leave through the node.
            .put(rule {
                put("inboundTag", JSONArray().put("shard-dns"))
                put("outboundTag", "proxy")
            })
            // 3. Everything else on port 53 is answered by the dns module, which is
            //    what makes the servers above apply at all.
            .put(rule {
                put("port", 53)
                put("outboundTag", "dns-out")
            })
            // 4-6. Sanctioned + Telegram + WhatsApp, by name and then by address.
            .put(rule {
                put("domain", JSONArray().apply { SANCTIONED_DOMAINS.forEach { put(it) } })
                put("outboundTag", "proxy")
            })
            // 4b. The signed-in Google session, and only the three hosts that were
            //     measured to take part in it. TCP/443 only: Firebase Cloud
            //     Messaging holds mtalk.google.com:5228-5230, every app's push
            //     notifications ride it, and an unreachable node must never cost the
            //     user their notifications. `full:` keeps this to exactly three
            //     names — see GOOGLE_SESSION_HOSTS for why it is not the whole
            //     cookie domain.
            .put(rule {
                put("domain", JSONArray().apply { GOOGLE_SESSION_HOSTS.forEach { put(it) } })
                put("network", "tcp")
                put("port", "443")
                put("outboundTag", "proxy")
            })
            // 5 exists only to protect 6 from itself. `geoip:facebook` is Meta's
            // whole address space, so Instagram and Facebook — which are supposed
            // to take the fast direct path — would be swallowed by the WhatsApp
            // rule below. Anything Meta-owned that arrives WITH a sniffed hostname
            // is therefore claimed here first; what falls through to 6 is Meta
            // traffic carrying no hostname at all, which in practice is WhatsApp's
            // Noise sockets. If a Meta app ever fails to sniff it lands on the
            // node: slower, still working, which is the safe direction.
            .put(rule {
                put(
                    "domain",
                    JSONArray().put("geosite:instagram").put("geosite:facebook")
                )
                put("outboundTag", "direct-frag")
            })
            .put(rule {
                put("ip", JSONArray().apply {
                    put("geoip:telegram")
                    WHATSAPP_TRANSPORT_IPS.forEach { put(it) }
                })
                put("outboundTag", "proxy")
            })
            // 7-8. Iranian and private: direct, and never fragmented. Fragmenting an
            //      Iranian CDN wastes 520 radio wake-ups against a DPI box that is
            //      not inspecting this traffic in the first place.
            .put(rule {
                put("domain", JSONArray().put("domain:ir").put("geosite:category-ir"))
                put("outboundTag", "direct-plain")
            })
            .put(rule {
                put("ip", JSONArray().put("geoip:ir").put("geoip:private"))
                put("outboundTag", "direct-plain")
            })
            // 9. The censor's own block-page host.
            .put(rule {
                put("ip", JSONArray().put("10.10.34.0/24"))
                put("outboundTag", "blackhole")
            })
            // 10. Foreign QUIC, so the fragmenter cannot be bypassed.
            .put(rule {
                put("network", "udp")
                put("port", "443")
                put("outboundTag", "blackhole")
            })
            // 11-12. Foreign TLS: the fragmenter's actual job.
            .put(rule {
                put("network", "tcp")
                put("protocol", JSONArray().put("tls"))
                put("outboundTag", "direct-frag")
            })
            .put(rule {
                put("network", "tcp")
                put("port", "443")
                put("outboundTag", "direct-frag")
            })
            // 13-14. Anything else: direct and unfragmented, not blocked.
            .put(rule {
                put("network", "tcp")
                put("outboundTag", "direct-plain")
            })
            .put(rule {
                put("network", "udp")
                put("outboundTag", "direct-plain")
            })
    }

    /** Write [config] to the process's private dir and return the file. */
    fun writeConfig(context: Context, name: String, config: String): File {
        val dir = File(context.filesDir, "shard").apply { mkdirs() }
        return File(dir, name).apply { writeText(config) }
    }
}
