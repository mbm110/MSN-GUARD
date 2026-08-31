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
    private fun outbound(node: ShardNode, tag: String): JSONObject {
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
            outbounds.put(outbound(node, tag))
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
            put("log", JSONObject().put("loglevel", "none"))
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
     */
    fun tunnelConfig(
        node: ShardNode,
        listenHost: String,
        listenPort: Int,
        logLevel: String,
    ): String {
        val outbounds = JSONArray()
            .put(outbound(node, "proxy"))
            .put(
                JSONObject().apply {
                    put("tag", "blackhole")
                    put("protocol", "blackhole")
                }
            )
        return JSONObject().apply {
            put("log", JSONObject().put("loglevel", logLevel))
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
            // No routing rules at all: with "proxy" first it is the default
            // outbound and everything goes through the node. blackhole is present
            // only so a future rule has something to point at.
            put("outbounds", outbounds)
        }.toString()
    }

    /** Write [config] to the process's private dir and return the file. */
    fun writeConfig(context: Context, name: String, config: String): File {
        val dir = File(context.filesDir, "shard").apply { mkdirs() }
        return File(dir, name).apply { writeText(config) }
    }
}
