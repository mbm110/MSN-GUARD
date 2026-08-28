package com.msnguard.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * Persistence for user-supplied configs.
 *
 * Stored as one JSON array under a single key rather than one entry per
 * profile. The list is small (tens of entries at most), it is always read and
 * written whole, and ordering is part of the data — the user drags to reorder
 * and expects that to stick. A single key makes the write atomic, so a crash
 * mid-save cannot leave half a profile behind.
 *
 * Credentials are kept in [SecureStore], not in plain prefs: a VLESS `id` is a
 * bearer credential for someone's server. The blob written here has every
 * `credential` field blanked, and the real values live under the profile id in
 * the encrypted store.
 */
object ConfigStore {

    private const val PREFS = "user_configs"
    private const val KEY_PROFILES = "profiles"
    private const val KEY_ACTIVE = "active_profile"
    /** Prefix for the per-profile secret entry in [SecureStore]. */
    private const val SECRET_PREFIX = "cfg_cred_"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun all(context: Context): List<ConfigProfile> {
        val raw = prefs(context).getString(KEY_PROFILES, null) ?: return emptyList()
        val array = runCatching { JSONArray(raw) }.getOrNull() ?: return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            val obj = array.optJSONObject(index) ?: return@mapNotNull null
            ConfigProfile.fromJson(obj)?.also { profile ->
                // The stored blob never holds the credential; rehydrate it.
                profile.credential = SecureStore.getSecret(context, SECRET_PREFIX + profile.id)
            }
        }
    }

    fun save(context: Context, profiles: List<ConfigProfile>) {
        val array = JSONArray()
        profiles.forEach { profile ->
            SecureStore.putSecret(context, SECRET_PREFIX + profile.id, profile.credential)
            array.put(profile.toJson().apply { put("credential", "") })
        }
        prefs(context).edit().putString(KEY_PROFILES, array.toString()).apply()
    }

    /** Insert or replace by id, preserving position on replace. */
    fun upsert(context: Context, profile: ConfigProfile) {
        val list = all(context).toMutableList()
        val index = list.indexOfFirst { it.id == profile.id }
        if (index >= 0) list[index] = profile else list += profile
        save(context, list)
    }

    fun addAll(context: Context, profiles: List<ConfigProfile>) {
        if (profiles.isEmpty()) return
        save(context, all(context) + profiles)
    }

    fun remove(context: Context, id: String) {
        SecureStore.removeSecret(context, SECRET_PREFIX + id)
        save(context, all(context).filterNot { it.id == id })
        if (activeId(context) == id) clearActive(context)
    }

    fun removeAll(context: Context) {
        all(context).forEach { SecureStore.removeSecret(context, SECRET_PREFIX + it.id) }
        prefs(context).edit().remove(KEY_PROFILES).remove(KEY_ACTIVE).apply()
    }

    /**
     * Persist a fresh latency reading without touching anything else.
     *
     * Deliberately narrow: the ping sweep runs while the user may be editing a
     * profile, and a full [save] from the sweep would overwrite their in-progress
     * edits with the pre-edit copy the sweep is holding.
     */
    fun recordPing(context: Context, id: String, ms: Int) {
        val list = all(context)
        val target = list.firstOrNull { it.id == id } ?: return
        target.lastPingMs = ms
        save(context, list)
    }

    fun activeId(context: Context): String? =
        prefs(context).getString(KEY_ACTIVE, null)?.takeIf { it.isNotBlank() }

    fun active(context: Context): ConfigProfile? {
        val id = activeId(context) ?: return null
        return all(context).firstOrNull { it.id == id }
    }

    fun setActive(context: Context, id: String) {
        prefs(context).edit().putString(KEY_ACTIVE, id).apply()
    }

    fun clearActive(context: Context) {
        prefs(context).edit().remove(KEY_ACTIVE).apply()
    }

    /**
     * How many configs are stored.
     *
     * Reads the JSON array's length rather than going through [all], because the
     * home-screen card asks for this on every resume and [all] does one Keystore
     * decryption per profile to rehydrate credentials the card never shows.
     */
    fun count(context: Context): Int {
        val raw = prefs(context).getString(KEY_PROFILES, null) ?: return 0
        return runCatching { JSONArray(raw).length() }.getOrDefault(0)
    }
}

/**
 * TCP-handshake latency for a config's endpoint.
 *
 * WHAT THIS MEASURES, AND WHAT IT DOES NOT: the time to complete a TCP
 * three-way handshake to `server:port`. It does not prove the credential is
 * valid, that TLS will negotiate, or that the config carries traffic — a
 * Cloudflare-fronted config answers the handshake whether or not the account
 * behind it works.
 *
 * It is measured this way on purpose. PattNG's green number is the same kind of
 * probe, users read it as "is this server reachable and how far away is it",
 * and a real end-to-end test would need the core running with that config
 * loaded, which cannot be done for twenty configs in a list without tearing the
 * live tunnel down twenty times.
 *
 * Runs on a small pool rather than one thread per config: a subscription import
 * can be 50 entries, and 50 simultaneous sockets on a mobile link produce
 * timeouts that look like dead servers.
 */
object ConfigPinger {

    private const val TIMEOUT_MS = 5_000
    private const val POOL_SIZE = 6

    private val pool = Executors.newFixedThreadPool(POOL_SIZE) { runnable ->
        Thread(runnable, "cfg-ping").apply { isDaemon = true }
    }

    /** Monotonic token so a stale sweep's results can be discarded. */
    private val generation = AtomicInteger(0)

    fun currentGeneration(): Int = generation.get()

    /** Invalidate every in-flight sweep; call when the list changes. */
    fun invalidate(): Int = generation.incrementAndGet()

    /**
     * Measure one profile. [onResult] fires on the calling thread's looper only
     * if [post] forwards it — callers on the UI thread must supply that.
     */
    fun ping(profile: ConfigProfile, post: (() -> Unit) -> Unit, onResult: (Int) -> Unit) {
        val token = generation.get()
        val host = profile.server
        val port = profile.portOrNull()
        if (host.isBlank() || port == null) {
            post { onResult(ConfigProfile.PING_FAILED) }
            return
        }
        pool.execute {
            val result = measure(host, port)
            if (token != generation.get()) return@execute
            post { onResult(result) }
        }
    }

    /**
     * Sweep a whole list, reporting each result as it lands.
     *
     * Results arrive out of order — that is the point of the pool — so the
     * callback carries the profile id rather than an index into the list.
     */
    fun pingAll(
        profiles: List<ConfigProfile>,
        post: (() -> Unit) -> Unit,
        onEach: (String, Int) -> Unit,
        onDone: (() -> Unit)? = null,
    ) {
        if (profiles.isEmpty()) {
            onDone?.let { post(it) }
            return
        }
        val token = generation.get()
        val remaining = AtomicInteger(profiles.size)
        profiles.forEach { profile ->
            val host = profile.server
            val port = profile.portOrNull()
            pool.execute {
                val result = if (host.isBlank() || port == null) {
                    ConfigProfile.PING_FAILED
                } else {
                    measure(host, port)
                }
                if (token != generation.get()) return@execute
                post { onEach(profile.id, result) }
                if (remaining.decrementAndGet() == 0) onDone?.let { post(it) }
            }
        }
    }

    /**
     * One handshake, measured with [System.nanoTime].
     *
     * nanoTime and not currentTimeMillis: the latter jumps when the clock is
     * corrected (NTP, or the user changing timezone mid-sweep) and can produce a
     * negative duration, which would render as a nonsense negative ping.
     */
    private fun measure(host: String, port: Int): Int {
        val started = System.nanoTime()
        return try {
            Socket().use { socket ->
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(host, port), TIMEOUT_MS)
            }
            ((System.nanoTime() - started) / 1_000_000L).toInt().coerceAtLeast(1)
        } catch (e: IOException) {
            ConfigProfile.PING_FAILED
        } catch (e: SecurityException) {
            ConfigProfile.PING_FAILED
        } catch (e: IllegalArgumentException) {
            ConfigProfile.PING_FAILED
        }
    }
}

/**
 * Builds the Xray JSON document for a profile.
 *
 * THE OPINIONATED PART. The user supplies an outbound; everything else — the
 * inbound, DNS, sniffing, routing, log level — is ours and is not exposed. That
 * is the whole difference between this and a general-purpose v2ray client:
 * PattNG has fifty settings screens because it must serve every possible
 * server; we have one paste box because we decide the rest.
 *
 * Kept as a separate object from [ConfigProfile] so the wire format can change
 * with the bundled core version without touching what is persisted on disk.
 */
object XrayConfigBuilder {

    /**
     * The local SOCKS port the generated inbound listens on.
     *
     * 1823 to stay clear of the ports already in use: 1819 Psiphon, 1821 Tor
     * front, 7300 udpgw.
     */
    const val LOCAL_SOCKS_PORT = 1823

    /**
     * Build the full document.
     *
     * [socksPort] is the inbound the tunnel will point tun2socks at.
     */
    fun build(profile: ConfigProfile, socksPort: Int = LOCAL_SOCKS_PORT): JSONObject {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        root.put("inbounds", JSONArray().put(socksInbound(socksPort)))
        root.put("outbounds", JSONArray().put(outbound(profile)).put(directOutbound()).put(blockOutbound()))
        root.put("dns", dns())
        root.put("routing", routing())
        return root
    }

    /**
     * A SOCKS5 inbound with UDP enabled and sniffing on.
     *
     * `udp: true` is what makes this path better than Psiphon's and Tor's: the
     * Xray SOCKS server implements real UDP ASSOCIATE, so tun2socks does not
     * need the udpgw sidecar and QUIC/games work unchanged.
     *
     * Sniffing is on so routing rules can match domains even though tun2socks
     * only ever presents us an IP.
     */
    private fun socksInbound(port: Int): JSONObject = JSONObject().apply {
        put("tag", "socks-in")
        put("port", port)
        put("listen", "127.0.0.1")
        put("protocol", "socks")
        put("settings", JSONObject().apply {
            put("auth", "noauth")
            put("udp", true)
        })
        put("sniffing", JSONObject().apply {
            put("enabled", true)
            put("destOverride", JSONArray().put("http").put("tls").put("quic"))
            // routeOnly keeps the sniffed domain for routing but still dials the
            // original destination, which avoids breaking configs whose SNI
            // deliberately disagrees with the address (every CDN-fronted config).
            put("routeOnly", true)
        })
    }

    private fun outbound(profile: ConfigProfile): JSONObject = JSONObject().apply {
        put("tag", "proxy")
        put("protocol", protocolName(profile.kind))
        put("settings", outboundSettings(profile))
        put("streamSettings", streamSettings(profile))
    }

    private fun protocolName(kind: ConfigProfile.Kind): String = when (kind) {
        ConfigProfile.Kind.VLESS -> "vless"
        ConfigProfile.Kind.VMESS -> "vmess"
        ConfigProfile.Kind.TROJAN -> "trojan"
        ConfigProfile.Kind.SHADOWSOCKS -> "shadowsocks"
        ConfigProfile.Kind.SOCKS -> "socks"
        // Hysteria2 is not an Xray protocol. It is accepted, stored and shown,
        // but building an outbound for it needs a separate engine; the UI marks
        // such profiles as unsupported rather than silently generating a
        // document the core will reject.
        ConfigProfile.Kind.HYSTERIA2 -> "hysteria2"
    }

    /** True when the bundled core can actually run this profile. */
    fun isSupported(profile: ConfigProfile): Boolean =
        profile.kind != ConfigProfile.Kind.HYSTERIA2

    private fun outboundSettings(p: ConfigProfile): JSONObject = when (p.kind) {
        ConfigProfile.Kind.VLESS -> JSONObject().put("vnext", JSONArray().put(
            JSONObject().apply {
                put("address", p.server)
                put("port", p.portOrNull() ?: 443)
                put("users", JSONArray().put(JSONObject().apply {
                    put("id", p.credential)
                    put("encryption", p.encryption.ifBlank { "none" })
                    if (p.flow.isNotBlank()) put("flow", p.flow)
                }))
            }
        ))
        ConfigProfile.Kind.VMESS -> JSONObject().put("vnext", JSONArray().put(
            JSONObject().apply {
                put("address", p.server)
                put("port", p.portOrNull() ?: 443)
                put("users", JSONArray().put(JSONObject().apply {
                    put("id", p.credential)
                    put("alterId", p.alterId.toIntOrNull() ?: 0)
                    put("security", p.encryption.ifBlank { "auto" })
                }))
            }
        ))
        ConfigProfile.Kind.TROJAN -> JSONObject().put("servers", JSONArray().put(
            JSONObject().apply {
                put("address", p.server)
                put("port", p.portOrNull() ?: 443)
                put("password", p.credential)
            }
        ))
        ConfigProfile.Kind.SHADOWSOCKS -> JSONObject().put("servers", JSONArray().put(
            JSONObject().apply {
                put("address", p.server)
                put("port", p.portOrNull() ?: 443)
                put("password", p.credential)
                put("method", p.encryption.ifBlank { "aes-256-gcm" })
            }
        ))
        ConfigProfile.Kind.SOCKS -> JSONObject().put("servers", JSONArray().put(
            JSONObject().apply {
                put("address", p.server)
                put("port", p.portOrNull() ?: 1080)
                if (p.credential.isNotBlank()) {
                    put("users", JSONArray().put(JSONObject().apply {
                        put("user", p.remarks.ifBlank { "user" })
                        put("pass", p.credential)
                    }))
                }
            }
        ))
        ConfigProfile.Kind.HYSTERIA2 -> JSONObject()
    }

    private fun streamSettings(p: ConfigProfile): JSONObject = JSONObject().apply {
        put("network", p.network.ifBlank { "tcp" })
        if (p.security.isNotBlank() && p.security != "none") put("security", p.security)

        when (p.security) {
            "tls" -> put("tlsSettings", tlsSettings(p))
            "reality" -> put("realitySettings", realitySettings(p))
        }

        when (p.network) {
            "ws" -> put("wsSettings", JSONObject().apply {
                if (p.path.isNotBlank()) put("path", p.path)
                if (p.host.isNotBlank()) {
                    put("headers", JSONObject().put("Host", p.host))
                }
            })
            "httpupgrade" -> put("httpupgradeSettings", JSONObject().apply {
                if (p.path.isNotBlank()) put("path", p.path)
                if (p.host.isNotBlank()) put("host", p.host)
            })
            "grpc" -> put("grpcSettings", JSONObject().apply {
                if (p.path.isNotBlank()) put("serviceName", p.path)
                if (p.host.isNotBlank()) put("authority", p.host)
            })
            "h2", "http" -> put("httpSettings", JSONObject().apply {
                if (p.path.isNotBlank()) put("path", p.path)
                if (p.host.isNotBlank()) put("host", JSONArray().put(p.host))
            })
        }

        // The anti-DPI blob goes through verbatim. It is the user's, it is
        // already valid JSON (checked on save), and reshaping it here would
        // silently change the behaviour they copied it for.
        if (p.finalMask.isNotBlank()) {
            runCatching { JSONObject(p.finalMask) }.getOrNull()?.let { put("finalMask", it) }
        }
    }

    private fun tlsSettings(p: ConfigProfile): JSONObject = JSONObject().apply {
        if (p.sni.isNotBlank()) put("serverName", p.sni)
        if (p.fingerprint.isNotBlank()) put("fingerprint", p.fingerprint)
        if (p.alpn.isNotBlank()) {
            put("alpn", JSONArray().apply { p.alpn.split(',').map(String::trim).filter { it.isNotEmpty() }.forEach(::put) })
        }
        if (p.allowInsecure) put("allowInsecure", true)
        if (p.cipherSuites.isNotBlank()) put("cipherSuites", p.cipherSuites)
        if (p.echConfigList.isNotBlank()) put("echConfigList", p.echConfigList)
        if (p.pinnedPeerName.isNotBlank()) put("pinnedPeerCertificateChainSha256", JSONArray().put(p.pinnedPeerName))
        if (p.certFingerprint.isNotBlank()) {
            put("pinnedPeerCertificatePublicKeySha256", JSONArray().put(p.certFingerprint))
        }
    }

    private fun realitySettings(p: ConfigProfile): JSONObject = JSONObject().apply {
        if (p.sni.isNotBlank()) put("serverName", p.sni)
        if (p.fingerprint.isNotBlank()) put("fingerprint", p.fingerprint)
        if (p.publicKey.isNotBlank()) put("publicKey", p.publicKey)
        if (p.shortId.isNotBlank()) put("shortId", p.shortId)
        if (p.spiderX.isNotBlank()) put("spiderX", p.spiderX)
    }

    /**
     * DNS over the proxy, with no plaintext fallback.
     *
     * A single DoH server reached through the outbound. There is deliberately no
     * `localhost` or plain-UDP entry in the list: on a censored network those
     * answer with poisoned records, and having them present means Xray may
     * prefer them because they reply first.
     */
    private fun dns(): JSONObject = JSONObject().apply {
        put("servers", JSONArray().put("https://1.1.1.1/dns-query"))
        put("queryStrategy", "UseIP")
        put("disableFallback", true)
    }

    /**
     * Routing: private ranges direct, everything else through the proxy.
     *
     * No geoip/geosite files are referenced. Shipping them would add ~6 MB
     * compressed to the APK, and the product decision is one-click connect —
     * splitting Iranian traffic off is a separate feature with its own list, not
     * something to smuggle in here.
     */
    private fun routing(): JSONObject = JSONObject().apply {
        put("domainStrategy", "AsIs")
        put("rules", JSONArray().apply {
            put(JSONObject().apply {
                put("type", "field")
                put("outboundTag", "direct")
                put("ip", JSONArray().put("geoip:private"))
            })
            put(JSONObject().apply {
                put("type", "field")
                put("outboundTag", "proxy")
                put("network", "tcp,udp")
            })
        })
    }

    private fun directOutbound(): JSONObject = JSONObject().apply {
        put("tag", "direct")
        put("protocol", "freedom")
        put("settings", JSONObject().put("domainStrategy", "UseIP"))
    }

    private fun blockOutbound(): JSONObject = JSONObject().apply {
        put("tag", "block")
        put("protocol", "blackhole")
    }
}
