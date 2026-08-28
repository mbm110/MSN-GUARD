package com.msnguard.vpn

import android.net.Uri
import android.util.Base64
import org.json.JSONObject
import java.util.UUID

/**
 * A user-supplied proxy configuration (VLESS / VMess / Trojan / Shadowsocks /
 * Hysteria2 / SOCKS).
 *
 * This is the app's own model, not Xray's. The core is fed a generated JSON
 * document at connect time; what the user edits and what we persist is this flat
 * object, because the fields in the editor map 1:1 to it and a flat object is
 * trivially versionable in SharedPreferences.
 *
 * WHY EVERY FIELD IS A STRING, INCLUDING THE PORT: these values come from
 * pasted URIs written by dozens of different panel generators, and a good number
 * of them are malformed in ways that still work — an empty `port`, a `sni` with
 * a trailing space, an `alpn` list with an empty element. Parsing into typed
 * fields means deciding, at paste time, that a config is invalid; keeping the
 * text means the user can open the editor and see exactly what arrived, fix the
 * one wrong character, and save. Validation happens on save and on connect, not
 * on paste.
 */
data class ConfigProfile(
    /** Stable identity, survives edits. Used as the key in [ConfigStore]. */
    val id: String = UUID.randomUUID().toString(),
    val kind: Kind,
    /** The display name; `remarks` in v2ray-family clients. */
    var remarks: String = "",
    var server: String = "",
    var port: String = "",
    /** UUID for VLESS/VMess, password for Trojan/Hysteria2/Shadowsocks. */
    var credential: String = "",
    /** VLESS: `none`. VMess: `auto`/`aes-128-gcm`/… Shadowsocks: the method. */
    var encryption: String = "",
    /** XTLS flow, e.g. `xtls-rprx-vision`. Empty for everything else. */
    var flow: String = "",
    /** VMess alterId; irrelevant elsewhere. */
    var alterId: String = "",
    /** Transport: `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `h2`, `quic`. */
    var network: String = "tcp",
    /** ws/httpupgrade Host header, or the gRPC authority. */
    var host: String = "",
    /** ws/httpupgrade path, or the gRPC serviceName. */
    var path: String = "",
    /** Security layer: ``, `tls`, `reality`. */
    var security: String = "",
    var sni: String = "",
    /** uTLS browser fingerprint: `chrome`, `firefox`, `safari`, `unsafe`, … */
    var fingerprint: String = "",
    var alpn: String = "",
    var allowInsecure: Boolean = false,
    /** REALITY public key. */
    var publicKey: String = "",
    /** REALITY shortId. */
    var shortId: String = "",
    /** REALITY spiderX. */
    var spiderX: String = "",
    /**
     * Raw fragmentation / anti-DPI JSON, PattNG's `finalMask`.
     *
     * Deliberately opaque: it is a nested object whose schema belongs to the
     * core, not to us, and users copy it verbatim from channels. Parsing it into
     * fields would mean rejecting any shape we had not anticipated. It is
     * validated as JSON on save and passed through untouched.
     */
    var finalMask: String = "",
    var cipherSuites: String = "",
    var echConfigList: String = "",
    /** Pin the peer certificate by name (`Verify peer certificate by name`). */
    var pinnedPeerName: String = "",
    /** Expected certificate SHA-256, hex or base64 as the user pasted it. */
    var certFingerprint: String = "",
    /**
     * Last measured latency in ms, or [PING_FAILED] / [PING_UNKNOWN].
     *
     * Cached in the profile rather than a side map so the list can paint the
     * previous result instantly on open, exactly as PattNG does. It is a
     * measurement, not configuration, so [ConfigStore] writes it without
     * bumping anything else.
     */
    var lastPingMs: Int = PING_UNKNOWN,
) {

    enum class Kind(
        /** URI scheme we parse and emit. */
        val scheme: String,
        /** What the amber line under the name says. */
        val label: String,
        val credentialLabel: String,
    ) {
        VLESS("vless", "VLESS", "id"),
        VMESS("vmess", "VMess", "id"),
        TROJAN("trojan", "Trojan", "password"),
        SHADOWSOCKS("ss", "Shadowsocks", "password"),
        HYSTERIA2("hysteria2", "Hysteria2", "password"),
        SOCKS("socks", "SOCKS", "password"),
    }

    /**
     * The amber summary line: `VLESS / ws / tls`.
     *
     * Empty segments are dropped rather than rendered as `//`, so a plain TCP
     * config with no TLS reads `Trojan / tcp` instead of `Trojan / tcp / `.
     */
    fun summary(): String = listOf(kind.label, network, security)
        .filter { it.isNotBlank() }
        .joinToString(" / ")

    /** `188.114.97.6 : 443`, matching the grey line in the list. */
    fun endpoint(): String = if (port.isBlank()) server else "$server : $port"

    fun portOrNull(): Int? = port.trim().toIntOrNull()?.takeIf { it in 1..65535 }

    /** A name to show when the config carried no remark. */
    fun displayName(): String = remarks.ifBlank { endpoint().ifBlank { kind.label } }

    /**
     * Why this profile cannot be connected, or null if it can.
     *
     * Returned as a message rather than a boolean because the editor shows it
     * verbatim; a bare "invalid" would leave the user guessing which of fifteen
     * fields is wrong.
     */
    fun validate(): String? = when {
        server.isBlank() -> "Server address is empty"
        portOrNull() == null -> "Port must be a number between 1 and 65535"
        kind != Kind.SOCKS && credential.isBlank() -> "${kind.credentialLabel} is empty"
        finalMask.isNotBlank() && !isJsonObject(finalMask) -> "finalMask is not valid JSON"
        else -> null
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("kind", kind.name)
        put("remarks", remarks)
        put("server", server)
        put("port", port)
        put("credential", credential)
        put("encryption", encryption)
        put("flow", flow)
        put("alterId", alterId)
        put("network", network)
        put("host", host)
        put("path", path)
        put("security", security)
        put("sni", sni)
        put("fingerprint", fingerprint)
        put("alpn", alpn)
        put("allowInsecure", allowInsecure)
        put("publicKey", publicKey)
        put("shortId", shortId)
        put("spiderX", spiderX)
        put("finalMask", finalMask)
        put("cipherSuites", cipherSuites)
        put("echConfigList", echConfigList)
        put("pinnedPeerName", pinnedPeerName)
        put("certFingerprint", certFingerprint)
        put("lastPingMs", lastPingMs)
    }

    companion object {
        const val PING_UNKNOWN = -2
        const val PING_FAILED = -1

        fun fromJson(json: JSONObject): ConfigProfile? {
            val kind = runCatching { Kind.valueOf(json.optString("kind")) }.getOrNull() ?: return null
            return ConfigProfile(
                id = json.optString("id").ifBlank { UUID.randomUUID().toString() },
                kind = kind,
                remarks = json.optString("remarks"),
                server = json.optString("server"),
                port = json.optString("port"),
                credential = json.optString("credential"),
                encryption = json.optString("encryption"),
                flow = json.optString("flow"),
                alterId = json.optString("alterId"),
                network = json.optString("network").ifBlank { "tcp" },
                host = json.optString("host"),
                path = json.optString("path"),
                security = json.optString("security"),
                sni = json.optString("sni"),
                fingerprint = json.optString("fingerprint"),
                alpn = json.optString("alpn"),
                allowInsecure = json.optBoolean("allowInsecure", false),
                publicKey = json.optString("publicKey"),
                shortId = json.optString("shortId"),
                spiderX = json.optString("spiderX"),
                finalMask = json.optString("finalMask"),
                cipherSuites = json.optString("cipherSuites"),
                echConfigList = json.optString("echConfigList"),
                pinnedPeerName = json.optString("pinnedPeerName"),
                certFingerprint = json.optString("certFingerprint"),
                lastPingMs = json.optInt("lastPingMs", PING_UNKNOWN),
            )
        }

        fun isJsonObject(text: String): Boolean =
            runCatching { JSONObject(text.trim()) }.isSuccess

        fun blank(kind: Kind): ConfigProfile = ConfigProfile(
            kind = kind,
            encryption = when (kind) {
                Kind.VLESS -> "none"
                Kind.VMESS -> "auto"
                Kind.SHADOWSOCKS -> "aes-256-gcm"
                else -> ""
            },
            security = if (kind == Kind.HYSTERIA2) "tls" else "",
            network = if (kind == Kind.HYSTERIA2) "hysteria" else "tcp",
        )
    }
}

/**
 * Turns a pasted string into a [ConfigProfile], detecting the type itself.
 *
 * The user never picks a protocol from a dropdown: they paste and the scheme
 * decides. That is the whole point of the feature, so this object is the part
 * that has to be forgiving.
 */
object ConfigParser {

    /** Everything we recognise, longest scheme first so `vless` beats `vmess`. */
    private val schemes = mapOf(
        "vless" to ConfigProfile.Kind.VLESS,
        "vmess" to ConfigProfile.Kind.VMESS,
        "trojan" to ConfigProfile.Kind.TROJAN,
        "ss" to ConfigProfile.Kind.SHADOWSOCKS,
        "hysteria2" to ConfigProfile.Kind.HYSTERIA2,
        "hy2" to ConfigProfile.Kind.HYSTERIA2,
        "socks" to ConfigProfile.Kind.SOCKS,
    )

    /** Result of a paste: what parsed, and what did not. */
    data class Batch(val profiles: List<ConfigProfile>, val failures: List<String>)

    fun detectKind(text: String): ConfigProfile.Kind? {
        val scheme = text.trim().substringBefore("://", "").lowercase()
        return schemes[scheme]
    }

    /**
     * Parse a whole clipboard: one URI per line, or a base64 subscription blob.
     *
     * Multi-line is the common case — channels post ten configs at once and the
     * user selects all of them. Failures are reported per line instead of
     * aborting the batch, so nine good configs are not lost to one typo.
     */
    fun parseMany(raw: String): Batch {
        val text = raw.trim()
        if (text.isEmpty()) return Batch(emptyList(), emptyList())

        // A subscription body is base64 with no scheme in it at all. Decode
        // first, then treat the result as ordinary lines.
        val expanded = if (!text.contains("://")) {
            decodeBase64(text)?.takeIf { it.contains("://") } ?: text
        } else {
            text
        }

        val good = mutableListOf<ConfigProfile>()
        val bad = mutableListOf<String>()
        expanded.lineSequence()
            .map(String::trim)
            .filter { it.isNotEmpty() }
            .forEach { line ->
                val parsed = runCatching { parseOne(line) }.getOrNull()
                if (parsed != null) good += parsed else bad += line.take(60)
            }
        return Batch(good, bad)
    }

    fun parseOne(raw: String): ConfigProfile? {
        val text = raw.trim()
        val kind = detectKind(text) ?: return null
        return when (kind) {
            ConfigProfile.Kind.VMESS -> parseVmess(text)
            ConfigProfile.Kind.SHADOWSOCKS -> parseShadowsocks(text)
            ConfigProfile.Kind.HYSTERIA2 -> parseHysteria2(text)
            else -> parseStandard(text, kind)
        }
    }

    /**
     * VLESS / Trojan / SOCKS: `scheme://credential@host:port?query#remark`.
     *
     * `Uri.parse` is used only for the structural split. The query is read with
     * our own helper because `Uri.getQueryParameter` throws on some of the
     * malformed queries panels emit (a bare `&&`, an unencoded `#` inside a
     * path), and one bad separator should not lose the whole config.
     */
    private fun parseStandard(text: String, kind: ConfigProfile.Kind): ConfigProfile? {
        val uri = runCatching { Uri.parse(text) }.getOrNull() ?: return null
        val host = uri.host?.takeIf { it.isNotBlank() } ?: return null
        val q = query(text)

        val profile = ConfigProfile.blank(kind).copy(
            remarks = decode(uri.fragment.orEmpty()),
            server = host,
            port = uri.port.takeIf { it > 0 }?.toString() ?: "443",
            credential = decode(uri.userInfo.orEmpty()),
        )
        profile.network = q["type"] ?: q["net"] ?: "tcp"
        profile.security = q["security"] ?: if (kind == ConfigProfile.Kind.TROJAN) "tls" else ""
        profile.encryption = q["encryption"] ?: if (kind == ConfigProfile.Kind.VLESS) "none" else ""
        profile.flow = q["flow"].orEmpty()
        profile.sni = q["sni"] ?: q["peer"].orEmpty()
        profile.fingerprint = q["fp"].orEmpty()
        profile.alpn = q["alpn"].orEmpty()
        profile.allowInsecure = q["allowInsecure"] == "1" || q["insecure"] == "1"
        profile.publicKey = q["pbk"].orEmpty()
        profile.shortId = q["sid"].orEmpty()
        profile.spiderX = q["spx"].orEmpty()
        applyTransport(profile, q)
        return profile
    }

    /**
     * VMess: `vmess://` + base64 of a JSON object (the "v2rayN" format).
     *
     * Note `add`/`aid`/`net` and friends: those key names are the de-facto
     * standard and are not ours to rename.
     */
    private fun parseVmess(text: String): ConfigProfile? {
        val body = text.removePrefix("vmess://").trim()
        val json = decodeBase64(body)?.let { decoded ->
            runCatching { JSONObject(decoded) }.getOrNull()
        } ?: return null

        val profile = ConfigProfile.blank(ConfigProfile.Kind.VMESS).copy(
            remarks = json.optString("ps"),
            server = json.optString("add"),
            port = json.optString("port"),
            credential = json.optString("id"),
        )
        profile.alterId = json.optString("aid", "0")
        profile.encryption = json.optString("scy").ifBlank { "auto" }
        profile.network = json.optString("net").ifBlank { "tcp" }
        profile.security = json.optString("tls")
        profile.sni = json.optString("sni")
        profile.fingerprint = json.optString("fp")
        profile.alpn = json.optString("alpn")
        profile.host = json.optString("host")
        profile.path = json.optString("path")
        return profile.takeIf { it.server.isNotBlank() }
    }

    /**
     * Shadowsocks, both encodings:
     *   `ss://base64(method:password)@host:port#remark`  (SIP002)
     *   `ss://base64(method:password@host:port)#remark`  (legacy, all encoded)
     */
    private fun parseShadowsocks(text: String): ConfigProfile? {
        val withoutScheme = text.removePrefix("ss://")
        val remark = decode(withoutScheme.substringAfter('#', ""))
        val body = withoutScheme.substringBefore('#').substringBefore('?')

        val (methodPass, hostPort) = if (body.contains('@')) {
            val userPart = body.substringBeforeLast('@')
            decodeBase64(userPart)?.takeIf { it.contains(':') }.orEmpty()
                .ifBlank { decode(userPart) } to body.substringAfterLast('@')
        } else {
            val decoded = decodeBase64(body) ?: return null
            decoded.substringBeforeLast('@') to decoded.substringAfterLast('@')
        }
        if (!hostPort.contains(':')) return null

        val q = query(text)
        val profile = ConfigProfile.blank(ConfigProfile.Kind.SHADOWSOCKS).copy(
            remarks = remark,
            server = hostPort.substringBeforeLast(':'),
            port = hostPort.substringAfterLast(':'),
            credential = methodPass.substringAfter(':'),
            encryption = methodPass.substringBefore(':'),
        )
        profile.network = q["type"] ?: "tcp"
        profile.security = q["security"].orEmpty()
        profile.sni = q["sni"].orEmpty()
        applyTransport(profile, q)
        return profile.takeIf { it.server.isNotBlank() }
    }

    /** Hysteria2: TLS is implicit and the transport is its own QUIC. */
    private fun parseHysteria2(text: String): ConfigProfile? {
        val uri = runCatching { Uri.parse(text) }.getOrNull() ?: return null
        val host = uri.host?.takeIf { it.isNotBlank() } ?: return null
        val q = query(text)
        val profile = ConfigProfile.blank(ConfigProfile.Kind.HYSTERIA2).copy(
            remarks = decode(uri.fragment.orEmpty()),
            server = host,
            port = uri.port.takeIf { it > 0 }?.toString() ?: "443",
            credential = decode(uri.userInfo.orEmpty()),
        )
        profile.sni = q["sni"].orEmpty()
        profile.alpn = q["alpn"].orEmpty()
        profile.allowInsecure = q["insecure"] == "1"
        profile.pinnedPeerName = q["pinSHA256"].orEmpty()
        return profile
    }

    /**
     * Map the transport-specific query keys onto [ConfigProfile.host]/[path].
     *
     * Each transport spells the same two ideas differently, and the editor shows
     * one pair of fields whose labels change. Doing the mapping here keeps that
     * knowledge in one place instead of spread across parser and editor.
     */
    private fun applyTransport(profile: ConfigProfile, q: Map<String, String>) {
        when (profile.network) {
            "ws", "httpupgrade", "xhttp" -> {
                profile.host = q["host"].orEmpty()
                profile.path = q["path"]?.let(::decode).orEmpty()
            }
            "grpc" -> {
                profile.host = q["authority"].orEmpty()
                profile.path = q["serviceName"]?.let(::decode).orEmpty()
            }
            "h2", "http" -> {
                profile.host = q["host"].orEmpty()
                profile.path = q["path"]?.let(::decode).orEmpty()
            }
            "quic" -> {
                profile.host = q["quicSecurity"].orEmpty()
                profile.path = q["key"].orEmpty()
            }
            else -> {
                // tcp with an HTTP header disguise still carries host/path.
                profile.host = q["host"].orEmpty()
                profile.path = q["path"]?.let(::decode).orEmpty()
            }
        }
    }

    /**
     * Read the query string by hand.
     *
     * Split on the FIRST `?` and drop any `#` tail, then split pairs on `&`.
     * Pairs without `=` are ignored rather than treated as empty-valued keys,
     * because that shape only ever appears in a malformed URI.
     */
    private fun query(text: String): Map<String, String> {
        val q = text.substringAfter('?', "").substringBefore('#')
        if (q.isEmpty()) return emptyMap()
        return q.split('&')
            .mapNotNull { pair ->
                if (!pair.contains('=')) return@mapNotNull null
                val key = pair.substringBefore('=')
                val value = pair.substringAfter('=')
                if (key.isBlank()) null else key to decode(value)
            }
            .toMap()
    }

    private fun decode(value: String): String =
        runCatching { Uri.decode(value) }.getOrDefault(value)

    /**
     * Base64 that accepts what real configs contain.
     *
     * URL-safe and standard alphabets both appear in the wild, and padding is
     * frequently missing. [Base64.URL_SAFE] rejects `+`/`/`, so both are tried,
     * and a non-UTF8 result is treated as a failure rather than returned as
     * mojibake that would fail JSON parsing later with a useless error.
     */
    private fun decodeBase64(input: String): String? {
        val cleaned = input.trim().replace("\n", "").replace("\r", "")
        if (cleaned.isEmpty()) return null
        val padded = cleaned.padEnd((cleaned.length + 3) / 4 * 4, '=')
        for (flags in intArrayOf(Base64.DEFAULT, Base64.URL_SAFE)) {
            val bytes = runCatching { Base64.decode(padded, flags) }.getOrNull() ?: continue
            val text = runCatching { String(bytes, Charsets.UTF_8) }.getOrNull() ?: continue
            // A wrong alphabet usually yields replacement characters rather than
            // an exception, so check the result is plausible text.
            if (text.isNotEmpty() && !text.contains('\uFFFD')) return text
        }
        return null
    }

    /**
     * Rebuild a shareable URI from a profile.
     *
     * Used by the list's share action. VMess round-trips through its base64
     * JSON; everything else is assembled as a query. Not guaranteed to be
     * byte-identical to what the user pasted — key order and default values may
     * differ — but semantically the same config.
     */
    fun toUri(p: ConfigProfile): String {
        if (p.kind == ConfigProfile.Kind.VMESS) {
            val json = JSONObject().apply {
                put("v", "2")
                put("ps", p.remarks)
                put("add", p.server)
                put("port", p.port)
                put("id", p.credential)
                put("aid", p.alterId.ifBlank { "0" })
                put("scy", p.encryption.ifBlank { "auto" })
                put("net", p.network)
                put("host", p.host)
                put("path", p.path)
                put("tls", p.security)
                put("sni", p.sni)
                put("fp", p.fingerprint)
                put("alpn", p.alpn)
            }
            val body = Base64.encodeToString(json.toString().toByteArray(), Base64.NO_WRAP)
            return "vmess://$body"
        }
        val params = buildList {
            if (p.kind == ConfigProfile.Kind.VLESS) add("encryption" to p.encryption.ifBlank { "none" })
            if (p.security.isNotBlank()) add("security" to p.security)
            if (p.network.isNotBlank()) add("type" to p.network)
            if (p.host.isNotBlank()) add("host" to p.host)
            if (p.path.isNotBlank()) add("path" to p.path)
            if (p.sni.isNotBlank()) add("sni" to p.sni)
            if (p.fingerprint.isNotBlank()) add("fp" to p.fingerprint)
            if (p.alpn.isNotBlank()) add("alpn" to p.alpn)
            if (p.flow.isNotBlank()) add("flow" to p.flow)
            if (p.publicKey.isNotBlank()) add("pbk" to p.publicKey)
            if (p.shortId.isNotBlank()) add("sid" to p.shortId)
            if (p.spiderX.isNotBlank()) add("spx" to p.spiderX)
            if (p.allowInsecure) add("allowInsecure" to "1")
        }.joinToString("&") { (k, v) -> "$k=${Uri.encode(v)}" }

        val credential = Uri.encode(p.credential)
        val tail = if (params.isEmpty()) "" else "?$params"
        val remark = if (p.remarks.isBlank()) "" else "#${Uri.encode(p.remarks)}"
        return "${p.kind.scheme}://$credential@${p.server}:${p.port}$tail$remark"
    }
}
