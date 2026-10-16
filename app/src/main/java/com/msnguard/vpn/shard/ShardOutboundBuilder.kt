package com.msnguard.vpn.shard

import org.json.JSONArray
import org.json.JSONObject

/** Renders JSONObject outbounds exactly like reference CoreOutboundBuilder — no Gson, no V2rayConfig. */
internal object ShardOutboundBuilder {

    fun outbound(profile: ShardProfile, tag: String): JSONObject {
        val settings = JSONObject()
        when (profile.configType) {
            ShardType.VLESS -> {
                val user = JSONObject().apply {
                    put("id", profile.password.orEmpty())
                    put("encryption", profile.method ?: "none")
                    if (!profile.flow.isNullOrBlank()) put("flow", profile.flow)
                }
                val vnext = JSONObject().apply {
                    put("address", serverAddress(profile))
                    put("port", profile.serverPort?.toIntOrNull() ?: 443)
                    put("users", JSONArray().put(user))
                }
                settings.put("vnext", JSONArray().put(vnext))
            }
            ShardType.TROJAN -> {
                val srv = JSONObject().apply {
                    put("address", serverAddress(profile)); put("port", profile.serverPort?.toIntOrNull() ?: 443)
                    put("password", profile.password.orEmpty())
                    if (!profile.flow.isNullOrBlank()) put("flow", profile.flow)
                }
                settings.put("servers", JSONArray().put(srv))
            }
            ShardType.SHADOWSOCKS -> {
                val srv = JSONObject().apply {
                    put("address", serverAddress(profile)); put("port", profile.serverPort?.toIntOrNull() ?: 443)
                    put("method", profile.method.orEmpty()); put("password", profile.password.orEmpty())
                }
                settings.put("servers", JSONArray().put(srv))
            }
            ShardType.SOCKS -> {
                val srv = JSONObject().apply {
                    put("address", serverAddress(profile)); put("port", profile.serverPort?.toIntOrNull() ?: 1080)
                    if (!profile.username.isNullOrEmpty()) {
                        put("users", JSONArray().put(JSONObject().apply { put("user", profile.username); put("pass", profile.password) }))
                    }
                }
                // SOCKS outbound has no streamSettings — return early with settings only
                return JSONObject().apply { put("tag", tag); put("protocol", "socks"); put("settings", srv) }
            }
            ShardType.HYSTERIA2 -> {
                settings.put("address", serverAddress(profile))
                settings.put("port", profile.serverPort?.toIntOrNull() ?: 443)
                settings.put("version", 2)
            }
            else -> {}
        }

        val stream = JSONObject()
        val sni = populateTransportSettings(stream, profile)
        populateTlsSettings(stream, profile, sni)

        // finalMask is handled inside populateTransportSettings (merged there); keep fallback
        // but reference does: finalMask?.let { parsed -> stream.finalmask = parsed } inside transport
        // So nothing extra here — transport already applied it.

        return JSONObject().apply {
            put("tag", tag)
            put("protocol", protoName(profile))
            put("settings", settings)
            put("streamSettings", stream)
        }
    }

    private fun protoName(p: ShardProfile): String = when (p.configType) {
        ShardType.VLESS -> "vless"; ShardType.TROJAN -> "trojan"; ShardType.SHADOWSOCKS -> "shadowsocks"
        ShardType.SOCKS -> "socks"; ShardType.HYSTERIA2 -> "hysteria"; else -> p.configType.name.lowercase()
    }

    private fun serverAddress(p: ShardProfile): String = p.server.orEmpty()

    // ---- transport ----

    fun populateTransportSettings(stream: JSONObject, p: ShardProfile): String? {
        val net = p.network?.lowercase().orEmpty().ifEmpty { ShardNetwork.TCP }
        stream.put("network", net)
        var sni: String? = null
        when (net) {
            ShardNetwork.TCP -> {
                val tcp = JSONObject()
                val header = JSONObject()
                if (p.headerType == "http") {
                    header.put("type", "http")
                    val req = JSONObject()
                    req.put("version", "1.1"); req.put("method", "GET")
                    val headers = JSONObject()
                    headers.put("User-Agent", JSONArray().put("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36"))
                    headers.put("Accept-Encoding", JSONArray().put("gzip, deflate"))
                    headers.put("Connection", JSONArray().put("keep-alive"))
                    headers.put("Pragma", "no-cache")
                    val hosts = p.host.orEmpty().split(",").map { it.trim() }.filter { it.isNotEmpty() }
                    if (hosts.isNotEmpty()) headers.put("Host", JSONArray().apply { hosts.forEach { put(it) } })
                    req.put("headers", headers)
                    val paths = p.path.orEmpty().split(",").map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { listOf("/") }
                    req.put("path", JSONArray().apply { paths.forEach { put(it) } })
                    header.put("request", req)
                    sni = hosts.firstOrNull()
                } else {
                    header.put("type", "none"); sni = p.host
                }
                tcp.put("header", header)
                stream.put("tcpSettings", tcp)
            }
            ShardNetwork.WS -> {
                stream.put("wsSettings", JSONObject().apply { put("host", p.host.orEmpty()); put("path", p.path ?: "/") })
                sni = p.host
            }
            ShardNetwork.HTTP_UPGRADE -> {
                stream.put("httpupgradeSettings", JSONObject().apply { put("host", p.host.orEmpty()); put("path", p.path ?: "/") })
                sni = p.host
            }
            ShardNetwork.XHTTP -> {
                val x = JSONObject().apply {
                    put("host", p.host.orEmpty()); put("path", p.path ?: "/")
                    if (!p.xhttpMode.isNullOrBlank()) put("mode", p.xhttpMode)
                    if (!p.xhttpExtra.isNullOrBlank()) try { put("extra", JSONObject(p.xhttpExtra)) } catch (_: Exception) {}
                }
                stream.put("xhttpSettings", x); sni = p.host
            }
            ShardNetwork.GRPC -> {
                stream.put("grpcSettings", JSONObject().apply {
                    put("multiMode", p.mode == "multi")
                    put("serviceName", p.serviceName.orEmpty())
                    put("authority", p.authority.orEmpty())
                    put("idle_timeout", 60); put("health_check_timeout", 20)
                })
                sni = p.authority
            }
            ShardNetwork.HYSTERIA -> {
                val h = JSONObject().apply { put("version", 2); put("auth", p.password.orEmpty()) }
                stream.put("hysteriaSettings", h)
                // brutal/quicParams handled via finalMask json if present — same as reference
            }
        }
        // finalMask overlay — exactly like reference: parse JSON and stash as JSONObject
        p.finalMask?.takeIf { it.isNotBlank() }?.let { fm ->
            try { stream.put("finalmask", JSONObject(fm)) } catch (_: Exception) {}
        }
        return sni
    }

    private fun alpnProtocols(alpn: String?): List<String> =
        alpn?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()

    // ---- TLS / Reality ----

    fun populateTlsSettings(stream: JSONObject, p: ShardProfile, sniExt: String?) {
        val sec = p.security.orEmpty()
        val allowInsecure = p.insecure == true && p.pinnedCA256.isNullOrEmpty()
        val sni = if (p.sni.isNullOrEmpty()) {
            when {
                !sniExt.isNullOrEmpty() && ShardUtils.isDomainName(sniExt) -> sniExt
                !p.server.isNullOrEmpty() && ShardUtils.isDomainName(p.server) -> p.server
                else -> sniExt
            }
        } else p.sni

        stream.put("security", sec.ifEmpty { null } ?: return)
        if (sec != "tls" && sec != "reality") return

        val tls = JSONObject().apply {
            put("allowInsecure", allowInsecure)
            if (!sni.isNullOrBlank()) put("serverName", sni)
            if (!p.fingerPrint.isNullOrBlank()) put("fingerprint", p.fingerPrint)
            val alpnList = alpnProtocols(p.alpn)
            if (alpnList.isNotEmpty()) put("alpn", JSONArray().apply { alpnList.forEach { put(it) } })
            if (!p.cipherSuites.isNullOrBlank()) put("cipherSuites", p.cipherSuites)
            if (!p.echConfigList.isNullOrBlank()) put("echConfigList", p.echConfigList)
            if (!p.verifyPeerCertByName.isNullOrBlank()) put("verifyPeerCertByName", p.verifyPeerCertByName)
            if (!p.pinnedCA256.isNullOrBlank()) put("pinnedPeerCertSha256", p.pinnedCA256)
            if (!p.publicKey.isNullOrBlank()) put("publicKey", p.publicKey)
            if (!p.shortId.isNullOrBlank()) put("shortId", p.shortId)
            if (!p.spiderX.isNullOrBlank()) put("spiderX", p.spiderX)
            if (!p.mldsa65Verify.isNullOrBlank()) put("mldsa65Verify", p.mldsa65Verify)
        }
        if (sec == "tls") {
            if (!p.echOutbound.isNullOrBlank()) tls.put("echOutbound", p.echOutbound)
            stream.put("tlsSettings", tls)
        } else {
            stream.put("realitySettings", tls)
        }
    }
}
