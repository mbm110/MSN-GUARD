package com.msnguard.vpn.shard

import java.net.URI

internal object VlessFmt : ShardFmtBase() {
    fun parse(str: String): ShardProfile? = try {
        val config = ShardProfile.create(ShardType.VLESS)
        val uri = URI(ShardUtils.fixIllegalUrl(str))
        if (uri.rawQuery.isNullOrEmpty()) return null
        val qp = getQueryParam(uri)
        config.remarks = ShardUtils.decodeURIComponent(uri.fragment.orEmpty()).let { if (it.isEmpty()) "none" else it }
        config.server = ShardUtils.idnHost(uri)
        config.serverPort = uri.port.toString()
        config.password = uri.userInfo
        config.method = qp["encryption"] ?: "none"
        getItemFormQuery(config, qp)
        config
    } catch (_: Exception) { null }
}

internal object TrojanFmt : ShardFmtBase() {
    fun parse(str: String): ShardProfile = ShardProfile.create(ShardType.TROJAN).apply {
        val uri = URI(ShardUtils.fixIllegalUrl(str))
        remarks = ShardUtils.decodeURIComponent(uri.fragment.orEmpty()).let { if (it.isEmpty()) "none" else it }
        server = ShardUtils.idnHost(uri)
        serverPort = uri.port.toString()
        password = uri.userInfo
        if (uri.rawQuery.isNullOrEmpty()) {
            network = ShardNetwork.TCP
            security = "tls"
            insecure = false
        } else {
            val qp = getQueryParam(uri)
            getItemFormQuery(this, qp)
            security = qp["security"] ?: "tls"
        }
    }
}

internal object ShadowsocksFmt : ShardFmtBase() {
    fun parse(str: String): ShardProfile? = parseSip002(str) ?: parseLegacy(str)

    private fun parseSip002(str: String): ShardProfile? = try {
        val uri = URI(ShardUtils.fixIllegalUrl(str))
        if (ShardUtils.idnHost(uri).isEmpty() || uri.port <= 0 || uri.userInfo.isNullOrEmpty()) return null
        val config = ShardProfile.create(ShardType.SHADOWSOCKS)
        config.remarks = ShardUtils.decodeURIComponent(uri.fragment.orEmpty()).let { if (it.isEmpty()) "none" else it }
        config.server = ShardUtils.idnHost(uri)
        config.serverPort = uri.port.toString()
        val parts = if (uri.userInfo.contains(":")) uri.userInfo.split(":", limit = 2)
                    else ShardUtils.decode(uri.userInfo).split(":", limit = 2)
        if (parts.size == 2) { config.method = parts[0]; config.password = parts[1] }
        if (!uri.rawQuery.isNullOrEmpty()) {
            val qp = getQueryParam(uri)
            if (qp["plugin"]?.contains("obfs=http") == true) {
                val pairs = HashMap<String, String>()
                for (p in qp["plugin"]?.split(";") ?: emptyList()) {
                    val kv = p.split("=", limit = 2); if (kv.size == 2) pairs[kv[0]] = kv[1]
                }
                config.network = ShardNetwork.TCP
                config.headerType = "http"
                config.host = pairs["obfs-host"]
                config.path = pairs["path"]
            }
        }
        config
    } catch (_: Exception) { null }

    private fun parseLegacy(str: String): ShardProfile? = try {
        val config = ShardProfile.create(ShardType.SHADOWSOCKS)
        var r = str.removePrefix(ShardType.SHADOWSOCKS.scheme)
        val hi = r.indexOf("#")
        if (hi > 0) { try { config.remarks = ShardUtils.decodeURIComponent(r.substring(hi + 1)) } catch (_: Exception) {}; r = r.substring(0, hi) }
        val atIdx = r.indexOf("@")
        r = if (atIdx > 0) ShardUtils.decode(r.substring(0, atIdx)) + r.substring(atIdx) else ShardUtils.decode(r)
        val m = Regex("^(.+?):(.*)@(.+?):(\\d+)/?$").matchEntire(r) ?: return null
        config.server = m.groupValues[3].removeSurrounding("[", "]")
        config.serverPort = m.groupValues[4]
        config.password = m.groupValues[2]
        config.method = m.groupValues[1].lowercase()
        config
    } catch (_: Exception) { null }
}

internal object SocksFmt : ShardFmtBase() {
    fun parse(str: String): ShardProfile? = try {
        val uri = URI(ShardUtils.fixIllegalUrl(str))
        if (ShardUtils.idnHost(uri).isEmpty() || uri.port <= 0) return null
        val c = ShardProfile.create(ShardType.SOCKS)
        c.remarks = ShardUtils.decodeURIComponent(uri.fragment.orEmpty()).let { if (it.isEmpty()) "none" else it }
        c.server = ShardUtils.idnHost(uri)
        c.serverPort = uri.port.toString()
        if (!uri.userInfo.isNullOrEmpty()) {
            val parts = if (uri.userInfo.contains(":")) uri.userInfo.split(":", limit = 2)
                        else ShardUtils.decode(uri.userInfo).split(":", limit = 2)
            if (parts.size == 2) { c.username = parts[0]; c.password = parts[1] }
        }
        c
    } catch (_: Exception) { null }
}

internal object Hysteria2Fmt : ShardFmtBase() {
    fun parse(str: String): ShardProfile = ShardProfile.create(ShardType.HYSTERIA2).apply {
        val uri = URI(ShardUtils.fixIllegalUrl(str))
        remarks = ShardUtils.decodeURIComponent(uri.fragment.orEmpty()).let { if (it.isEmpty()) "none" else it }
        server = ShardUtils.idnHost(uri)
        serverPort = uri.port.toString()
        password = uri.userInfo
        security = "tls"
        network = ShardNetwork.HYSTERIA
        if (!uri.rawQuery.isNullOrEmpty()) {
            val qp = getQueryParam(uri)
            getItemFormQuery(this, qp)
            security = qp["security"] ?: "tls"
            obfsPassword = qp["obfs-password"]
            portHopping = qp["mport"]
            pinnedCA256 = qp["pinSHA256"]
        }
    }
}

internal object WireguardFmt {
    fun parse(str: String): ShardProfile? = null // SHARD has no wireguard nodes today — stub
}
