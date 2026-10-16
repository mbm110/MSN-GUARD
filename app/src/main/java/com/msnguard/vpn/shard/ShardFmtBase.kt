package com.msnguard.vpn.shard

import java.net.URI

internal open class ShardFmtBase {
    fun getQueryParam(uri: URI): Map<String, String> {
        val q = uri.rawQuery ?: return emptyMap()
        if (q.isEmpty()) return emptyMap()
        return q.split("&").mapNotNull { part ->
            val idx = part.indexOf('=')
            if (idx < 0) null else part.substring(0, idx) to ShardUtils.decodeURIComponent(part.substring(idx + 1))
        }.toMap()
    }

    fun getItemFormQuery(config: ShardProfile, qp: Map<String, String>) {
        config.network = qp["type"] ?: ShardNetwork.TCP
        config.headerType = qp["headerType"]
        config.host = qp["host"]
        config.path = qp["path"]
        config.seed = qp["seed"]
        config.mode = qp["mode"]
        config.serviceName = qp["serviceName"]
        config.authority = qp["authority"]
        config.xhttpMode = qp["mode"]
        config.xhttpExtra = qp["extra"]
        config.finalMask = qp["fm"]
        config.dialMode = qp["dialMode"]
        config.security = qp["security"]
        if (config.security != "tls" && config.security != "reality") config.security = null
        val allowKeys = arrayOf("insecure", "allowInsecure", "allow_insecure")
        config.insecure = when {
            allowKeys.any { qp[it] == "1" } -> true
            allowKeys.any { qp[it] == "0" } -> false
            else -> false
        }
        config.sni = qp["sni"]
        config.fingerPrint = qp["fp"]
        config.alpn = qp["alpn"]
        config.cipherSuites = qp["cs"]
        config.echConfigList = qp["ech"]
        config.echOutbound = qp["echOutbound"]
        config.verifyPeerCertByName = qp["vcn"]
        config.pinnedCA256 = qp["pcs"]
        config.publicKey = qp["pbk"]
        config.shortId = qp["sid"]
        config.spiderX = qp["spx"]
        config.mldsa65Verify = qp["pqv"]
        config.flow = qp["flow"]
    }
}
