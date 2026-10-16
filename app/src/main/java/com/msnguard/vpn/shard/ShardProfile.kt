package com.msnguard.vpn.shard

import java.util.Locale

/** Minimal profile for SHARD pool — only fields SHARD actually uses. */
data class ShardProfile(
    var configType: ShardType,
    var remarks: String = "",
    var server: String? = null,
    var serverPort: String? = null,
    var password: String? = null,
    var method: String? = null,
    var flow: String? = null,
    var username: String? = null,
    var network: String? = null,
    var headerType: String? = null,
    var host: String? = null,
    var path: String? = null,
    var seed: String? = null,
    var mode: String? = null,
    var serviceName: String? = null,
    var authority: String? = null,
    var xhttpMode: String? = null,
    var xhttpExtra: String? = null,
    var finalMask: String? = null,
    var dialMode: String? = null,
    var security: String? = null,
    var sni: String? = null,
    var alpn: String? = null,
    var fingerPrint: String? = null,
    var cipherSuites: String? = null,
    var insecure: Boolean? = null,
    var echConfigList: String? = null,
    var echOutbound: String? = null,
    var verifyPeerCertByName: String? = null,
    var pinnedCA256: String? = null,
    var publicKey: String? = null,
    var shortId: String? = null,
    var spiderX: String? = null,
    var mldsa65Verify: String? = null,
    var obfsPassword: String? = null,
    var portHopping: String? = null,
    var portHoppingInterval: String? = null,
    var bandwidthDown: String? = null,
    var bandwidthUp: String? = null,
) {
    companion object {
        fun create(type: ShardType) = ShardProfile(configType = type)
    }
}

enum class ShardType(val value: Int, val scheme: String) {
    VLESS(5, "vless://"),
    TROJAN(6, "trojan://"),
    SHADOWSOCKS(3, "ss://"),
    SOCKS(4, "socks://"),
    HYSTERIA2(9, "hysteria2://"),
    VMESS(1, "vmess://"),
    WIREGUARD(7, "wireguard://"),
}

object ShardNetwork {
    const val TCP = "tcp"
    const val WS = "ws"
    const val HTTP_UPGRADE = "httpupgrade"
    const val XHTTP = "xhttp"
    const val GRPC = "grpc"
    const val HYSTERIA = "hysteria"
    fun fromString(t: String?): String = when (t?.lowercase(Locale.US)) {
        "ws" -> WS
        "httpupgrade" -> HTTP_UPGRADE
        "xhttp" -> XHTTP
        "grpc" -> GRPC
        "hysteria" -> HYSTERIA
        "tcp" -> TCP
        else -> t?.lowercase(Locale.US) ?: TCP
    }
}
