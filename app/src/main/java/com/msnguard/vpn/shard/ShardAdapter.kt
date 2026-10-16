package com.msnguard.vpn.shard

import com.msnguard.vpn.ShardNode

internal fun ShardProfile.toShardNode(): ShardNode = ShardNode(
    protocol = when (configType) {
        ShardType.VLESS -> "vless"; ShardType.TROJAN -> "trojan"; ShardType.SHADOWSOCKS -> "shadowsocks"
        ShardType.SOCKS -> "socks"; ShardType.HYSTERIA2 -> "hysteria2"; else -> configType.scheme.removeSuffix("://")
    },
    credential = password.orEmpty(),
    address = server.orEmpty(),
    port = serverPort?.toIntOrNull() ?: 443,
    network = network.orEmpty().ifEmpty { "tcp" },
    security = security.orEmpty().ifEmpty { "none" },
    path = path.orEmpty().ifEmpty { "/" },
    host = host.orEmpty(),
    serverName = sni?.takeIf { it.isNotBlank() } ?: host.orEmpty(),
    fingerprint = fingerPrint.orEmpty(),
    cipherSuites = cipherSuites.orEmpty(),
    finalMask = finalMask.orEmpty(),
    alpn = alpn.orEmpty(),
    echConfigList = echConfigList.orEmpty(),
    echOutbound = echOutbound.orEmpty(),
    allowInsecure = insecure == true && pinnedCA256.isNullOrEmpty(),
    verifyPeerCertByName = verifyPeerCertByName.orEmpty(),
    pinnedPeerCertSha256 = pinnedCA256.orEmpty(),
    flow = flow.orEmpty(),
    realityPublicKey = publicKey.orEmpty(),
    realityShortId = shortId.orEmpty(),
    realitySpiderX = spiderX.orEmpty(),
    realityMldsa65Verify = mldsa65Verify.orEmpty(),
    extra = xhttpExtra.orEmpty(),
    label = remarks,
)

internal fun ShardNode.toShardProfile(): ShardProfile {
    val ct = when (protocol) {
        "vless" -> ShardType.VLESS; "trojan" -> ShardType.TROJAN; "shadowsocks" -> ShardType.SHADOWSOCKS
        "socks" -> ShardType.SOCKS; "hysteria2","hysteria" -> ShardType.HYSTERIA2; else -> ShardType.VLESS
    }
    return ShardProfile.create(ct).apply {
        server = this@toShardProfile.address
        serverPort = this@toShardProfile.port.toString()
        password = this@toShardProfile.credential
        method = if (ct == ShardType.SHADOWSOCKS) this@toShardProfile.credential else "none"
        network = this@toShardProfile.network
        security = this@toShardProfile.security
        path = this@toShardProfile.path
        host = this@toShardProfile.host
        sni = this@toShardProfile.serverName
        fingerPrint = this@toShardProfile.fingerprint
        cipherSuites = this@toShardProfile.cipherSuites
        finalMask = this@toShardProfile.finalMask
        alpn = this@toShardProfile.alpn
        echConfigList = this@toShardProfile.echConfigList
        echOutbound = this@toShardProfile.echOutbound
        insecure = this@toShardProfile.allowInsecure
        verifyPeerCertByName = this@toShardProfile.verifyPeerCertByName
        pinnedCA256 = this@toShardProfile.pinnedPeerCertSha256
        flow = this@toShardProfile.flow
        publicKey = this@toShardProfile.realityPublicKey
        shortId = this@toShardProfile.realityShortId
        spiderX = this@toShardProfile.realitySpiderX
        mldsa65Verify = this@toShardProfile.realityMldsa65Verify
        xhttpExtra = this@toShardProfile.extra
        remarks = this@toShardProfile.label
    }
}
