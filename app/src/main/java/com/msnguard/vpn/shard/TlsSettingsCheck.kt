package com.msnguard.vpn.shard

/** Mirrors TlsSettingsCheck exactly. */
internal object TlsSettingsCheck {
    const val UNSAFE_FINGERPRINT = "unsafe"
    private const val HTTP1 = "http/1.1"

    fun fixImportedAlpn(p: ShardProfile) {
        if (!appliesTo(p)) return
        if (!isUpgrade(p)) return
        if (isHttp1OrNone(p.alpn)) return
        p.alpn = HTTP1
    }

    private fun appliesTo(p: ShardProfile): Boolean {
        if (p.security != "tls") return false
        return p.configType == ShardType.VLESS || p.configType == ShardType.TROJAN ||
               p.configType == ShardType.SHADOWSOCKS
    }

    private fun isUpgrade(p: ShardProfile): Boolean =
        p.network == ShardNetwork.WS || p.network == ShardNetwork.HTTP_UPGRADE

    private fun isHttp1OrNone(alpn: String?): Boolean {
        val parts = alpnProtocols(alpn)
        return parts.isEmpty() || parts == listOf(HTTP1)
    }

    private fun alpnProtocols(alpn: String?): List<String> =
        alpn?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()
}
