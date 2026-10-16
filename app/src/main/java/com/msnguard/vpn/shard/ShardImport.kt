package com.msnguard.vpn.shard

/** Batch import — mirrors AngConfigManager.parseBatchConfig order exactly. */
internal object ShardImport {

    fun parseBatch(body: String?): List<ShardProfile> {
        if (body.isNullOrEmpty()) return emptyList()
        // Try decoded then raw — exactly like importBatchConfig
        var list = tryParse(ShardUtils.decode(body))
        if (list.isNotEmpty()) return list
        list = tryParse(body)
        return list
    }

    private fun tryParse(text: String?): List<ShardProfile> {
        if (text.isNullOrEmpty()) return emptyList()
        val profiles = mutableListOf<ShardProfile>()
        val distinctReversed = text.lines().distinct().reversed()
        for (raw in distinctReversed) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            // Skip vmess json lines — not in SHARD pool
            if (line.startsWith("vmess://", ignoreCase = true)) continue // vmess not in SHARD pool
            val p = parseOne(line) ?: continue
            TlsSettingsCheck.fixImportedAlpn(p)
            profiles.add(p)
        }
        return profiles
    }

    fun parseOne(line: String): ShardProfile? = try {
        when {
            line.startsWith(ShardType.VLESS.scheme, ignoreCase = true) -> VlessFmt.parse(line)
            line.startsWith(ShardType.TROJAN.scheme, ignoreCase = true) -> TrojanFmt.parse(line)
            line.startsWith(ShardType.SHADOWSOCKS.scheme, ignoreCase = true) -> ShadowsocksFmt.parse(line)
            line.startsWith("socks://", ignoreCase = true) || line.startsWith("socks5://", ignoreCase = true) -> SocksFmt.parse(line)
            line.startsWith(ShardType.HYSTERIA2.scheme, ignoreCase = true) || line.startsWith("hysteria://", ignoreCase = true) -> Hysteria2Fmt.parse(line)
            line.startsWith(ShardType.WIREGUARD.scheme, ignoreCase = true) -> WireguardFmt.parse(line)
            else -> null
        }
    } catch (_: Exception) { null }
}
