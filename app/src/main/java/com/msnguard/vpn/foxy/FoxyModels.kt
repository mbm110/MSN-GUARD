package com.msnguard.vpn.foxy

enum class ConnectionState { DISCONNECTED, CONNECTING, CONNECTED }

data class VpnProtocol(
    val name: String,
    val host: String = "",
    val port: Int = 0,
    val scheme: String = "",
    val templateString: String = "",
)

data class VpnServerNode(
    val hostname: String,
    val port: Int = 0,
    val quarantined: Boolean = false,
    val protocols: List<VpnProtocol> = emptyList(),
)

data class VpnCity(
    val name: String,
    val code: String,
    val servers: List<VpnServerNode> = emptyList(),
)

data class VpnCountry(
    val name: String,
    val code: String,
    val cities: List<VpnCity> = emptyList(),
    /** Latest measured TCP connect latency to the best usable server, -1 when unknown. */
    val pingMs: Long = -1L,
) {
    fun displayNameWithPing(): String = if (pingMs > 0) "$name  ${pingMs}ms" else name
}

data class ProxyCandidate(
    val host: String,
    val port: Int,
    val countryCode: String,
    val countryName: String,
    val cityCode: String = "",
) {
    val authority: String get() = "$host:$port"
}

data class Entitlement(
    val subscribed: Boolean,
    val uid: String,
    val maxBytes: Long?,
    val limitedBandwidth: Boolean,
    val quotaRemaining: Long? = null,
)

data class RuntimeAuth(
    val accessToken: String,
    val refreshToken: String?,
    val expiresAtEpochSeconds: Long,
)

fun countryCodeToEmojiFlag(countryCode: String): String {
    if (countryCode.equals("REC", ignoreCase = true) || countryCode.length != 2) return ""
    val upper = countryCode.uppercase()
    val first = upper[0]
    val second = upper[1]
    if (first !in 'A'..'Z' || second !in 'A'..'Z') return ""

    val firstCodePoint = 0x1F1E6 + (first - 'A')
    val secondCodePoint = 0x1F1E6 + (second - 'A')

    return String(Character.toChars(firstCodePoint)) + String(Character.toChars(secondCodePoint))
}

val VpnCountry.emojiFlag: String get() = countryCodeToEmojiFlag(code)
val ProxyCandidate.emojiFlag: String get() = countryCodeToEmojiFlag(countryCode)

