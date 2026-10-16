package com.msnguard.vpn.shard

import android.util.Base64
import java.net.IDN
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Locale
import java.util.UUID

internal object ShardUtils {
    fun decode(text: String?): String = tryDecodeBase64(text) ?: text?.trimEnd('=')?.let { tryDecodeBase64(it) }.orEmpty()

    private fun tryDecodeBase64(text: String?): String? {
        if (text.isNullOrEmpty()) return null
        try { return Base64.decode(text, Base64.NO_WRAP).toString(Charsets.UTF_8) } catch (_: Exception) {}
        try { return Base64.decode(text, Base64.NO_WRAP or Base64.URL_SAFE).toString(Charsets.UTF_8) } catch (_: Exception) {}
        return null
    }

    fun encode(text: String, removePadding: Boolean = false): String = try {
        var e = Base64.encodeToString(text.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        if (removePadding) e = e.trimEnd('=')
        e
    } catch (_: Exception) { "" }

    fun decodeURIComponent(url: String): String = try {
        URLDecoder.decode(url.replace("+", "%2B"), Charsets.UTF_8.toString())
    } catch (_: Exception) { url }

    fun encodeURIComponent(url: String): String = try {
        URLEncoder.encode(url, Charsets.UTF_8.toString()).replace("+", "%20")
    } catch (_: Exception) { url }

    fun fixIllegalUrl(str: String): String = str.replace(" ", "%20").replace("|", "%7C")

    fun getIpv6Address(address: String?): String {
        if (address.isNullOrEmpty()) return ""
        return if (address.contains(":") && !address.contains("[") && !address.contains("]")) "[$address]" else address
    }

    fun isPureIpAddress(value: String): Boolean {
        if (value.isEmpty()) return false
        val v = value.removeSurrounding("[", "]")
        return v.matches(Regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}$")) ||
            v.contains(":") && v.matches(Regex("^[0-9a-fA-F:]+$"))
    }

    fun isDomainName(input: String?): Boolean {
        if (input.isNullOrEmpty()) return false
        if (isPureIpAddress(input)) return false
        return input.contains(".") && !input.contains(" ") && !input.contains("/")
    }

    fun isValidUrl(url: String?): Boolean {
        if (url.isNullOrEmpty()) return false
        return try { URI(url); true } catch (_: Exception) { false }
    }

    fun toIdnDomain(domain: String): String = try { IDN.toASCII(domain) } catch (_: Exception) { domain }

    fun idnHost(uri: URI): String = uri.host?.removeSurrounding("[", "]").orEmpty()

    fun getUuid(): String = try { UUID.randomUUID().toString().replace("-", "") } catch (_: Exception) { "" }
}

internal fun String?.nullIfBlank(): String? = if (this.isNullOrBlank()) null else this
internal fun String?.isNotNullEmpty(): Boolean = !this.isNullOrEmpty()
