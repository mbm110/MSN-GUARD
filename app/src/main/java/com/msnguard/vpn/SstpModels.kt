package com.msnguard.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

data class SstpServer(val host: String, val port: Int = 443, val country: String = "", val sources: Set<String> = emptySet(), val latencyMs: Long? = null) {
    val key get() = "${host.lowercase()}:$port"
    fun json() = JSONObject().apply { put("host", host); put("port", port); put("country", country); put("sources", JSONArray(sources.toList())); latencyMs?.let { put("latency", it) } }
    companion object { fun from(o: JSONObject) = SstpServer(o.optString("host"), o.optInt("port", 443), o.optString("country"), emptySet(), o.optLong("latency", -1).takeIf { it >= 0 }) }
}

object SstpServerRepository {
    private const val PREF = "sstp_servers_json"
    private const val MAX_BODY = 2_000_000
    private val SOURCES = listOf(
        "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/sstp-configs/sstp_with_country.txt" to "F0rc3Run",
        "https://www.vpngate.net/api/iphone/" to "VPN Gate",
        "https://omgvpn.com/" to "OMGVPN",
        "http://v-dot-pn-ams2.opengw.net:34637/en/" to "OpenGW",
    )
    fun cached(context: Context): List<SstpServer> = runCatching { val a = JSONArray(context.profiled().getString(PREF, "[]")); (0 until a.length()).map { SstpServer.from(a.getJSONObject(it)) } }.getOrDefault(emptyList())
    suspend fun refresh(context: Context): List<SstpServer> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val all = SOURCES.flatMap { fetch(it.first, it.second) }
        val unique = all.groupBy { it.key }.map { (_, values) -> values.first().copy(sources = values.flatMap { it.sources }.toSet()) }
        if (unique.isNotEmpty()) context.profiled().edit().putString(PREF, JSONArray(unique.map { it.json() }).toString()).apply()
        unique.ifEmpty { cached(context) }
    }
    private fun fetch(url: String, source: String): List<SstpServer> = runCatching {
        val c = java.net.URL(url).openConnection() as java.net.HttpURLConnection; c.connectTimeout = 8000; c.readTimeout = 8000
        val body = c.inputStream.bufferedReader().use { it.readText().take(MAX_BODY) }
        Regex("(?i)([a-z0-9][a-z0-9.-]{2,252})[:;, ](443|8443|34637)").findAll(body).map { SstpServer(it.groupValues[1], it.groupValues[2].toInt(), sources = setOf(source)) }.toList()
    }.getOrDefault(emptyList())
}
