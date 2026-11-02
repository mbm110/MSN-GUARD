package com.msnguard.vpn.foxy

import android.content.Context
import com.msnguard.vpn.foxy.ProxyCandidate
import com.msnguard.vpn.foxy.VpnCity
import com.msnguard.vpn.foxy.VpnCountry
import com.msnguard.vpn.foxy.VpnProtocol
import com.msnguard.vpn.foxy.VpnServerNode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException

private const val TAG = "ServerListClient"
private const val MAX_REMOTE_BYTES = 2 * 1024 * 1024
private const val MAX_CACHE_AGE_MS = 7L * 24 * 60 * 60 * 1000
private const val MAX_COUNTRIES = 256
private const val MAX_CITIES_PER_COUNTRY = 128
private const val MAX_SERVERS_PER_CITY = 256
private const val MAX_PROTOCOLS_PER_SERVER = 32
private val SAFE_HOST = Regex("^[A-Za-z0-9.-]{1,253}$")

private fun readBounded(input: java.io.InputStream, limit: Int): String {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(16 * 1024)
    var total = 0
    while (true) {
        val count = input.read(buffer)
        if (count < 0) break
        total += count
        if (total > limit) throw IOException("Remote Settings response is too large")
        output.write(buffer, 0, count)
    }
    return output.toString(Charsets.UTF_8.name())
}

private fun validHost(host: String): Boolean =
    host.isNotBlank() && SAFE_HOST.matches(host) && !host.startsWith(".") && !host.endsWith(".")

private fun validPort(port: Int): Boolean = port in 1..65535

private fun <T> distinctByStable(values: List<T>, key: (T) -> String): List<T> =
    values.filter { key(it).isNotBlank() }.distinctBy(key)

private fun stableServerKey(server: VpnServerNode): String =
    "${server.hostname.lowercase()}:${server.port}:${server.protocols.joinToString("|") { it.name.lowercase() }}"

private fun stableCountryKey(country: VpnCountry): String = country.code.trim().uppercase()

private const val REMOTE_SETTINGS_URL =
    "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

const val RECOMMENDED_COUNTRY_CODE = "REC"

private val EXCLUDED_COUNTRY_NAMES = setOf("CatchAll Anycast")

class ServerListClient(
    private val context: Context? = null,
    private val client: OkHttpClient = FoxyControlPlaneHttp.client,
) {

    private val cacheFile: File?
        get() = context?.let { File(it.filesDir, "vpn_serverlist_cache.json") }

    suspend fun fetchCountries(): List<VpnCountry> = withContext(Dispatchers.IO) {
        val request = Request.Builder().url(REMOTE_SETTINGS_URL).applyMozillaVpnHeaders().build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IOException("Remote Settings fetch failed: HTTP ${response.code}")
            }
            val body = response.body ?: throw IOException("Remote Settings response has no body")
            val raw = body.byteStream().use { readBounded(it, MAX_REMOTE_BYTES) }
            val countries = parseRecords(raw)
            if (countries.isNotEmpty()) {
                saveCache(raw)
            }
            FoxyLog.i(TAG, "fetched ${countries.size} countries from Remote Settings")
            countries
        }
    }

    fun loadCachedCountries(): List<VpnCountry> {
        val file = cacheFile ?: return emptyList()
        if (!file.exists() || !file.isFile) return emptyList()
        if (System.currentTimeMillis() - file.lastModified() > MAX_CACHE_AGE_MS) return emptyList()
        return runCatching {
            val raw = file.inputStream().use { readBounded(it, MAX_REMOTE_BYTES) }
            val parsed = parseRecords(raw)
            if (parsed.isNotEmpty()) {
                FoxyLog.d(TAG, "loaded ${parsed.size} countries from local cache")
            }
            parsed
        }.getOrElse {
            FoxyLog.w(TAG, "failed to read server list cache", it)
            emptyList()
        }
    }

    private fun saveCache(rawJson: String) {
        val file = cacheFile ?: return
        runCatching {
            val tempFile = File.createTempFile("serverlist", ".tmp", file.parentFile)
            tempFile.writeText(rawJson)
            if (!tempFile.renameTo(file)) {
                tempFile.copyTo(file, overwrite = true)
                tempFile.delete()
            }
            FoxyLog.d(TAG, "updated local server list cache")
        }.onFailure {
            FoxyLog.w(TAG, "failed to save server list cache", it)
        }
    }

    private fun parseRecords(rawJson: String): List<VpnCountry> {
        if (rawJson.isBlank()) return emptyList()
        val body = JSONObject(rawJson)
        val records = body.optJSONArray("data") ?: JSONArray()
        val countries = mutableListOf<VpnCountry>()
        for (i in 0 until minOf(records.length(), MAX_COUNTRIES)) {
            val record = records.optJSONObject(i) ?: continue
            val countryJson = record.optJSONObject("country") ?: record
            val country = parseCountry(countryJson)
            // "Recomended Location" ( Mozilla's own REC pseudo-country, their
            //  spelling ) duplicates our Automatic entry in the chooser — drop it
            //  from the user-facing list; the connect path never selects REC.
            val isExcluded = EXCLUDED_COUNTRY_NAMES.any { it.equals(country.name, ignoreCase = true) } ||
                country.code.equals(RECOMMENDED_COUNTRY_CODE, ignoreCase = true)
            if (country.code.isNotBlank() && country.cities.isNotEmpty() && !isExcluded) {
                countries.add(country)
            }
        }
        return distinctByStable(countries, ::stableCountryKey)
    }

    private fun parseCountry(json: JSONObject): VpnCountry {
        val cities = json.optJSONArray("cities") ?: JSONArray()
        val parsedCities = buildList {
            for (i in 0 until minOf(cities.length(), MAX_CITIES_PER_COUNTRY)) {
                cities.optJSONObject(i)?.let { add(parseCity(it)) }
            }
        }
        return VpnCountry(
            name = json.optString("name").trim(),
            code = json.optString("code").trim().uppercase(),
            cities = distinctByStable(parsedCities) { it.code.uppercase() },
        )
    }

    private fun parseCity(json: JSONObject): VpnCity {
        val servers = json.optJSONArray("servers") ?: JSONArray()
        val parsedServers = buildList {
            for (i in 0 until minOf(servers.length(), MAX_SERVERS_PER_CITY)) {
                servers.optJSONObject(i)?.let { parseServer(it)?.let(::add) }
            }
        }
        return VpnCity(
            name = json.optString("name").trim(),
            code = json.optString("code").trim(),
            servers = distinctByStable(parsedServers, ::stableServerKey),
        )
    }

    private fun parseServer(json: JSONObject): VpnServerNode? {
        val hostname = json.optString("hostname").trim()
        val port = json.optInt("port", 0)
        if (!validHost(hostname) || !validPort(port)) return null
        val protocols = json.optJSONArray("protocols") ?: JSONArray()
        val parsedProtocols = buildList {
            for (i in 0 until minOf(protocols.length(), MAX_PROTOCOLS_PER_SERVER)) {
                protocols.optJSONObject(i)?.let { parseProtocol(it)?.let(::add) }
            }
        }
        return VpnServerNode(
            hostname = hostname,
            port = port,
            quarantined = json.optBoolean("quarantined", false),
            protocols = distinctByStable(parsedProtocols) { "${it.name}:${it.host}:${it.port}" },
        )
    }

    private fun parseProtocol(json: JSONObject): VpnProtocol? {
        val host = json.optString("host").trim()
        val port = json.optInt("port", 0)
        if (host.isNotBlank() && !validHost(host)) return null
        if (port != 0 && !validPort(port)) return null
        return VpnProtocol(
            name = json.optString("name").trim(),
            host = host,
            port = port,
            scheme = json.optString("scheme").trim(),
            templateString = json.optString("templateString"),
        )
    }

    companion object {

        fun defaultConnectTarget(server: VpnServerNode): Pair<String, Int>? {
            for (proto in server.protocols) {
                if (proto.name == "connect") {
                    val host = proto.host.ifBlank { server.hostname }
                    val port = if (proto.port != 0) proto.port else server.port
                    return host to port
                }
            }
            if (server.protocols.isEmpty()) return server.hostname to server.port
            return null
        }

        fun candidatesForCountry(countries: List<VpnCountry>, countryCode: String): List<ProxyCandidate> {
            val out = mutableListOf<ProxyCandidate>()
            for (country in countries) {
                if (!country.code.equals(countryCode, ignoreCase = true)) continue
                for (city in country.cities) {
                    for (server in city.servers) {
                        if (server.quarantined) continue
                        val target = defaultConnectTarget(server) ?: continue
                        out.add(
                            ProxyCandidate(
                                host = target.first,
                                port = target.second,
                                countryCode = country.code,
                                countryName = country.name,
                                cityCode = city.code,
                            ),
                        )
                    }
                }
            }
            return out
        }

        fun candidatesForCity(countries: List<VpnCountry>, countryCode: String, cityCode: String): List<ProxyCandidate> =
            candidatesForCountry(countries, countryCode).filter { it.cityCode.equals(cityCode, ignoreCase = true) }
    }
}
