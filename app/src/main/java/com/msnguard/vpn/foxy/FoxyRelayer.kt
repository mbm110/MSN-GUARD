package com.msnguard.vpn.foxy

import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response

/** Relayer failover ported from the reference FoxyVPN 2.0.3 data layer.
 * Direct connection is always attempted first; when the network fails or the
 * endpoint answers with a failover code (HTTP 451 for sanctioned regions),
 * the request is retried through the relayers published in FoxyRemoteConfig.
 */
data class FoxyRelayerConfig(
    val provider: String,
    val customUrl: String,
    val relayedEndpoints: Set<String>,
    val availableRelayers: Map<String, String>,
    val failoverCodes: Set<Int> = DEFAULT_FAILOVER_CODES,
)

const val RELAYER_AUTOMATIC = "AUTOMATIC"
const val RELAYER_DIRECT = "DIRECT"
const val RELAYER_CUSTOM = "CUSTOM"

private const val DIRECT_CONNECT_TIMEOUT_SECONDS = 5

internal class FoxyRelayerInterceptor(
    private val configProvider: () -> FoxyRelayerConfig?,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val config = configProvider() ?: return chain.proceed(chain.request())
        if (config.provider == RELAYER_DIRECT) {
            return chain.proceed(chain.request())
        }

        val request = chain.request()
        if (request.body?.isOneShot() == true) {
            return chain.proceed(request)
        }

        val urlStr = request.url.toString()
        val shouldRelay = config.relayedEndpoints.any { matchesCategory(urlStr, it) }
        if (!shouldRelay) {
            return chain.proceed(request)
        }

        val candidates = getCandidateRelayers(config)
        if (candidates.isEmpty()) {
            return chain.proceed(request)
        }

        var directException: Exception? = null
        var directFailoverCode: Int? = null
        try {
            val directResponse = chain.withConnectTimeout(DIRECT_CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS).proceed(request)
            if (directResponse.isSuccessful || directResponse.code !in config.failoverCodes) {
                return directResponse
            }
            FoxyLog.i("Relayer", "Direct connection returned status ${directResponse.code}, starting relayer failover")
            directFailoverCode = directResponse.code
            directResponse.close()
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            FoxyLog.i("Relayer", "Direct connection failed (${e.message ?: e::class.java.simpleName}), starting relayer failover")
            directException = e
        }

        for (relayerUrl in candidates) {
            try {
                FoxyLog.i("Relayer", "Attempting request via $relayerUrl")
                val relayed = buildRelayedRequest(request, relayerUrl)
                val response = chain.proceed(relayed)
                val relayError = response.header("X-Relay-Error")
                if (relayError != null) {
                    FoxyLog.w("Relayer", "Relayer $relayerUrl refused: $relayError")
                    response.close()
                    continue
                }
                if (response.code !in config.failoverCodes) {
                    FoxyLog.i("Relayer", "Request succeeded via $relayerUrl (status ${response.code})")
                    return response
                }
                FoxyLog.w("Relayer", "Relayer $relayerUrl returned failover status ${response.code}")
                response.close()
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                FoxyLog.w("Relayer", "Relayer $relayerUrl failed (${e.message ?: e::class.java.simpleName})")
            }
        }

        FoxyLog.w("Relayer", "All candidate relayers failed for request")
        if (directException != null) {
            when (directException) {
                is IOException -> throw directException
                is RuntimeException -> throw directException
                else -> throw IOException(directException)
            }
        }
        if (directFailoverCode != null) {
            throw IOException("Direct request failed with HTTP $directFailoverCode and all candidate relayers failed")
        }
        return chain.proceed(request)
    }

    private fun getCandidateRelayers(config: FoxyRelayerConfig): List<String> {
        val provider = config.provider.trim()

        if (provider.equals(RELAYER_CUSTOM, ignoreCase = true)) {
            val custom = config.customUrl.trim()
            return if (custom.isNotBlank() && isValidRelayerUrl(custom)) {
                listOf(custom)
            } else {
                emptyList()
            }
        }

        if (provider.equals(RELAYER_AUTOMATIC, ignoreCase = true)) {
            val list = mutableListOf<String>()
            config.availableRelayers.values.forEach { url ->
                val trimmed = url.trim()
                if (trimmed.isNotBlank() && !list.contains(trimmed)) list.add(trimmed)
            }
            return list
        }

        val match = config.availableRelayers.entries.firstOrNull {
            it.key.equals(provider, ignoreCase = true)
        }
        if (match != null && match.value.isNotBlank()) {
            return listOf(match.value.trim())
        } else if (isValidRelayerUrl(provider)) {
            return listOf(provider)
        }

        return emptyList()
    }

    private fun buildRelayedRequest(originalRequest: Request, relayerBaseUrl: String): Request {
        val originalUrl = originalRequest.url.toString()
        val rawBase = relayerBaseUrl.trim()
        val base = if (rawBase.startsWith("http://", ignoreCase = true) || rawBase.startsWith("https://", ignoreCase = true)) {
            rawBase
        } else {
            "https://$rawBase"
        }
        val targetHttpUrl = base.toHttpUrlOrNull()
        val relayerUrl: String = if (targetHttpUrl != null) {
            targetHttpUrl.newBuilder()
                .setQueryParameter("url", originalUrl)
                .build()
                .toString()
        } else {
            val sep = if (base.contains("?")) "&" else "?"
            val encoded = java.net.URLEncoder.encode(originalUrl, "UTF-8")
            "$base${sep}url=$encoded"
        }
        return originalRequest.newBuilder()
            .url(relayerUrl)
            .build()
    }

    private fun matchesCategory(urlStr: String, category: String): Boolean {
        val ep = FoxyRemoteConfig.current.endpoints
        return when (category) {
            "guardian" ->
                urlStr == ep.guardian.token ||
                    urlStr == ep.guardian.status ||
                    urlStr == ep.guardian.activate ||
                    urlStr.contains("/api/v1/fpn/")
            "fxa" ->
                urlStr == ep.controlPlane.oauthToken ||
                    urlStr == ep.controlPlane.oauthFallback ||
                    urlStr == ep.controlPlane.authorization ||
                    urlStr == ep.controlPlane.recoveryStatus ||
                    urlStr == ep.controlPlane.sessionDestroy ||
                    urlStr.contains("accounts.firefox.com")
            "config" ->
                urlStr.contains("FoxyConfig") || urlStr.contains("foxy_config")
            "server_list" ->
                urlStr == ep.serverList || urlStr.contains("vpn-serverlist")
            else -> false
        }
    }
}

internal fun isValidRelayerUrl(value: String): Boolean =
    runCatching {
        val trimmed = value.trim()
        val normalized = if (trimmed.startsWith("http://", ignoreCase = true) || trimmed.startsWith("https://", ignoreCase = true)) {
            trimmed
        } else {
            "https://$trimmed"
        }
        val uri = java.net.URI(normalized)
        (uri.scheme.equals("https", ignoreCase = true) || uri.scheme.equals("http", ignoreCase = true)) &&
            !uri.host.isNullOrBlank() &&
            uri.rawUserInfo == null &&
            uri.rawFragment == null &&
            (uri.port == -1 || uri.port in 1..65_535)
    }.getOrDefault(false)

/** Default relayer policy: the user's provider choice from FoxySettings with
 * the relayer list, routes and failover codes from the remote config. Falls
 * back to AUTOMATIC (reference out-of-the-box behavior) until the app
 * context is captured.
 */
internal fun defaultRelayerConfig(): FoxyRelayerConfig? {
    val config = FoxyRemoteConfig.current
    val provider = FoxySettings.relayerProviderOrNull() ?: RELAYER_AUTOMATIC
    if (provider.equals(RELAYER_AUTOMATIC, ignoreCase = true) && config.relayers.isEmpty()) return null
    return FoxyRelayerConfig(
        provider = provider,
        customUrl = FoxySettings.customRelayerUrlOrNull(),
        relayedEndpoints = config.relayerRoutes,
        availableRelayers = config.relayers,
        failoverCodes = config.failoverCodes,
    )
}
