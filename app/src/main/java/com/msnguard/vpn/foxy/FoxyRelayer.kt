package com.msnguard.vpn.foxy

import java.util.Base64
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
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
        var directFailureResponse: Response? = null
        try {
            val directResponse = chain.withConnectTimeout(DIRECT_CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS).proceed(request)
            if (directResponse.isSuccessful || directResponse.code !in config.failoverCodes) {
                return directResponse
            }
            FoxyLog.i("Relayer", "Direct connection returned status ${directResponse.code}, starting relayer failover")
            // Buffer only a bounded error body, then release the connection before retrying.
            directFailureResponse = directResponse.newBuilder()
                .body(directResponse.peekBody(65_536L)).build()
            directResponse.close()
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            FoxyLog.i("Relayer", "Direct connection failed (${e::class.java.simpleName}), starting relayer failover")
            directException = e
        }

        for (relayerUrl in candidates) {
            try {
                FoxyLog.i("Relayer", "Attempting request via configured relayer")
                val relayed = buildRelayedRequest(request, relayerUrl)
                val response = chain.proceed(relayed)
                if (response.code !in config.failoverCodes) {
                    FoxyLog.i("Relayer", "Relayer returned status ${response.code}")
                    directFailureResponse?.close()
                    return response
                }
                FoxyLog.w("Relayer", "Relayer returned failover status ${response.code}")
                response.close()
            } catch (e: Exception) {
                if (e is CancellationException) { directFailureResponse?.close(); throw e }
                FoxyLog.w("Relayer", "Relayer failed (${e::class.java.simpleName})")
            }
        }

        FoxyLog.w("Relayer", "All candidate relayers failed for request")
        if (directFailureResponse != null) {
            return directFailureResponse
        }
        if (directException != null) {
            when (directException) {
                is IOException -> throw directException
                is RuntimeException -> throw directException
                else -> throw IOException(directException)
            }
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
                if (isValidRelayerUrl(trimmed) && !list.contains(trimmed)) list.add(trimmed)
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
        val b64 = Base64.getUrlEncoder().encodeToString(originalUrl.toByteArray(Charsets.UTF_8))
        val rawBase = relayerBaseUrl.trim()
        val base = if (rawBase.startsWith("http://", ignoreCase = true) || rawBase.startsWith("https://", ignoreCase = true)) {
            rawBase
        } else {
            "https://$rawBase"
        }
        val relayerUrl = when {
            base.endsWith("?url=") -> "$base$b64"
            base.endsWith("&url=") -> "$base$b64"
            base.contains("?") -> "${base}&url=$b64"
            else -> "${base.trimEnd('/')}/?url=$b64"
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
                    urlStr == ep.guardian.activate
            "fxa" ->
                urlStr == ep.controlPlane.oauthToken ||
                    urlStr == ep.controlPlane.oauthFallback ||
                    urlStr == ep.controlPlane.authorization ||
                    urlStr == ep.controlPlane.recoveryStatus ||
                    urlStr == ep.controlPlane.sessionDestroy
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
        uri.scheme.equals("https", ignoreCase = true) &&
            !uri.host.isNullOrBlank() &&
            uri.rawUserInfo == null &&
            uri.rawFragment == null &&
            (uri.port == -1 || uri.port in 1..65_535)
    }.getOrDefault(false)

/** Default relayer policy: automatic relayers from the remote config,
 * matching the reference app's out-of-the-box behavior.
 */
internal fun defaultRelayerConfig(): FoxyRelayerConfig? {
    val config = FoxyRemoteConfig.current
    if (config.relayers.isEmpty()) return null
    return FoxyRelayerConfig(
        provider = RELAYER_AUTOMATIC,
        customUrl = "",
        relayedEndpoints = config.relayerRoutes,
        availableRelayers = config.relayers,
        failoverCodes = config.failoverCodes,
    )
}
