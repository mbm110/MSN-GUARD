package com.msnguard.vpn.foxy

import android.util.Base64
import com.msnguard.vpn.foxy.Entitlement
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject

const val GUARDIAN_ENDPOINT_DEFAULT = "https://vpn.mozilla.org"
private const val GUARDIAN_MAX_CHALLENGE_ATTEMPTS = 5

class GuardianHttpError(message: String, val statusCode: Int? = null) : Exception(message)
class QuotaExceededError(message: String) : Exception(message)
class TokenInvalidError(message: String) : Exception(message)

data class ProxyPass(
    val token: String,
    val expiresAtEpochSeconds: Long?,
    val quotaMax: Long? = null,
    val quotaRemaining: Long? = null,
    val quotaReset: Long? = null,
)

class GuardianClient(
    private val challengeSolver: FastlyChallengeSolver = FastlyChallengeSolver(FoxyControlPlaneHttp.cookieJar),
) {

    suspend fun fetchProxyPass(endpoint: String, accessToken: String): ProxyPass = withContext(Dispatchers.IO) {
        val url = "${endpoint.trimEnd('/')}/api/v1/fpn/token"
        authorizedRequest("GET", url, accessToken).use { resp ->
            when (resp.code) {
                401, 403 -> throw TokenInvalidError("access token was rejected by Guardian")
                429 -> throw QuotaExceededError("account proxy quota exceeded")
            }
            val text = resp.body?.string().orEmpty()
            if (resp.code != 200) {
                throw GuardianHttpError("failed to fetch proxy pass: HTTP ${resp.code}: ${text.take(2048)}", resp.code)
            }
            val body = JSONObject(text)
            val token = body.optString("token", "")
            if (token.isEmpty()) throw GuardianHttpError("proxy pass response did not contain a token")
            ProxyPass(
                token = token,
                expiresAtEpochSeconds = body.optLong("expires_at", 0L).takeIf { it > 0 }
                    ?: jwtExpiryEpochSeconds(token),
                quotaMax = resp.header("X-Quota-Limit")?.toLongOrNull(),
                quotaRemaining = resp.header("X-Quota-Remaining")?.toLongOrNull(),
                quotaReset = resp.header("X-Quota-Reset")?.toLongOrNull(),
            )
        }
    }

    suspend fun fetchUserInfo(endpoint: String, accessToken: String): Entitlement = withContext(Dispatchers.IO) {
        val url = "${endpoint.trimEnd('/')}/api/v1/fpn/status"
        val entitlement = authorizedRequest("GET", url, accessToken).use { resp ->
            val text = resp.body?.string().orEmpty()
            if (resp.code != 200) {
                throw GuardianHttpError("failed to fetch account info: HTTP ${resp.code}: ${text.take(2048)}", resp.code)
            }
            parseEntitlement(JSONObject(text))
        }

        if (entitlement.limitedBandwidth) {
            val pass = runCatching { fetchProxyPass(endpoint, accessToken) }.getOrNull()
            entitlement.copy(quotaRemaining = pass?.quotaRemaining ?: entitlement.quotaRemaining)
        } else {
            entitlement
        }
    }

    suspend fun activateGuardian(endpoint: String, accessToken: String): Entitlement = withContext(Dispatchers.IO) {
        val url = "${endpoint.trimEnd('/')}/api/v1/fpn/activate"
        authorizedRequest("POST", url, accessToken).use { resp ->
            val text = resp.body?.string().orEmpty()
            if (resp.code != 200) {
                throw GuardianHttpError("failed to activate guardian entitlement: HTTP ${resp.code}: ${text.take(2048)}", resp.code)
            }
            parseEntitlement(JSONObject(text))
        }
    }

    private fun parseEntitlement(body: JSONObject): Entitlement = Entitlement(
        subscribed = body.optBoolean("subscribed", false),
        uid = body.optString("uid", ""),

        maxBytes = if (body.has("maxBytes") && !body.isNull("maxBytes")) {
            body.optLong("maxBytes", -1L).takeIf { it >= 0 }
        } else {
            null
        },
        limitedBandwidth = body.optBoolean("limited_bandwidth", false),
    )

    private suspend fun authorizedRequest(method: String, url: String, accessToken: String): Response {
        fun buildRequest(): Request {
            val builder = Request.Builder().url(url).applyMozillaVpnHeaders()
            builder.header("Content-Type", "application/json")
            builder.header("Authorization", "Bearer $accessToken")
            if (method == "POST") builder.post(ByteArray(0).toRequestBody(null))
            return builder.build()
        }
        var response = FoxyControlPlaneHttp.client.newCall(buildRequest()).execute()
        var attempts = 1
        while (response.code == 406 && attempts < GUARDIAN_MAX_CHALLENGE_ATTEMPTS) {
            val challengedBody = response.use { it.body?.string().orEmpty() }
            challengeSolver.solveAndInstall(challengedBody, url.substringBefore("/api/").trimEnd('/'), MOZILLA_VPN_USER_AGENT)
            response = FoxyControlPlaneHttp.client.newCall(buildRequest()).execute()
            attempts++
        }
        return response
    }
}

internal fun jwtExpiryEpochSeconds(token: String): Long? {
    val parts = token.split('.')
    if (parts.size < 2) return null
    val payload = runCatching {
        var b64 = parts[1]
        while (b64.length % 4 != 0) b64 += "="
        String(
            android.util.Base64.decode(b64, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP),
            Charsets.UTF_8,
        )
    }.getOrNull() ?: return null
    return runCatching { JSONObject(payload).optLong("exp", 0L) }.getOrNull()?.takeIf { it > 0 }
}
