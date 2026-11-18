package com.msnguard.vpn.foxy

import android.util.Base64
import com.msnguard.vpn.ConnectionLog
import com.msnguard.vpn.foxy.RuntimeAuth
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val TAG = "FxaAuthRepository"

enum class SessionStatus {
    ACTIVE,
    NEEDS_LOGIN,
    UNREACHABLE,
}

class FastlyBlockedException(cause: Throwable? = null) : Exception("Firefox Accounts challenge could not be completed", cause)

class FxaApiError(message: String, val errno: Int?, val statusCode: Int?) : Exception(message)

val FxaApiError.isUnconfirmedSession: Boolean
    get() =
        errno == 104 ||
            errno == 138 ||
            ((statusCode == 400 || statusCode == 401) &&
                (message?.contains("unconfirmed", ignoreCase = true) == true ||
                    message?.contains("unverified", ignoreCase = true) == true))

fun Throwable.isUnconfirmedSession(): Boolean =
    (this as? FxaApiError)?.isUnconfirmedSession == true ||
        message?.contains("unconfirmed", ignoreCase = true) == true ||
        message?.contains("unverified", ignoreCase = true) == true

class FxaRefreshFailure(
    message: String,
    val permanent: Boolean,
    cause: Throwable? = null,
) : Exception(message, cause)

private const val FIREFOX_CLIENT_ID = "5882386c6d801776"
private const val OAUTH_SCOPE = "profile https://identity.mozilla.com/apps/vpn"
private const val PROTOCOL_VERSION = "identity.mozilla.com/picl/v1/"
private const val PBKDF2_ROUNDS = 1000
private const val STRETCHED_PW_LEN = 32
private const val HKDF_LEN = 32
private const val VERIFICATION_METHOD_EMAIL_2FA = "email-2fa"
private const val FXA_ERRNO_INVALID_PARAMETER = 107
private const val FXA_MAX_CHALLENGE_ATTEMPTS = 5
private const val DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60
private const val MAX_CONFIRM_ATTEMPTS = 100
private const val CONFIRM_POLL_DELAY_MS = 3000L

private val jsonMediaType = "application/json".toMediaType()

class FxaAuthRepository(
    private val tokenStore: FxoTokenStore,
    private val challengeSolver: FastlyChallengeSolver = FastlyChallengeSolver(FoxyControlPlaneHttp.cookieJar),
) {
    var pendingSessionToken: String?
        get() = tokenStore.pendingSessionToken
        set(value) { tokenStore.pendingSessionToken = value }

    fun clearPendingSession() {
        tokenStore.pendingSessionToken = null
    }

    /** URL opened in the in-app Firefox Accounts sign-in page. */
    fun browserLoginUrl(): String =
        FoxyRemoteConfig.current.endpoints.controlPlane.login

    suspend fun completeBrowserLogin(sessionToken: String): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                val clean = sessionToken.trim().replace(Regex("[\\s\\\"]"), "").lowercase()
                require(Regex("^[0-9a-f]{64}$").matches(clean)) { "Invalid Firefox session token" }
                FirefoxAccountHeaders.refresh(FoxyControlPlaneHttp.client)
                completeLogin(clean)
            }
        }

    private suspend fun isSessionVerified(sessionToken: String): Boolean = withContext(Dispatchers.IO) {
        val clean = sessionToken.trim().replace(Regex("[\\s\\\"]"), "").lowercase()
        if (!Regex("^[0-9a-f]{64}$").matches(clean)) return@withContext false
        val url = FoxyRemoteConfig.current.endpoints.controlPlane.recoveryStatus.toHttpUrl()
        val (id, key) = deriveHawkCredentials(clean)
        val request = FirefoxAccountHeaders.apply(Request.Builder().url(url))
            .header("Authorization", hawkHeader("GET", url, id, key, ByteArray(0)))
            .get()
            .build()
        runCatching {
            FoxyControlPlaneHttp.client.newCall(request).execute().use { response ->
                response.code == 200 &&
                    response.body?.string()?.let { body ->
                        JSONObject(body).optBoolean("verified", false)
                    } == true
            }
        }.getOrDefault(false)
    }

    /** Legacy request helper retained for tests and non-UI callers. */
    fun browserOAuthRequest(sessionToken: String): Pair<String, String> {
        val clean = sessionToken.trim().lowercase()
        require(Regex("^[0-9a-f]{64}$").matches(clean)) { "Invalid Firefox session token" }
        val url = FoxyRemoteConfig.current.endpoints.controlPlane.oauthToken.toHttpUrl()
        val body = JSONObject().apply {
            put("client_id", FIREFOX_CLIENT_ID)
            put("grant_type", "fxa-credentials")
            put("scope", OAUTH_SCOPE)
            put("access_type", "offline")
        }.toString()
        val (id, key) = deriveHawkCredentials(clean)
        return hawkHeader("POST", url, id, key, body.toByteArray(Charsets.UTF_8)) to body
    }

    suspend fun completeBrowserSession(sessionToken: String): Result<Unit> = runCatching {
        FoxyControlPlaneHttp.cookieJar.syncFromWebView()
        val tokenData = oauthToken(sessionToken.trim().lowercase())
        tokenStore.saveAuth(RuntimeAuth(
            accessToken = tokenData.getString("access_token"),
            refreshToken = tokenData.optString("refresh_token", "").ifBlank { null },
            expiresAtEpochSeconds = expiryFrom(tokenData),
        ))
    }

    companion object {
        fun normalizeEmail(email: String): String =
            email.replace(Regex("[\\p{Z}\\u200B-\\u200D\\uFEFF\\u00A0\\s]+"), "").trim().lowercase()

        fun sanitizeCode(code: String): String =
            code.replace(Regex("[\\p{Z}\\u200B-\\u200D\\uFEFF\\u00A0\\s]+"), "").trim()
    }

    suspend fun startLogin(email: String, password: String): Result<Boolean> = runCatching {
        val cleanEmail = normalizeEmail(email)
        val data = loginAttempt(cleanEmail, password)
        val sessionToken = data.getString("sessionToken")
        pendingSessionToken = sessionToken
        val verified = data.optBoolean("verified", false)
        if (!verified) {
            true
        } else {
            completeLogin(sessionToken)
            clearPendingSession()
            false
        }
    }

    suspend fun submitTwoFactorCode(code: String): Result<Boolean> = runCatching {
        val cleanCode = sanitizeCode(code)
        val sessionToken = pendingSessionToken ?: error("No pending FxA session. Start sign-in again.")
        fxaDo("POST", "/session/verify_code", sessionToken = sessionToken, jsonBody = JSONObject().put("code", cleanCode))
        completeLogin(sessionToken)
        clearPendingSession()
        false
    }

    suspend fun restoreSession(): SessionStatus {
        val stored = runCatching { tokenStore.loadAuth() }.getOrNull()
            ?: return SessionStatus.NEEDS_LOGIN
        if (stored.refreshToken == null && !tokenStore.hasValidAccessToken()) {
            runCatching { tokenStore.clear() }
            return SessionStatus.NEEDS_LOGIN
        }
        if (tokenStore.hasValidAccessToken()) return SessionStatus.ACTIVE

        return try {
            ensureFreshAccessToken()
            SessionStatus.ACTIVE
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: FxaRefreshFailure) {
            if (failure.permanent) {
                FoxyLog.w(TAG, "FxA rejected the stored session; signing out", failure)
                runCatching { tokenStore.clear() }
                SessionStatus.NEEDS_LOGIN
            } else {
                FoxyLog.w(TAG, "could not renew the session right now; staying signed in", failure)
                SessionStatus.UNREACHABLE
            }
        } catch (unexpected: Exception) {
            FoxyLog.w(TAG, "unexpected error while restoring the session", unexpected)
            SessionStatus.UNREACHABLE
        }
    }

    suspend fun ensureFreshAccessToken(force: Boolean = false): RuntimeAuth {
        val current = tokenStore.loadAuth()
            ?: throw FxaRefreshFailure("Not signed in", permanent = true)
        if (!force && tokenStore.hasValidAccessToken()) return current

        val refreshToken = current.refreshToken
            ?: throw FxaRefreshFailure(
                "The stored session has no refresh token; sign in again.",
                permanent = true,
            )

        val body = JSONObject().apply {
            put("client_id", FIREFOX_CLIENT_ID)
            put("grant_type", "refresh_token")
            put("refresh_token", refreshToken)
            put("scope", OAUTH_SCOPE)
        }

        val tokenData = try {
            try {
                FirefoxAccountHeaders.refresh(FoxyControlPlaneHttp.client)
                val primaryUrl = FoxyRemoteConfig.current.endpoints.controlPlane.oauthToken
                executeFxaRequest(
                    fullUrl = primaryUrl,
                    jsonBody = body,
                    fallbackUrl = resolveOAuthFallback(primaryUrl),
                    isOAuth = true,
                )
            } catch (_: FastlyBlockedException) {
                val primaryUrl = FoxyRemoteConfig.current.endpoints.controlPlane.oauthToken
                executeFxaRequest(
                    fullUrl = FoxyRemoteConfig.current.endpoints.controlPlane.oauthFallback,
                    jsonBody = body,
                    fallbackUrl = resolveOAuthFallback(primaryUrl),
                    isOAuth = true,
                )
            }
        } catch (rejected: FxaApiError) {
            val permanent = rejected.isPermanentRefreshRejection()
            if (permanent) {
                // The refresh token is dead for good (errno 108 / invalid_grant):
                // every future Foxy connect would fail in mintPass while the UI
                // kept claiming "signed in", and the watchdog re-queried FxA every
                // few seconds forever. Clear the store so signInStatus() flips to
                // null, the UI shows signed-out, and the connect gate sends the
                // user back to the sign-in page (v3.2.27 audit).
                tokenStore.clearSession()
                ConnectionLog.record("Foxy: refresh token permanently rejected — signed out (sign in again)")
                FoxyLog.w(TAG, "refresh token permanently rejected; local session cleared", rejected)
            }
            throw FxaRefreshFailure(
                rejected.message ?: "FxA rejected the refresh token",
                permanent = permanent,
                cause = rejected,
            )
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (transport: Exception) {
            throw FxaRefreshFailure(
                transport.message ?: "Could not reach the Firefox Accounts server",
                permanent = false,
                cause = transport,
            )
        }

        val accessToken = tokenData.optString("access_token").takeIf { it.isNotBlank() }
            ?: throw FxaRefreshFailure(
                "FxA returned no access token for the refresh grant",
                permanent = false,
            )

        val renewed = RuntimeAuth(
            accessToken = accessToken,
            refreshToken = tokenData.optString("refresh_token", "").ifBlank { null } ?: refreshToken,
            expiresAtEpochSeconds = expiryFrom(tokenData),
        )
        runCatching { tokenStore.saveAuth(renewed) }
            .onFailure { FoxyLog.w(TAG, "could not persist the renewed token", it) }
        return renewed
    }

    suspend fun currentAccessToken(): String? = try {
        ensureFreshAccessToken().accessToken
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (failure: FxaRefreshFailure) {
        if (failure.permanent) null else tokenStore.loadAuth()?.accessToken
    }

    suspend fun refreshAccessToken(): RuntimeAuth? = try {
        ensureFreshAccessToken(force = true)
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (failure: FxaRefreshFailure) {
        FoxyLog.w(TAG, "access token renewal failed", failure)
        null
    }

    private fun FxaApiError.isPermanentRefreshRejection(): Boolean {
        return errno == 108 || (statusCode == 400 && (
            message?.contains("invalid_grant", ignoreCase = true) == true ||
                message?.contains("invalid token", ignoreCase = true) == true
        ))
    }

    /** Pick the OAuth fallback URL: the configured one when it differs from
     *  the primary, otherwise the mirror host (reference v2.0.4). */
    private fun resolveOAuthFallback(primaryUrl: String): String {
        val configured = FoxyRemoteConfig.current.endpoints.controlPlane.oauthFallback
        return if (configured != primaryUrl) configured
        else if (primaryUrl.contains("oauth.accounts.firefox.com")) "https://api.accounts.firefox.com/v1/oauth/token"
        else "https://oauth.accounts.firefox.com/v1/token"
    }

    private fun expiryFrom(tokenData: JSONObject): Long {
        val expiresIn = tokenData.optInt("expires_in", 0)
            .takeIf { it > 0 } ?: DEFAULT_ACCESS_TOKEN_TTL_SECONDS
        return System.currentTimeMillis() / 1000 + expiresIn
    }

    private suspend fun completeLogin(sessionToken: String) {
        var confirmed = false
        for (attempt in 0 until MAX_CONFIRM_ATTEMPTS) {
            coroutineContext.ensureActive()
            if (isSessionVerified(sessionToken)) { confirmed = true; break }
            delay(CONFIRM_POLL_DELAY_MS)
        }
        check(confirmed) { "Firefox account session is not verified yet" }
        var tokenData: JSONObject? = null
        var lastError: Throwable? = null
        try {
            tokenData = exchangeSessionDirect(sessionToken)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            tokenData = null
        }
        if (tokenData == null) {
            for (attempt in 0 until 10) {
                coroutineContext.ensureActive()
                try {
                    tokenData = exchangeSessionWithOAuthCode(sessionToken)
                    break
                } catch (cancellation: CancellationException) {
                    throw cancellation
                } catch (e: Exception) {
                    lastError = e
                    if (e.isUnconfirmedSession() && attempt < 9) {
                        delay(CONFIRM_POLL_DELAY_MS)
                        continue
                    }
                    throw e
                }
            }
        }
        val data = tokenData ?: throw (lastError ?: FxaApiError("Sign-in failed", null, 500))
        coroutineContext.ensureActive()
        val accessToken = data.optString("access_token").takeIf { it.isNotBlank() }
            ?: error("Firefox Accounts returned no access token")
        val refreshToken = data.optString("refresh_token", "").ifBlank { null }
        tokenStore.saveAuth(
            RuntimeAuth(
                accessToken = accessToken,
                refreshToken = refreshToken,
                expiresAtEpochSeconds = expiryFrom(data),
            ),
        )
        clearPendingSession()
        // NonCancellable: cancellation landing exactly between saveAuth and the
        // server-side session destroy (user hit Back at that instant) used to
        // leave the FxA session alive on Mozilla's servers with the user never
        // shown as signed in (v3.2.27 audit). The tokens are already saved —
        // the destroy MUST run.
        withContext(kotlinx.coroutines.NonCancellable) {
            destroySession(sessionToken)
        }
    }

    /** Straight fxa-credentials grant against the OAuth token endpoint —
     *  tried before the authorization-code path (reference v2.0.4). */
    private suspend fun exchangeSessionDirect(sessionToken: String): JSONObject = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("client_id", FIREFOX_CLIENT_ID)
            put("grant_type", "fxa-credentials")
            put("scope", OAUTH_SCOPE)
            put("access_type", "offline")
        }
        val primaryUrl = FoxyRemoteConfig.current.endpoints.controlPlane.oauthToken
        val tokens = executeFxaRequest(
            fullUrl = primaryUrl,
            jsonBody = body,
            sessionToken = sessionToken,
            fallbackUrl = resolveOAuthFallback(primaryUrl),
            isOAuth = true,
        )
        if (tokens.optString("access_token").isBlank()) {
            throw FxaApiError("Direct token response is missing access token", null, 500)
        }
        tokens
    }

    /** Destroy the FxA session behind the handed-over token; any non-
     *  cancellation error is swallowed (reference v2.0.4). */
    suspend fun destroySession(sessionToken: String) = withContext(Dispatchers.IO) {
        val clean = sessionToken.trim().replace(Regex("[\\s\\\"]"), "").lowercase()
        if (!Regex("^[0-9a-f]{64}$").matches(clean)) return@withContext
        val url = FoxyRemoteConfig.current.endpoints.controlPlane.sessionDestroy.toHttpUrl()
        val (tokenId, hmacKey) = deriveHawkCredentials(clean)
        val bodyBytes = "{}".toByteArray(Charsets.UTF_8)
        val header = hawkHeader("POST", url, tokenId, hmacKey, bodyBytes)
        val request = FirefoxAccountHeaders.apply(Request.Builder().url(url))
            .header("Content-Type", "application/json")
            .header("Authorization", header)
            .post("{}".toRequestBody(jsonMediaType))
            .build()
        try {
            FoxyControlPlaneHttp.client.newCall(request).execute().use { }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
        }
    }

    private suspend fun exchangeSessionWithOAuthCode(sessionToken: String): JSONObject = withContext(Dispatchers.IO) {
        val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val verifier = Base64.encodeToString(secret, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        val challenge = Base64.encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
        val stateBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val state = Base64.encodeToString(stateBytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        val authorization = JSONObject().apply {
            put("client_id", FIREFOX_CLIENT_ID)
            put("response_type", "code")
            put("scope", OAUTH_SCOPE)
            put("state", state)
            put("access_type", "offline")
            put("code_challenge", challenge)
            put("code_challenge_method", "S256")
        }
        val authResponse = executeFxaRequest(
            fullUrl = FoxyRemoteConfig.current.endpoints.controlPlane.authorization,
            jsonBody = authorization,
            sessionToken = sessionToken,
            isOAuth = true,
        )
        val code = authResponse.optString("code", "")
        val returnedState = authResponse.optString("state", "")
        check(code.isNotBlank() && returnedState == state) { "Invalid Firefox OAuth authorization response" }
        val tokenBody = JSONObject().apply {
            put("client_id", FIREFOX_CLIENT_ID)
            put("grant_type", "authorization_code")
            put("code", code)
            put("code_verifier", verifier)
        }
        val primaryUrl = FoxyRemoteConfig.current.endpoints.controlPlane.oauthToken
        val tokens = executeFxaRequest(
            fullUrl = primaryUrl,
            jsonBody = tokenBody,
            sessionToken = null,
            fallbackUrl = resolveOAuthFallback(primaryUrl),
            isOAuth = true,
        )
        check(tokens.optString("access_token").isNotBlank()) { "Firefox OAuth response has no access token" }
        tokens
    }

    private suspend fun loginAttempt(email: String, password: String, withVerificationMethod: Boolean = true): JSONObject {
        val body = JSONObject().apply {
            put("email", email)
            put("authPW", deriveAuthPw(email, password))
            if (withVerificationMethod) put("verificationMethod", VERIFICATION_METHOD_EMAIL_2FA)
        }
        return try {
            fxaDo("POST", "/account/login", jsonBody = body)
        } catch (e: FxaApiError) {
            if (e.errno == FXA_ERRNO_INVALID_PARAMETER && withVerificationMethod) {
                loginAttempt(email, password, withVerificationMethod = false)
            } else {
                throw e
            }
        }
    }

    private suspend fun oauthToken(sessionToken: String): JSONObject {
        val body = JSONObject().apply {
            put("client_id", FIREFOX_CLIENT_ID)
            put("grant_type", "fxa-credentials")
            put("scope", OAUTH_SCOPE)
            put("access_type", "offline")
        }
        return executeFxaRequest(
            fullUrl = FoxyRemoteConfig.current.endpoints.controlPlane.oauthToken,
            jsonBody = body,
            sessionToken = sessionToken,
        )
    }

    /** Base origin for the legacy password/2FA login API — derived from the
     *  configured FxA host instead of a hard-coded constant. */
    private fun fxaBaseServer(): String {
        val url = FoxyRemoteConfig.current.endpoints.controlPlane.recoveryStatus.toHttpUrl()
        return "${url.scheme}://${url.host}"
    }

    private suspend fun fxaDo(
        method: String,
        path: String,
        sessionToken: String? = null,
        jsonBody: JSONObject,
    ): JSONObject = executeFxaRequest(
        fullUrl = fxaBaseServer() + path,
        method = method,
        jsonBody = jsonBody,
        sessionToken = sessionToken,
    )

    /** Reference v2.0.4 executeFxaRequest: single request path with an OAuth
     *  fallback host attempt on 406, Fastly challenge solving, and a 120 s
     *  overall timeout. */
    private suspend fun executeFxaRequest(
        fullUrl: String,
        method: String = "POST",
        jsonBody: JSONObject,
        sessionToken: String? = null,
        fallbackUrl: String? = null,
        isOAuth: Boolean = false,
    ): JSONObject = withTimeout(120_000L) {
        withContext(Dispatchers.IO) {
            var currentUrl = fullUrl.toHttpUrl()
            val bodyBytes = jsonBody.toString().toByteArray(Charsets.UTF_8)
            val hawkCreds = sessionToken?.let { deriveHawkCredentials(it) }

            fun buildRequest(targetUrl: HttpUrl): Request {
                val builder = Request.Builder().url(targetUrl)
                if (isOAuth) {
                    FirefoxAccountHeaders.applyOAuth(builder)
                } else {
                    FirefoxAccountHeaders.apply(builder).header("Content-Type", "application/json")
                }
                if (hawkCreds != null) {
                    builder.header(
                        "Authorization",
                        hawkHeader(method, targetUrl, hawkCreds.first, hawkCreds.second, bodyBytes),
                    )
                }
                builder.method(method, bodyBytes.toRequestBody(jsonMediaType))
                return builder.build()
            }

            var response: Response = FoxyControlPlaneHttp.client.newCall(buildRequest(currentUrl)).execute()

            if (response.code == 406 && fallbackUrl != null) {
                val candidateFallback = fallbackUrl.toHttpUrl()
                val fallbackReq = buildRequest(candidateFallback)
                val fallbackResp =
                    try {
                        FoxyControlPlaneHttp.client.newCall(fallbackReq).execute()
                    } catch (cancellation: CancellationException) {
                        throw cancellation
                    } catch (_: Exception) {
                        null
                    }
                if (fallbackResp != null) {
                    if (fallbackResp.isSuccessful) {
                        response.close()
                        response = fallbackResp
                        currentUrl = candidateFallback
                    } else if (fallbackResp.code == 400) {
                        val fbText = fallbackResp.body?.string().orEmpty()
                        // Parse errno properly: a substring "108" match used to
                        // fire on ANY response containing the number (e.g. a
                        // timestamp), misclassifying ordinary failures as a
                        // permanent invalid-grant rejection.
                        val fbErrno = try { JSONObject(fbText).optInt("errno", -1) } catch (_: Exception) { -1 }
                        val isInvalid = fbErrno == 108 || fbText.contains("invalid_grant", ignoreCase = true)
                        if (isInvalid) {
                            response.close()
                            response = fallbackResp
                            currentUrl = candidateFallback
                        } else {
                            fallbackResp.close()
                        }
                    } else {
                        fallbackResp.close()
                    }
                }
            }

            var attempts = 1
            while (response.code == 406 && attempts < FXA_MAX_CHALLENGE_ATTEMPTS) {
                val challengedBody = response.use { it.body?.string().orEmpty() }
                try {
                    val solverUA =
                        if (isOAuth) FirefoxAccountHeaders.browserUserAgent
                        else FirefoxAccountHeaders.controlPlaneUserAgent
                    challengeSolver.solveAndInstall(
                        challengedBody,
                        currentUrl.toString(),
                        solverUA,
                    )
                } catch (cancellation: CancellationException) {
                    throw cancellation
                } catch (solveFailure: Exception) {
                    FoxyLog.w(TAG, "could not solve the Fastly challenge", solveFailure)
                    FoxyRemoteConfig.triggerRefresh()
                    throw FastlyBlockedException(solveFailure)
                }
                response = FoxyControlPlaneHttp.client.newCall(buildRequest(currentUrl)).execute()
                attempts++
            }

            response.use { resp ->
                val text = resp.body?.string().orEmpty()
                if (resp.code >= 400) {
                    if (resp.code == 406) {
                        FoxyRemoteConfig.triggerRefresh()
                        throw FastlyBlockedException()
                    }
                    val errorBody = try {
                        JSONObject(text)
                    } catch (e: Exception) {
                        JSONObject()
                    }
                    val errno = if (errorBody.has("errno")) errorBody.optInt("errno") else null
                    val message =
                        when {
                            errorBody.has("message") && errorBody.optString("message").isNotBlank() ->
                                errorBody.optString("message")
                            errorBody.has("error") && errorBody.optString("error").isNotBlank() ->
                                errorBody.optString("error")
                            text.isEmpty() -> "HTTP ${resp.code}"
                            else -> text.take(200)
                        }
                    throw FxaApiError(message, errno, resp.code)
                }
                if (text.isEmpty()) return@withContext JSONObject()
                return@withContext JSONObject(text)
            }
        }
    }

    private fun deriveQuickStretch(email: String, password: String): ByteArray {
        val salt = "${PROTOCOL_VERSION}quickStretch:$email".toByteArray(Charsets.UTF_8)
        return pbkdf2HmacSha256(password.toByteArray(Charsets.UTF_8), salt, PBKDF2_ROUNDS, STRETCHED_PW_LEN)
    }

    private fun deriveAuthPw(email: String, password: String): String {
        val quickStretched = deriveQuickStretch(email, password)
        return hkdf(quickStretched, "${PROTOCOL_VERSION}authPW", HKDF_LEN).toHex()
    }

    private fun deriveHawkCredentials(sessionTokenHex: String): Pair<String, ByteArray> {
        val sessionToken = sessionTokenHex.hexToBytes()
        val expanded = hkdf(sessionToken, "${PROTOCOL_VERSION}sessionToken", 64)
        return expanded.copyOfRange(0, 32).toHex() to expanded.copyOfRange(32, 64)
    }

    private fun hawkHeader(method: String, url: HttpUrl, tokenId: String, hmacKey: ByteArray, body: ByteArray): String {
        val ts = (System.currentTimeMillis() / 1000).toString()
        val nonceBytes = ByteArray(6).also { SecureRandom().nextBytes(it) }
        val nonce = Base64.encodeToString(nonceBytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        val path = url.encodedPath + if (url.encodedQuery != null) "?${url.encodedQuery}" else ""

        var payloadHash = ""
        if (body.isNotEmpty()) {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("hawk.1.payload\napplication/json\n".toByteArray(Charsets.UTF_8))
            digest.update(body)
            digest.update("\n".toByteArray(Charsets.UTF_8))
            payloadHash = Base64.encodeToString(digest.digest(), Base64.NO_WRAP)
        }

        val normalized = "hawk.1.header\n$ts\n$nonce\n${method.uppercase()}\n$path\n${url.host}\n${url.port}\n$payloadHash\n\n"

        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(hmacKey, "HmacSHA256")) }
        val macB64 = Base64.encodeToString(mac.doFinal(normalized.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)

        var header = "Hawk id=\"$tokenId\", ts=\"$ts\", nonce=\"$nonce\", mac=\"$macB64\""
        if (payloadHash.isNotEmpty()) header += ", hash=\"$payloadHash\""
        return header
    }
}

private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

private fun hkdf(ikm: ByteArray, info: String, length: Int, salt: ByteArray = ByteArray(32)): ByteArray {
    val prk = hmacSha256(salt, ikm)
    val infoBytes = info.toByteArray(Charsets.UTF_8)
    val result = ByteArray(length)
    var previousBlock = ByteArray(0)
    var generated = 0
    var counter = 1
    while (generated < length) {
        val block = hmacSha256(prk, previousBlock + infoBytes + byteArrayOf(counter.toByte()))
        val toCopy = minOf(block.size, length - generated)
        System.arraycopy(block, 0, result, generated, toCopy)
        generated += toCopy
        previousBlock = block
        counter++
    }
    return result
}

private fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, keyLengthBytes: Int): ByteArray {
    val hLen = 32
    val numBlocks = (keyLengthBytes + hLen - 1) / hLen
    val result = ByteArray(numBlocks * hLen)
    val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(password, "HmacSHA256")) }
    for (blockIndex in 1..numBlocks) {
        val blockIndexBytes = ByteBuffer.allocate(4).putInt(blockIndex).array()
        var u = mac.doFinal(salt + blockIndexBytes)
        val t = u.copyOf()
        for (iter in 2..iterations) {
            u = mac.doFinal(u)
            for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
        }
        System.arraycopy(t, 0, result, (blockIndex - 1) * hLen, hLen)
    }
    return result.copyOf(keyLengthBytes)
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
