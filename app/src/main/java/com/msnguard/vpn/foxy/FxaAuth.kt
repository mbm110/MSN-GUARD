package com.msnguard.vpn.foxy

import android.util.Base64
import com.msnguard.vpn.foxy.RuntimeAuth
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

class FxaApiError(message: String, val errno: Int?, val statusCode: Int?) : Exception(message)

class FxaRefreshFailure(
    message: String,
    val permanent: Boolean,
    cause: Throwable? = null,
) : Exception(message, cause)

private const val FXA_AUTH_SERVER = "https://api.accounts.firefox.com/v1"
private const val FXA_OAUTH_SERVER = "https://oauth.accounts.firefox.com/v1"
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
        "https://accounts.firefox.com/?context=fx_desktop_v3&service=sync&action=email"

    /** Same Hawk request as the reference browser flow. */
    fun buildOAuthHawkHeader(sessionToken: String): Pair<String, String> {
        val clean = sessionToken.trim().lowercase()
        require(Regex("^[0-9a-f]{64}$").matches(clean)) { "Invalid Firefox session token" }
        val url = "$FXA_AUTH_SERVER/oauth/token".toHttpUrl()
        val body = JSONObject().apply {
            put("client_id", FIREFOX_CLIENT_ID)
            put("grant_type", "fxa-credentials")
            put("scope", OAUTH_SCOPE)
            put("access_type", "offline")
        }.toString()
        val (id, key) = deriveHawkCredentials(clean)
        return hawkHeader("POST", url, id, key, body.toByteArray(Charsets.UTF_8)) to body
    }

    suspend fun completeBrowserLoginWithTokens(
        accessToken: String,
        refreshToken: String?,
        expiresInSeconds: Long,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            require(accessToken.isNotBlank()) { "Firefox OAuth returned an empty access token" }
            FoxyControlPlaneHttp.cookieJar.syncFromWebView()
            tokenStore.saveAuth(RuntimeAuth(
                accessToken = accessToken.trim(),
                refreshToken = refreshToken?.trim()?.ifBlank { null },
                expiresAtEpochSeconds = System.currentTimeMillis() / 1000 +
                    expiresInSeconds.coerceAtLeast(DEFAULT_ACCESS_TOKEN_TTL_SECONDS.toLong()),
            ))
        }
    }

    suspend fun completeBrowserLogin(sessionToken: String): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                val clean = sessionToken.trim().replace(Regex("[\\s\\\"]"), "").lowercase()
                require(Regex("^[0-9a-f]{64}$").matches(clean)) { "Invalid Firefox session token" }
                completeLogin(clean)
            }
        }

    private suspend fun isSessionVerified(sessionToken: String): Boolean = withContext(Dispatchers.IO) {
        val clean = sessionToken.trim().replace(Regex("[\\s\\\"]"), "").lowercase()
        if (!Regex("^[0-9a-f]{64}$").matches(clean)) return@withContext false
        val url = "$FXA_AUTH_SERVER/recovery_email/status".toHttpUrl()
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
        val url = "$FXA_AUTH_SERVER/oauth/token".toHttpUrl()
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
            fxaDoAt(FXA_OAUTH_SERVER, "POST", "/oauth/token", jsonBody = body)
        } catch (rejected: FxaApiError) {
            throw FxaRefreshFailure(
                rejected.message ?: "FxA rejected the refresh token",
                permanent = rejected.isPermanentRefreshRejection(),
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
        return statusCode == 400 || statusCode == 401 || statusCode == 403
    }

    private fun expiryFrom(tokenData: JSONObject): Long {
        val expiresIn = tokenData.optInt("expires_in", 0)
            .takeIf { it > 0 } ?: DEFAULT_ACCESS_TOKEN_TTL_SECONDS
        return System.currentTimeMillis() / 1000 + expiresIn
    }

    private suspend fun completeLogin(sessionToken: String) {
        var verified = false
        repeat(10) {
            coroutineContext.ensureActive()
            if (isSessionVerified(sessionToken)) { verified = true; return@repeat }
            delay(1500L)
        }
        check(verified) { "Firefox account session is not verified yet" }
        val tokenData = exchangeSessionWithOAuthCode(sessionToken)
        tokenStore.saveAuth(
            RuntimeAuth(
                accessToken = tokenData.getString("access_token"),
                refreshToken = tokenData.optString("refresh_token", "").ifBlank { null },
                expiresAtEpochSeconds = expiryFrom(tokenData),
            ),
        )
        clearPendingSession()
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
        val result = fxaDo("POST", "/oauth/authorization", sessionToken = sessionToken, jsonBody = authorization)
        val code = result.optString("code")
        check(code.isNotBlank() && result.optString("state") == state) { "Invalid Firefox OAuth authorization response" }
        val tokenBody = JSONObject().apply {
            put("client_id", FIREFOX_CLIENT_ID)
            put("grant_type", "authorization_code")
            put("code", code)
            put("code_verifier", verifier)
        }
        val tokens = fxaDoAt(FXA_OAUTH_SERVER, "POST", "/token", null, tokenBody)
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
        return fxaDoAt(FXA_OAUTH_SERVER, "POST", "/oauth/token", sessionToken, body)
    }

    private suspend fun fxaDo(
        method: String,
        path: String,
        sessionToken: String? = null,
        jsonBody: JSONObject,
    ): JSONObject = fxaDoAt(FXA_AUTH_SERVER, method, path, sessionToken, jsonBody)

    private suspend fun fxaDoAt(
        baseUrl: String,
        method: String,
        path: String,
        sessionToken: String? = null,
        jsonBody: JSONObject,
    ): JSONObject = withContext(Dispatchers.IO) {
        val url = "$baseUrl$path".toHttpUrl()
        val bodyBytes = jsonBody.toString().toByteArray(Charsets.UTF_8)
        var tokenId: String? = null
        var hmacKey: ByteArray? = null
        if (sessionToken != null) {
            val (id, key) = deriveHawkCredentials(sessionToken)
            tokenId = id
            hmacKey = key
        }

        fun buildRequest(): Request {
            val builder = FirefoxAccountHeaders.apply(Request.Builder().url(url))
            builder.header("Content-Type", "application/json")
            if (sessionToken != null) {
                builder.header("Authorization", hawkHeader(method, url, tokenId!!, hmacKey!!, bodyBytes))
            }
            builder.method(method, bodyBytes.toRequestBody(jsonMediaType))
            return builder.build()
        }

        var response: Response = FoxyControlPlaneHttp.client.newCall(buildRequest()).execute()
        var attempts = 1
        while (response.code == 406 && attempts < FXA_MAX_CHALLENGE_ATTEMPTS) {
            val challengedBody = response.use { it.body?.string().orEmpty() }
            challengeSolver.solveAndInstall(challengedBody, url.scheme + "://" + url.host, FirefoxAccountHeaders.controlPlaneUserAgent)
            response = FoxyControlPlaneHttp.client.newCall(buildRequest()).execute()
            attempts++
        }
        if (response.code == 406) FoxyRemoteConfig.triggerRefresh()

        response.use { resp ->
            val text = resp.body?.string().orEmpty()
            if (resp.code >= 400) {
                val errorBody = try {
                    JSONObject(text)
                } catch (e: Exception) {
                    JSONObject()
                }
                val errno = if (errorBody.has("errno")) errorBody.optInt("errno") else null
                val message = errorBody.optString("message", text.ifEmpty { "HTTP ${resp.code}" })
                throw FxaApiError(message, errno, resp.code)
            }
            if (text.isEmpty()) return@withContext JSONObject()
            return@withContext JSONObject(text)
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
