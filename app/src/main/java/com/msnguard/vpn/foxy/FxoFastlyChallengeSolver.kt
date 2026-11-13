package com.msnguard.vpn.foxy

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Cookie
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

class FastlyChallengeError(message: String) : Exception(message)

private const val SOLVE_TIMEOUT_SECONDS = 60L

private const val MAX_POST_BACK_ROUNDS = 8


private const val POW_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

private const val HTML_ACCEPT =
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

private val CHALLENGE_PREFIX_REGEX = Regex("/_fs-ch-[A-Za-z0-9]+")
private val INIT_CALL_REGEX = Regex("init\\((\\[[^\\]]*\\]),\\s*\"([^\"]+)\",\\s*\"([^\"]+)\"")

class FastlyChallengeSolver(private val cookieJar: SimpleCookieJar) {

    private fun allowedHosts(): Set<String> {
        val ep = FoxyRemoteConfig.current.endpoints
        return (listOf(ep.controlPlane.login, ep.controlPlane.recoveryStatus,
            ep.controlPlane.oauthToken, ep.controlPlane.oauthFallback,
            ep.controlPlane.authorization, ep.controlPlane.sessionDestroy,
            ep.guardian.token, ep.guardian.status, ep.guardian.activate, ep.serverList,
            ep.productDetails).mapNotNull { runCatching { it.toHttpUrl().host }.getOrNull() } +
            listOf("accounts.firefox.com", "api.accounts.firefox.com", "oauth.accounts.firefox.com")).toSet()
    }

    private class NoChallengePage : Exception()

    suspend fun solveAndInstall(
        challengedBody: String? = null,
        challengedOrigin: String? = null,
        userAgent: String = FirefoxAccountHeaders.controlPlaneUserAgent,
    ) = withContext(Dispatchers.IO) {
        if (!challengedBody.isNullOrBlank() && challengedBody.contains("/_fs-ch-")) {
            val origin = challengedOrigin?.trimEnd('/') ?: "https://api.accounts.firefox.com"
            val url = runCatching { origin.toHttpUrl() }.getOrNull()
            if (url == null || !url.isHttps || url.host !in allowedHosts()) {
                throw FastlyChallengeError("untrusted challenge origin")
            }
            solveChallengeBody(origin, challengedBody, userAgent)
            return@withContext
        }
        var lastError: Exception? = null
        for (base in listOf("https://api.accounts.firefox.com", "https://accounts.firefox.com")) {
            try {
                solveOnHost(base)
                return@withContext
            } catch (_: NoChallengePage) {
                continue
            } catch (e: FastlyChallengeError) {
                lastError = e
            }
        }
        throw lastError ?: FastlyChallengeError("host did not serve a Fastly challenge page")
    }

    private fun baseOrigin(prefixUrl: String): String {
        val idx = prefixUrl.indexOf("/_fs-ch-")
        return if (idx > 0) prefixUrl.substring(0, idx) else prefixUrl
    }

    private fun solveChallengeBody(origin: String, page: String, userAgent: String) {
        val solverJar = SimpleCookieJar()
        val solver = FoxyControlPlaneHttp.client.newBuilder().cookieJar(solverJar)
            .connectTimeout(SOLVE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(SOLVE_TIMEOUT_SECONDS, TimeUnit.SECONDS).build()
        val prefix = CHALLENGE_PREFIX_REGEX.find(page)?.value
            ?: throw FastlyChallengeError("challenge asset prefix not found")
        val prefixUrl = origin.trimEnd('/') + prefix
        val script = fetchText(solver, "$prefixUrl/script.js?reload=true")
        var (challenges, token) = parseChallengeInit(script)
        repeat(MAX_POST_BACK_ROUNDS) {
            val answers = JSONArray()
            for (i in 0 until challenges.length()) {
                answers.put(answerChallenge(solver, prefixUrl, token, challenges.getJSONObject(i)))
            }
            val body = JSONObject().put("token", token).put("data", answers)
                .toString().toRequestBody("application/json".toMediaType())
            val request = FirefoxAccountHeaders.apply(Request.Builder().url("$prefixUrl/fst-post-back"), FoxyRemoteConfig.current.solver)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .header("User-Agent", userAgent).header("Origin", origin)
                .post(body).build()
            solver.newCall(request).execute().use { response ->
                val text = response.body?.string().orEmpty()
                if (!response.isSuccessful) throw FastlyChallengeError("challenge post-back returned HTTP ${response.code}")
                val result = JSONObject(text)
                if (result.optString("status") == "success") {
                    installChallengeCookies(solverJar)
                    return
                }
                challenges = result.optJSONArray("ch") ?: throw FastlyChallengeError("missing next challenge")
                token = result.optString("tok").ifBlank { throw FastlyChallengeError("missing challenge token") }
            }
        }
        throw FastlyChallengeError("Fastly challenge did not complete")
    }

    private fun solvePow(base: String, targetHex: String): String? {
        val target = try {
            targetHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } catch (e: Exception) {
            return null
        }
        if (target.size != 32) return null
        val digest = MessageDigest.getInstance("SHA-256")
        for (a in POW_ALPHABET) {
            for (b in POW_ALPHABET) {
                val suffix = "$a$b"
                val hash = digest.digest((base + suffix).toByteArray(Charsets.UTF_8))
                if (hash.contentEquals(target)) return suffix
            }
        }
        return null
    }

    private fun fetchText(
        client: OkHttpClient,
        url: String,
        userAgent: String = FirefoxAccountHeaders.controlPlaneUserAgent,
        accept: String = HTML_ACCEPT,
    ): String {
        val request = FirefoxAccountHeaders.apply(Request.Builder().url(url), FoxyRemoteConfig.current.solver)
            .header("User-Agent", userAgent)
            .header("Accept", accept)
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw FastlyChallengeError("GET $url returned HTTP ${response.code}")
            return response.body?.string().orEmpty()
        }
    }

    private fun fetchChallengePage(client: OkHttpClient, pageUrl: String): Pair<String, Boolean> {
        val body = fetchText(client, pageUrl)
        val isChallenge = body.contains("/_fs-ch-") && body.contains("Client Challenge")
        return body to isChallenge
    }

    private fun parseChallengeInit(script: String): Pair<JSONArray, String> {
        val matches = INIT_CALL_REGEX.findAll(script).toList()
        if (matches.isEmpty()) throw FastlyChallengeError("challenge init() call not found in script")
        val last = matches.last()
        val challenges = try {
            JSONArray(last.groupValues[1])
        } catch (e: Exception) {
            throw FastlyChallengeError("could not parse challenge list: ${e.message}")
        }
        if (challenges.length() == 0) throw FastlyChallengeError("empty challenge list")
        return challenges to last.groupValues[2]
    }

    private fun fetchPat(client: OkHttpClient, prefixUrl: String, token: String): String {
        val patUrl = "$prefixUrl/pat?token=${URLEncoder.encode(token, "UTF-8")}"
        val request = Request.Builder()
            .url(patUrl)
            .header("Accept", "text/plain")
            .header("Content-Type", "application/json")
            .header("User-Agent", FirefoxAccountHeaders.controlPlaneUserAgent)
            .header("Origin", baseOrigin(prefixUrl))
            .post(ByteArray(0).toRequestBody(null))
            .build()
        client.newCall(request).execute().use { response ->
            if (response.code == 400 || response.code == 401) return ""
            if (!response.isSuccessful) throw FastlyChallengeError("PAT request returned HTTP ${response.code}")
            val json = try {
                JSONObject(response.body?.string().orEmpty())
            } catch (e: Exception) {
                throw FastlyChallengeError("could not parse PAT response: ${e.message}")
            }
            val auth = json.optString("auth", "")
            if (auth.isEmpty()) throw FastlyChallengeError("empty PAT auth token")
            return auth
        }
    }

    private fun clientMetricsAnswer(): JSONObject = JSONObject().apply {
        put("ty", "clientmetrics")
        put("webdriver", false)
        put(
            "bot_detection_result",
            JSONObject().apply {
                put("bot_detected", false)
                put("bot_kind", JSONObject.NULL)
            },
        )
        put(
            "browser_metrics",
            JSONObject().apply {
                put("client_data", "{}")
                put("error_trace", JSONObject.NULL)
            },
        )
        put("detector_results", JSONObject())
        put("v", 2)
    }

    private fun answerChallenge(client: OkHttpClient, prefixUrl: String, token: String, challenge: JSONObject): JSONObject {
        val data = challenge.optJSONObject("data") ?: JSONObject()
        return when (val type = challenge.optString("ty")) {
            "pow" -> {
                val base = data.optString("base", "")
                val answer = solvePow(base, data.optString("hash", ""))
                    ?: throw FastlyChallengeError("no proof-of-work solution found for base $base")
                JSONObject().apply {
                    put("ty", "pow")
                    put("base", base)
                    put("answer", answer)
                    put("hmac", data.optString("hmac", ""))
                    put("expires", data.optString("expires", ""))
                }
            }
            "pat" -> JSONObject().apply {
                put("ty", "pat")
                put("auth", fetchPat(client, prefixUrl, token))
            }
            "clientmetrics" -> clientMetricsAnswer()
            else -> throw FastlyChallengeError("unsupported Fastly challenge type '$type' (captcha cannot be solved automatically)")
        }
    }

    private fun installChallengeCookies(solverJar: SimpleCookieJar) {
        val cookies = solverJar.snapshotAll()
        if (cookies.isEmpty()) throw FastlyChallengeError("challenge completed but no cookies were issued")
        val hosts = allowedHosts()
        for (cookie in cookies) {
            if (hosts.none { it == cookie.domain || it.endsWith(".${cookie.domain}") }) continue
            for (host in hosts) {
                val installed = Cookie.Builder().name(cookie.name).value(cookie.value)
                    .hostOnlyDomain(host).path("/").expiresAt(cookie.expiresAt)
                    .apply { if (cookie.secure) secure() }
                    .apply { if (cookie.httpOnly) httpOnly() }.build()
                cookieJar.saveFromResponse("https://$host/".toHttpUrl(), listOf(installed))
                runCatching {
                    android.webkit.CookieManager.getInstance().setCookie("https://$host/", installed.toString())
                }
            }
        }
        runCatching { android.webkit.CookieManager.getInstance().flush() }
    }

    private fun solveOnHost(base: String) {
        val solverJar = SimpleCookieJar()
        val solver = FoxyControlPlaneHttp.client.newBuilder()
            .cookieJar(solverJar)
            .connectTimeout(SOLVE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(SOLVE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build()

        val pageUrl = "$base/"
        val (page, isChallenge) = fetchChallengePage(solver, pageUrl)
        if (!isChallenge) throw NoChallengePage()

        val prefixMatch = CHALLENGE_PREFIX_REGEX.find(page)
            ?: throw FastlyChallengeError("challenge asset prefix not found on $base")
        val prefixUrl = base + prefixMatch.value

        val script = fetchText(solver, "$prefixUrl/script.js?reload=true")
        var (challenges, token) = parseChallengeInit(script)

        repeat(MAX_POST_BACK_ROUNDS) {
            val answers = JSONArray()
            for (i in 0 until challenges.length()) {
                answers.put(answerChallenge(solver, prefixUrl, token, challenges.getJSONObject(i)))
            }
            val postBody = JSONObject().apply {
                put("token", token)
                put("data", answers)
            }.toString().toRequestBody("application/json".toMediaType())
            val request = Request.Builder()
                .url("$prefixUrl/fst-post-back")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", FirefoxAccountHeaders.controlPlaneUserAgent)
                .header("Origin", baseOrigin(prefixUrl))
                .post(postBody)
                .build()
            solver.newCall(request).execute().use { response ->
                if (!response.isSuccessful) throw FastlyChallengeError("challenge post-back returned HTTP ${response.code}")
                val body = JSONObject(response.body?.string().orEmpty())
                if (body.optString("status") == "success") {
                    val (_, stillChallenged) = fetchChallengePage(solver, pageUrl)
                    if (stillChallenged) throw FastlyChallengeError("challenge cookie not accepted on this exit IP")
                    installChallengeCookies(solverJar)
                    return
                }
                val nextChallenges = body.optJSONArray("ch")
                val nextToken = body.optString("tok", "")
                if (nextChallenges == null || nextChallenges.length() == 0 || nextToken.isEmpty()) {
                    throw FastlyChallengeError("unexpected post-back response: $body")
                }
                challenges = nextChallenges
                token = nextToken
            }
        }
        throw FastlyChallengeError("Fastly challenge did not complete within $MAX_POST_BACK_ROUNDS rounds")
    }
}
