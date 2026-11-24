package com.msnguard.vpn.foxy

import android.os.Build
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

/** Runtime headers used by FxA, Guardian and the Fastly solver.
 * Values are cache-backed through [FoxyRemoteConfig], so a 406 can recover
 * after Mozilla changes its edge policy without an APK release.
 */
internal object FirefoxAccountHeaders {
    private val refreshMutex = Mutex()

    /** Firefox major version learned from Mozilla's product-details endpoint;
     *  feeds the browser User-Agent so the OAuth side looks like a current
     *  Firefox release (reference v2.0.4 behavior). */
    @Volatile
    private var major = "159"

    private var nextRefreshNanos: Long? = null

    private val release = Build.VERSION.RELEASE?.trim().orEmpty().ifBlank { "14" }

    val controlPlaneUserAgent: String
        get() = FoxyRemoteConfig.current.controlPlane.headers["User-Agent"]
            ?: "MozillaVPN/2.24.0 (sys:android $release)"

    val browserUserAgent: String
        get() = FoxyRemoteConfig.current.browser.headers["User-Agent"]
            ?: "Mozilla/5.0 (Android $release; Mobile; rv:$major.0) Gecko/$major.0 Firefox/$major.0"

    fun apply(builder: Request.Builder, component: ComponentConfig = FoxyRemoteConfig.current.controlPlane): Request.Builder {
        for ((key, value) in component.headers) builder.header(key, value)
        return builder
    }

    fun applyOAuth(builder: Request.Builder): Request.Builder = apply(builder)

    /** Refresh the learned Firefox major version from product-details
     *  (URL from [FoxyRemoteConfig]); cached for 24 h on success, retried
     *  after 1 h on failure. Never throws. */
    suspend fun refresh(client: OkHttpClient) {
        refreshMutex.withLock {
            nextRefreshNanos?.let { if (System.nanoTime() - it < 0L) return }
            val refreshed =
                try {
                    withTimeoutOrNull(5_000L) {
                        val request =
                            apply(Request.Builder().url(FoxyRemoteConfig.current.endpoints.productDetails)).get().build()
                        client.newCall(request).execute().use { response ->
                            if (!response.isSuccessful) return@withTimeoutOrNull false
                            val text = response.body?.string().orEmpty()
                            if (text.isBlank()) return@withTimeoutOrNull false
                            val version = JSONObject(text).optString("LATEST_FIREFOX_VERSION").trim()
                            val candidate = version.substringBefore('.')
                            if (!candidate.matches(Regex("[0-9]{1,4}"))) return@withTimeoutOrNull false
                            major = candidate
                            true
                        }
                    } ?: false
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    false
                }
            nextRefreshNanos =
                System.nanoTime() + TimeUnit.HOURS.toNanos(if (refreshed) 24L else 1L)
        }
    }
}
