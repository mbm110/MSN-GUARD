package com.msnguard.vpn.foxy

import android.content.Context
import android.os.Build
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import org.json.JSONObject

data class ComponentConfig(
    val headers: Map<String, String>,
    val protocols: List<Protocol> = listOf(Protocol.HTTP_2, Protocol.HTTP_1_1),
)

data class RemoteConfig(
    val version: Int,
    val controlPlane: ComponentConfig,
    val guardian: ComponentConfig,
    val solver: ComponentConfig,
    val browser: ComponentConfig,
)

internal val ANDROID_RELEASE: String =
    Build.VERSION.RELEASE?.trim()?.takeIf { it.isNotEmpty() } ?: "14"

internal val ANDROID_SDK: String =
    Build.VERSION.SDK_INT.toString()

internal fun resolvePlaceholders(raw: String): String =
    raw.replace("\${android_version}", ANDROID_RELEASE, ignoreCase = true)
        .replace("{android_version}", ANDROID_RELEASE, ignoreCase = true)
        .replace("\${os_version}", ANDROID_RELEASE, ignoreCase = true)
        .replace("{os_version}", ANDROID_RELEASE, ignoreCase = true)
        .replace("\${android_sdk}", ANDROID_SDK, ignoreCase = true)
        .replace("{android_sdk}", ANDROID_SDK, ignoreCase = true)

private val DEFAULT_CONTROL_PLANE =
    ComponentConfig(
        headers =
            mapOf(
                "User-Agent" to resolvePlaceholders("MozillaVPN/2.24.0 (sys:android {android_version})"),
                "Accept" to "*/*",
                "Accept-Encoding" to "identity",
            ),
        protocols = listOf(Protocol.HTTP_2, Protocol.HTTP_1_1),
    )

private val DEFAULT_GUARDIAN =
    ComponentConfig(
        headers =
            mapOf(
                "User-Agent" to resolvePlaceholders("MozillaVPN/2.24.0 (sys:android {android_version})"),
                "Accept" to "application/json",
                "Accept-Encoding" to "identity",
                "Content-Type" to "application/json",
                "Cache-Control" to "max-age=0",
            ),
    )

private val DEFAULT_SOLVER =
    ComponentConfig(
        headers =
            mapOf(
                "User-Agent" to resolvePlaceholders("MozillaVPN/2.24.0 (sys:android {android_version})"),
                "Accept-Encoding" to "identity",
            ),
    )

private val DEFAULT_BROWSER =
    ComponentConfig(
        headers =
            mapOf(
                "User-Agent" to
                    resolvePlaceholders(
                        "Mozilla/5.0 (Android {android_version}; Mobile; rv:159.0) Gecko/159.0 Firefox/159.0"
                    ),
            ),
    )

val DEFAULT_REMOTE_CONFIG =
    RemoteConfig(
        version = 1,
        controlPlane = DEFAULT_CONTROL_PLANE,
        guardian = DEFAULT_GUARDIAN,
        solver = DEFAULT_SOLVER,
        browser = DEFAULT_BROWSER,
    )

object FoxyRemoteConfig {
    private const val TAG = "FoxyRemoteConfig"
    private const val FILE_NAME = "foxy_config.json"
    private const val PRIMARY_URL =
        "https://raw.githubusercontent.com/Vauth/FoxyConfig/main/config.json"
    private const val FALLBACK_URL =
        "https://cdn.jsdelivr.net/gh/Vauth/FoxyConfig@main/config.json"

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val refreshMutex = Mutex()
    private val isRefreshing = AtomicBoolean(false)

    @Volatile
    private var appContext: Context? = null

    @Volatile
    var current: RemoteConfig = DEFAULT_REMOTE_CONFIG
        private set

    @Volatile
    private var lastRawJson: String = ""

    fun resolvePlaceholders(raw: String): String = com.msnguard.vpn.foxy.resolvePlaceholders(raw)

    fun init(context: Context) {
        val app = context.applicationContext
        appContext = app
        val file = File(app.filesDir, FILE_NAME)
        if (file.isFile && file.length() > 0) {
            val text = runCatching { file.readText() }.getOrNull().orEmpty()
            val parsed = parseConfig(text)
            if (parsed != null) {
                current = parsed
                lastRawJson = text
            }
        }
    }

    fun triggerRefresh(client: OkHttpClient = FoxyControlPlaneHttp.client) {
        val context = appContext ?: return
        if (!isRefreshing.compareAndSet(false, true)) return
        scope.launch {
            try {
                refresh(context, client)
            } finally {
                isRefreshing.set(false)
            }
        }
    }

    suspend fun refresh(context: Context, client: OkHttpClient = FoxyControlPlaneHttp.client) {
        withContext(Dispatchers.IO) {
            refreshMutex.withLock {
                val fetchedJson =
                    fetchRemoteJson(client, PRIMARY_URL)
                        ?: fetchRemoteJson(client, FALLBACK_URL)
                        ?: return@withContext

                if (fetchedJson == lastRawJson) return@withContext

                val parsed = parseConfig(fetchedJson) ?: return@withContext

                val file = File(context.filesDir, FILE_NAME)
                val tempFile = File(context.filesDir, "$FILE_NAME.tmp")
                val writeSuccess =
                    runCatching {
                        tempFile.writeText(fetchedJson)
                        if (tempFile.renameTo(file)) {
                            true
                        } else {
                            tempFile.copyTo(file, overwrite = true)
                            tempFile.delete()
                            true
                        }
                    }.getOrDefault(false)

                if (writeSuccess) {
                    current = parsed
                    lastRawJson = fetchedJson
                    FoxyLog.i(TAG, "config updated")
                }
            }
        }
    }

    private suspend fun fetchRemoteJson(client: OkHttpClient, url: String): String? {
        return try {
            withTimeoutOrNull(8_000L) {
                val request =
                    Request.Builder()
                        .url(url)
                        .header("Accept", "application/json")
                        .header("Cache-Control", "no-cache")
                        .build()
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) return@withTimeoutOrNull null
                    val text = response.body?.string().orEmpty().trim()
                    if (text.startsWith("{") && text.endsWith("}")) text else null
                }
            }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            null
        }
    }

    private fun parseConfig(jsonString: String): RemoteConfig? {
        return runCatching {
            val root = JSONObject(jsonString)
            val version = root.optInt("version", 1)

            fun parseComponent(name: String, default: ComponentConfig): ComponentConfig {
                val obj = root.optJSONObject(name) ?: return default
                val headersObj = obj.optJSONObject("headers")
                val headers =
                    if (headersObj != null) {
                        val map = mutableMapOf<String, String>()
                        for (key in headersObj.keys()) {
                            val value = headersObj.optString(key, "")
                            if (value.isNotEmpty()) {
                                map[key] = resolvePlaceholders(value)
                            }
                        }
                        if (map.isNotEmpty()) map else default.headers
                    } else default.headers

                val settingsObj = obj.optJSONObject("settings")
                val protocols =
                    if (settingsObj != null && settingsObj.has("protocols")) {
                        val arr = settingsObj.optJSONArray("protocols")
                        if (arr != null && arr.length() > 0) {
                            val list = mutableListOf<Protocol>()
                            for (i in 0 until arr.length()) {
                                when (arr.optString(i).uppercase()) {
                                    "HTTP_2", "H2" -> list.add(Protocol.HTTP_2)
                                    "HTTP_1_1", "HTTP1.1" -> list.add(Protocol.HTTP_1_1)
                                }
                            }
                            if (list.isNotEmpty()) list else default.protocols
                        } else default.protocols
                    } else default.protocols

                return ComponentConfig(headers = headers, protocols = protocols)
            }

            RemoteConfig(
                version = version,
                controlPlane = parseComponent("controlPlane", DEFAULT_CONTROL_PLANE),
                guardian = parseComponent("guardian", DEFAULT_GUARDIAN),
                solver = parseComponent("solver", DEFAULT_SOLVER),
                browser = parseComponent("browser", DEFAULT_BROWSER),
            )
        }.getOrNull()
    }
}
