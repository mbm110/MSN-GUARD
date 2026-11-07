package com.msnguard.vpn.foxy

import android.os.Build
import okhttp3.Request

/** Runtime headers used by FxA, Guardian and the Fastly solver.
 * Values are cache-backed through [FoxyRemoteConfig], so a 406 can recover
 * after Mozilla changes its edge policy without an APK release.
 */
internal object FirefoxAccountHeaders {
    private val release = Build.VERSION.RELEASE?.trim().orEmpty().ifBlank { "14" }

    val controlPlaneUserAgent: String
        get() = FoxyRemoteConfig.current.controlPlane.headers["User-Agent"]
            ?: "MozillaVPN/2.24.0 (sys:android $release)"

    val browserUserAgent: String
        get() = FoxyRemoteConfig.current.browser.headers["User-Agent"]
            ?: "Mozilla/5.0 (Android $release; Mobile; rv:159.0) Gecko/159.0 Firefox/159.0"

    val desktopUserAgent: String
        get() = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0"

    fun apply(builder: Request.Builder, component: ComponentConfig = FoxyRemoteConfig.current.controlPlane): Request.Builder {
        for ((key, value) in component.headers) builder.header(key, value)
        return builder
    }
}
