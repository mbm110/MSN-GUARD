package com.msnguard.vpn

import org.json.JSONObject

object NativeCore {
    init {
        System.loadLibrary("aether")
        System.loadLibrary("aether_jni")
    }

    data class TunnelAddresses(
        val ipv4: String,
        val ipv6: String,
        val gatewayProxy: String = "",
        val organization: String = "",
    )

    fun prepare(config: String): TunnelAddresses {
        check(nativePrepare(config) == 0) { nativeLastError() }
        val result = JSONObject(nativeLastResult())
        return TunnelAddresses(
            result.getString("ipv4"),
            result.optString("ipv6"),
            result.optString("gateway_proxy"),
            result.optString("organization"),
        )
    }

    fun requestEmailCode(team: String, email: String) {
        check(nativeRequestEmailCode(team, email) == 0) { nativeLastError() }
    }

    fun confirmEmailCode(code: String): String {
        check(nativeConfirmEmailCode(code) == 0) { nativeLastError() }
        return JSONObject(nativeLastResult()).getString("token")
    }

    fun start(config: String, tunFd: Int): Int = nativeStart(config, tunFd)
    fun stop(): Int = nativeStop()
    fun isRunning(): Boolean = nativeIsRunning()
    fun isReady(): Boolean = nativeIsReady()
    fun lastError(): String = nativeLastError()
    fun lastLog(): String = nativeLastLog()
    fun attach(service: MsnGuardVpnService) = nativeAttach(service)
    fun detach() = nativeDetach()

    interface CoreCallback {
        fun onEvent(json: String)
    }

    @JvmStatic private external fun nativePrepare(config: String): Int
    @JvmStatic private external fun nativeLastResult(): String
    @JvmStatic private external fun nativeRequestEmailCode(team: String, email: String): Int
    @JvmStatic private external fun nativeConfirmEmailCode(code: String): Int
    @JvmStatic private external fun nativeStart(config: String, tunFd: Int): Int
    @JvmStatic private external fun nativeStop(): Int
    @JvmStatic private external fun nativeIsRunning(): Boolean
    @JvmStatic private external fun nativeIsReady(): Boolean
    @JvmStatic private external fun nativeLastError(): String
    @JvmStatic private external fun nativeLastLog(): String
    @JvmStatic private external fun nativeAttach(service: MsnGuardVpnService)
    @JvmStatic private external fun nativeDetach()
}
