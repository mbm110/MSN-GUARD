package studio.cluvex.aethery

import org.json.JSONObject

object NativeCore {
    init {
        System.loadLibrary("aether")
        System.loadLibrary("aether_jni")
    }

    data class TunnelAddresses(val ipv4: String, val ipv6: String)

    fun prepare(config: String): TunnelAddresses {
        check(nativePrepare(config) == 0) { nativeLastError() }
        val result = JSONObject(nativeLastResult())
        return TunnelAddresses(
            result.getString("ipv4"),
            result.getString("ipv6"),
        )
    }

    fun start(config: String, tunFd: Int): Int = nativeStart(config, tunFd)
    fun startProxy(config: String): Int = nativeStartProxy(config)
    fun stop(): Int = nativeStop()
    fun isRunning(): Boolean = nativeIsRunning()
    fun isReady(): Boolean = nativeIsReady()
    fun lastError(): String = nativeLastError()
    fun lastLog(): String = nativeLastLog()
    fun attach(service: AetherVpnService) = nativeAttach(service)
    fun detach() = nativeDetach()

    @JvmStatic private external fun nativePrepare(config: String): Int
    @JvmStatic private external fun nativeLastResult(): String
    @JvmStatic private external fun nativeStart(config: String, tunFd: Int): Int
    @JvmStatic private external fun nativeStartProxy(config: String): Int
    @JvmStatic private external fun nativeStop(): Int
    @JvmStatic private external fun nativeIsRunning(): Boolean
    @JvmStatic private external fun nativeIsReady(): Boolean
    @JvmStatic private external fun nativeLastError(): String
    @JvmStatic private external fun nativeLastLog(): String
    @JvmStatic private external fun nativeAttach(service: AetherVpnService)
    @JvmStatic private external fun nativeDetach()
}
