package com.msnguard.vpn

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.UnknownHostException

/**
 * Mo-be-mo copy of PattNG handler/SpeedtestManager.socketConnectTime.
 * Single change: logging via android.util.Log instead of LogUtil.
 */
object SpeedtestManager {

    /**
     * Measures TCP connect time to [url]:[port].
     * @return elapsed ms on success, -1 on any failure.
     */
    fun socketConnectTime(url: String, port: Int, timeoutMs: Int = 1500): Long {
        var socket: Socket? = null
        val start = System.currentTimeMillis()
        return try {
            socket = Socket()
            socket.connect(InetSocketAddress(url, port), timeoutMs)
            System.currentTimeMillis() - start
        } catch (_: UnknownHostException) {
            -1
        } catch (_: IOException) {
            -1
        } catch (_: Exception) {
            -1
        } finally {
            try { if (socket?.isClosed == false) socket.close() } catch (_: IOException) {}
        }
    }
}
