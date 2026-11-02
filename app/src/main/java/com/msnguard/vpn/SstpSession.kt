package com.msnguard.vpn

import android.content.Context
import android.net.VpnService
import com.msnguard.vpn.sstp.SharedBridge
import com.msnguard.vpn.sstp.SstpHost
import com.msnguard.vpn.sstp.control.Controller
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

class SstpSession(
    private val context: Context,
    private val vpn: VpnService,
    private val onEvent: (String) -> Unit,
) : SstpHost {
    override val preferences = context.profiled()
    override val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var controller: Controller? = null

    fun start(server: SstpServer, username: String, password: String) {
        preferences.edit()
            .putString("sstp_host", server.host)
            .putInt("sstp_port", server.port)
            .putString("sstp_user", username)
            .putString("sstp_password", password)
            .apply()
        onEvent("SSTP connecting to ${server.host}:${server.port}")
        controller = Controller(SharedBridge(this)).also { it.launchJobMain() }
    }

    fun stop() {
        controller?.disconnect()
        controller = null
        scope.cancel()
    }

    override fun newBuilder(): VpnService.Builder = vpn.Builder()
        .setSession("MSN-GUARD SSTP")
        .setMtu(1500)
        .addAddress("10.0.0.2", 32)
        .addRoute("0.0.0.0", 0)
        .addRoute("::", 0)
        .addDnsServer("1.1.1.1")

    override fun protectSocket(socket: java.net.Socket): Boolean = vpn.protect(socket)
    override fun networkManager(): android.net.ConnectivityManager =
        context.getSystemService(android.net.ConnectivityManager::class.java)
            ?: error("Connectivity service unavailable")
    override fun onSstpLog(message: String) = onEvent(message)
    override fun onSstpReady(ipv4: String?, dns: String?) = onEvent("SSTP PPP ready${ipv4?.let { " — $it" } ?: ""}")
    override fun onSstpStopped(reason: String) = onEvent(reason)
}
