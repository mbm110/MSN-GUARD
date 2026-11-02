package com.msnguard.vpn.sstp

import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.UUID

enum class Where { CERT, CERT_PATH, SSL, PROXY, SSTP_DATA, SSTP_CONTROL, SSTP_REQUEST, SSTP_HASH, PPP, PAP, CHAP, MSCHAPV2, EAP, LCP, LCP_MRU, LCP_AUTH, IPCP, IPCP_IP, IPV6CP, IPV6CP_IDENTIFIER, IP, IPv4, IPv6, ROUTE, INCOMING, OUTGOING }
data class ControlMessage(val from: Where, val result: Result, val supplement: String? = null)
enum class Result { PROCEEDED, ERR_TIMEOUT, ERR_COUNT_EXHAUSTED, ERR_UNKNOWN_TYPE, ERR_UNEXPECTED_MESSAGE, ERR_PARSING_FAILED, ERR_VERIFICATION_FAILED, ERR_NEGATIVE_ACKNOWLEDGED, ERR_ABORT_REQUESTED, ERR_DISCONNECT_REQUESTED, ERR_TERMINATE_REQUESTED, ERR_PROTOCOL_REJECTED, ERR_CODE_REJECTED, ERR_AUTHENTICATION_FAILED, ERR_ADDRESS_REJECTED, ERR_OPTION_REJECTED, ERR_INVALID_ADDRESS, ERR_INVALID_PACKET_SIZE }

class SharedBridge(internal val service: SstpHost) {
    internal val prefs: SharedPreferences = service.preferences
    internal val builder = service.newBuilder()
    internal lateinit var handler: CoroutineExceptionHandler
    internal val controlMailbox = Channel<ControlMessage>(Channel.BUFFERED)
    internal var sslTerminal: com.msnguard.vpn.sstp.terminal.SSLTerminal? = null
    internal var ipTerminal: com.msnguard.vpn.sstp.terminal.IPTerminal? = null
    internal val HOME_USERNAME = getStringPrefValue(OscPrefKey.HOME_USERNAME, prefs)
    internal val HOME_PASSWORD = getStringPrefValue(OscPrefKey.HOME_PASSWORD, prefs)
    internal val PPP_MRU = getIntPrefValue(OscPrefKey.PPP_MRU, prefs)
    internal val PPP_MTU = getIntPrefValue(OscPrefKey.PPP_MTU, prefs)
    internal val PPP_AUTH_PROTOCOLS = setOf(AUTH_PROTOCOl_PAP, AUTH_PROTOCOL_MSCHAPv2)
    internal val PPP_IPv4_ENABLED = true
    internal val PPP_IPv6_ENABLED = true
    internal var hlak: ByteArray? = null
    internal val nonce = ByteArray(32)
    internal val guid = UUID.randomUUID().toString()
    internal var hashProtocol: Byte = 0
    private val mutex = Mutex()
    private var frameID = -1
    internal var currentMRU = PPP_MRU
    internal var currentAuth = ""
    internal val currentIPv4 = ByteArray(4)
    internal val currentIPv6 = ByteArray(8)
    internal val currentProposedDNS = ByteArray(4)
    internal val selectedApps: List<AppString> = emptyList()
    internal fun isEnabled(authProtocol: String) = authProtocol in PPP_AUTH_PROTOCOLS
    internal fun attachSSLTerminal() { sslTerminal = com.msnguard.vpn.sstp.terminal.SSLTerminal(this) }
    internal fun attachIPTerminal() { ipTerminal = com.msnguard.vpn.sstp.terminal.IPTerminal(this) }
    internal suspend fun allocateNewFrameID(): Byte = mutex.withLock { frameID += 1; frameID.toByte() }
}

interface SstpHost {
    val preferences: SharedPreferences
    val scope: kotlinx.coroutines.CoroutineScope
    fun newBuilder(): android.net.VpnService.Builder
    fun protectSocket(socket: java.net.Socket): Boolean
    fun networkManager(): android.net.ConnectivityManager
    fun onSstpLog(message: String)
    fun onSstpReady(ipv4: String?, dns: String?)
    fun onSstpStopped(reason: String)
}
