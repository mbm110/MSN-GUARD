package com.msnguard.vpn.sstp.io.incoming

import com.msnguard.vpn.sstp.*
import com.msnguard.vpn.sstp.ControlMessage
import com.msnguard.vpn.sstp.MAX_MRU
import com.msnguard.vpn.sstp.SharedBridge
import com.msnguard.vpn.sstp.Where
import com.msnguard.vpn.sstp.client.SstpClient
import com.msnguard.vpn.sstp.client.ppp.IpcpClient
import com.msnguard.vpn.sstp.client.ppp.Ipv6cpClient
import com.msnguard.vpn.sstp.client.ppp.LCPClient
import com.msnguard.vpn.sstp.client.ppp.PPPClient
import com.msnguard.vpn.sstp.client.ppp.auth.ChapClient
import com.msnguard.vpn.sstp.client.ppp.auth.EAPClient
import com.msnguard.vpn.sstp.client.ppp.auth.PAPClient
import com.msnguard.vpn.sstp.extension.probeByte
import com.msnguard.vpn.sstp.extension.probeShort
import com.msnguard.vpn.sstp.extension.toIntAsUShort
import com.msnguard.vpn.sstp.unit.ppp.Frame
import com.msnguard.vpn.sstp.unit.ppp.IpcpConfigureFrame
import com.msnguard.vpn.sstp.unit.ppp.Ipv6cpConfigureFrame
import com.msnguard.vpn.sstp.unit.ppp.LCPConfigureFrame
import com.msnguard.vpn.sstp.unit.ppp.LCPEchoRequest
import com.msnguard.vpn.sstp.unit.ppp.PPP_HDLC_HEADER
import com.msnguard.vpn.sstp.unit.ppp.PPP_PROTOCOL_CHAP
import com.msnguard.vpn.sstp.unit.ppp.PPP_PROTOCOL_EAP
import com.msnguard.vpn.sstp.unit.ppp.PPP_PROTOCOL_IP
import com.msnguard.vpn.sstp.unit.ppp.PPP_PROTOCOL_IPCP
import com.msnguard.vpn.sstp.unit.ppp.PPP_PROTOCOL_IPv6
import com.msnguard.vpn.sstp.unit.ppp.PPP_PROTOCOL_IPv6CP
import com.msnguard.vpn.sstp.unit.ppp.PPP_PROTOCOL_LCP
import com.msnguard.vpn.sstp.unit.ppp.PPP_PROTOCOL_PAP
import com.msnguard.vpn.sstp.unit.ppp.auth.ChapFrame
import com.msnguard.vpn.sstp.unit.ppp.auth.EAPFrame
import com.msnguard.vpn.sstp.unit.ppp.auth.PAPFrame
import com.msnguard.vpn.sstp.unit.sstp.ControlPacket
import com.msnguard.vpn.sstp.unit.sstp.SSTP_PACKET_TYPE_CONTROL
import com.msnguard.vpn.sstp.unit.sstp.SSTP_PACKET_TYPE_DATA
import com.msnguard.vpn.sstp.unit.sstp.SstpEchoRequest
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.nio.ByteBuffer


private const val SSTP_ECHO_INTERVAL = 20_000L
private const val PPP_ECHO_INTERVAL = 20_000L

internal class IncomingManager(internal val bridge: SharedBridge) {
    private val bufferSize = bridge.sslTerminal!!.getApplicationBufferSize() + MAX_MRU + 8 // MAX_MRU + 8 for fragment

    private var jobMain: Job? = null

    internal var lcpMailbox: Channel<LCPConfigureFrame>? = null
    internal var papMailbox: Channel<PAPFrame>? = null
    internal var chapMailbox: Channel<ChapFrame>? = null
    internal var eapMailbox: Channel<EAPFrame>? = null
    internal var ipcpMailbox: Channel<IpcpConfigureFrame>? = null
    internal var ipv6cpMailbox: Channel<Ipv6cpConfigureFrame>? = null
    internal var pppMailbox: Channel<Frame>? = null
    internal var sstpMailbox: Channel<ControlPacket>? = null

    private val sstpTimer = EchoTimer(SSTP_ECHO_INTERVAL) {
        SstpEchoRequest().also {
            bridge.sslTerminal!!.send(it.toByteBuffer())
        }
    }

    private val pppTimer = EchoTimer(PPP_ECHO_INTERVAL) {
        LCPEchoRequest().also {
            it.id = bridge.allocateNewFrameID()
            it.holder = "Abura Mashi Mashi".toByteArray(Charsets.US_ASCII)
            bridge.sslTerminal!!.send(it.toByteBuffer())
        }
    }

    internal fun <T> registerMailbox(client: T) {
        when (client) {
            is LCPClient -> lcpMailbox = client.mailbox
            is PAPClient -> papMailbox = client.mailbox
            is ChapClient -> chapMailbox = client.mailbox
            is EAPClient -> eapMailbox = client.mailbox
            is IpcpClient -> ipcpMailbox = client.mailbox
            is Ipv6cpClient -> ipv6cpMailbox = client.mailbox
            is PPPClient -> pppMailbox = client.mailbox
            is SstpClient -> sstpMailbox = client.mailbox
            else -> throw NotImplementedError(client?.toString() ?: "")
        }
    }

    internal fun <T> unregisterMailbox(client: T) {
        when (client) {
            is LCPClient -> lcpMailbox = null
            is PAPClient -> papMailbox = null
            is ChapClient -> chapMailbox = null
            is EAPClient -> eapMailbox = null
            is IpcpClient -> ipcpMailbox = null
            is Ipv6cpClient -> ipv6cpMailbox = null
            is PPPClient -> pppMailbox = null
            is SstpClient -> sstpMailbox = null
            else -> throw NotImplementedError(client?.toString() ?: "")
        }
    }

    internal fun launchJobMain() {
        jobMain = bridge.service.scope.launch(bridge.handler) {
            val buffer = ByteBuffer.allocate(bufferSize).also { it.limit(0) }

            sstpTimer.tick()
            pppTimer.tick()

            while (isActive) {
                if (!sstpTimer.checkAlive()) {
                    bridge.controlMailbox.send(
                        ControlMessage(Where.SSTP_CONTROL, Result.ERR_TIMEOUT)
                    )

                    return@launch
                }

                if (!pppTimer.checkAlive()) {
                    bridge.controlMailbox.send(
                        ControlMessage(Where.PPP, Result.ERR_TIMEOUT)
                    )

                    return@launch
                }


                val size = getPacketSize(buffer)
                when (size) {
                    in 4..bufferSize -> { }

                    -1 -> {
                        bridge.sslTerminal!!.receive(buffer)
                        continue
                    }

                    else -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.INCOMING, Result.ERR_INVALID_PACKET_SIZE)
                        )
                        return@launch
                    }
                }

                if (size > buffer.remaining()) {
                    bridge.sslTerminal!!.receive(buffer)
                    continue
                }

                sstpTimer.tick()

                when (buffer.probeShort(0)) {
                    SSTP_PACKET_TYPE_DATA -> {
                        if (buffer.probeShort(4) != PPP_HDLC_HEADER) {
                            bridge.controlMailbox.send(
                                ControlMessage(Where.SSTP_DATA, Result.ERR_UNKNOWN_TYPE)
                            )
                            return@launch
                        }

                        pppTimer.tick()

                        val protocol = buffer.probeShort(6)


                        // DATA
                        if (protocol == PPP_PROTOCOL_IP) {
                            processIPPacket(bridge.PPP_IPv4_ENABLED, size, buffer)
                            continue
                        }

                        if (protocol == PPP_PROTOCOL_IPv6) {
                            processIPPacket(bridge.PPP_IPv6_ENABLED, size, buffer)
                            continue
                        }
                        

                        // CONTROL
                        val code = buffer.probeByte(8)
                        val isGo = when (protocol) {
                            PPP_PROTOCOL_LCP -> processLcpFrame(code, buffer)
                            PPP_PROTOCOL_PAP -> processPAPFrame(code, buffer)
                            PPP_PROTOCOL_CHAP -> processChapFrame(code, buffer)
                            PPP_PROTOCOL_EAP -> processEAPFrame(code, buffer)
                            PPP_PROTOCOL_IPCP -> processIpcpFrame(code, buffer)
                            PPP_PROTOCOL_IPv6CP -> processIpv6cpFrame(code, buffer)
                            else -> processUnknownProtocol(protocol, size, buffer)
                        }

                        if (!isGo) {
                            return@launch
                        }
                    }

                    SSTP_PACKET_TYPE_CONTROL -> {
                        if (!processControlPacket(buffer.probeShort(4), buffer)) {
                            return@launch
                        }
                    }

                    else -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.INCOMING, Result.ERR_UNKNOWN_TYPE)
                        )

                        return@launch
                    }
                }
            }
        }
    }

    private fun getPacketSize(buffer: ByteBuffer): Int {
        return if (buffer.remaining() < 4) {
            -1
        } else {
            buffer.probeShort(2).toIntAsUShort()
        }
    }

    internal fun cancel() {
        jobMain?.cancel()
    }
}
