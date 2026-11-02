package com.msnguard.vpn.sstp.client.ppp

import com.msnguard.vpn.sstp.*
import com.msnguard.vpn.sstp.ControlMessage
import com.msnguard.vpn.sstp.SharedBridge
import com.msnguard.vpn.sstp.Where
import com.msnguard.vpn.sstp.unit.ppp.Frame
import com.msnguard.vpn.sstp.unit.ppp.LCPCodeReject
import com.msnguard.vpn.sstp.unit.ppp.LCPEchoReply
import com.msnguard.vpn.sstp.unit.ppp.LCPEchoRequest
import com.msnguard.vpn.sstp.unit.ppp.LCPProtocolReject
import com.msnguard.vpn.sstp.unit.ppp.LCPTerminalAck
import com.msnguard.vpn.sstp.unit.ppp.LCPTerminalRequest
import com.msnguard.vpn.sstp.unit.ppp.LcpDiscardRequest
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch


internal class PPPClient(val bridge: SharedBridge) {
    internal val mailbox = Channel<Frame>(Channel.BUFFERED)

    private var jobControl: Job? = null

    internal fun launchJobControl() {
        jobControl = bridge.service.scope.launch(bridge.handler) {
            while (isActive) {
                when (val received = mailbox.receive()) {
                    is LCPEchoRequest -> {
                        LCPEchoReply().also {
                            it.id = received.id
                            it.holder = "Abura Mashi Mashi".toByteArray(Charsets.US_ASCII)
                            bridge.sslTerminal!!.send(it.toByteBuffer())
                        }
                    }

                    is LCPEchoReply -> { }

                    is LcpDiscardRequest -> { }

                    is LCPTerminalRequest -> {
                        LCPTerminalAck().also {
                            it.id = received.id
                            bridge.sslTerminal!!.send(it.toByteBuffer())
                        }

                        bridge.controlMailbox.send(
                            ControlMessage(Where.PPP, Result.ERR_TERMINATE_REQUESTED)
                        )
                    }

                    is LCPProtocolReject -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.PPP, Result.ERR_PROTOCOL_REJECTED)
                        )
                    }

                    is LCPCodeReject -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.PPP, Result.ERR_CODE_REJECTED)
                        )
                    }

                    else -> {
                        bridge.controlMailbox.send(
                            ControlMessage(Where.PPP, Result.ERR_UNEXPECTED_MESSAGE)
                        )
                    }
                }
            }
        }
    }

    internal fun cancel() {
        jobControl?.cancel()
        mailbox.close()
    }
}
