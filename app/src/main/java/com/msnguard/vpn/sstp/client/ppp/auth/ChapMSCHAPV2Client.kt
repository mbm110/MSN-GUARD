package com.msnguard.vpn.sstp.client.ppp.auth

import com.msnguard.vpn.sstp.*
import com.msnguard.vpn.sstp.ControlMessage
import com.msnguard.vpn.sstp.SharedBridge
import com.msnguard.vpn.sstp.Where
import com.msnguard.vpn.sstp.unit.ppp.auth.ChapChallenge
import com.msnguard.vpn.sstp.unit.ppp.auth.ChapFailure
import com.msnguard.vpn.sstp.unit.ppp.auth.ChapMessageFrame
import com.msnguard.vpn.sstp.unit.ppp.auth.ChapResponse
import com.msnguard.vpn.sstp.unit.ppp.auth.ChapSuccess


internal class ChapMSCHAPV2Client(bridge: SharedBridge) : ChapClient(bridge) {
    private val authClient = MSCHAPV2Client(bridge)

    override suspend fun responseChallenge(challenge: ChapChallenge) {
        ChapResponse().also {
            it.id = challengeID
            it.valueName = authClient.processChallenge(challenge.valueName)

            bridge.sslTerminal!!.send(it.toByteBuffer())
        }
    }

    override suspend fun processResult(result: ChapMessageFrame) {
        when (result) {
            is ChapSuccess -> {
                if (authClient.verifyAuthenticator(result.message)) {
                    authClient.prepareHlak()

                    bridge.controlMailbox.send(
                        ControlMessage(Where.CHAP, Result.PROCEEDED)
                    )
                } else {
                    bridge.controlMailbox.send(
                        ControlMessage(Where.MSCHAPV2, Result.ERR_VERIFICATION_FAILED)
                    )
                }
            }

            is ChapFailure -> {
                bridge.controlMailbox.send(
                    ControlMessage(Where.MSCHAPV2, Result.ERR_AUTHENTICATION_FAILED)
                )
            }
        }
    }
}
