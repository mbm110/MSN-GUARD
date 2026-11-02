package com.msnguard.vpn.sstp.client.ppp.auth

import com.msnguard.vpn.sstp.*
import com.msnguard.vpn.sstp.ControlMessage
import com.msnguard.vpn.sstp.SharedBridge
import com.msnguard.vpn.sstp.Where
import com.msnguard.vpn.sstp.debug.assertAlways
import com.msnguard.vpn.sstp.extension.toIntAsUShort
import com.msnguard.vpn.sstp.unit.ppp.PPP_HEADER_SIZE
import com.msnguard.vpn.sstp.unit.ppp.auth.CHAP_CODE_CHALLENGE
import com.msnguard.vpn.sstp.unit.ppp.auth.CHAP_CODE_FAILURE
import com.msnguard.vpn.sstp.unit.ppp.auth.CHAP_CODE_RESPONSE
import com.msnguard.vpn.sstp.unit.ppp.auth.CHAP_CODE_SUCCESS
import com.msnguard.vpn.sstp.unit.ppp.auth.ChapMessageField
import com.msnguard.vpn.sstp.unit.ppp.auth.ChapValueNameFiled
import com.msnguard.vpn.sstp.unit.ppp.auth.EAPRequest
import com.msnguard.vpn.sstp.unit.ppp.auth.EAPResponse
import com.msnguard.vpn.sstp.unit.ppp.auth.EAP_TYPE_MS_AUTH
import java.nio.ByteBuffer

internal class EAPMSAuthClient(bridge: SharedBridge) : EAPClient(bridge) {
    override val algorithm = EAP_TYPE_MS_AUTH
    private var challengeID: Byte = 0
    private val authClient = MSCHAPV2Client(bridge)

    override suspend fun responseRequest(request: EAPRequest) {
        val wrapped = ByteBuffer.wrap(request.typeData)

        val opCode = wrapped.get()
        val givenInnerID = wrapped.get()
        val fieldLength = wrapped.getShort().toIntAsUShort() - PPP_HEADER_SIZE
        assertAlways(fieldLength == wrapped.remaining())

        when (opCode) {
            CHAP_CODE_CHALLENGE -> {
                isResultAcceptable = false // ensure this for (re)starting authentication
                challengeID = givenInnerID

                val response = ChapValueNameFiled().let {
                    it.givenLength = fieldLength
                    it.read(wrapped)

                    authClient.processChallenge(it)
                }

                EAPResponse().also {
                    it.id = request.id
                    it.type = EAP_TYPE_MS_AUTH

                    val header = ByteBuffer.allocate(PPP_HEADER_SIZE)
                    header.put(CHAP_CODE_RESPONSE)
                    header.put(challengeID)
                    header.putShort((PPP_HEADER_SIZE + response.length).toShort())

                    it.typeData = header.array() + response.toByteBuffer().array()

                    bridge.sslTerminal!!.send(it.toByteBuffer())
                }
            }

            CHAP_CODE_SUCCESS -> {
                assertAlways(givenInnerID == challengeID)

                val message = ChapMessageField().also {
                    it.givenLength = fieldLength
                    it.read(wrapped)
                }

                if (authClient.verifyAuthenticator(message)) {
                    isResultAcceptable = true
                    authClient.prepareHlak()

                    EAPResponse().also {
                        it.id = request.id
                        it.type = EAP_TYPE_MS_AUTH
                        it.typeData = ByteArray(1) { CHAP_CODE_SUCCESS }

                        bridge.sslTerminal!!.send(it.toByteBuffer())
                    }
                } else {
                    bridge.controlMailbox.send(
                        ControlMessage(Where.MSCHAPV2, Result.ERR_VERIFICATION_FAILED)
                    )
                }
            }

            CHAP_CODE_FAILURE -> {
                assertAlways(givenInnerID == challengeID)

                bridge.controlMailbox.send(
                    ControlMessage(Where.MSCHAPV2, Result.ERR_AUTHENTICATION_FAILED)
                )
            }
        }
    }
}
