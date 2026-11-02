package com.msnguard.vpn.sstp.extension

import com.msnguard.vpn.sstp.*

internal fun Short.toIntAsUShort(): Int {
    return this.toInt() and 0x0000FFFF
}
