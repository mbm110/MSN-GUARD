package com.msnguard.vpn.sstp.extension

import com.msnguard.vpn.sstp.*

internal fun Byte.toIntAsUByte(): Int {
    return this.toInt() and 0x000000FF
}
