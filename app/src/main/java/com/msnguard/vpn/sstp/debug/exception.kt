package com.msnguard.vpn.sstp.debug

import com.msnguard.vpn.sstp.*

internal class ParsingDataUnitException : Exception("Failed to parse data unit")

internal fun assertAlways(value: Boolean) {
    if (!value) {
        throw AssertionError()
    }
}
