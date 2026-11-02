package com.msnguard.vpn.sstp.extension

import com.msnguard.vpn.sstp.*
import android.net.Uri


internal fun sum(vararg words: String): String {
    var result = ""

    words.forEach {
        result += it
    }

    return result
}

internal fun String.toUri(): Uri? {
    return if (this.isEmpty()) {
        null
    } else {
        Uri.parse(this)
    }
}
