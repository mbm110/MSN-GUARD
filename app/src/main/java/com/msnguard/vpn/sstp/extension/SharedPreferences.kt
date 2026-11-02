package com.msnguard.vpn.sstp.extension

import com.msnguard.vpn.sstp.*
import android.content.SharedPreferences
import androidx.core.content.edit
import com.msnguard.vpn.sstp.TEMP_KEY_HEADER


internal fun SharedPreferences.removeTemporaryPreferences() {
    edit {
        all.keys.filter { it.startsWith(TEMP_KEY_HEADER) }.forEach { remove(it) }
    }
}
