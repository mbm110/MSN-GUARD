package com.msnguard.vpn

import android.content.Context

class SplitTunnelSettings(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    enum class Mode(val label: String) {
        ALL("All apps"),
        INCLUDE("Only selected apps"),
        EXCLUDE("Exclude selected apps"),
    }

    fun mode(): Mode = preferences.getString(MODE, Mode.ALL.name)
        ?.let { runCatching { Mode.valueOf(it) }.getOrNull() }
        ?: Mode.ALL

    fun packages(): Set<String> = preferences.getStringSet(PACKAGES, emptySet()).orEmpty()

    fun save(mode: Mode, packages: Set<String>) {
        preferences.edit()
            .putString(MODE, mode.name)
            .putStringSet(PACKAGES, packages.toHashSet())
            .commit()
    }

    fun cleanup(installedPackages: Set<String>) {
        val current = packages()
        val filtered = current.filter { it in installedPackages }.toSet()
        if (filtered.size != current.size) {
            preferences.edit().putStringSet(PACKAGES, filtered).apply()
        }
    }

    private companion object {
        const val PREFERENCES = "split_tunneling"
        const val MODE = "mode"
        const val PACKAGES = "packages"
    }
}
