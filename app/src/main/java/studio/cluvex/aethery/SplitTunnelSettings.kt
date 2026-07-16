package studio.cluvex.aethery

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
            .putStringSet(PACKAGES, packages)
            .apply()
    }

    private companion object {
        const val PREFERENCES = "split_tunneling"
        const val MODE = "mode"
        const val PACKAGES = "packages"
    }
}
