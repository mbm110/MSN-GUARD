package com.msnguard.vpn.foxy

/** Minimal settings surface for the Foxy transport in MSN-GUARD. */
object FoxySettings {
    enum class TlsSplitMode { OFF, FIRST_BYTE, SNI }

    /** Persisted location choice for the Foxy dial (null = Automatic). */
    const val COUNTRY_PREF_KEY = "foxy_selected_country"
    private const val COUNTRY_PREFS_FILE = "foxy_settings"
    private const val TLS_SPLIT_PREF_KEY = "foxy_tls_split_mode"
    private const val UPSTREAM_PROXY_PREF_KEY = "foxy_upstream_proxy_enabled"
    private const val MTU_PREF_KEY = "foxy_mtu"
    private const val MULTIPLEX_PREF_KEY = "foxy_multiplex_streams"

    private fun prefs(ctx: android.content.Context): android.content.SharedPreferences =
        ctx.getSharedPreferences(COUNTRY_PREFS_FILE, android.content.Context.MODE_PRIVATE)

    fun selectedCountryCode(ctx: android.content.Context): String? =
        prefs(ctx).getString(COUNTRY_PREF_KEY, null)?.trim()?.takeIf { it.isNotBlank() }

    fun saveSelectedCountryCode(ctx: android.content.Context, code: String?) {
        prefs(ctx).edit()
            .putString(COUNTRY_PREF_KEY, code?.trim()?.takeIf { it.isNotBlank() })
            .apply()
    }

    fun tlsSplitMode(ctx: android.content.Context): TlsSplitMode =
        runCatching { TlsSplitMode.valueOf(prefs(ctx).getString(TLS_SPLIT_PREF_KEY, TlsSplitMode.OFF.name)!!) }
            .getOrDefault(TlsSplitMode.OFF)

    fun saveTlsSplitMode(ctx: android.content.Context, mode: TlsSplitMode) {
        prefs(ctx).edit().putString(TLS_SPLIT_PREF_KEY, mode.name).apply()
    }

    fun upstreamProxyEnabled(ctx: android.content.Context): Boolean =
        prefs(ctx).getBoolean(UPSTREAM_PROXY_PREF_KEY, false)

    fun saveUpstreamProxyEnabled(ctx: android.content.Context, enabled: Boolean) {
        prefs(ctx).edit().putBoolean(UPSTREAM_PROXY_PREF_KEY, enabled).apply()
    }

    fun mtu(ctx: android.content.Context): Int = prefs(ctx).getInt(MTU_PREF_KEY, 1400).coerceIn(1280, 1500)
    fun saveMtu(ctx: android.content.Context, mtu: Int) {
        prefs(ctx).edit().putInt(MTU_PREF_KEY, mtu.coerceIn(1280, 1500)).apply()
    }

    fun multiplexStreams(ctx: android.content.Context): Int = prefs(ctx).getInt(MULTIPLEX_PREF_KEY, 32).coerceIn(1, 64)
    fun saveMultiplexStreams(ctx: android.content.Context, streams: Int) {
        prefs(ctx).edit().putInt(MULTIPLEX_PREF_KEY, streams.coerceIn(1, 64)).apply()
    }

    // ------------------------------------------------------------------
    // Relayer policy (FoxyVPN 2.0.3/2.0.4 port). Provider choice and the
    // custom relayer URL are user prefs; the candidate relayer list, routed
    // categories and failover codes still come from FoxyRemoteConfig.
    // ------------------------------------------------------------------

    private const val RELAYER_PROVIDER_PREF_KEY = "foxy_relayer_provider"
    private const val CUSTOM_RELAYER_URL_PREF_KEY = "foxy_custom_relayer_url"

    /** App context captured at init so the relayer interceptor (no Context
     *  in its signature) can read the user's relayer preferences. */
    @Volatile
    private var cachedContext: android.content.Context? = null

    fun init(context: android.content.Context) {
        cachedContext = context.applicationContext
    }

    fun relayerProvider(ctx: android.content.Context): String =
        prefs(ctx).getString(RELAYER_PROVIDER_PREF_KEY, null)?.trim()?.takeIf { it.isNotBlank() }
            ?: RELAYER_AUTOMATIC

    fun customRelayerUrl(ctx: android.content.Context): String =
        prefs(ctx).getString(CUSTOM_RELAYER_URL_PREF_KEY, null)?.trim().orEmpty()

    /** Provider without a Context (null when the app context was not captured). */
    internal fun relayerProviderOrNull(): String? = cachedContext?.let { relayerProvider(it) }

    /** Custom relayer URL without a Context ("" when unavailable). */
    internal fun customRelayerUrlOrNull(): String = cachedContext?.let { customRelayerUrl(it) } ?: ""

    fun saveRelayer(ctx: android.content.Context, provider: String, customUrl: String) {
        prefs(ctx).edit()
            .putString(RELAYER_PROVIDER_PREF_KEY, provider.trim())
            .putString(CUSTOM_RELAYER_URL_PREF_KEY, customUrl.trim())
            .apply()
    }

    /** Custom relayer URL validation for the settings row (http/https, host
     *  present) — the top-level helper lives in FoxyRelayer.kt. */
    fun validCustomRelayerUrl(value: String): Boolean = isValidRelayerUrl(value)

    // Compatibility defaults for existing call sites.
    fun tlsSplitMode(): TlsSplitMode = TlsSplitMode.OFF
    fun upstreamProxyEnabled(): Boolean = false
}

/** Fake-DNS range guard (ported helper): 100.64.0.0/10 netmask mapped range. */
object FoxySocksGuard {
    private val MAPDNS_NETWORK_BITS = 100L shl 24 or (64L shl 16)
    private val MAPDNS_NETMASK_BITS = 255L shl 24 or (192L shl 16)

    fun isFakeDnsAddress(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        var packed = 0L
        for (part in parts) {
            if (part.isEmpty() || part.length > 3) return false
            val octet = part.toIntOrNull() ?: return false
            if (octet !in 0..255) return false
            packed = (packed shl 8) or octet.toLong()
        }
        return (packed and MAPDNS_NETMASK_BITS) == MAPDNS_NETWORK_BITS
    }
}
