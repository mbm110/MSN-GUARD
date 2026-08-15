package studio.cluvex.aethery

import android.content.Context
import org.json.JSONObject
import java.io.File

object CoreConfig {
    /**
     * The one SOCKS port the app uses, everywhere.
     *
     * Was user-configurable, which served no purpose once proxy mode was removed:
     * in VPN mode nothing binds this port except Psiphon's own Go controller, and
     * the TUN is created *before* Psiphon starts, so the port has to be known up
     * front anyway. Hardcoding it removes a setting that could only break things.
     */
    const val SOCKS_PORT = 1819

    fun json(context: Context, protocol: String? = null): String {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        fun text(key: String, fallback: String = "") =
            prefs.getString(key, fallback)?.trim().orEmpty()
        val manualObfuscation = JSONObject().apply {
            text("obfuscation_jc").toIntOrNull()?.let { put("jc", it) }
            text("obfuscation_jmin").toIntOrNull()?.let { put("jmin", it) }
            text("obfuscation_jmax").toIntOrNull()?.let { put("jmax", it) }
            putOpt("i1", text("obfuscation_i1").ifBlank { null })
            putOpt("i2", text("obfuscation_i2").ifBlank { null })
        }

        return JSONObject().apply {
            put("config_path", File(context.filesDir, "aether.toml").absolutePath)
            put("protocol", protocol ?: text("default_protocol", "masque"))
            // The app is VPN-mode only: the whole device is tunnelled and there is
            // no user-facing proxy any more. `listen` is still sent because the
            // core requires the field, but in VPN mode no SOCKS listener is ever
            // bound from it — MASQUE/WireGuard/WARP-on-WARP take the `tun_fd`
            // branch in main.rs, and Psiphon owns this port itself via
            // LocalSocksProxyPort. Fixed at 1819 so the TUN can be pre-created
            // before Psiphon starts.
            put("listen", "127.0.0.1:$SOCKS_PORT")
            put("scan_mode", text("default_scan_mode", "balanced"))
            put("ip_scan", text("default_scan", "v4"))
            put("endpoint_cache_path", File(context.filesDir, "masque-gateway-cache.json").absolutePath)
            put("endpoint_discovery", text("endpoint_discovery", "cache"))
            put("masque_transport", text("default_masque_transport", "h3"))
            putOpt("forced_peer", text("manual_endpoint").ifBlank { null })
            put("obfuscation_profile", text("obfuscation_profile", "balanced"))
            putOpt("obfuscation_parameters", manualObfuscation.takeIf { it.length() > 0 }?.toString())
            put("retry_obfuscation_profiles", prefs.getBoolean("retry_obfuscation_profiles", true))
            put("tls_curve_preset", text("tls_curve_preset", "chrome"))
            put("wireguard_data_check", prefs.getBoolean("wireguard_data_check", true))
            put("log_level", text("log_level", "info"))
            put("perf_profile", text("perf_profile", "auto"))
            put("h2_fragmentation", text("h2_fragmentation", "on") == "on")
            putOpt("dns_servers", text("dns_servers").ifBlank { null })
            putOpt("route_block", text("route_block").ifBlank { null })
            putOpt("route_direct", text("route_direct").ifBlank { null })
            putOpt("team", SecureStore.getSecret(context, "zero_trust_team").ifBlank { null })
            putOpt("access_client_id", SecureStore.getSecret(context, "zero_trust_client_id").ifBlank { null })
            putOpt("access_client_secret", SecureStore.getSecret(context, "zero_trust_client_secret").ifBlank { null })
            putOpt("access_token", SecureStore.getSecret(context, "zero_trust_token").ifBlank { null })
            putOpt("access_email", SecureStore.getSecret(context, "zero_trust_email").ifBlank { null })
            put("gateway", prefs.getBoolean("zero_trust_gateway", false))
        }.toString()
    }
}
