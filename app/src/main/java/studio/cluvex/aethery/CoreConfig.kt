package studio.cluvex.aethery

import android.content.Context
import org.json.JSONObject
import java.io.File

object CoreConfig {
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

        val proxy = text("connection_type", "VPN") == "PROXY"
        val lan = prefs.getBoolean("lan_sharing", false)
        return JSONObject().apply {
            put("config_path", File(context.filesDir, "aether.toml").absolutePath)
            put("protocol", protocol ?: text("default_protocol", "masque"))
            put("listen", "${if (proxy && lan) "0.0.0.0" else "127.0.0.1"}:${prefs.getInt("default_socks_port", 1819)}")
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
            put("h2_fragmentation", text("h2_fragmentation", "off") == "on")
            putOpt("dns_servers", text("dns_servers").ifBlank { null })
            putOpt("route_block", text("route_block").ifBlank { null })
            putOpt("route_direct", text("route_direct").ifBlank { null })
            putOpt("team", text("zero_trust_team").ifBlank { null })
            putOpt("access_client_id", text("zero_trust_client_id").ifBlank { null })
            putOpt("access_client_secret", text("zero_trust_client_secret").ifBlank { null })
            putOpt("access_token", text("zero_trust_token").ifBlank { null })
            putOpt("access_email", text("zero_trust_email").ifBlank { null })
            put("gateway", prefs.getBoolean("zero_trust_gateway", false))
        }.toString()
    }
}
