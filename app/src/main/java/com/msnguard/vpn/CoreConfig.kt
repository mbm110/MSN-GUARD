package com.msnguard.vpn

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

    /**
     * Where the Rust core publishes its SOCKS5 listener in Psiphon-over-WARP mode.
     *
     * Must differ from [SOCKS_PORT]: in that mode both listeners exist at once —
     * the core's (WARP, the outer leg) and Psiphon's (the inner leg, which
     * tun2socks dials). Reusing one port would make the second bind fail and the
     * chain would silently collapse to whichever came up first.
     */
    const val CHAIN_SOCKS_PORT = 1820

    /**
     * Which outer transport last carried the chain on this device.
     *
     * An index into [CHAIN_OUTER_LADDER]. The next connect starts there instead of
     * walking the whole ladder again, so a SIM that needs WireGuard pays the MASQUE
     * timeout only once, ever.
     */
    const val CHAIN_OUTER_PREF = "chain_outer_index"

    fun json(context: Context, protocol: String? = null): String =
        json(context, protocol, listenOverride = null)

    /**
     * @param listenOverride binds the core's SOCKS listener somewhere other than
     *   [SOCKS_PORT]. Only the outer leg of Psiphon-over-WARP uses this: Psiphon
     *   owns [SOCKS_PORT] in that mode, so the core has to move aside.
     */
    fun json(context: Context, protocol: String?, listenOverride: Int?): String {
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
            put("listen", "127.0.0.1:${listenOverride ?: SOCKS_PORT}")
            put("scan_mode", text("default_scan_mode", "balanced"))
            put("ip_scan", text("default_scan", "v4"))
            put("endpoint_cache_path", File(context.filesDir, "masque-gateway-cache.json").absolutePath)
            put("endpoint_discovery", text("endpoint_discovery", "cache"))
            put("masque_transport", text("default_masque_transport", "h3"))
            // A manual peer pins ONE address, and it belongs to whichever transport
            // the user entered it for. Handing it to the chain's ladder would send a
            // MASQUE gateway to the WireGuard rung, where it cannot work — so the
            // chain's outer legs always scan.
            if (listenOverride == null) {
                putOpt("forced_peer", text("manual_endpoint").ifBlank { null })
            }
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
            // Psiphon-over-WARP: the core's SOCKS listener is the upstream proxy
            // Psiphon dials, so the core itself needs no upstream. Left unset.
        }.toString()
    }

    /**
     * Config for the OUTER leg of Psiphon-over-WARP.
     *
     * Differences from a normal connect, each one load-bearing:
     *  - `protocol` is a WARP transport, never "psiphon"; the chain's Psiphon half
     *    is the Go library, not the core.
     *  - `listen` moves to [CHAIN_SOCKS_PORT] because Psiphon keeps [SOCKS_PORT].
     *  - no `tun_fd` is passed by the caller (see NativeCore.startProxy), so the
     *    core runs its userspace netstack and publishes SOCKS instead of taking
     *    the device TUN — tun2socks owns that, on Psiphon's side.
     *
     * @param protocol which WARP transport carries this attempt. The service walks
     *   [CHAIN_OUTER_LADDER] and calls this once per rung, so the choice belongs to
     *   the caller rather than to a stored preference.
     */
    fun chainOuterJson(context: Context, protocol: String): String =
        json(context, protocol, listenOverride = CHAIN_SOCKS_PORT)

    /**
     * The outer transports tried, in order, until one carries Psiphon.
     *
     * Ordered by measured likelihood of working on an Iranian carrier, cheapest
     * first:
     *
     *  - `masque` leads because it has two transports of its own (HTTP/3 over
     *    UDP/443, then HTTP/2 over TCP/443 with TLS fragmentation) and a gateway
     *    cache plus a last-known-good endpoint, so a repeat connect is fast.
     *  - `wireguard` next: it is blocked outright on some carriers (Hamrah-e-Aval
     *    has never carried it) but connects immediately on others.
     *  - `gool` last. It is WARP-on-WARP, so it stacks two tunnels under Psiphon
     *    for three in total — the slowest rung, and only worth reaching when the
     *    single-layer ones are blocked.
     *
     * The rung that works is remembered per device, so this ordering only decides
     * the very first attempt.
     */
    val CHAIN_OUTER_LADDER = listOf("masque", "wireguard", "gool")

    /** Human-readable name for a rung of [CHAIN_OUTER_LADDER]. */
    fun chainOuterLabel(protocol: String): String = when (protocol) {
        "masque" -> "MASQUE"
        "wireguard" -> "WireGuard"
        "gool" -> "WoW"
        else -> protocol.uppercase()
    }
}
