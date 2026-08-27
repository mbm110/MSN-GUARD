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

    /**
     * Which transport last carried a PLAIN (unchained) tunnel far enough to move
     * real bytes, as a `CHAIN_OUTER_LADDER` entry — or absent if none ever has.
     *
     * Separate key from [CHAIN_OUTER_PREF] because they are different measurements
     * and must not overwrite each other:
     *
     *  - [CHAIN_OUTER_PREF] = "this transport carried Psiphon **inside** it". Direct
     *    evidence about the chain.
     *  - this key = "this transport reached the internet on this carrier **on its
     *    own**". Weaker evidence for the chain — carrying Psiphon is a harder job
     *    than carrying ordinary traffic — but far better than the static ladder
     *    order when the chain has no history yet.
     *
     * So the chain's own memory always wins; this is only consulted when it is
     * absent. See [MsnGuardVpnService.raiseOuterLeg].
     *
     * Written only after the byte threshold in
     * [MsnGuardVpnService.recordWorkingPlainTransport] — a handshake is not
     * evidence, which is the whole lesson of the fake-connected bugs.
     */
    const val PLAIN_WORKING_TRANSPORT_PREF = "plain_working_transport"


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

    /**
     * Which transport the user pinned for the chain's outer leg, or "auto".
     *
     * Separate from [CHAIN_OUTER_PREF]: this is a choice, that is a measurement.
     * Pinning is for the case where the user already knows what their carrier
     * allows and does not want to sit through the search — the automatic ladder
     * remains the default because it is right without being told anything.
     */
    const val CHAIN_OUTER_MODE_PREF = "chain_outer_mode"

    /**
     * Tor's own outer-transport pin. Separate key from [CHAIN_OUTER_MODE_PREF].
     *
     * The two inner tunnels have genuinely different outer needs, so one shared pin
     * would be wrong in both directions. Tor bootstraps through a SOCKS proxy and
     * cares only that it is reachable; Psiphon runs its own protocol ladder inside
     * and is far more sensitive to the outer leg's latency. A user who pins WoW to
     * get Psiphon through a hostile carrier should not thereby force every Tor
     * bootstrap through three stacked tunnels.
     *
     * Absent means auto, exactly as for Psiphon, so nothing changes for anyone who
     * never opens the row.
     */
    const val CHAIN_OUTER_MODE_TOR_PREF = "chain_outer_mode_tor"

    /** Value of [CHAIN_OUTER_MODE_PREF] meaning "try them all, in order". */
    const val CHAIN_OUTER_AUTO = "auto"

    /**
     * Which egress country the user asked Psiphon to try first, or "auto".
     *
     * A *preference*, not a constraint. Psiphon's own `EgressRegion` key is a hard
     * filter — set it and every server outside that country disappears from the
     * candidate pool — and pinning it for the whole session would break the one
     * path that works on the worst domestic operator: of the 430 embedded server
     * entries only 5 advertise FRONTED-MEEK, and all 5 are US/GB. So the country is
     * used for a single short attempt in front of the ladder, then dropped.
     *
     * Shared by both Psiphon paths (plain and chained) on purpose: the question
     * "which country do you want to come out in" has the same answer either way.
     *
     * Read only on the chained path, though — see
     * [MsnGuardVpnService.armRegionPhase]. A plain Psiphon connect always takes
     * whichever server answers first, which is the fastest path and the behaviour
     * that predates this setting.
     */
    const val EGRESS_REGION_PREF = "psiphon_egress_region"

    /** Value of [EGRESS_REGION_PREF] meaning "let Psiphon choose". */
    const val EGRESS_REGION_AUTO = "auto"

    /**
     * Whether Psiphon's local proxies listen on 0.0.0.0 instead of 127.0.0.1.
     *
     * Off by default, and deliberately so: binding to 0.0.0.0 exposes an OPEN,
     * UNAUTHENTICATED proxy to every device that can reach the phone. On a hotspot
     * that is only the tethered clients, but on a public Wi-Fi it is everyone on
     * the network, and psiphon-tunnel-core has no authentication for its local
     * proxies. It is a real exposure, not a theoretical one, so it stays an
     * explicit opt-in with the risk stated in the UI rather than a silent default.
     *
     * Psiphon-only. MASQUE, WireGuard and WoW take the `tun_fd` branch in the Rust
     * core and never bind a local listener at all, so there is nothing to share;
     * Tor's SOCKS front is TCP-only and stays on loopback.
     */
    const val LAN_SHARING_PREF = "psiphon_lan_sharing"

    /**
     * HTTP proxy port for LAN sharing, alongside SOCKS on [SOCKS_PORT].
     *
     * Both are offered because they are not interchangeable to the client: Windows
     * takes an HTTP proxy system-wide from Internet Options, while SOCKS has to be
     * configured per-application. 8080 is the conventional choice and does not
     * collide with anything else this app binds.
     */
    const val HTTP_PROXY_PORT = 8080

    /** Whether the user has opted into exposing the local proxies on the LAN. */
    fun lanSharingEnabled(context: Context): Boolean =
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getBoolean(LAN_SHARING_PREF, false)

    /**
     * The phone's own address on the local network, or null when it has none.
     *
     * Used to show the user the address to type on the other device. Skips loopback
     * and the app's own TUN addresses — 10.0.0.1 and friends from
     * [Tun2SocksManager.selectPrivateAddress] are ours, not reachable from the LAN,
     * and offering one would send the user chasing an address that cannot work.
     */
    fun localNetworkAddress(): String? {
        val interfaces = try {
            java.net.NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        } catch (_: java.net.SocketException) {
            return null
        }
        // Tethering interfaces first: when a user shares their VPN, the client is
        // almost always on the hotspot, and that address is the one that works.
        val ordered = interfaces.sortedBy { nic ->
            val name = nic.name.orEmpty()
            when {
                name.startsWith("ap") || name.startsWith("swlan") || name.startsWith("rndis") -> 0
                name.startsWith("wlan") -> 1
                else -> 2
            }
        }
        for (nic in ordered) {
            if (!runCatching { nic.isUp }.getOrDefault(false)) continue
            if (runCatching { nic.isLoopback }.getOrDefault(true)) continue
            // Our own TUN. Named tun0 on every Android release that matters here.
            if (nic.name.orEmpty().startsWith("tun")) continue
            for (address in nic.inetAddresses) {
                if (address !is java.net.Inet4Address) continue
                if (address.isLoopbackAddress) continue
                val text = address.hostAddress ?: continue
                if (!address.isSiteLocalAddress && !text.startsWith("169.254")) continue
                return text
            }
        }
        return null
    }

    /**
     * The preferred egress country, or null when the user has not picked one.
     *
     * Anything that is not two ASCII letters is treated as "auto" rather than
     * passed through: an invalid region would silently empty Psiphon's candidate
     * pool and every rung would then fail for a reason that looks like censorship.
     */
    fun egressRegion(context: Context): String? {
        val stored = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getString(EGRESS_REGION_PREF, EGRESS_REGION_AUTO)
            ?.trim()
            ?.uppercase()
            .orEmpty()
        if (stored.isEmpty() || stored.equals(EGRESS_REGION_AUTO, ignoreCase = true)) return null
        return if (PsiphonRegions.isCode(stored)) stored else null
    }


    /**
     * The transports this connect may use for the outer leg.
     *
     * Auto returns the whole ladder. A pinned transport returns only itself — no
     * silent fallback, because a pin exists precisely to stop the app spending time
     * on transports the user knows are blocked. A stale or unknown pin falls back
     * to auto rather than producing an empty ladder.
     *
     * [forTor] selects Tor's pin instead of Psiphon's. The caller has to say which
     * inner tunnel it is raising the leg for, since the two keys are independent.
     */
    fun chainOuterCandidates(context: Context, forTor: Boolean = false): List<String> {
        val key = if (forTor) CHAIN_OUTER_MODE_TOR_PREF else CHAIN_OUTER_MODE_PREF
        val mode = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .getString(key, CHAIN_OUTER_AUTO)
            ?.trim()
            .orEmpty()
        return when {
            mode.isEmpty() || mode == CHAIN_OUTER_AUTO -> CHAIN_OUTER_LADDER
            CHAIN_OUTER_LADDER.contains(mode) -> listOf(mode)
            else -> CHAIN_OUTER_LADDER
        }
    }

    /** Whether the outer transport is being chosen automatically. */
    fun chainOuterIsAuto(context: Context, forTor: Boolean = false): Boolean =
        chainOuterCandidates(context, forTor).size > 1

    /** Human-readable name for a rung of [CHAIN_OUTER_LADDER]. */
    fun chainOuterLabel(protocol: String): String = when (protocol) {
        "masque" -> "MASQUE"
        "wireguard" -> "WireGuard"
        "gool" -> "WoW"
        else -> protocol.uppercase()
    }
}
