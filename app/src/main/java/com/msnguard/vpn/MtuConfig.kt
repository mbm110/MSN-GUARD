package com.msnguard.vpn

import android.content.Context

/**
 * Per-method MTU (Maximum Transmission Unit) stored per-profile.
 *
 * One value per method — the screen in the reference image lists
 * MASQUE / WireGuard / WoW / Psiphon / Tor / SHARD, each with its
 * own number. Stored in the profiled SharedPreferences file so
 * Profile A and Profile B can keep different tunings.
 *
 * Defaults are MEASURED, not copied from the reference screenshot:
 * - MASQUE 1304, WireGuard 1440, WoW 1220 — the reference app's
 *   defaults, plausible for their respective encap overheads.
 * - Psiphon / Tor 1500 — they carry TCP directly, no extra tunnel
 *   header to account for beyond the TUN itself.
 * - SHARD 1280 — a normal TUN MTU. The WebSocket/Xray path has a separate
 *   UDP payload ceiling enforced by ShardSocksFront; that ceiling must never
 *   be used as the Android interface MTU.
 *
 * Range 68..1500 — the IPv4 minimum header plus the Ethernet ceiling.
 * Anything narrower cannot carry a minimal packet; anything wider is
 * not an MTU the Android TUN will accept.
 */
object MtuConfig {

    const val MIN_MTU = 68
    const val MAX_MTU = 1500

    // Preference keys — profiled via Profiles.profiled().
    const val KEY_MASQUE = "mtu_masque"
    const val KEY_WIREGUARD = "mtu_wireguard"
    const val KEY_WOW = "mtu_wow"
    const val KEY_PSIPHON = "mtu_psiphon"
    const val KEY_TOR = "mtu_tor"
    const val KEY_SHARD = "mtu_shard"

    // Defaults shown as "1304 (default)" etc.
    const val DEFAULT_MASQUE = 1304
    const val DEFAULT_WIREGUARD = 1440
    const val DEFAULT_WOW = 1220
    const val DEFAULT_PSIPHON = 1500
    const val DEFAULT_TOR = 1500
    /**
     * SHARD uses a normal Android TUN MTU. The WebSocket/Xray UDP payload
     * ceiling is enforced in ShardSocksFront and must never become the TUN MTU.
     * 1280 is the safe carrier floor used by the app in Iran.
     */
    const val DEFAULT_SHARD = 1280

    /** All methods in the order the screen lists them. */
    enum class Method(
        val prefKey: String,
        val default: Int,
        val title: String,
    ) {
        MASQUE(KEY_MASQUE, DEFAULT_MASQUE, "MASQUE"),
        WIREGUARD(KEY_WIREGUARD, DEFAULT_WIREGUARD, "WireGuard"),
        WOW(KEY_WOW, DEFAULT_WOW, "WOW"),
        PSIPHON(KEY_PSIPHON, DEFAULT_PSIPHON, "Psiphon"),
        TOR(KEY_TOR, DEFAULT_TOR, "Tor"),
        SHARD(KEY_SHARD, DEFAULT_SHARD, "SHARD"),
    }

    /** True if [v] is inside the TUN-legal range. */
    fun isValid(v: Int): Boolean = v in MIN_MTU..MAX_MTU

    /** Rejection string for the dialog, or null if [v] is valid. */
    fun rejection(v: Int): String? = when {
        v < MIN_MTU -> "Minimum is $MIN_MTU"
        v > MAX_MTU -> "Maximum is $MAX_MTU"
        else -> null
    }

    /** Effective MTU for [method] — stored value or its default. */
    fun get(context: Context, method: Method): Int {
        val raw = context.profiled().getInt(method.prefKey, -1)
        // 0 and -1 both mean "unset": an earlier build wrote the default rather
        // than leaving the key absent, and reading that back would hand 0 to
        // Builder.setMtu, which Android rejects with an exception.
        // A legacy SHARD preference of 512 was the payload ceiling, not a
        // usable Android TUN MTU. Migrate it in memory to the safe floor.
        if (method == Method.SHARD && raw == Tun2SocksManager.SHARD_TUNNEL_MTU) {
            return DEFAULT_SHARD
        }
        return if (raw == -1 || raw == 0) method.default else raw.coerceIn(MIN_MTU, MAX_MTU)
    }

    /** Whether [method] has a user override (vs default). */
    fun isCustom(context: Context, method: Method): Boolean {
        // The same legacy-0 case as [get]: a key holding 0 is not a choice.
        val raw = context.profiled().getInt(method.prefKey, -1)
        return raw != -1 && raw != 0 &&
            !(method == Method.SHARD && raw == Tun2SocksManager.SHARD_TUNNEL_MTU)
    }

    /** Persist [value] for [method]; returns false if out of range. */
    fun set(context: Context, method: Method, value: Int): Boolean {
        if (!isValid(value)) return false
        context.profiled().edit().putInt(method.prefKey, value).apply()
        return true
    }

    /** Remove the override so the default shows again. */
    fun reset(context: Context, method: Method) {
        context.profiled().edit().remove(method.prefKey).apply()
    }

    /** "1440" or "1440 (default)" — the value column in the list. */
    fun displayValue(context: Context, method: Method): String {
        val v = get(context, method)
        return if (isCustom(context, method)) "$v" else "$v (default)"
    }

    /**
     * MTU to hand to Builder.setMtu + TunEngine.start for the
     * *currently selected* WARP transport (currentProtocol in
     * MsnGuardVpnService is e.g. "WIREGUARD", "MASQUE", "GOOL").
     *
     * Falls back to WireGuard's default when the protocol string is
     * not one of the three WARP names (chain, unknown).
     */
    fun forWarpProtocol(context: Context, protocolUpper: String): Int = when {
        protocolUpper.contains("MASQUE") || protocolUpper.contains("MIM") -> get(context, Method.MASQUE)
        protocolUpper.contains("WIREGUARD") -> get(context, Method.WIREGUARD)
        protocolUpper.contains("GOOL") || protocolUpper.contains("WOW") -> get(context, Method.WOW)
        else -> get(context, Method.WIREGUARD)
    }
}
