package com.msnguard.vpn

/**
 * Single source of truth for "is a tunnel carrying traffic right now".
 *
 * Before badvpn this was just NativeCore.isRunning(), because the Rust core was
 * in every data path. In VPN mode the data path is now lwIP inside
 * libtun2socks.so and the Rust core is never started — so NativeCore.isRunning()
 * returns false while the device is fully tunnelled. Every UI surface that asked
 * NativeCore directly therefore reported "Not Connected" on a working tunnel.
 *
 * Ask this object instead of NativeCore.isRunning() anywhere the question is
 * "should the UI look connected". Ask NativeCore directly only when the question
 * is specifically about the Rust core (e.g. routing an HTTP check through its
 * local SOCKS listener in proxy mode).
 *
 * The app is single-process (no android:process in the manifest), so the service
 * and the activity see the same statics here.
 */
object TunnelStatus {

    /** True when either data path is up: Rust core (proxy/other protocols) or tun2socks (VPN). */
    fun isActive(): Boolean = NativeCore.isRunning() || Tun2SocksManager.isRunning

    /** True when the whole device is being routed through tun2socks. */
    val isWholeDeviceRouting: Boolean
        get() = Tun2SocksManager.isRunning

    /**
     * True while the Rust core is driving an Android TUN directly.
     *
     * This is the WireGuard / MASQUE VPN-mode data path: `aether_start_json_with_tun`
     * takes the `Some(fd)` branch in main.rs and spawns `tun::bridge`, so
     * `socks::serve` — which lives in the `else` arm — never runs and **no local
     * SOCKS listener exists**.
     *
     * Anything that wants to send a request "through the tunnel" must go direct
     * in this mode. Dialling 127.0.0.1:<socksPort> gets connection-refused, which
     * is what made the health check fail and paint "Connection degraded" over a
     * perfectly working WireGuard tunnel.
     */
    @Volatile
    var isNativeTunMode: Boolean = false
        internal set
}
