package studio.cluvex.aethery

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
 */
object TunnelStatus {

    /** True when either data path is up: Rust core (proxy/other protocols) or tun2socks (VPN). */
    fun isActive(): Boolean = NativeCore.isRunning() || Tun2SocksManager.isRunning

    /** True when the whole device is being routed through tun2socks. */
    val isWholeDeviceRouting: Boolean
        get() = Tun2SocksManager.isRunning
}
