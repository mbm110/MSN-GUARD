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

    /**
     * True while a proxy-only session is live.
     *
     * Set by the service, because in proxy mode NOTHING else in this object can
     * tell: the Rust core is not started and tun2socks is not started, so
     * [isActive] would answer false over a perfectly working Psiphon proxy and
     * every UI surface — dial, tile, header, the connect/disconnect decision in
     * MainActivity — would call it disconnected.
     */
    @Volatile
    var isProxyMode: Boolean = false
        internal set

    /**
     * True when either data path is up: Rust core (proxy/other protocols), any
     * shared TUN engine (VPN), the proxy-only Psiphon path — or Foxy's OWN Hev
     * engine, which lives outside TunEngineManager by design (isolated config,
     * timeouts and fd). Without it the dial, the tile and the header all read a
     * live Foxy session as "Disconnected" and a second tile tap routes to
     * ACTION_CONNECT, which silently no-ops behind the connected guard.
     */
    fun isActive(): Boolean = NativeCore.isRunning() || TunEngineManager.isRunningAny ||
        isProxyMode || com.msnguard.vpn.foxy.FoxyHevEngine.isRunning ||
        LanternEngine.isSessionActive

    /**
     * True when the whole device is being routed through tun2socks.
     *
     * Deliberately NOT true in proxy mode — that is the entire distinction the
     * setting exists to make, and anything asking this question wants the honest
     * answer (e.g. the header's "all apps protected" claim).
     */
    val isWholeDeviceRouting: Boolean
        get() = TunEngineManager.isRunningAny || LanternEngine.isSessionActive ||
            com.msnguard.vpn.foxy.FoxyHevEngine.isRunning

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

    /**
     * MSN 3.4.23: the service's LAST broadcast status, set inside sendStatus.
     *
     * Why this exists (field bug, 2026-11): tap Connect, screen off while the
     * dial still reads CONNECTING. The service connects in the background is
     * fine — but its STATUS_CONNECTED broadcast reaches nobody, because
     * MainActivity unregisters its receiver in onStop. On return the screen
     * stays "Connecting" forever over a working tunnel: adoptRunningTunnel
     * refuses to touch a CONNECTING paint ("the gate owns the paint") and the
     * gate never started, so nobody republishes the state.
     *
     * This field is the replay path: it is written exactly where the broadcast
     * is sent, so "last status == CONNECTED" is the same fact the missed
     * broadcast carried — no guessing, no probing, no battery. The activity
     * reads it on resume/recreate to detect a missed edge and feeds it to the
     * SAME verification gate the broadcast would have reached
     * (beginVerification), so the screen still never claims connected on a
     * handshake-only tunnel.
     */
    @Volatile
    var lastServiceStatus: String = ""
        internal set

    /**
     * The UI's verification gate is still proving that payload crosses.
     *
     * The service's "connected" (the SOCKS listener answered) and the dial's
     * "connected" (beginVerification passed a real probe through the tunnel)
     * are two different moments by design — the gate exists to catch
     * handshake-only tunnels. The notification reads these so its row and the
     * screen never disagree: while [uiVerifying] is set the row still says
     * "Connecting…", and it claims "VPN connected" only once the UI itself
     * did ([sessionVerified]). Set by MainActivity, cleared by both sides.
     */
    @Volatile
    var uiVerifying: Boolean = false
        internal set

    /** The UI's verification passed for this session; see [uiVerifying]. */
    @Volatile
    var sessionVerified: Boolean = false
        internal set
}
