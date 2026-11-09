package com.msnguard.vpn

import android.content.Context
import android.os.ParcelFileDescriptor

/**
 * Abstraction over the three TUN→SOCKS engines.
 *
 * badvpn (Tun2SocksManager) owns a full lwIP stack; Zeptun and Hev each own
 * theirs. All three expose "take a TUN fd and pump it into a SOCKS5 listener".
 * This interface makes the choice swappable without touching MsnGuardVpnService
 * call sites more than once.
 *
 * Thread-safety: every method is called from MsnGuardVpnService's worker
 * thread, never concurrently. isRunning may be read from any thread.
 */
interface TunEngine {
    val label: String
    val isRunning: Boolean
    fun start(fd: ParcelFileDescriptor, socksPort: Int, mtu: Int, dnsOnly: Boolean): Boolean
    fun stop()
}

object TunEnginePref {
    const val KEY = "tun_engine"
    const val LEGACY = "legacy"   // badvpn Tun2SocksManager
    const val ZEPTUN = "zeptun"
    const val HEV = "hev"
    private val ALL = setOf(LEGACY, ZEPTUN, HEV)

    fun get(ctx: Context): String {
        val v = ctx.profiled().getString(KEY, LEGACY) ?: LEGACY
        return if (v in ALL) v else LEGACY
    }
    fun label(key: String, ctx: Context): String = when (key) {
        ZEPTUN -> Strings.t("Zeptun")
        HEV    -> Strings.t("Hev Tun2Socks")
        else   -> Strings.t("BadVPN Tun2Socks")
    }
    fun description(key: String): String = when (key) {
        ZEPTUN -> Strings.t("High speed & low latency · Next-gen kernel engine")
        HEV    -> Strings.t("Lightweight & stable · Low battery consumption")
        else   -> Strings.t("High compatibility · Best for older Android versions")
    }
}

object TunEngineManager {
    // Lazily resolved — each engine object is an `object` so class loading
    // does not trigger native load until the engine is actually chosen.

    fun current(ctx: Context): TunEngine = when (TunEnginePref.get(ctx)) {
        TunEnginePref.ZEPTUN -> ZeptunEngine
        TunEnginePref.HEV    -> HevEngine
        else                 -> LegacyEngine
    }

    /** For TunnelStatus / health checks: true if any engine is routing. */
    val isRunningAny: Boolean
        get() = try { LegacyEngine.isRunning || ZeptunEngine.isRunning || HevEngine.isRunning } catch (_: Throwable) { false }

    /** Unified isRunning for the selected engine — with fallback probe. */
    fun isRunning(ctx: Context): Boolean = try { current(ctx).isRunning } catch (_: Throwable) { LegacyEngine.isRunning }

    /** Start the engine selected in prefs. Falls back to legacy on link error. */
    fun start(ctx: Context, fd: ParcelFileDescriptor, socksPort: Int, mtu: Int = Tun2SocksManager.VPN_INTERFACE_MTU, dnsOnly: Boolean = false, psiphon: Boolean = false): Boolean {
        val engine = current(ctx)
        return try {
            val ok = if (psiphon && engine === ZeptunEngine) {
                ZeptunEngine.startPsiphon(fd, socksPort, mtu, dnsOnly)
            } else engine.start(fd, socksPort, mtu, dnsOnly)
            if (!ok) {
                ConnectionLog.record("TunEngine ${engine.label} start returned false, falling back to Legacy")
                if (engine !== LegacyEngine) LegacyEngine.start(fd, socksPort, mtu, dnsOnly) else false
            } else ok
        } catch (e: UnsatisfiedLinkError) {
            ConnectionLog.record("TunEngine ${engine.label} missing native lib: ${e.message}, falling back to Legacy")
            try { LegacyEngine.start(fd, socksPort, mtu, dnsOnly) } catch (_: Throwable) { false }
        } catch (e: Throwable) {
            ConnectionLog.record("TunEngine ${engine.label} start failed: ${e.message}, falling back to Legacy")
            try { LegacyEngine.start(fd, socksPort, mtu, dnsOnly) } catch (_: Throwable) { false }
        }
    }

    fun stop(ctx: Context) {
        // Stop the selected engine first; also stop legacy if it happens to be
        // running (e.g. after a fallback). Ordering matters: only one should be
        // active but be defensive.
        try { current(ctx).stop() } catch (_: Throwable) {}
        try { if (LegacyEngine.isRunning) LegacyEngine.stop() } catch (_: Throwable) {}
        // Also stop the *other* engines if they were left running after a pref
        // change mid-session — prevents two lwIP instances asserting have_netif.
        try { if (ZeptunEngine.isRunning) ZeptunEngine.stop() } catch (_: Throwable) {}
        try { if (HevEngine.isRunning) HevEngine.stop() } catch (_: Throwable) {}
    }

    /** No-Context variant — stops all engines (used where no Context is handy). */
    fun stopAll() {
        try { if (LegacyEngine.isRunning) LegacyEngine.stop() } catch (_: Throwable) {}
        try { if (ZeptunEngine.isRunning) ZeptunEngine.stop() } catch (_: Throwable) {}
        try { if (HevEngine.isRunning) HevEngine.stop() } catch (_: Throwable) {}
    }

    /** Refresh Tun2SocksManager.privateAddress so engines that read it (Hev) match Builder's addresses. */
    fun syncPrivateAddress(addr: Tun2SocksManager.PrivateAddress) {
        Tun2SocksManager.privateAddress = addr
    }

    /** Used by MsnGuardVpnService chain/shard/tor to pick a private subnet without duplicating logic. */
    fun selectPrivateAddress(): Tun2SocksManager.PrivateAddress = Tun2SocksManager.selectPrivateAddress()
}
