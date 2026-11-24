package com.msnguard.vpn.foxy

import android.content.Context
import android.os.ParcelFileDescriptor
import com.msnguard.vpn.HevNativeLease
import hev.htproxy.TProxyService
import java.io.File
import java.util.concurrent.atomic.AtomicLong

/**
 * The FOXY transport's own Hev (hev-socks5-tunnel) engine.
 *
 * libhev is a process-wide singleton — one native tunnel per process — so
 * this object does not create a second native instance. What it DOES own is
 * everything the shared `HevEngine` used to share with it:
 *
 *  - its own config file (filesDir/foxy/hev-foxy-<port>.yml, written by
 *    [FoxyHevConfig] with the reference project's values),
 *  - its own dup'ed TUN fd, closed by this class and not by the shared
 *    engine, so a teardown on another transport can no longer take FOXY's
 *    interface down,
 *  - its own start/stop, so the "TUN engine" preference the user picked for
 *    WireGuard/MASQUE/Psiphon never reaches the FOXY path.
 *
 * The shared `HevEngine` is left exactly as it was for every other
 * transport; the only thing they share is the native thread, which cannot
 * run twice anyway.
 */
object FoxyHevEngine {

    /**
     * Raw fd detached from the dup and handed to libhev. detachFd() strips
     * ownership from the ParcelFileDescriptor, so this class must close it
     * itself — same contract as the shared engine.
     */
    @Volatile private var ownedFd: Int = -1

    @Volatile private var configPath: String? = null

    /**
     * Process-wide serialization of the native Hev singleton plus an epoch:
     * every start() bumps the epoch, so a detached stop thread from a previous
     * session that wakes up LATE can detect "a newer engine exists" and leave
     * the native thread alone instead of killing the new session's tunnel.
     */
    private val nativeLock = Any()
    private val nativeEpoch = AtomicLong(0L)

    /** True while this class owns the process-wide native Hev thread. */
    @Volatile private var ownsNative: Boolean = false

    val isRunning: Boolean
        get() = ownsNative && runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)

    private fun closeOwnedFd() {
        val fd = ownedFd
        ownedFd = -1
        if (fd < 0) return
        try { ParcelFileDescriptor.adoptFd(fd).close() } catch (_: Throwable) {}
    }

    /**
     * Start Hev on [fd], forwarding into 127.0.0.1:[socksPort].
     *
     * @param context used only to place the config file under filesDir/foxy.
     */
    fun start(fd: ParcelFileDescriptor, socksPort: Int, mtu: Int, context: Context): Boolean {
        // Invalidate any still-pending detached stop from a previous session:
        // from here on, that thread must not touch the native thread.
        nativeEpoch.incrementAndGet()
        // A leftover native instance (previous session, another transport) has
        // to go before ours can bind: libhev keeps one tunnel per process.
        // Under nativeLock so it cannot interleave with a pending stop thread.
        synchronized(nativeLock) {
            if (runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)) {
                FoxyLog.w(
                    TAG,
                    "a native Hev instance was already running — stopping it before starting FOXY's own",
                )
                runCatching { TProxyService.TProxyStopService() }
                ownsNative = false
            }
        }

        val dup = try { fd.dup() } catch (e: Exception) {
            FoxyLog.e(TAG, "could not dup the TUN fd", e)
            return false
        }
        val rawFd = try { dup.detachFd() } catch (e: Exception) {
            FoxyLog.e(TAG, "could not detach the TUN fd", e)
            try { dup.close() } catch (_: Exception) {}
            return false
        }
        ownedFd = rawFd

        val cfgFile = try {
            FoxyHevConfig.write(context, socksPort, mtu)
        } catch (e: Exception) {
            FoxyLog.e(TAG, "could not write the Hev config", e)
            closeOwnedFd()
            return false
        }
        configPath = cfgFile.absolutePath

        return try {
            // Under nativeLock: if a previous session's detached stop thread is
            // mid-join, start waits for it here (on the service worker, never
            // the main thread) instead of racing it for the native singleton.
            val ok = synchronized(nativeLock) {
                TProxyService.TProxyStartService(cfgFile.absolutePath, rawFd)
            }
            if (ok) {
                ownsNative = true
                // The lease records who owns the process-wide native thread so
                // the shared engine's teardown cannot touch ours.
                HevNativeLease.claim(HevNativeLease.FOXY)
                FoxyLog.i(
                    TAG,
                    "started → SOCKS 127.0.0.1:$socksPort mtu=$mtu (config ${cfgFile.name})",
                )
            } else {
                FoxyLog.e(TAG, "Hev start returned false (see logcat hev)")
                // libhev may still hold the fd on a failed start — ours is
                // unconditionally ours (detachFd), and a leak here leaves the
                // TUN interface up with no engine behind it.
                closeOwnedFd()
            }
            ok
        } catch (e: Throwable) {
            FoxyLog.e(TAG, "Hev start threw", e)
            closeOwnedFd()
            false
        }
    }

    /** Stop Hev and release everything this object owns. */
    fun stop() {
        // Psiphon-style detach + off-thread stop. stopTunnel() reaches here on
        // the MAIN thread (notification Disconnect / tile toggle) and
        // TProxyStopService does pthread_join — exactly the teardown that
        // froze the UI (v3.2.27 audit). start() already stops a leftover
        // native instance before binding, so a connect racing this stop is
        // safe; the epoch + nativeLock below additionally guarantee a LATE
        // stop can never kill a NEWER Hev instance (any engine's).
        ownsNative = false
        HevNativeLease.release(HevNativeLease.FOXY)
        val cfg = configPath
        configPath = null
        val fd = ownedFd
        ownedFd = -1
        val myEpoch = nativeEpoch.get()
        Thread({
            synchronized(nativeLock) {
                if (nativeEpoch.get() != myEpoch) return@synchronized
                try {
                    if (runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)) {
                        TProxyService.TProxyStopService()
                        FoxyLog.i(TAG, "stopped")
                    }
                } catch (e: Throwable) {
                    FoxyLog.e(TAG, "Hev stop failed", e)
                }
            }
            // Best-effort remove the ephemeral config so filesDir does not pile up.
            try { cfg?.let { File(it).delete() } } catch (_: Exception) {}
            // The detached fd is the last reference to the TUN — closing it is
            // what takes the interface down. Only ever our fd: start() swapped
            // ownedFd before any newer session could exist.
            if (fd >= 0) {
                try { ParcelFileDescriptor.adoptFd(fd).close() } catch (_: Throwable) {}
            }
        }, "foxy-hev-stop").start()
    }

    private const val TAG = "FoxyHevEngine"
}
