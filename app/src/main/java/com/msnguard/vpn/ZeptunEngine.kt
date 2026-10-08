package com.msnguard.vpn

import android.os.ParcelFileDescriptor

/**
 * Zeptun 1.1.1 engine.
 *
 * Takes the TUN fd + SOCKS port and builds a minimal TOML that mirrors the
 * Hev path but leverages Zeptun's strengths:
 *  - userspace stack (no kernel NAT) so elastic queues + GSO work
 *  - DNS: hijack + fake-ip are ON. The Builder publishes only the synthetic
 *    fake-ip resolver (HevEngine.MAP_DNS_ADDRESS), Zeptun answers it from its
 *    own fake-ip table, and real resolvers are handed to the engine here so
 *    it resolves the domain itself over SOCKS. Carrying a bare UDP/53 query
 *    for an Iran-only server (e.g. 111.88.96.50) out of a foreign WARP
 *    egress never gets an answer, which is exactly what killed UDP DNS.
 *  - protect callback is handled inside libzeptun-jni.so via
 *    VpnService.protect(int) reflection, so upstream sockets bypass the TUN
 *    without the Kotlin side having to do anything.
 */
object ZeptunEngine : TunEngine {
    override val label: String = "Zeptun"
    @Volatile private var running: Boolean = false
    @Volatile private var lastToml: String = ""

    // The raw fd we detached from the dup and handed to libzeptun (see start()).
    // detachFd() strips ownership from the ParcelFileDescriptor, so this number is
    // ours alone to close — nobody else knows it exists. See stop().
    @Volatile private var ownedFd: Int = -1

    override val isRunning: Boolean get() = running

    /**
     * Close the fd we detached in [start].
     *
     * libzeptun dups the fd it is given (inside zeptun_create_from_toml and
     * zeptun_set_device_fd) and closes only its own copies when it stops; the
     * original we detached is never closed by it. Left open, the TUN interface
     * outlives the service and the VPN key stays in the status bar after a
     * disconnect ("app says disconnected, key icon still there"). This is the
     * last reference once the engine has stopped, which is what takes the
     * interface down.
     */
    private fun closeOwnedFd() {
        val fd = ownedFd
        ownedFd = -1
        if (fd < 0) return
        try {
            ParcelFileDescriptor.adoptFd(fd).close()
        } catch (_: Throwable) {
            // Already gone (or never established) — nothing to release.
        }
    }

    /**
     * Custom resolvers the user set (dns_servers preference), followed by the
     * public fallbacks the TUN had before. Same parsing rules as
     * MsnGuardVpnService.applyDns so one field works everywhere.
     */
    private fun customResolverList(): List<String> {
        val raw = runCatching { AppContext.get()!!.profiled().getString("dns_servers", null)?.trim().orEmpty() }
            .getOrDefault("")
        val out = ArrayList<String>()
        if (raw.isNotEmpty()) {
            raw.split(',', ';', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }.forEach { token ->
                // Encrypted entries (tls://, dot://, https://) are passed
                // through untouched: the scheme is what the core keys on and
                // the port belongs to it (853/443), so stripping it would
                // corrupt the entry. Plain entries keep the old host-only
                // normalisation below.
                if (token.startsWith("tls://") || token.startsWith("dot://") ||
                    token.startsWith("https://")
                ) {
                    if (token !in out) out.add(token)
                    return@forEach
                }
                var host = token
                if (host.startsWith("[")) {
                    host = host.substringAfter("[").substringBefore("]")
                } else if (host.count { it == ':' } > 1 && !host.contains('.')) {
                    // bare v6 without brackets — keep as is
                } else if (host.contains(":")) {
                    host = host.substringBefore(":")
                }
                host = host.trim().removePrefix("[").removeSuffix("]")
                if (host.isNotEmpty() && host !in out) out.add(host)
            }
        }
        for (fallback in listOf("1.1.1.1", "8.8.8.8")) {
            if (fallback !in out) out.add(fallback)
        }
        return out
    }

    private fun firstZeptunCompatibleUpstream(): String {
        // Zeptun's [dns].upstream takes ONE plain UDP address. Encrypted
        // entries (tls://, https://) cannot go there — Zeptun has no DoT/DoH
        // client — but they must not silently win the slot either: skip them
        // and keep looking for a plain entry the engine can actually use.
        for (entry in customResolverList()) {
            val low = entry.lowercase()
            if (low.startsWith("tls://") || low.startsWith("dot://")) {
                val body = entry.substringAfter("://").substringBefore("#").trim()
                val looksIp = body.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+.*")) || body.startsWith("[")
                if (!looksIp) continue
            }
            if (low.startsWith("https://") || low.startsWith("doh:")) continue
            return entry
        }
        return "1.1.1.1"
    }

    override fun start(fd: ParcelFileDescriptor, socksPort: Int, mtu: Int, dnsOnly: Boolean): Boolean {
        if (running) return true
        val dup = try { fd.dup() } catch (e: Exception) {
            ConnectionLog.record("Zeptun: dup fd failed: ${e.message}")
            return false
        }
        val rawFd = try { dup.detachFd() } catch (e: Exception) {
            ConnectionLog.record("Zeptun: detachFd failed: ${e.message}")
            try { dup.close() } catch (_: Exception) {}
            return false
        }
        // Remember it so stop() can release it — detachFd() handed us sole
        // ownership, and libzeptun only ever closes its own dup.
        ownedFd = rawFd

        // Custom resolvers the user set, to the engine. Zeptun's [dns].upstream
        // takes ONE address, so the first custom entry wins (that is the
        // Iran-only server the user actually wants). If none is set, the public
        // fallback is used so resolution still works.
        //
        // Encrypted entries (tls://, https://) are deliberately NOT passed here:
        // Zeptun speaks plain UDP/53 only, so it cannot reach a DoT/DoH server
        // itself. They stay in AETHER_DNS, which the aether core reads on its
        // own leg — every name Zeptun hands up as a domain is resolved by
        // aether's socks5 server, and that is where DoT/DoH actually run.
        // Falling back to 1.1.1.1 below when only encrypted entries exist is
        // what keeps name resolution alive; the encrypted path is not bypassed
        // because it never went through this field.
        val upstream = firstZeptunCompatibleUpstream()
        ConnectionLog.record("Zeptun DNS upstream=$upstream (hijack+fake_ip, range 198.18.0.0/15)")

        // Minimal TOML: device is the supplied fd, stack is userspace,
        // handler is socks5 at 127.0.0.1:port. auto_route is OFF because the
        // VpnService.Builder already installed addresses/routes/DNS.
        //
        // mtu: pass through the caller's choice. PattNG parity: SHARD is the
        // PattNG VLESS/Reality core — TUN MTU is 1500 like every transport
        // (AppConfig.VPN_MTU). The WebSocket UDP ceiling (500) is per-datagram
        // inside ShardSocksFront, not an IP MTU.
        val toml = buildString {
            appendLine("preset = \"mobile\"")
            appendLine("log_level = \"warn\"")
            appendLine()
            appendLine("[tun]")
            appendLine("fd = $rawFd")
            appendLine("mtu = $mtu")
            // address/configure false — Builder owns the TUN identity
            appendLine("configure = false")
            appendLine()
            appendLine("[stack]")
            appendLine("mode = \"userspace\"")
            appendLine("udp = true")
            appendLine("icmp = \"auto\"")
            appendLine()
            // DNS: hijack + fake-ip. The Builder publishes only the synthetic
            // fake-ip resolver (198.18.0.2, inside Zeptun's default
            // 198.18.0.0/15 fake range), Zeptun answers it from its own
            // fake-ip table, and the real resolver is named here so the engine
            // resolves the domain itself over SOCKS. A bare UDP/53 query for an
            // Iran-only server (e.g. 111.88.96.50) leaving a foreign WARP
            // egress never gets an answer — that is what killed UDP DNS.
            appendLine("[dns]")
            appendLine("hijack = true")
            appendLine("fake_ip = true")
            appendLine("upstream = \"$upstream\"")
            appendLine("cache_size = 10000")
            appendLine()
            appendLine("[handler]")
            appendLine("kind = \"socks5\"")
            appendLine()
            appendLine("[handler.socks5]")
            appendLine("server = \"127.0.0.1:$socksPort\"")
            appendLine("udp_mode = \"udp\"")
            // pool_size 4 mirrors the default; enough for bursty browsing without
            // holding a socket per flow.
            appendLine("pool_size = 4")
            appendLine()
            appendLine("[route]")
            appendLine("auto_route = false")
        }
        lastToml = toml
        return try {
            // dev.zeptun.Zeptun.nativeStart(Object service, int fd, String toml)
            // We pass null for service + reuse rawFd via TOML fd; the JNI also
            // dup()s inside zeptun_create_from_toml + zeptun_set_device_fd.
            // Passing the fd twice is harmless — the TOML fd is used, the
            // Object/protect path is optional. For fd-based mode the JNI's
            // protect fallback (no service) means upstream sockets use the
            // system routing, which is fine because Builder already protect()d
            // the whole process? No — we need upstream to bypass the TUN, so
            // try to pass a VpnService if we can find one.
            val rc = dev.zeptun.Zeptun.nativeStart(null, rawFd, toml)
            if (rc == 0) {
                running = true
                ConnectionLog.record("Zeptun started → SOCKS 127.0.0.1:$socksPort mtu=$mtu (rc=0)")
                true
            } else {
                ConnectionLog.record("Zeptun start failed rc=$rc toml:\n$toml")
                running = false
                // Release the detached fd: nothing else owns it, and a failed
                // start would otherwise leave the TUN interface — and the VPN
                // key — up with no engine behind it.
                closeOwnedFd()
                false
            }
        } catch (e: Throwable) {
            ConnectionLog.record("Zeptun start exception: ${e.message}")
            running = false
            closeOwnedFd()
            false
        }
    }

    override fun stop() {
        if (!running) {
            // Even on this path the detached fd must be released: a start that
            // returned non-zero could still have created libzeptun's dup, but
            // ours is unconditionally ours, and leaving it open is exactly the
            // "key icon stays" symptom.
            closeOwnedFd()
            return
        }
        try {
            dev.zeptun.Zeptun.nativeStop()
            ConnectionLog.record("Zeptun stopped")
        } catch (e: Throwable) {
            ConnectionLog.record("Zeptun stop error: ${e.message}")
        } finally {
            running = false
            // nativeStop has unwound its side by now (stop() is called off the
            // engine's own thread and this is the last reference to the TUN),
            // so closing here is what takes the interface — and the status-bar
            // key — down. Adopting the raw int is safe: detachFd() made us the
            // sole owner and nothing else ever touches this number.
            closeOwnedFd()
        }
    }
}
