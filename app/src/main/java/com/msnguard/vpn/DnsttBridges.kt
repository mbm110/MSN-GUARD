package com.msnguard.vpn

import android.content.Context
import java.io.File

/** DNSTT bridge lines used by Orbot for Iran, with ordered resolver caching. */
internal object DnsttBridges {
    // Probe and Tor must use the same single verified path. Sending 30
    // simultaneous DNSTT sessions made Tor lose its relay TLS handshakes.
    private const val BATCH_SIZE = 1
    private const val BATCH_OFFSET_PREF = "dnstt_bridge_batch_offset"
    const val PUBKEY_1 = "241169008830694749fe96bb070c4855c5bb5b9c47b3833ed7d88521ba30a43f"
    const val PUBKEY_2 = "a2fb71077eeaa54a02cda7a90be306af5d299ab21822a8b277d4eacbc9168631"
    const val DOMAIN_1 = "t.ruhnama.net"
    const val DOMAIN_2 = "t2.bypasscensorship.org"

    fun lines(context: Context, dataDir: File): List<String> {
        val paths = DnsttResolverScanner.cachedPaths(dataDir)
        if (paths.isEmpty()) return emptyList()
        // Use the same one path that passed the end-to-end probe, then advance
        // through the ordered cache after a failed Tor attempt.
        val offset = context.profiled().getInt(BATCH_OFFSET_PREF, 0).coerceAtLeast(0)
        val normalizedOffset = offset.takeIf { it < paths.size } ?: 0
        if (normalizedOffset != offset) context.profiled().edit().putInt(BATCH_OFFSET_PREF, 0).apply()
        val batch = paths.drop(normalizedOffset).take(BATCH_SIZE)
        ConnectionLog.record("DNSTT Tor bridge batch: ${normalizedOffset + 1}..${normalizedOffset + batch.size} of ${paths.size} verified paths")
        return batch.mapIndexed { index, (resolver, domain) ->
            val pubkey = if (domain == DOMAIN_1) PUBKEY_1 else PUBKEY_2
            "dnstt 192.0.2.4:${index + 1} udp=$resolver:53 pubkey=$pubkey domain=$domain"
        }
    }

    fun advanceAfterFailure(context: Context, dataDir: File) {
        val count = DnsttResolverScanner.cachedPaths(dataDir).size
        if (count == 0) return
        val next = (context.profiled().getInt(BATCH_OFFSET_PREF, 0).coerceAtLeast(0) + BATCH_SIZE) % count
        context.profiled().edit().putInt(BATCH_OFFSET_PREF, next).apply()
        ConnectionLog.record("DNSTT Tor bridge batch failed; next verified resolver offset $next/$count")
    }

    fun reset(context: Context) {
        context.profiled().edit().putInt(BATCH_OFFSET_PREF, 0).apply()
    }
}
