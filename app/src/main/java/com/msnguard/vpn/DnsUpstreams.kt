package com.msnguard.vpn

import android.content.Context

/**
 * The plain-UDP resolver list the tun2socks-based transports use.
 *
 * WireGuard, MASQUE and WoW resolve inside the Rust core, so the user's DoT/DoH
 * lists reach them through `dns_servers_dot` / `dns_servers_doh`. Psiphon, Tor
 * and SHARD do not — they route their DNS through a tun2socks front-end, which
 * can only speak plain UDP. Before 2.0.17 each of those front-ends carried its
 * own hardcoded pair, so a user who set a custom resolver on the DNS screen saw
 * it applied on one transport family and ignored on the other. This is the one
 * place that list is read for the UDP-only transports.
 *
 * DoT/DoH URLs are deliberately rejected here, not silently truncated: these
 * front-ends have no TLS stack, and an https:// entry would resolve to nothing.
 * Callers fall back to [DEFAULT].
 */
object DnsUpstreams {

    const val PREF = "dns_servers_udp"

    val DEFAULT = listOf("1.1.1.1", "8.8.8.8")

    /**
     * The user's plain-UDP list when it parses, otherwise [DEFAULT]. A host that
     * does not resolve is dropped rather than fatal — one mistyped entry must not
     * take DNS away from every SHARD/Tor/Psiphon session.
     */
    fun list(context: Context): List<String> {
        val raw = context.profiled().getString(PREF, null)
            ?.split(',', ';', ' ', '\n')
            ?.map(String::trim)
            ?.filter(String::isNotEmpty)
            ?: return DEFAULT

        if (raw.isEmpty()) return DEFAULT

        val parsed = raw.mapNotNull { entry ->
            // Only a bare IP is useful here. The encrypted schemes need a TLS
            // stack these front-ends do not have; a hostname would need a lookup
            // before the first query, and there is no resolver to look it up
            // against yet.
            val address = when {
                entry.startsWith("https://", ignoreCase = true) ||
                    entry.startsWith("tls://", ignoreCase = true) ||
                    entry.startsWith("dot://", ignoreCase = true) ||
                    entry.startsWith("doh://", ignoreCase = true) ||
                    entry.startsWith("doh:", ignoreCase = true) ||
                    entry.startsWith("dot:", ignoreCase = true) -> return@mapNotNull null

                entry.startsWith('[') -> entry.substringAfter('[').substringBefore(']')

                entry.count { it == ':' } == 1 -> entry.substringBefore(':')

                else -> entry
            }
            runCatching { java.net.InetAddress.getByName(address) }
                .getOrNull()
                ?.let { address }
        }

        return parsed.ifEmpty { DEFAULT }
    }
}
