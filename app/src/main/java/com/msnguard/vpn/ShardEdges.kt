package com.msnguard.vpn

import android.content.Context

/**
 * Fans every node out across several Cloudflare edge addresses.
 *
 * ## Why this multiplies the pool
 *
 * Every node in this subscription is a WebSocket tunnel behind Cloudflare. The
 * address in the URL is not the server — it is only which edge IP to open a TCP
 * connection to. What decides where the connection actually lands is the `Host`
 * header (and the SNI, when TLS is on), because that is what Cloudflare routes
 * on. So the same credential, path and host reached through a different edge IP
 * is a genuinely different network path to the same working endpoint.
 *
 * That matters because the edge IP is what gets blocked. The publisher's whole
 * list currently sits on one address — measured on the shipped seed: all 45 lines
 * use `104.21.70.21` — so a carrier that throttles or blackholes that single IP
 * takes out the entire pool at once, no matter how many nodes are in it.
 *
 * ## Where the addresses come from
 *
 * [edges] is the publisher's own list of edges on which the fragment+fingerprint
 * approach was reported still working, plus whatever address the subscription
 * itself carries — which is kept, never replaced, so a good path we already have
 * cannot be lost by this expansion.
 *
 * It is **fetched at runtime** ([RemotePolicy]), because this is the fact that
 * ages fastest: the publisher declared three of the original four dead in one
 * message, and replacing them used to mean a release.
 *
 * ## Why not every Cloudflare IP
 *
 * Cloudflare announces millions of addresses and most are useless here: an edge
 * has to actually be reachable and unthrottled on the user's carrier. Scanning
 * for them on the device would be a long, battery-expensive sweep for a marginal
 * gain over a handful of edges that are known to work.
 *
 * If the subscription later moves to an address that is not in the list, that
 * address is kept as an extra, so the pool follows the publisher instead of being
 * pinned to a list that ages.
 *
 * ## Guardrails
 *
 * Expansion is deliberately conservative. A node is fanned out only when
 *
 *  * it carries a `host`, i.e. it is CDN-fronted and therefore routed by name —
 *    without one, the address is the actual server and swapping it is nonsense;
 *  * its address is an IPv4 literal inside Cloudflare's published ranges, so we
 *    know the node really is behind this CDN and not some other host that merely
 *    happens to set a Host header; and
 *  * its port is one Cloudflare serves.
 *
 * Anything else is passed through untouched. A wrong variant is not dangerous —
 * it just fails its probe and [ShardHealth] demotes it — but it wastes race slots
 * that a real candidate could have used.
 */
object ShardEdges {

    /**
     * Cloudflare edge addresses to try each node through.
     *
     * Reported working with this transport's fragment+fingerprint parameters,
     * including on connections where uploads are throttled. Order is not
     * significant: [ShardHealth] learns which of them is fast on this particular
     * network and [ShardManager] spreads each race across them.
     *
     * **Fetched, not compiled in.** An edge dies when a carrier blackholes it, and
     * that used to cost a release: three of the original four were reported dead at
     * once, taking three quarters of the pool's paths with them. [RemotePolicy]
     * holds the live list and falls back to the built-in one when it has nothing,
     * so this is now an edit in a JSON file rather than a version bump.
     */
    fun edges(context: Context): List<String> = RemotePolicy.edges(context)

    /**
     * Ports Cloudflare terminates. A node on anything else is not fanned out,
     * because the edge would simply not answer.
     *
     * 443 and 8080 are the two the live pool uses; the rest are the remaining
     * documented HTTP/HTTPS ports, listed so a future subscription that moves to
     * one of them keeps working without a code change.
     */
    private val CDN_PORTS = setOf(
        80, 8080, 8880, 2052, 2082, 2086, 2095,
        443, 2053, 2083, 2087, 2096, 8443,
    )

    /**
     * Cloudflare's published IPv4 ranges, as `first address` to `last address`
     * pairs held as unsigned 32-bit values in a Long.
     *
     * Hardcoded rather than fetched: this list changes on the order of years, and
     * a network call here would run on the connect path — the one place that must
     * not wait on anything.
     */
    private val CF_RANGES: List<LongRange> = listOf(
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ).mapNotNull { cidrToRange(it) }

    /**
     * Expand [nodes] across [edges].
     *
     * Deduped on [ShardNode.key], which includes the address — so the publisher's
     * own address is not duplicated when it happens to be one of [edges], and two
     * nodes that differ only by edge remain separate entries with their own health
     * memory. That per-edge memory is the point: on a network where one edge is
     * throttled, the ranking learns it once and stops racing it.
     *
     * ## Why each node starts on a different edge
     *
     * Variants are emitted rotated by the node's position, so the first variant of
     * node 0 is edge 0, of node 1 is edge 1, and so on. Without that stagger every
     * node's first variant would be the same address the subscription shipped, and
     * since a cold pool has no health data to reorder it, the first race would
     * spend all twelve slots on that one edge. If that edge is the blocked one —
     * the entire reason this file exists — the connect fails while a hundred live
     * paths sit untried behind it.
     *
     * Health data overrides the stagger as soon as it exists: [ShardHealth.rank]
     * sorts on measured latency and streaks, and only falls back to this order for
     * nodes it knows nothing about.
     */
    fun expand(context: Context, nodes: List<ShardNode>): List<ShardNode> {
        val edges = edges(context)
        val out = ArrayList<ShardNode>(nodes.size * (edges.size + 1))
        val seen = HashSet<String>()
        nodes.forEachIndexed { index, node ->
            if (!isExpandable(node)) {
                if (seen.add(node.key)) out.add(node)
                return@forEachIndexed
            }
            // The subscription's own address first in the rotation, so it is always
            // present even when it is not one of [edges].
            val addresses = ArrayList<String>(edges.size + 1)
            addresses.add(node.address)
            edges.forEach { if (it != node.address) addresses.add(it) }
            val offset = index % addresses.size
            for (step in addresses.indices) {
                val address = addresses[(offset + step) % addresses.size]
                val variant = if (address == node.address) node else node.copy(address = address)
                if (seen.add(variant.key)) out.add(variant)
            }
        }
        return out
    }

    /** Whether swapping this node's address for another edge is meaningful. */
    private fun isExpandable(node: ShardNode): Boolean {
        // No Host header means the address is the server itself.
        if (node.host.isBlank()) return false
        if (node.port !in CDN_PORTS) return false
        return isCloudflareAddress(node.address)
    }

    /**
     * Is [address] a dotted-quad literal inside Cloudflare's published ranges?
     *
     * Public because [RemotePolicy] validates fetched edges with it. That check is
     * what stops a bad or hostile policy file from pointing every node's TLS — real
     * SNI and all — at an address the operator picked.
     */
    fun isCloudflareAddress(address: String): Boolean {
        val numeric = ipv4ToLong(address) ?: return false
        return CF_RANGES.any { numeric in it }
    }

    /**
     * Address without the port, as an unsigned 32-bit value, or null when it is
     * not a dotted-quad literal — a hostname included, which is the common
     * not-an-IP case and is correctly rejected here.
     */
    private fun ipv4ToLong(address: String): Long? {
        val parts = address.split('.')
        if (parts.size != 4) return null
        var value = 0L
        parts.forEach { part ->
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            value = (value shl 8) or octet.toLong()
        }
        return value
    }

    private fun cidrToRange(cidr: String): LongRange? {
        val slash = cidr.indexOf('/')
        if (slash < 0) return null
        val base = ipv4ToLong(cidr.substring(0, slash)) ?: return null
        val bits = cidr.substring(slash + 1).toIntOrNull() ?: return null
        if (bits !in 0..32) return null
        val size = 1L shl (32 - bits)
        val first = base and (0xFFFFFFFFL - (size - 1))
        return first..(first + size - 1)
    }
}
