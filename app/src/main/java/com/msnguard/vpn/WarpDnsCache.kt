package com.msnguard.vpn

import android.content.Context
import com.msnguard.vpn.ConnectionLog.record
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * A conservative, DNS-only answer cache for the WARP carrier path (3.2.47,
 * experimental — revert whole-file plus the two hooks in [WarpUdpgwFront] and
 * the warm-up call in [MsnGuardVpnService] to return to the old behaviour).
 *
 * Field report: opening Telegram right after a WARP-class connect (WireGuard,
 * WoW, either masque carrier, MIM) waited seconds-to-30s while the Lantern
 * transport felt instant. Every DNS query has to cross the freshly
 * established tunnel twice (the udpgw stream, then aether's SOCKS UDP
 * associate, then the tunnel), and an app resolves several names before its
 * first byte. Lantern answers DNS locally (sing-box fake-IP), so its apps
 * never pay that round trip.
 *
 * This cache sits inside [WarpUdpgwFront] — the exact point every
 * WARP-class datagram already crosses — and only ever:
 *  - caches a datagram that parsed fully as standard DNS (QR=1, opcode 0,
 *    NOERROR, answers present, not truncated) AND arrived on a port-53
 *    association — mDNS (5353) and QUIC (443) datagrams never qualify;
 *  - serves an entry while its shortest real TTL is still positive — never
 *    stale, so a service that moved addresses is never handed an old one;
 *  - rewrites TTLs to the remaining time on every hit (the OPT pseudo-RR,
 *    whose "TTL" field is not a TTL, is never touched), so apps still see a
 *    truthful, expiring record;
 *  - leaves every non-DNS datagram and every cache miss byte-identical to
 *    today's path.
 *
 * Answers survive reconnects through a small file so a quick
 * disconnect/connect cycle starts warm; [WarpUdpgwFront.warmDnsCache]
 * refreshes nearly-expired names right after the tunnel is up.
 */
object WarpDnsCache {

    private const val TAG = "WarpDnsCache"

    /** Never cache or replay anything larger than this. */
    private const val MAX_MESSAGE = 1400

    /** Entries kept in memory / on disk, most-recently-stored first. */
    private const val MAX_ENTRIES = 256

    /** A stored response is eligible for warm-up refresh while younger than this. */
    private const val REFRESH_ELIGIBLE_MS = 10 * 60_000L

    /** Refresh when the shortest remaining TTL falls under this. */
    private const val REFRESH_TTL_THRESHOLD_S = 120L

    /** How many names one warm-up pass refreshes. */
    private const val WARM_BATCH = 32

    private class Entry(
        val resolver: ByteArray,
        val query: ByteArray,
        val response: ByteArray,
        val storedAt: Long,
    )

    private val entries = ConcurrentHashMap<String, Entry>()
    private val lock = Any()

    @Volatile
    private var cacheFile: File? = null

    @Volatile
    private var dirtySinceSave = 0

    val size: Int
        get() = entries.size

    /** Point the cache at its file and load what is still meaningful. */
    fun configure(context: Context) {
        val file = File(context.filesDir, "warp_dns_cache.bin")
        synchronized(lock) {
            cacheFile = file
            entries.clear()
            loadLocked(file)
        }
        if (entries.isNotEmpty()) {
            record("$TAG loaded ${entries.size} answers")
        }
    }

    // ------------------------------------------------------------- DNS parse

    /**
     * The question key: wire-format name (labels verbatim, case preserved
     * aside from the lookup), type, class. Returns null unless the message
     * parses as a clean single-question standard DNS message.
     */
    private fun questionKey(message: ByteArray, isResponse: Boolean): String? {
        if (message.size < 12 || message.size > MAX_MESSAGE) return null
        val flags = ((message[2].toInt() and 0xFF) shl 8) or (message[3].toInt() and 0xFF)
        val qr = (flags shr 15) and 1
        val opcode = (flags shr 11) and 0xF
        if (qr != if (isResponse) 1 else 0) return null
        if (opcode != 0) return null
        val qd = ((message[4].toInt() and 0xFF) shl 8) or (message[5].toInt() and 0xFF)
        if (qd != 1) return null

        var pos = 12
        val nameStart = pos
        pos = skipName(message, pos) ?: return null
        if (pos + 4 > message.size) return null
        val name = message.copyOfRange(nameStart, pos)
        val type = ((message[pos].toInt() and 0xFF) shl 8) or (message[pos + 1].toInt() and 0xFF)
        val clazz = ((message[pos + 2].toInt() and 0xFF) shl 8) or (message[pos + 3].toInt() and 0xFF)
        return buildKey(name, type, clazz)
    }

    private fun buildKey(name: ByteArray, type: Int, clazz: Int): String {
        // DNS names are case-insensitive and resolvers may randomize case
        // (0x20 bit), so the key lowercases ASCII letters. The cached
        // response keeps its original case — apps match replies by ID, not
        // by the question's case.
        val sb = StringBuilder(name.size * 2 + 12)
        for (b in name) {
            var c = b.toInt() and 0xFF
            if (c in 0x41..0x5A) c += 0x20
            sb.append(((c and 0xF0) shr 4).toString(16))
            sb.append((c and 0xF).toString(16))
        }
        sb.append('|').append(type).append('|').append(clazz)
        return sb.toString()
    }

    /** Walk a (possibly compressed) name; null on any malformed form. */
    private fun skipName(message: ByteArray, start: Int): Int? {
        var pos = start
        var jumped = false
        var guard = 0
        while (true) {
            if (pos >= message.size || guard > 64) return null
            val len = message[pos].toInt() and 0xFF
            if (len and 0xC0 == 0xC0) {
                if (pos + 2 > message.size) return null
                return if (jumped) pos + 2 else pos + 2
            }
            if (len == 0) return pos + 1
            if (len > 63) return null
            pos += 1 + len
            guard++
            if (!jumped && pos > message.size) return null
        }
    }

    /**
     * Positions of every answer/authority/additional RR's TTL field, in
     * order, with the RR type. The OPT pseudo-RR (type 41) is included with
     * its position but must never be rewritten — its "TTL" is the extended
     * rcode and flags.
     */
    private class TtlField(val position: Int, val type: Int, val seconds: Long)

    private fun walkAnswerTtls(message: ByteArray): List<TtlField>? {
        val an = ((message[6].toInt() and 0xFF) shl 8) or (message[7].toInt() and 0xFF)
        val ns = ((message[8].toInt() and 0xFF) shl 8) or (message[9].toInt() and 0xFF)
        val ar = ((message[10].toInt() and 0xFF) shl 8) or (message[11].toInt() and 0xFF)
        var pos = questionEnd(message) ?: return null
        val fields = ArrayList<TtlField>(an + ns + ar)
        var remaining = an + ns + ar
        while (remaining > 0) {
            pos = skipName(message, pos) ?: return null
            if (pos + 10 > message.size) return null
            val type = ((message[pos].toInt() and 0xFF) shl 8) or (message[pos + 1].toInt() and 0xFF)
            val ttlPos = pos + 4
            val ttl = readUInt32(message, ttlPos)
            val rdLen = ((message[pos + 8].toInt() and 0xFF) shl 8) or (message[pos + 9].toInt() and 0xFF)
            pos += 10 + rdLen
            if (pos > message.size) return null
            fields.add(TtlField(ttlPos, type, ttl))
            remaining--
        }
        return fields
    }

    private fun readUInt32(bytes: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 4) v = (v shl 8) or (bytes[at + i].toLong() and 0xFF)
        return v
    }

    private fun writeUInt32(bytes: ByteArray, at: Int, value: Long) {
        for (i in 0 until 4) {
            bytes[at + i] = ((value shr (8 * (3 - i))) and 0xFF).toByte()
        }
    }

    private fun questionEnd(message: ByteArray): Int? {
        val pos = skipName(message, 12) ?: return null
        return pos + 4
    }

    private fun shortestTtl(fields: List<TtlField>): Long {
        var min = Long.MAX_VALUE
        for (f in fields) {
            if (f.type == 41) continue // OPT: not a real TTL
            if (f.seconds < min) min = f.seconds
        }
        return if (min == Long.MAX_VALUE) 0 else min
    }

    // ---------------------------------------------------------------- public

    /**
     * A cached answer for this query, with the query's ID and the remaining
     * TTLs, or null (miss, unparsable, or expired — an expired entry is
     * dropped, never served).
     */
    fun lookup(query: ByteArray): ByteArray? {
        val key = questionKey(query, isResponse = false) ?: return null
        val entry = entries[key] ?: return null
        val elapsedS = (System.currentTimeMillis() - entry.storedAt) / 1000L
        val ttls = walkAnswerTtls(entry.response) ?: run {
            entries.remove(key)
            return null
        }
        if (shortestTtl(ttls) - elapsedS <= 0) {
            entries.remove(key)
            return null
        }
        val answer = entry.response.copyOf()
        // The query's transaction ID, so the app matches the reply.
        answer[0] = query[0]
        answer[1] = query[1]
        for (f in ttls) {
            if (f.type == 41) continue
            val remaining = (f.seconds - elapsedS).coerceAtLeast(0)
            writeUInt32(answer, f.position, remaining)
        }
        return answer
    }

    /**
     * Offer an upstream response for caching. True when it parsed as a clean,
     * untruncated, answered, standard DNS message and was stored.
     */
    fun offer(response: ByteArray, resolver: ByteArray): Boolean {
        val key = questionKey(response, isResponse = true) ?: return false
        val flags = ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF)
        if ((flags shr 9) and 1 != 0) return false // truncated: client retries over TCP
        val rcode = flags and 0xF
        if (rcode != 0) return false
        val an = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
        if (an < 1) return false
        if (walkAnswerTtls(response) == null) return false

        // The stored query is the response's header+question rewritten as a
        // clean standard query (the response's own flags would carry QR=1 and
        // its answer counts, which no resolver accepts); warm-up re-sends it
        // and rewrites the ID like any other client.
        val query = response.copyOf(questionEnd(response) ?: return false)
        query[0] = 0
        query[1] = 0
        query[2] = 0x01
        query[3] = 0x00
        query[6] = 0
        query[7] = 0
        query[8] = 0
        query[9] = 0
        query[10] = 0
        query[11] = 0

        synchronized(lock) {
            if (entries.size >= MAX_ENTRIES) {
                entries.entries.minByOrNull { it.value.storedAt }?.let { entries.remove(it.key) }
            }
            // The warm-up refresh path offers without knowing the resolver
            // (its datagrams return from aether's relay, not the original
            // association); keep the resolver the entry already had.
            val storedResolver = if (resolver.isEmpty()) {
                entries[key]?.resolver ?: ByteArray(0)
            } else {
                resolver.copyOf()
            }
            entries[key] = Entry(
                storedResolver,
                query,
                response.copyOf(),
                System.currentTimeMillis(),
            )
            dirtySinceSave++
            if (dirtySinceSave >= 16) saveLocked()
        }
        return true
    }

    /**
     * The warm-up batch: queries whose answers are within [REFRESH_TTL_THRESHOLD_S]
     * of expiring, or expired but still recent enough to be worth refreshing.
     * Expired entries are never served by [lookup] — refresh is the only way
     * they come back.
     */
    fun takeRefreshBatch(): List<Pair<ByteArray, ByteArray>> {
        val now = System.currentTimeMillis()
        val batch = ArrayList<Pair<ByteArray, ByteArray>>(WARM_BATCH)
        val victims = ArrayList<String>()
        for ((key, entry) in entries) {
            val elapsedS = (now - entry.storedAt) / 1000L
            val ttls = walkAnswerTtls(entry.response)
            if (ttls == null) {
                victims.add(key)
                continue
            }
            val remaining = shortestTtl(ttls) - elapsedS
            if (remaining <= 0) {
                if (now - entry.storedAt > REFRESH_ELIGIBLE_MS) {
                    victims.add(key)
                } else if (batch.size < WARM_BATCH) {
                    batch.add(entry.resolver.copyOf() to entry.query.copyOf())
                }
            } else if (remaining < REFRESH_TTL_THRESHOLD_S && batch.size < WARM_BATCH) {
                batch.add(entry.resolver.copyOf() to entry.query.copyOf())
            }
        }
        victims.forEach { entries.remove(it) }
        return batch
    }

    // ----------------------------------------------------------- persistence

    private fun loadLocked(file: File) {
        try {
            if (!file.exists()) return
            DataInputStream(file.inputStream().buffered()).use { input ->
                val count = input.readInt()
                if (count < 0 || count > MAX_ENTRIES) return
                repeat(count) {
                    val resolver = ByteArray(input.readInt()).also { input.readFully(it) }
                    val query = ByteArray(input.readInt()).also { input.readFully(it) }
                    val response = ByteArray(input.readInt()).also { input.readFully(it) }
                    val storedAt = input.readLong()
                    val key = questionKey(response, isResponse = true) ?: return@repeat
                    entries[key] = Entry(resolver, query, response, storedAt)
                }
            }
        } catch (_: Exception) {
            entries.clear()
        }
    }

    private fun saveLocked() {
        val file = cacheFile ?: return
        try {
            DataOutputStream(file.outputStream().buffered()).use { output ->
                output.writeInt(entries.size)
                for ((_, entry) in entries) {
                    output.writeInt(entry.resolver.size)
                    output.write(entry.resolver)
                    output.writeInt(entry.query.size)
                    output.write(entry.query)
                    output.writeInt(entry.response.size)
                    output.write(entry.response)
                    output.writeLong(entry.storedAt)
                }
            }
            dirtySinceSave = 0
        } catch (e: Exception) {
            record("$TAG save failed: ${e.message}")
        }
    }

    /** Flush to disk; called from [WarpUdpgwFront.stop]. */
    fun flush() {
        synchronized(lock) { saveLocked() }
    }

    /** Drop everything (used by identity reset flows if ever needed). */
    fun clear() {
        synchronized(lock) {
            entries.clear()
            cacheFile?.delete()
            dirtySinceSave = 0
        }
    }
}
