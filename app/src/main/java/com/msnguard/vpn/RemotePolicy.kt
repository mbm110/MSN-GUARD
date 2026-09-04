package com.msnguard.vpn

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The two lists that used to require a new build, moved out of the APK.
 *
 * ## Why this file exists
 *
 * Two facts about this app age faster than releases do:
 *
 *  * **Which Cloudflare edge addresses still work.** Every node in the pool is a
 *    WebSocket behind Cloudflare, so the edge IP is what a carrier blocks — see
 *    [ShardEdges]. When three of them died the whole pool lost three quarters of
 *    its paths, and the only way to replace them was a version bump.
 *  * **Which hosts refuse an Iranian source address.** [ShardConfigs] has to send
 *    those through the node; adding one meant another release.
 *  * **Which services are sanctioned.** Same problem, opposite cause: a new AI
 *    service appears, answers 403 on the direct path, and the fix was a release.
 *    This one is additive on top of the compiled list — see [BUILTIN_SANCTIONED].
 *
 * Neither is code. All three are a handful of strings that change when someone
 * else's infrastructure changes, and shipping a new APK to fix a typo-sized fact
 * is the wrong shape. So they live in one small JSON file fetched over HTTPS, with
 * the values compiled in as the fallback rather than as the source of truth.
 *
 * ## Shape of the file
 *
 * Deliberately the smallest thing that can be edited from GitHub's web editor
 * without breaking anything:
 *
 * ```json
 * {
 *   "version": 1,
 *   "edges": ["104.21.70.21", "104.21.33.59", "188.114.97.0"],
 *   "geoblocked": ["www.nvidia.com", "nvidia.com", "www.avast.com"],
 *   "sanctioned": ["claude.ai", "*.perplexity.ai"]
 * }
 * ```
 *
 * Bare hostnames, bare IPv4 literals, and in `sanctioned` an optional `*.`
 * prefix. Nothing else that looks like a routing rule: this file must never be
 * able to inject a `geosite:` token or a CIDR into the config. Measured against
 * Xray 26.3.27, an injected token does **not** make the core exit — `xray run
 * -test` accepts `full:geosite:instagram` and friends with rc=0 — so what the
 * validator actually prevents is a silent widening of the blast radius, which is
 * worse than a crash because nobody notices. [ShardConfigs] wraps the hostnames
 * in `full:` or `domain:` itself, and [validateEdges] refuses any address that is
 * not inside Cloudflare's published ranges.
 *
 * ## Failure is always backwards, never sideways
 *
 * Every path ends in a usable list:
 *
 *  * no network, 404, timeout, malformed JSON, empty list after validation →
 *    the previous cache, and if there is none, [BUILTIN_EDGES] /
 *    [BUILTIN_GEOBLOCKED] / [BUILTIN_SANCTIONED] as shipped.
 *  * a fetched list that validates → cached and used.
 *
 * A fresh install with no network therefore behaves exactly like the version that
 * had these values hardcoded, which is the property that makes this safe to add.
 *
 * ## Cadence
 *
 * The same 6-hour floor and ETag conditional request as [ShardSubscription], and
 * it rides the same triggers — app resume, SHARD connect, the periodic job. A
 * `304` is a few hundred bytes. There is no separate wakeup and no extra radio
 * cost: when nothing changed this is cheaper than a single DNS lookup.
 */
object RemotePolicy {

    private const val TAG = "RemotePolicy"

    /**
     * Where the lists live.
     *
     * The release branch of the app's own public repo, so updating a dead edge or
     * adding a sanctioned site is an edit in GitHub's web UI — no build, no
     * release, no version bump. Raw githubusercontent is already a proven-reachable
     * host from Iranian carriers with no tunnel: [ShardSubscription] has been
     * fetching the node list from it since 1.7.0.
     */
    private const val POLICY_URL =
        "https://raw.githubusercontent.com/mbm110/MSN-GUARD/master/remote/policy.json"

    private const val CACHE_FILE = "remote-policy.json"
    private const val ETAG_PREF = "policy_etag"
    private const val LAST_CHECK_PREF = "policy_last_check"

    /** Same floor as the subscription: see [ShardSubscription.refreshIfDue]. */
    private const val MIN_INTERVAL_MS = 6 * 60 * 60 * 1000L

    private const val CONNECT_TIMEOUT_MS = 12_000
    private const val READ_TIMEOUT_MS = 20_000

    /**
     * Caps, so a wrong or hostile file cannot make the config pathological.
     *
     * The edge cap is well above anything useful — a connect races 12 paths at a
     * time, so more than a couple of dozen edges is already unreachable work. The
     * host cap is generous for the same reason: each one is a routing rule xray
     * evaluates per connection.
     */
    private const val MAX_EDGES = 24
    private const val MAX_HOSTS = 64
    private const val MAX_SANCTIONED = 64

    /**
     * How much of an oversized array is even looked at.
     *
     * The caps above bound the *output*; this bounds the *work*. A 680 000-entry
     * array costs one validation and one log line per entry otherwise, and
     * `ConnectionLog.record` is a synchronized file append — enough to evict every
     * real connect diagnostic from the ring buffer before the cap is ever reached.
     */
    private const val SCAN_FACTOR = 8

    /**
     * Ceiling on the body itself. The real file is ~300 bytes.
     *
     * Without it, `readText` plus `JSONObject`'s parse tree plus the `writeText`
     * below are three copies of whatever the URL served — an OOM on a low-RAM
     * phone, and a multi-megabyte cache re-parsed on every launch afterwards.
     * Truncation yields unparsable JSON, which is the correct outcome: previous
     * lists kept.
     */
    private const val MAX_BODY_CHARS = 64 * 1024

    /**
     * How long to wait after a body that would not validate.
     *
     * Shorter than [MIN_INTERVAL_MS] because the fix is one edit away, but not
     * zero: with no floor at all every app resume issues a fresh GET for the life
     * of the install, which is a radio wake each time and a repeating pattern on a
     * metered, watched link.
     */
    private const val RETRY_AFTER_BAD_MS = 30 * 60 * 1000L

    /**
     * Canonical dotted quad, checked before the range test.
     *
     * [ShardEdges.ipv4ToLong] parses with `toIntOrNull`, which accepts `+21`,
     * `021` and any Unicode decimal digit (`٢١`, `２１`). Such a value passes the
     * range check and is then dialled verbatim, so it becomes a resolution failure
     * or a duplicate health entry — a slower connect after a policy edit. `[0-9]`
     * is ASCII-only by definition, unlike `\d` under Java's default flags.
     */
    private val DOTTED_QUAD = Regex("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")

    /**
     * Two-label public suffixes a `*.` entry may not expand to.
     *
     * `*.example.com` is the intended shape. `*.co.uk` is the same syntax and
     * routes an entire country's namespace through one node — well-formed, so no
     * character check can catch it. Single-label suffixes (`*.com`, `*.ir`) are
     * already impossible: [isHostname] requires a dot in the remainder.
     *
     * This is a floor against a typo in a file that ships with no review, not a
     * public-suffix list; it covers the suffixes an Iranian user's traffic would
     * plausibly touch plus the common generics.
     */
    private val WILDCARD_DENY = setOf(
        "co.ir", "ac.ir", "org.ir", "net.ir", "gov.ir", "id.ir", "sch.ir",
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "com.br", "com.cn", "com.tr", "com.mx", "com.ar",
        "co.jp", "co.kr", "co.in", "co.za", "co.nz", "com.sa", "com.eg",
    )

    /**
     * The edges as of this build. Two of the previous four (`172.67.141.182` and
     * `172.67.217.240`) were reported dead by the publisher and are gone; the
     * addresses kept are the ones still reported working with this transport's
     * fragment+fingerprint parameters.
     *
     * This is a fallback, not the list: a policy file that validates replaces it
     * entirely.
     */
    val BUILTIN_EDGES = listOf(
        "104.21.70.21",
        "104.21.33.59",
        "188.114.97.0",
    )

    /**
     * Hosts that refuse an Iranian source address, as of this build.
     *
     * Bare hostnames. [ShardConfigs] turns them into `full:` rules, which is why
     * both `nvidia.com` and `www.nvidia.com` are listed — `full:` matches one name
     * exactly, and that precision is deliberate. See
     * `ShardConfigs.geoBlockedRuleHosts` for why this is not `domain:`.
     */
    val BUILTIN_GEOBLOCKED = listOf(
        "www.nvidia.com",
        "nvidia.com",
        "images.nvidia.com",
        "www.avast.com",
        "avast.com",
        "www.android.com",
        "android.com",
    )

    /**
     * Extra sanctioned names, on top of the ones compiled into [ShardConfigs].
     *
     * Empty by design. This list is **additive**: `ShardConfigs.SANCTIONED_DOMAINS`
     * stays compiled in because it is mostly `geosite:` tokens — whole categories
     * this file is not allowed to write — and losing them to a bad edit would send
     * every AI service down the direct path where it answers 403. So the shipped
     * behaviour with an empty or unreachable policy file is exactly today's
     * behaviour, and the file can only ever add.
     *
     * Accepted forms, both far narrower than a `geosite:`:
     *
     *  * `example.com` → `full:example.com`, one exact name.
     *  * `*.example.com` → `domain:example.com`, the name and its subdomains.
     *
     * The wrapping happens in [ShardConfigs], never here — see [validateSanctioned]
     * for why the prefix is the only metacharacter allowed through.
     */
    val BUILTIN_SANCTIONED = emptyList<String>()

    /** Parsed lists, or null until something has read the cache once. */
    @Volatile
    private var cached: Policy? = null

    private val refreshing = AtomicBoolean(false)

    /** One resolved policy. Every list is already validated. */
    private class Policy(
        val edges: List<String>,
        val geoBlocked: List<String>,
        val sanctioned: List<String>,
    )

    private fun prefs(context: Context) =
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    private fun cacheFile(context: Context) = File(context.filesDir, CACHE_FILE)

    /** When the last check happened, 0 if never. Used by [refreshIfDue]'s floor. */
    fun lastCheckMillis(context: Context): Long = prefs(context).getLong(LAST_CHECK_PREF, 0L)

    /**
     * Cloudflare edge addresses to fan the pool across.
     *
     * Never empty: falls back through cache to [BUILTIN_EDGES].
     */
    fun edges(context: Context): List<String> = policy(context).edges

    /**
     * Hostnames that must leave through the node.
     *
     * Never empty: falls back through cache to [BUILTIN_GEOBLOCKED].
     */
    fun geoBlockedHosts(context: Context): List<String> = policy(context).geoBlocked

    /**
     * Extra names to route through the node, on top of the compiled-in list.
     *
     * Empty unless a policy file adds some — see [BUILTIN_SANCTIONED]. Entries are
     * either a bare hostname or a `*.`-prefixed one; [ShardConfigs] decides how each
     * becomes a rule.
     */
    fun sanctionedHosts(context: Context): List<String> = policy(context).sanctioned

    private fun policy(context: Context): Policy {
        cached?.let { return it }
        // Read once per process. The connect path calls this, so it must not be a
        // file read per rule — and it cannot be a lazy initialiser either, because
        // a successful refresh has to be able to invalidate it.
        val loaded = readCache(context)
            ?: Policy(BUILTIN_EDGES, BUILTIN_GEOBLOCKED, BUILTIN_SANCTIONED)
        cached = loaded
        return loaded
    }

    private fun readCache(context: Context): Policy? {
        val file = cacheFile(context)
        if (!file.exists()) return null
        return try {
            parse(file.readText())
        } catch (e: Exception) {
            ConnectionLog.record("$TAG cached policy unusable: ${e.message}")
            null
        }
    }

    /**
     * Parse and validate. Returns null when the body cannot be trusted, which
     * leaves the caller on whatever it had.
     *
     * A partially valid file is honoured per list rather than rejected whole: a
     * broken `edges` array must not also throw away a good `geoblocked` one, or
     * one typo would revert both. A file whose `sanctioned` list is the only thing
     * present is valid too — that list is additive, so adding one name is a
     * legitimate edit on its own.
     */
    private fun parse(body: String): Policy? {
        val root = try {
            JSONObject(body)
        } catch (e: Exception) {
            return null
        }
        val edges = validateEdges(root.optJSONArray("edges"))
        val hosts = validateHosts(root.optJSONArray("geoblocked"))
        val sanctioned = validateSanctioned(root.optJSONArray("sanctioned"))
        if (edges == null && hosts == null && sanctioned == null) return null
        // Fall back to what is currently in force for the list that failed, not to
        // the shipped constants: a typo in one array must not revert months of edits
        // to another. `cached` is null on the first read, and readCache's own parse()
        // then supplies the built-ins.
        val current = cached
        return Policy(
            edges ?: current?.edges ?: BUILTIN_EDGES,
            hosts ?: current?.geoBlocked ?: BUILTIN_GEOBLOCKED,
            sanctioned ?: current?.sanctioned ?: BUILTIN_SANCTIONED,
        )
    }

    /**
     * Accept only dotted-quad IPv4 literals that really are Cloudflare edges.
     *
     * The range check is the important half. Without it this file could point the
     * whole pool at an address the operator chose, and every node's TLS would be
     * offered to it with the real SNI — so it is checked against Cloudflare's
     * published ranges, the same test [ShardEdges] already applies to the
     * subscription's own addresses.
     *
     * @return the list, or null when nothing survived (caller keeps its previous).
     */
    private fun validateEdges(array: org.json.JSONArray?): List<String>? {
        if (array == null) return null
        val out = LinkedHashSet<String>()
        var rejected = 0
        // Bound the scan, not just the output: see SCAN_FACTOR.
        val limit = minOf(array.length(), MAX_EDGES * SCAN_FACTOR)
        for (index in 0 until limit) {
            val value = array.optString(index).trim()
            if (value.isEmpty()) continue
            if (!DOTTED_QUAD.matches(value) || !ShardEdges.isCloudflareAddress(value)) {
                rejected++
                continue
            }
            out.add(value)
            if (out.size >= MAX_EDGES) break
        }
        if (rejected > 0) ConnectionLog.record("$TAG rejected $rejected edge(s) — not a CDN address")
        return out.toList().takeIf { it.isNotEmpty() }
    }

    /**
     * Accept only things that can be a hostname.
     *
     * No `:`, no `/`, no `*`, no leading `geosite`/`domain`/`full` prefix — those
     * are rule syntax, and this file is not allowed to write rules. A label that
     * fails is skipped rather than failing the file, so one bad line does not cost
     * the rest of the list.
     */
    private fun validateHosts(array: org.json.JSONArray?): List<String>? {
        if (array == null) return null
        val out = LinkedHashSet<String>()
        var rejected = 0
        val limit = minOf(array.length(), MAX_HOSTS * SCAN_FACTOR)
        for (index in 0 until limit) {
            val value = array.optString(index).trim().lowercase()
            if (!isHostname(value)) {
                if (value.isNotEmpty()) rejected++
                continue
            }
            out.add(value)
            if (out.size >= MAX_HOSTS) break
        }
        if (rejected > 0) ConnectionLog.record("$TAG rejected $rejected malformed host entry/entries")
        return out.toList().takeIf { it.isNotEmpty() }
    }

    private fun isHostname(value: String): Boolean {
        if (value.length < 4 || value.length > 253) return false
        if (!value.contains('.')) return false
        if (value.startsWith('.') || value.endsWith('.')) return false
        if (value.startsWith('-') || value.endsWith('-')) return false
        if (value.contains("..")) return false
        return value.all { it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '-' }
    }

    /**
     * Accept a sanctioned entry: a bare hostname, or one `*.` prefix and nothing
     * else.
     *
     * The `*.` prefix is the only metacharacter this file may carry, and it is
     * stripped here before [isHostname] sees the rest — so `*.*.x`, `*x.y`, `x.*`
     * and a bare `*.` all fail on the remainder, and no other rule syntax
     * (`geosite:`, `domain:`, a CIDR, a path) can survive. What comes out is a
     * plain hostname plus one boolean's worth of information, which is exactly what
     * [ShardConfigs] needs to choose between `full:` and `domain:`.
     *
     * @return the entries with their prefix intact, or null when nothing survived.
     */
    private fun validateSanctioned(array: org.json.JSONArray?): List<String>? {
        if (array == null) return null
        val out = LinkedHashSet<String>()
        var rejected = 0
        val limit = minOf(array.length(), MAX_SANCTIONED * SCAN_FACTOR)
        for (index in 0 until limit) {
            val raw = array.optString(index).trim().lowercase()
            if (raw.isEmpty()) continue
            val wildcard = raw.startsWith("*.")
            val host = if (wildcard) raw.substring(2) else raw
            // A second `*` anywhere — including `*.*.x` — dies here, because the
            // remainder is checked as a hostname and `*` is not a hostname character.
            if (!isHostname(host)) {
                rejected++
                continue
            }
            // Syntax cannot catch this one: `*.co.uk` is well formed and would send a
            // whole namespace through one node. See WILDCARD_DENY.
            if (wildcard && (host.count { it == '.' } < 1 || host in WILDCARD_DENY)) {
                rejected++
                continue
            }
            out.add(if (wildcard) "*.$host" else host)
            if (out.size >= MAX_SANCTIONED) break
        }
        if (rejected > 0) ConnectionLog.record("$TAG rejected $rejected sanctioned entry/entries")
        return out.toList().takeIf { it.isNotEmpty() }
    }

    /**
     * Refresh if due. Safe from any thread, returns immediately.
     *
     * @param force ignores [MIN_INTERVAL_MS]; used by the manual settings row.
     */
    fun refreshIfDue(context: Context, force: Boolean = false) {
        val elapsed = System.currentTimeMillis() - lastCheckMillis(context)
        if (!force && elapsed in 0 until MIN_INTERVAL_MS) return
        if (!refreshing.compareAndSet(false, true)) return
        Thread({
            try {
                refreshBlocking(context)
            } catch (e: Exception) {
                ConnectionLog.record("$TAG refresh failed: ${e.message}")
            } finally {
                refreshing.set(false)
            }
        }, "policy-refresh").apply { isDaemon = true }.start()
    }

    private fun refreshBlocking(context: Context) {
        val connection = URL(POLICY_URL).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = true
            // Same plain client string as ShardSubscription, for the same reason: this
            // request goes out over the carrier link unwrapped, and a default Dalvik UA
            // next to the subscription's Mozilla one is a distinguisher between two
            // requests that are supposed to look alike.
            connection.setRequestProperty("User-Agent", "Mozilla/5.0")
            connection.setRequestProperty("Accept", "application/json")
            // Only conditional when there is something to keep: a 304 against a
            // missing cache file would leave the app on the built-ins for a full
            // interval. Same guard as ShardSubscription.
            prefs(context).getString(ETAG_PREF, null)
                ?.takeIf { it.isNotBlank() && cacheFile(context).exists() }
                ?.let { connection.setRequestProperty("If-None-Match", it) }
            val code = connection.responseCode
            if (code == HttpURLConnection.HTTP_NOT_MODIFIED) {
                // Nothing changed. Advance the clock so the next resume does not
                // re-ask, and leave the cache alone.
                prefs(context).edit().putLong(LAST_CHECK_PREF, System.currentTimeMillis()).apply()
                return
            }
            if (code != HttpURLConnection.HTTP_OK) {
                ConnectionLog.record("$TAG policy fetch returned $code")
                // 404 is the normal answer until the file is pushed to the release
                // branch. Without a floor here every app resume issues a fresh GET for
                // the life of the install — a radio wake each time, for an answer that
                // will not change today.
                prefs(context).edit()
                    .putLong(LAST_CHECK_PREF, System.currentTimeMillis())
                    .apply()
                return
            }
            // Bounded read: see MAX_BODY_CHARS.
            val body = connection.inputStream.bufferedReader().use { reader ->
                val buffer = CharArray(MAX_BODY_CHARS)
                var total = 0
                while (total < MAX_BODY_CHARS) {
                    val read = reader.read(buffer, total, MAX_BODY_CHARS - total)
                    if (read < 0) break
                    total += read
                }
                String(buffer, 0, total)
            }
            val parsed = parse(body)
            if (parsed == null) {
                ConnectionLog.record("$TAG policy rejected — keeping previous lists")
                // Re-check sooner than the full interval, since the fix is one edit
                // away — but still with a floor. See RETRY_AFTER_BAD_MS.
                prefs(context).edit()
                    .putLong(
                        LAST_CHECK_PREF,
                        System.currentTimeMillis() - MIN_INTERVAL_MS + RETRY_AFTER_BAD_MS,
                    )
                    .apply()
                return
            }
            // writeText truncates before it writes, so a kill mid-write leaves a half
            // file — and the ETag stored below would then pin the app to the built-ins
            // until the next interval. Rename is atomic on the same filesystem.
            val target = cacheFile(context)
            val temp = File(target.parentFile, "$CACHE_FILE.tmp")
            temp.writeText(body)
            if (!temp.renameTo(target)) {
                temp.delete()
                ConnectionLog.record("$TAG could not replace the policy cache")
                return
            }
            cached = parsed
            // Explicit editor: `.apply { }` (scope function) next to `.apply()`
            // (commit) is one refactor away from silently dropping the ETag, and
            // dropping it means every refresh transfers the whole body.
            val editor = prefs(context).edit()
                .putLong(LAST_CHECK_PREF, System.currentTimeMillis())
            connection.getHeaderField("ETag")
                ?.takeIf { it.isNotBlank() }
                ?.let { editor.putString(ETAG_PREF, it) }
            editor.apply()
            ConnectionLog.record(
                "$TAG policy updated — ${parsed.edges.size} paths, " +
                    "${parsed.geoBlocked.size} hosts, ${parsed.sanctioned.size} extra"
            )
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Forget the fetched lists and fall back to what is compiled in.
     *
     * Not wired to a settings row: the lists are self-correcting, so there is no
     * user-facing reason to reset them. It exists because a cache this file writes
     * must be removable by the code that owns it — and it is what the harness uses
     * to prove the fallback ladder.
     */
    fun clear(context: Context) {
        cacheFile(context).delete()
        prefs(context).edit().remove(ETAG_PREF).remove(LAST_CHECK_PREF).apply()
        cached = null
    }
}
