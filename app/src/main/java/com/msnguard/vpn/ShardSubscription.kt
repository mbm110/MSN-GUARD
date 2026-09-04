package com.msnguard.vpn

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Keeps the SHARD node pool fresh, without the user knowing it exists.
 *
 * ## Cadence, and why there is no alarm or periodic worker
 *
 * The publisher rebuilds the list once a day (its own `#profile-update-interval`
 * says `1`, and its workflow cron is `0 10 * * *` — the "every 12 hours" figure
 * in the instructions was wrong). Nothing about that needs a wakeup: the refresh
 * runs when the app comes to the foreground and when a SHARD connect starts, and
 * only if [MIN_INTERVAL_MS] has elapsed. An app that is closed costs zero
 * battery, because there is no scheduled work to fire.
 *
 * ## ETag, so a no-change refresh is nearly free
 *
 * The stored ETag is sent back as `If-None-Match`. When nothing changed GitHub
 * answers `304` with no body — a few hundred bytes for the whole check. Measured
 * against the live URL: the body is ~41 KB, so this is the difference between a
 * daily 41 KB and a daily ~0.
 *
 * ## Reachability
 *
 * Confirmed by the user on Hamrah-e-Aval with no VPN: `raw.githubusercontent.com`
 * is reachable and the subscription updates. So the refresh runs unconditionally,
 * tunnel up or down. It stays best-effort regardless — a failed refresh keeps the
 * previous cache, and a first run with no cache at all falls back to the seed
 * list shipped in assets, so the button still works offline on a fresh install.
 */
object ShardSubscription {

    private const val TAG = "ShardSubscription"

    /**
     * The subscription. Not user-visible and not user-editable, by design: the
     * whole point of this transport is one button with nothing to configure.
     */
    const val SUBSCRIPTION_URL =
        "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt"

    /** Seed list in assets, so the first ever connect works with no network. */
    private const val SEED_ASSET = "shard-seed.txt"

    private const val CACHE_FILE = "shard-configs.txt"
    private const val ETAG_PREF = "shard_etag"
    private const val LAST_CHECK_PREF = "shard_last_check"
    private const val LAST_COUNT_PREF = "shard_last_count"
    private const val LAST_PATHS_PREF = "shard_last_paths"

    /**
     * Floor between two network checks.
     *
     * Six hours against a once-a-day rebuild: frequent enough that a user who
     * opens the app daily always has the current list within a day, sparse enough
     * that opening the app ten times in an afternoon costs one request.
     */
    private const val MIN_INTERVAL_MS = 6 * 60 * 60 * 1000L

    private const val CONNECT_TIMEOUT_MS = 12_000
    private const val READ_TIMEOUT_MS = 20_000

    /** Guards against two refreshes racing to write the same cache file. */
    private val refreshing = AtomicBoolean(false)

    private fun prefs(context: Context) =
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    private fun cacheFile(context: Context) = File(context.filesDir, CACHE_FILE)

    /** When the last successful check happened, 0 if never. */
    fun lastCheckMillis(context: Context): Long = prefs(context).getLong(LAST_CHECK_PREF, 0L)

    /** How many nodes the cache last yielded. Shown in settings as a subtitle. */
    fun cachedCount(context: Context): Int = prefs(context).getInt(LAST_COUNT_PREF, 0)

    /**
     * How many distinct paths those nodes expand to across the CDN edges.
     *
     * Stored at refresh time rather than computed on demand: the settings screen
     * would otherwise re-read and re-parse the 41 KB cache on the main thread just
     * to render a subtitle. Falls back to a multiply when the value predates this
     * field, which is only ever the first run after an update.
     */
    fun cachedPathCount(context: Context): Int {
        val stored = prefs(context).getInt(LAST_PATHS_PREF, 0)
        if (stored > 0) return stored
        return cachedCount(context) * ShardEdges.edges(context).size
    }

    /**
     * The pool to connect from, best available source.
     *
     * Order is cache, then seed asset. Never an empty list without having tried
     * both — a user tapping SHARD must not get "no nodes" because a refresh failed.
     */
    fun nodes(context: Context): List<ShardNode> {
        val cached = cacheFile(context).takeIf { it.exists() }?.readText().orEmpty()
        if (cached.isNotBlank()) {
            val parsed = ShardConfigs.parse(cached)
            if (parsed.isNotEmpty()) return parsed
        }
        return seedNodes(context)
    }

    private fun seedNodes(context: Context): List<ShardNode> = try {
        val body = context.assets.open(SEED_ASSET).bufferedReader().use { it.readText() }
        ShardConfigs.parse(body)
    } catch (e: Exception) {
        ConnectionLog.record("$TAG no seed list: ${e.message}")
        emptyList()
    }

    /**
     * Refresh if it is due. Cheap to call from anywhere, including the UI thread —
     * it hands the work to [worker] and returns immediately.
     *
     * @param force ignores [MIN_INTERVAL_MS]; used by the manual settings row.
     */
    fun refreshIfDue(context: Context, force: Boolean = false, onDone: ((Int) -> Unit)? = null) {
        val elapsed = System.currentTimeMillis() - lastCheckMillis(context)
        if (!force && elapsed in 0 until MIN_INTERVAL_MS) {
            onDone?.invoke(cachedCount(context))
            return
        }
        if (!refreshing.compareAndSet(false, true)) {
            onDone?.invoke(cachedCount(context))
            return
        }
        Thread({
            val count = try {
                refreshBlocking(context)
            } catch (e: Exception) {
                ConnectionLog.record("$TAG refresh failed: ${e.message}")
                cachedCount(context)
            } finally {
                refreshing.set(false)
            }
            onDone?.invoke(count)
        }, "shard-refresh").apply { isDaemon = true }.start()
    }

    /**
     * Fetch and store. Returns the node count now available.
     *
     * A `304` is a success with no work: the timestamp advances so the next
     * foreground does not re-ask, and the cache stays as it is.
     */
    private fun refreshBlocking(context: Context): Int {
        val connection = URL(SUBSCRIPTION_URL).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = true
            // A plain client string. Nothing identifying: the request goes out over
            // the carrier link in the clear, and naming the app in it would tell
            // anyone watching that this device runs a VPN client.
            connection.setRequestProperty("User-Agent", "Mozilla/5.0")
            connection.setRequestProperty("Accept", "text/plain")
            prefs(context).getString(ETAG_PREF, null)
                ?.takeIf { it.isNotBlank() && cacheFile(context).exists() }
                ?.let { connection.setRequestProperty("If-None-Match", it) }

            val status = connection.responseCode
            if (status == HttpURLConnection.HTTP_NOT_MODIFIED) {
                prefs(context).edit()
                    .putLong(LAST_CHECK_PREF, System.currentTimeMillis())
                    .apply()
                ConnectionLog.record("$TAG unchanged (304)")
                return cachedCount(context)
            }
            if (status != HttpURLConnection.HTTP_OK) {
                ConnectionLog.record("$TAG HTTP $status")
                return cachedCount(context)
            }

            val body = connection.inputStream.bufferedReader().use { it.readText() }
            val parsed = ShardConfigs.parse(body)
            // Refuse to replace a working cache with something that yields nothing.
            // A truncated response or a publisher mistake must not disarm the
            // button — the user would see a transport that worked yesterday and
            // has no nodes today, with nothing to point at.
            if (parsed.isEmpty()) {
                ConnectionLog.record("$TAG response parsed to 0 nodes — keeping previous cache")
                return cachedCount(context)
            }

            val paths = ShardEdges.expand(context, parsed).size
            cacheFile(context).writeText(body)
            prefs(context).edit()
                .putString(ETAG_PREF, connection.getHeaderField("ETag").orEmpty())
                .putLong(LAST_CHECK_PREF, System.currentTimeMillis())
                .putInt(LAST_COUNT_PREF, parsed.size)
                .putInt(LAST_PATHS_PREF, paths)
                .apply()
            ConnectionLog.record("$TAG updated — ${parsed.size} nodes, $paths paths")
            return parsed.size
        } finally {
            connection.disconnect()
        }
    }
}
