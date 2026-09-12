package com.msnguard.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Keeps the Smart Split fragment profiles fresh, from our own mirror of
 * patterniha's Serverless-for-Iran subscription.
 *
 * ## Why a mirror and not the publisher's URL directly
 *
 * The publisher's subscription is a full client config list (~36 KB, two
 * complete xray configs with inbounds, DNS, policy). The app needs exactly one
 * field from each entry: the `tcp-fragment-tls` mask pair. Fetching the whole
 * thing on the phone would pull 36 KB where 1.4 KB does, and would couple our
 * cadence to a file whose every unrelated edit (DNS tweaks, policy levels)
 * invalidates our ETag. So a scheduled workflow in our own repo extracts the
 * masks into `remote/smart-split.json` (this file's [SUBSCRIPTION_URL]) and the
 * phone fetches only that.
 *
 * The mirror is rebuilt by `.github/workflows/smart-split-sync.yml` every six
 * hours from the publisher's live subscription, so a publisher change reaches
 * the fleet with no build and no version bump — the same arrangement as the
 * SHARD node list and [RemotePolicy]'s edges.
 *
 * ## Cadence
 *
 * The same shape as [ShardSubscription]: a six-hour floor, an ETag so a
 * no-change check is a few hundred bytes, refresh on app resume / Smart Split
 * connect / the periodic job, and best-effort failure — a failed refresh keeps
 * the previous cache, and a first run with no cache falls back to the seed
 * shipped in assets, so Smart Split still works offline on a fresh install.
 */
object SmartSplitSub {

    private const val TAG = "SmartSplitSub"

    /**
     * The mirror. Our own repo, so the cadence and the format are ours to
     * change; the publisher's names never appear in a URL the phone dials.
     */
    const val SUBSCRIPTION_URL =
        "https://raw.githubusercontent.com/mbm110/MSN-GUARD/master/remote/smart-split.json"

    /** Seed in assets, so a first-ever connect works with no network. */
    private const val SEED_ASSET = "smart-split-seed.json"

    private const val CACHE_FILE = "smart-split-profiles.json"
    private const val ETAG_PREF = "smart_split_etag"
    private const val LAST_CHECK_PREF = "smart_split_last_check"

    private const val MIN_INTERVAL_MS = 6 * 60 * 60 * 1000L
    private const val CONNECT_TIMEOUT_MS = 12_000
    private const val READ_TIMEOUT_MS = 20_000

    private val refreshing = AtomicBoolean(false)

    private fun prefs(context: Context) =
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    private fun cacheFile(context: Context) = File(context.filesDir, CACHE_FILE)

    /**
     * Only the profile the user verified in the field. See [profiles] — the
     * publisher's fragA probes dead on his carrier, so the ladder is fragB
     * alone until that changes.
     */
    private val WORKING_PROFILES = setOf("Serverless-v50-fragB")

    /**
     * The profiles to try, in mirror order — filtered to [WORKING_PROFILES].
     *
     * Field report (محسن, 2026-09-12): of the subscription's two configs only
     * `Serverless-v50-fragB` works on his carrier; fragA probes dead and the
     * wasted attempt costs a full probe budget on every uncached connect.
     * Filtered by name here rather than by index so a publisher-side change
     * to the list order cannot reintroduce the dead profile, and so deleting
     * the filter (the day fragA is fixed upstream) is a one-line change.
     *
     * Never an empty list without having tried both cache and seed: an empty
     * pool would silently disarm Smart Split on a network where it works. If
     * the filter ever empties the pool entirely, fall back to the unfiltered
     * mirror — a dead fragA attempt is cheaper than Smart Split silently off.
     */
    fun profiles(context: Context): List<SmartSplit.FragmentProfile> {
        val all = parse(readCache(context) ?: readSeed(context)).orEmpty()
        val working = all.filter { it.name in WORKING_PROFILES }
        return if (working.isNotEmpty()) working else all
    }

    /** Parse the mirror format into profiles. Null when unparseable/empty. */
    fun parse(body: String?): List<SmartSplit.FragmentProfile>? {
        if (body.isNullOrBlank()) return null
        return try {
            val root = JSONObject(body)
            val array = root.optJSONArray("profiles") ?: return null
            val out = ArrayList<SmartSplit.FragmentProfile>(array.length())
            for (i in 0 until array.length()) {
                val entry = array.optJSONObject(i) ?: continue
                val masks = entry.optJSONArray("masks") ?: continue
                if (masks.length() == 0) continue
                val profile = SmartSplit.FragmentProfile(
                    key = i.toString(),
                    name = entry.optString("name"),
                    masks = masks,
                    probeBudgetMs = SmartSplit.budgetFor(masks),
                )
                profile.ordinal = i
                profile.total = array.length()
                out.add(profile)
            }
            if (out.isEmpty()) null else out
        } catch (_: Exception) {
            null
        }
    }

    private fun readCache(context: Context): String? =
        cacheFile(context).takeIf { it.exists() }?.readText()

    private fun readSeed(context: Context): String? = try {
        context.assets.open(SEED_ASSET).bufferedReader().use { it.readText() }
    } catch (e: Exception) {
        ConnectionLog.record("$TAG no seed: ${e.message}")
        null
    }

    /** The cached profiles without a context-free accessor — used by [SmartSplit.FragmentProfile.byKey]. */
    fun cachedProfiles(): List<SmartSplit.FragmentProfile> = lastParsed.toList()

    @Volatile
    private var lastParsed: List<SmartSplit.FragmentProfile> = emptyList()

    /**
     * Refresh if due. Cheap to call from anywhere including the UI thread —
     * hands the work to a thread and returns immediately.
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
        }, "smart-split-refresh").apply { isDaemon = true }.start()
    }

    private fun lastCheckMillis(context: Context): Long =
        prefs(context).getLong(LAST_CHECK_PREF, 0L)

    /**
     * Fetch and store. A `304` advances the timestamp and keeps the cache.
     * A body that parses to zero profiles keeps the previous cache: a mirror
     * mistake or a truncated fetch must not disarm the feature.
     */
    private fun refreshBlocking(context: Context) {
        val connection = URL(SUBSCRIPTION_URL).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("User-Agent", "Mozilla/5.0")
            connection.setRequestProperty("Accept", "application/json")
            prefs(context).getString(ETAG_PREF, null)
                ?.takeIf { it.isNotBlank() && cacheFile(context).exists() }
                ?.let { connection.setRequestProperty("If-None-Match", it) }

            val status = connection.responseCode
            if (status == HttpURLConnection.HTTP_NOT_MODIFIED) {
                prefs(context).edit()
                    .putLong(LAST_CHECK_PREF, System.currentTimeMillis())
                    .apply()
                ConnectionLog.record("$TAG unchanged (304)")
                return
            }
            if (status != HttpURLConnection.HTTP_OK) {
                ConnectionLog.record("$TAG HTTP $status")
                return
            }

            val body = connection.inputStream.bufferedReader().use { it.readText() }
            if (parse(body) == null) {
                ConnectionLog.record("$TAG response parsed to 0 profiles — keeping previous cache")
                return
            }
            cacheFile(context).writeText(body)
            prefs(context).edit()
                .putString(ETAG_PREF, connection.getHeaderField("ETag").orEmpty())
                .putLong(LAST_CHECK_PREF, System.currentTimeMillis())
                .apply()
            ConnectionLog.record("$TAG updated — ${parse(body)?.size} profiles")
        } finally {
            connection.disconnect()
        }
    }
}
