package com.msnguard.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.Calendar

/**
 * Hourly and daily traffic history.
 *
 * The service already keeps a per-session counter and a month total
 * ([MsnGuardVpnService] `monthTxTotal`/`monthRxTotal`). Those answer "how much
 * this month", which is the billing question, but not "when did it go" — and a
 * user on a metered Iranian plan wants to see the spike, not just the total.
 *
 * Design constraints this shape satisfies:
 *
 * - **Bucketed deltas, never absolute counters.** [add] takes the same deltas the
 *   month total is fed, so it inherits the rebase/throttle discipline in
 *   `updateTrafficNotification()` rather than re-deriving it. A cumulative
 *   counter that can restart is exactly what produced the 60x monthly inflation
 *   bug; nothing here reads one.
 * - **Written on a slow timer, not per sample.** [flush] is called from the same
 *   60-second path as the month total plus every teardown, so an ordinary
 *   disconnect always persists an exact figure.
 * - **Bounded retention.** Hourly buckets older than [HOURLY_RETENTION_HOURS] and
 *   daily buckets older than [DAILY_RETENTION_DAYS] are dropped on load and on
 *   flush, so the JSON blob cannot grow without limit.
 *
 * Not a `SharedPreferences`-per-bucket design: one JSON string per resolution
 * keeps the write to a single `putString`, which matters because this is on the
 * traffic path.
 */
object TrafficHistory {

    /** ~31 days of hourly detail. */
    private const val HOURLY_RETENTION_HOURS = 24 * 31

    /** ~13 months of daily totals, so a year-over-year glance works. */
    private const val DAILY_RETENTION_DAYS = 400

    private const val PREFS = "traffic_history"
    private const val KEY_HOURLY = "hourly"
    private const val KEY_DAILY = "daily"

    /** bucket key -> [tx, rx] */
    private val hourly = HashMap<String, LongArray>()
    private val daily = HashMap<String, LongArray>()

    private var loaded = false
    private val lock = Any()

    /** One bucket, ready for rendering. */
    data class Bucket(val key: String, val label: String, val tx: Long, val rx: Long) {
        val total: Long get() = tx + rx
    }

    // ---------------------------------------------------------------- keys

    /**
     * Bucket keys are zero-padded and big-endian (`yyyy-MM-dd-HH`) on purpose:
     * that makes them **lexicographically sortable and comparable**, so retention
     * trimming is a string compare against a cutoff key and needs no date parsing.
     * `java.time` is avoided because minSdk is 26 and `Calendar` is already used
     * elsewhere in this app.
     */
    private fun hourKey(calendar: Calendar): String = String.format(
        java.util.Locale.US,
        "%04d-%02d-%02d-%02d",
        calendar.get(Calendar.YEAR),
        calendar.get(Calendar.MONTH) + 1,
        calendar.get(Calendar.DAY_OF_MONTH),
        calendar.get(Calendar.HOUR_OF_DAY),
    )

    private fun dayKey(calendar: Calendar): String = String.format(
        java.util.Locale.US,
        "%04d-%02d-%02d",
        calendar.get(Calendar.YEAR),
        calendar.get(Calendar.MONTH) + 1,
        calendar.get(Calendar.DAY_OF_MONTH),
    )

    // ---------------------------------------------------------------- writes

    /**
     * Adds one sample's deltas to the current hour and day.
     *
     * Deltas only — see the class doc. Zero/negative input is ignored so a rebase
     * cannot write an empty bucket and make the chart show a phantom active hour.
     */
    fun add(context: Context, txDelta: Long, rxDelta: Long) {
        if (txDelta <= 0 && rxDelta <= 0) return
        synchronized(lock) {
            load(context)
            val now = Calendar.getInstance()
            bump(hourly, hourKey(now), txDelta, rxDelta)
            bump(daily, dayKey(now), txDelta, rxDelta)
        }
    }

    private fun bump(into: HashMap<String, LongArray>, key: String, tx: Long, rx: Long) {
        val current = into[key]
        if (current == null) {
            into[key] = longArrayOf(tx, rx)
        } else {
            current[0] += tx
            current[1] += rx
        }
    }

    fun flush(context: Context) {
        synchronized(lock) {
            if (!loaded) return
            trim()
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY_HOURLY, encode(hourly))
                .putString(KEY_DAILY, encode(daily))
                .apply()
        }
    }

    /** Drops buckets past their retention window. Caller holds [lock]. */
    private fun trim() {
        val hourCutoff = Calendar.getInstance()
            .apply { add(Calendar.HOUR_OF_DAY, -HOURLY_RETENTION_HOURS) }
            .let(::hourKey)
        hourly.keys.retainAll { it >= hourCutoff }

        val dayCutoff = Calendar.getInstance()
            .apply { add(Calendar.DAY_OF_MONTH, -DAILY_RETENTION_DAYS) }
            .let(::dayKey)
        daily.keys.retainAll { it >= dayCutoff }
    }

    // ---------------------------------------------------------------- reads

    /**
     * The last [hours] hourly buckets, oldest first, including empty ones.
     *
     * Empty buckets are included deliberately: a bar chart with gaps omitted
     * misrepresents an idle night as continuous use.
     */
    fun lastHours(context: Context, hours: Int): List<Bucket> = synchronized(lock) {
        load(context)
        val cursor = Calendar.getInstance()
        (hours - 1 downTo 0).map { back ->
            val slot = (cursor.clone() as Calendar).apply { add(Calendar.HOUR_OF_DAY, -back) }
            val key = hourKey(slot)
            val value = hourly[key] ?: EMPTY
            Bucket(
                key = key,
                label = String.format(java.util.Locale.US, "%02d", slot.get(Calendar.HOUR_OF_DAY)),
                tx = value[0],
                rx = value[1],
            )
        }
    }

    /** The last [days] daily buckets, oldest first, including empty ones. */
    fun lastDays(context: Context, days: Int): List<Bucket> = synchronized(lock) {
        load(context)
        val cursor = Calendar.getInstance()
        (days - 1 downTo 0).map { back ->
            val slot = (cursor.clone() as Calendar).apply { add(Calendar.DAY_OF_MONTH, -back) }
            val key = dayKey(slot)
            val value = daily[key] ?: EMPTY
            Bucket(
                key = key,
                label = "${slot.get(Calendar.MONTH) + 1}/${slot.get(Calendar.DAY_OF_MONTH)}",
                tx = value[0],
                rx = value[1],
            )
        }
    }

    fun sum(buckets: List<Bucket>): LongArray {
        var tx = 0L
        var rx = 0L
        buckets.forEach { tx += it.tx; rx += it.rx }
        return longArrayOf(tx, rx)
    }

    /**
     * Discards all history.
     *
     * Used by the one-time reset that accompanies the monthly-total fix: history
     * accumulated from the inflated counters is wrong by the same factor, so it
     * has to go with it rather than be left to contradict the corrected total.
     */
    fun reset(context: Context) {
        synchronized(lock) {
            hourly.clear()
            daily.clear()
            loaded = true
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
        }
    }

    // ---------------------------------------------------------------- storage

    private val EMPTY = longArrayOf(0L, 0L)

    /** Caller holds [lock]. */
    private fun load(context: Context) {
        if (loaded) return
        loaded = true
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        decode(prefs.getString(KEY_HOURLY, null), hourly)
        decode(prefs.getString(KEY_DAILY, null), daily)
        trim()
    }

    private fun decode(raw: String?, into: HashMap<String, LongArray>) {
        if (raw.isNullOrBlank()) return
        runCatching {
            val root = JSONObject(raw)
            root.keys().forEach { key ->
                val pair = root.getJSONArray(key)
                into[key] = longArrayOf(pair.optLong(0), pair.optLong(1))
            }
        }
    }

    private fun encode(from: Map<String, LongArray>): String {
        val root = JSONObject()
        from.forEach { (key, value) ->
            root.put(key, JSONArray().put(value[0]).put(value[1]))
        }
        return root.toString()
    }
}
