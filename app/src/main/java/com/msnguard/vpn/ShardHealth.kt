package com.msnguard.vpn

import android.content.Context

/**
 * Per-node health memory: which nodes worked, how fast, and which just failed.
 *
 * ## Why this exists
 *
 * Without it every connect pays the full race from scratch. Measured against the
 * live pool from this machine: a cold race over the publisher's first 12 nodes
 * found a winner in 760–864 ms across three runs, while probing all 28 nodes one
 * at a time took 82 s. The memory is also what makes a bad node stop being tried
 * first after it dies.
 *
 * ## Why latency alone is not the ranking
 *
 * Measured on the live pool: of 28 unique nodes, 20 carried a real HTTP request
 * and 8 did not — and the failures were not uniformly dead, several timed out at
 * exactly the 5 s ceiling while others answered in under a second. A pure "lowest
 * last latency" ranking promotes the intermittent ones, because a node that
 * half-works often answers fast when it answers at all.
 *
 * The score therefore carries a success streak alongside the latency, and a
 * failure is remembered rather than merely forgetting a success.
 */
object ShardHealth {

    private const val PREFS = "shard_health"

    /**
     * Highest latency still treated as a real measurement, in ms.
     *
     * Above this the node is recorded as a failure instead: the working nodes in
     * the live pool measured 727–5735 ms, so 8 s is not "slow but usable", it is a
     * node that will feel broken.
     */
    private const val LATENCY_CEILING_MS = 8_000

    /** How many consecutive failures before a node drops behind untried ones. */
    private const val FAILURE_TOLERANCE = 2

    /**
     * Ceiling and exchange rate for the measured-bandwidth bonus in [Score.rank].
     *
     * 30 Mbps × 50 ms = 1500 ms, i.e. a fast node may jump ahead of one whose
     * probe was up to 1.5 s quicker. Chosen so the bonus can overcome the
     * latency spread actually seen among working nodes (727–1773 ms) without
     * overwhelming the failure and streak terms, which are about reliability.
     */
    private const val THROUGHPUT_BONUS_CEILING_MBPS = 30
    private const val THROUGHPUT_BONUS_PER_MBPS = 50

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * How much a node that the destination refuses is pushed down the order.
     *
     * Deliberately modest, and it is a *penalty on the sort key*, never an
     * exclusion: such a node still carries everything else perfectly, so a pool
     * where every exit is refused must keep working. 2 s is enough to lose to any
     * comparable node and not enough to lose to a broken one.
     *
     * Measured on the live pool it costs nothing anyway: the refused exits were
     * the slow ones (1326 ms and worse) and the accepted ones the fast ones
     * (867 ms), so preferring an accepted exit improves latency rather than
     * trading it away.
     */
    private const val REFUSED_EXIT_PENALTY_MS = 2_000

    /** Stored reach verdicts. 0 is also what every pre-existing entry reads as. */
    const val REACH_UNKNOWN = 0
    const val REACH_USABLE = 1
    const val REACH_REFUSED = 2

    /**
     * How long a stored verdict is trusted, in hours.
     *
     * A verdict must expire, or a node whose operator moves it to a served exit
     * would carry its penalty forever and could only be forgiven by the user
     * resetting the transport. Six hours matches the subscription refresh, so a
     * node is re-judged about as often as the pool itself changes.
     *
     * Expiry is why the stamp exists at all — and it also means an entry written
     * by an older version, which has no stamp, reads as expired rather than as a
     * verdict, so an upgrade starts from measurement instead of from a guess.
     */
    private const val REACH_TTL_HOURS = 6

    /**
     * What we know about one node.
     *
     * @param latencyMs last successful probe, 0 if never measured.
     * @param streak consecutive successes, reset to 0 by any failure.
     * @param failures consecutive failures, reset to 0 by any success.
     * @param kbps last measured download rate, 0 if never measured. See
     *   [recordThroughput] for why latency alone is not enough.
     * @param reach whether the destination that geolocates its callers will serve
     *   this exit — see [ShardReach]. [REACH_UNKNOWN] until measured, which is
     *   what every entry written by an older version reads as.
     * @param reachAtMs when [reach] was measured. A verdict older than
     *   [REACH_TTL_HOURS] is treated as unmeasured — see [reachEffective].
     */
    data class Score(
        val latencyMs: Int,
        val streak: Int,
        val failures: Int,
        val kbps: Int = 0,
        val reach: Int = REACH_UNKNOWN,
        val reachAtMs: Long = 0L,
    ) {
        val everWorked: Boolean get() = latencyMs > 0

        /**
         * The verdict, or [REACH_UNKNOWN] once it is too old to trust.
         *
         * Everything reads this rather than [reach] directly, so an expired
         * verdict stops shaping the order and gets re-measured on the next race,
         * while the stored value survives for the writers that only update one
         * other field.
         */
        val reachEffective: Int
            get() = if (reach == REACH_UNKNOWN || isReachExpired()) REACH_UNKNOWN else reach

        private fun isReachExpired(): Boolean {
            if (reachAtMs <= 0L) return true
            val age = System.currentTimeMillis() - reachAtMs
            // A clock moved backwards reads as expired rather than as fresh
            // forever, which is the safe direction: it costs one measurement.
            return age < 0L || age > REACH_TTL_HOURS * 60L * 60L * 1000L
        }

        /**
         * Sort key: lower is tried earlier.
         *
         * A node that has failed [FAILURE_TOLERANCE] times in a row is pushed
         * behind everything untried, but not removed — the pool is small and a
         * node whose owner fixed their worker deserves another look eventually.
         * Untried nodes sort in the middle: ahead of known-bad, behind known-good.
         */
        fun rank(): Int = when {
            failures >= FAILURE_TOLERANCE -> 900_000 + latencyMs
            !everWorked -> 500_000
            // Two consecutive successes are worth roughly a second of latency:
            // enough to prefer a steady 2 s node over a flaky 1.2 s one, not
            // enough to bury a genuinely fast newcomer.
            else -> latencyMs - (streak.coerceAtMost(5) * 500) - throughputBonus() +
                refusedExitPenalty()
        }

        /**
         * Penalty for an exit the destination refuses to serve. See
         * [REFUSED_EXIT_PENALTY_MS] for why it is a penalty and not a filter.
         *
         * Applies only inside the "known-good" branch above, so it can reorder
         * working nodes among themselves and can never promote a failing node or
         * demote one below the known-bad tier.
         */
        private fun refusedExitPenalty(): Int =
            if (reachEffective == REACH_REFUSED) REFUSED_EXIT_PENALTY_MS else 0

        /**
         * How much measured bandwidth is allowed to outweigh probe latency.
         *
         * Needed because the two are close to unrelated. Measured across the 23
         * reachable nodes of the live pool, probe latency against the rate of a
         * 4 MB download through the same node in the same minute:
         *
         * ```
         *   probe  778 ms -> 108 Mbps        probe 1488 ms ->   5.1 Mbps
         *   probe  942 ms ->  25 Mbps        probe 1773 ms ->  98.5 Mbps
         * ```
         *
         * A pure latency ranking therefore prefers the 5 Mbps node to the
         * 98 Mbps one. The bonus is capped at 30 Mbps' worth (1500 ms) so a
         * genuinely fast link cannot bury a node that is merely well-connected,
         * and so the ordering stays dominated by "does it work at all".
         */
        private fun throughputBonus(): Int {
            if (kbps <= 0) return 0
            val mbps = kbps / 1000
            return mbps.coerceAtMost(THROUGHPUT_BONUS_CEILING_MBPS) * THROUGHPUT_BONUS_PER_MBPS
        }
    }

    fun score(context: Context, node: ShardNode): Score {
        val raw = prefs(context).getString(node.key, null) ?: return Score(0, 0, 0)
        val parts = raw.split(':')
        return Score(
            latencyMs = parts.getOrNull(0)?.toIntOrNull() ?: 0,
            streak = parts.getOrNull(1)?.toIntOrNull() ?: 0,
            failures = parts.getOrNull(2)?.toIntOrNull() ?: 0,
            // Absent in entries written by older versions, which read back as 0
            // and simply score no bonus until the node is measured again.
            kbps = parts.getOrNull(3)?.toIntOrNull() ?: 0,
            // Same: an older entry reads as REACH_UNKNOWN, i.e. no penalty, so an
            // upgrade cannot reorder the pool until each node is measured.
            reach = parts.getOrNull(4)?.toIntOrNull() ?: REACH_UNKNOWN,
            // Absent in an older entry, which therefore reads as expired.
            reachAtMs = parts.getOrNull(5)?.toLongOrNull() ?: 0L,
        )
    }

    /** Record a successful probe. A latency past the ceiling counts as a failure. */
    fun recordSuccess(context: Context, node: ShardNode, latencyMs: Int) {
        if (latencyMs > LATENCY_CEILING_MS) {
            recordFailure(context, node)
            return
        }
        val previous = score(context, node)
        // Smoothed, not replaced: one lucky sample on a congested carrier link
        // should not promote a node to the top of the list on its own. Weighted
        // toward the new value so a genuine improvement is still visible quickly.
        val blended = if (previous.everWorked) {
            ((previous.latencyMs + latencyMs * 2) / 3)
        } else {
            latencyMs
        }
        prefs(context).edit()
            .putString(
                node.key,
                "$blended:${previous.streak + 1}:0:${previous.kbps}" +
                    ":${previous.reach}:${previous.reachAtMs}"
            )
            .apply()
    }

    /**
     * Record how fast [node] actually carried data, in kbit/s.
     *
     * Kept separate from [recordSuccess] because the two are measured at
     * different moments: latency comes from the race, which must stay cheap,
     * while this comes from a real transfer over the live tunnel once it is up.
     * A missing or failed measurement leaves the previous value alone rather
     * than clearing it — an interrupted sample says nothing about the node.
     */
    fun recordThroughput(context: Context, node: ShardNode, kbps: Int) {
        if (kbps <= 0) return
        val previous = score(context, node)
        // Same smoothing as latency, and for the same reason: one sample taken
        // while the user was streaming video is not the node's capability.
        val blended = if (previous.kbps > 0) {
            ((previous.kbps + kbps * 2) / 3)
        } else {
            kbps
        }
        prefs(context).edit()
            .putString(
                node.key,
                "${previous.latencyMs}:${previous.streak}:${previous.failures}" +
                    ":$blended:${previous.reach}:${previous.reachAtMs}"
            )
            .apply()
    }

    /**
     * Record whether the destination that geolocates its callers will serve this
     * exit — see [ShardReach] for how that is measured for under a kilobyte.
     *
     * [ShardReach.Verdict.UNKNOWN] is not written at all: a check that could not
     * run is not evidence, and overwriting a real verdict with it would make the
     * order flap on a bad network. Only a definite answer is stored.
     */
    fun recordReach(context: Context, node: ShardNode, verdict: ShardReach.Verdict) {
        val value = when (verdict) {
            ShardReach.Verdict.USABLE -> REACH_USABLE
            ShardReach.Verdict.WALLED -> REACH_REFUSED
            ShardReach.Verdict.UNKNOWN -> return
        }
        val previous = score(context, node)
        // Written even when the verdict is unchanged, because the stamp is what
        // keeps it from expiring — but only the stamp moves, so this is not a
        // reordering.
        prefs(context).edit()
            .putString(
                node.key,
                "${previous.latencyMs}:${previous.streak}:${previous.failures}" +
                    ":${previous.kbps}:$value:${System.currentTimeMillis()}"
            )
            .apply()
    }

    /** True when this node's exit was measured, recently, and refused. */
    fun isRefusedExit(context: Context, node: ShardNode): Boolean =
        score(context, node).reachEffective == REACH_REFUSED

    /** True when this node's exit was measured, recently, and accepted. */
    fun isUsableExit(context: Context, node: ShardNode): Boolean =
        score(context, node).reachEffective == REACH_USABLE

    fun recordFailure(context: Context, node: ShardNode) {
        val previous = score(context, node)
        prefs(context).edit()
            .putString(
                node.key,
                "${previous.latencyMs}:0:${previous.failures + 1}:${previous.kbps}" +
                    ":${previous.reach}:${previous.reachAtMs}"
            )
            .apply()
    }

    /**
     * Order the pool for the next race: most likely to work, fastest first.
     *
     * Stable within a rank, so nodes we know nothing about keep the publisher's
     * own order — which is itself the output of a 3-of-3 health check, so it is
     * better than random.
     */
    fun rank(context: Context, nodes: List<ShardNode>): List<ShardNode> {
        val scores = nodes.associateWith { score(context, it) }
        return nodes.sortedBy { scores[it]?.rank() ?: 500_000 }
    }

    /**
     * Drop memory for nodes that are no longer in the pool.
     *
     * Called after each subscription refresh. Without it this file grows forever:
     * the publisher's nodes rotate, and every departed node would keep its entry
     * indefinitely.
     */
    fun prune(context: Context, nodes: List<ShardNode>) {
        val live = nodes.map { it.key }.toSet()
        val editor = prefs(context).edit()
        prefs(context).all.keys.forEach { key ->
            if (key !in live) editor.remove(key)
        }
        editor.apply()
    }

    /** Forget everything. Exposed for the settings row that resets the transport. */
    fun clear(context: Context) {
        prefs(context).edit().clear().apply()
    }
}
