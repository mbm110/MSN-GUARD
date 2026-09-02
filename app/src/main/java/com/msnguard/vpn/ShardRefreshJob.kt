package com.msnguard.vpn

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context

/**
 * Keeps the SHARD node list fresh in the background.
 *
 * ## Why a job and not a thread
 *
 * The user's requirement was that the list update itself whether the VPN is on or
 * off, and without costing battery. Those two pull in opposite directions if you
 * implement it yourself: a `ScheduledExecutorService` inside the app process only
 * runs while the process is alive, and an alarm that wakes the device on a timer is
 * exactly the battery drain we were told to avoid.
 *
 * [JobScheduler] resolves both. It survives process death and reboot, and the OS
 * decides *when* inside our window — it batches our fetch with whatever else on the
 * device is already waking the radio, so in the common case the update costs no
 * extra radio wake at all. One HTTP GET against a text file every few hours, which
 * usually answers `304 Not Modified` and transfers nothing.
 *
 * ## Why it does not depend on the VPN
 *
 * Deliberately unconditional, per the user's field test: `raw.githubusercontent.com`
 * is reachable on Iranian carriers without a tunnel — verified by adding the same
 * subscription to another client on Hamrah-e-Aval and refreshing it. So the fetch
 * goes out over whatever link exists. That is also the only order that works: the
 * list is what SHARD needs *in order to* connect, so requiring a tunnel first would
 * be circular.
 *
 * ## Interaction with the foreground refresh
 *
 * [MainActivity] also calls [ShardSubscription.refreshIfDue] when it resumes. The
 * two cannot double-fetch: `refreshIfDue` holds a min-interval and a single-flight
 * flag, so whichever arrives second returns the cached count and does no I/O.
 */
class ShardRefreshJob : android.app.job.JobService() {

    override fun onStartJob(params: JobParameters?): Boolean {
        ShardSubscription.refreshIfDue(applicationContext) {
            // Never reschedule on failure. The next periodic window is minutes to
            // hours away and the cache is still serviceable; retrying a blocked or
            // flaky network immediately is how a background fetch turns into the
            // battery drain this design exists to avoid.
            jobFinished(params, false)
        }
        // Work continues on ShardSubscription's own thread.
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        // The fetch is a short GET with its own timeouts and it writes the cache
        // atomically enough (single writeText) that being killed mid-flight leaves
        // either the old file or the new one. Nothing to unwind, and no reason to
        // ask for a re-run.
        return false
    }

    companion object {

        private const val JOB_ID = 0x5A4D

        /**
         * How often the OS may run us. Six hours matches
         * [ShardSubscription]'s own min-interval, and the publisher rebuilds the
         * list once a day at 10:00 UTC — measured from their own workflow — so
         * four opportunities a day already means we are never more than a few
         * hours behind a rebuild.
         */
        private const val PERIOD_MS = 6 * 60 * 60 * 1000L

        /**
         * Register the periodic job. Idempotent: scheduling the same id replaces
         * the previous registration rather than stacking a second one.
         *
         * Called from [MainActivity.onCreate], and that call site is what makes the
         * job survive reboots here.
         *
         * **No `setPersisted(true)`.** It looks like the obvious way to survive a
         * reboot, and it is what this code used to do, but JobScheduler rejects a
         * persisted job unless the app holds `RECEIVE_BOOT_COMPLETED` — and the
         * rejection is an exception from `schedule()`, not a downgrade. Field log,
         * twice per launch on a real device:
         *
         * ```
         * ShardRefreshJob could not be scheduled: Requested job cannot be persisted
         *   without holding android.permission.RECEIVE_BOOT_COMPLETED permission
         * ```
         *
         * So the flag meant to protect the job across reboots was in fact stopping
         * it from ever being registered at all: no periodic refresh had ever run on
         * any device, and the node list only advanced when the user opened the app.
         *
         * Dropping the flag rather than adding the permission, because the permission
         * buys nothing here. A non-persisted job is lost on reboot and re-registered
         * the next time [MainActivity] starts, and this app cannot refresh a node
         * list usefully without the user opening it to connect anyway. The manifest's
         * standing rule — request nothing Play Protect scores as boot-persistent
         * behaviour — is the tiebreaker.
         */
        fun schedule(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            val job = JobInfo.Builder(JOB_ID, ComponentName(context, ShardRefreshJob::class.java))
                // ANY, not UNMETERED: the list is a few tens of kilobytes and a
                // user on mobile data only — which is the common case for this
                // app's users — would otherwise never get an update at all.
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPeriodic(PERIOD_MS)
                // Explicitly not requiring charging or idle. Both would mean a
                // phone that is used all day and charged overnight in a country
                // where the pool churns daily gets its update at the worst
                // possible time, or not at all.
                .build()
            try {
                scheduler.schedule(job)
            } catch (e: Exception) {
                // Some OEM builds cap the number of jobs per app. Not fatal: the
                // foreground refresh in MainActivity still keeps the list current
                // for anyone who opens the app.
                ConnectionLog.record("ShardRefreshJob could not be scheduled: ${e.message}")
            }
        }
    }
}
