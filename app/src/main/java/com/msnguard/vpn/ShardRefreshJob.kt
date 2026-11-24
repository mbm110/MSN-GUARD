package com.msnguard.vpn

import android.app.job.JobScheduler
import android.content.Context

/**
 * SHARD list refresh: RETIRED background job (3.4.15 EXIT-STOP).
 *
 * ## Why this file still exists
 *
 * This class was a JobScheduler job that woke the app process every six
 * hours to refresh the SHARD node list "whether or not a tunnel is up" —
 * a feature the user asked for at the time. It is retired by a later,
 * standing user rule (2026-11-24): once the user disconnects and LEAVES
 * the app, the app must draw zero battery — "no background wake-ups of
 * any kind". A periodic job violates that by design.
 *
 * The class stays (manifest entry removed, [onStartJob] gone) for one
 * reason: upgrade hygiene. Devices upgrading from an older build still
 * carry the old registration in JobScheduler's table; [MainActivity]
 * calls [cancel] on every launch so no stale registration — including one
 * re-armed by a package reinstall of an old APK — can ever fire again.
 *
 * ## What replaced the background refresh
 *
 * The foreground path only: [MainActivity] calls
 * [ShardSubscription.refreshIfDue] (plus the RemotePolicy and SmartSplit
 * equivalents) in `onCreate`, and [MsnGuardVpnService] refreshes them
 * too when a session starts. `refreshIfDue` holds a min-interval and a
 * single-flight flag, so whichever call arrives second returns the cached
 * count and does no I/O: opening the app already keeps every list fresh,
 * with zero cost once the app is closed.
 */
class ShardRefreshJob {

    companion object {

        /**
         * The historical job id — MUST stay identical to the one the retired
         * `schedule()` used, or cancel() would miss the stale registrations.
         */
        private const val JOB_ID = 0x5A4D

        /**
         * Retire any registration the old builds left in JobScheduler's
         * table. Idempotent and safe to call on every launch.
         */
        fun cancel(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            // The old jobs were scheduled (not persisted: see the history
            // in git), so a reboot clears them anyway; this handles the
            // no-reboot upgrade path.
            scheduler.cancel(JOB_ID)
        }
    }
}
