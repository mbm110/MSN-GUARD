package com.msnguard.vpn

import android.app.Activity
import android.os.Bundle

/**
 * A window that exists only so the Quick Settings shade will close.
 *
 * Android has no public "collapse the notification shade" API. The only supported
 * way for a [android.service.quicksettings.TileService] to close it is
 * `startActivityAndCollapse(...)`, which insists on actually starting an activity.
 * So this one starts, finishes before it can draw anything, and suppresses both
 * transition animations — the visible effect is the shade sliding away, which is
 * what a tile tap should do.
 *
 * Declared with `noHistory`, `excludeFromRecents` and its own empty `taskAffinity`
 * so it never appears in the recents list and never lands on top of MainActivity's
 * task. Without the separate affinity, tapping the tile while the app is open would
 * push this on top of the real UI.
 */
class ShadeCollapseActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        finish()
        // finish() alone still plays the theme's close transition, which reads as a
        // flicker behind the collapsing shade. Zero out both directions.
        @Suppress("DEPRECATION")
        overridePendingTransition(0, 0)
    }
}
