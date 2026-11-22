package backend

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/getlantern/broflake/common/helperticket"

	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/peer"
)

// A volunteer serves its helper pairings over its direct TCP route even with
// Share My Connection off: having a pairing is consent to serve that friend.
// The peer client then runs pairings-only, mapping a port and registering
// serve_pool=false, so the route never reaches the general pool. Sharing and
// the pairings-only route are one client on one port mapping. It is
// best-effort: a router that won't map a port, or a route lantern-cloud can't
// verify, leaves the friend on Unbounded rooms, and the attempt is retried with
// backoff and after a network change. It never runs where this device's
// country is unknown or censored: lantern-cloud refuses such a volunteer, but
// only after the port is mapped, and its geolocation can fail open.

// pairingRouteRetryFirst and pairingRouteRetryMax bound the backoff between
// failed pairings-only starts. pairingRouteRetryFirst is also the least time
// between attempts a network change can force. Vars so tests can shorten them.
var (
	pairingRouteRetryFirst = time.Minute
	pairingRouteRetryMax   = 30 * time.Minute
)

// pairingRunStableAfter is how long a pairings-only run must stay up before
// it stopping restarts the backoff. A var so tests can shorten it.
var pairingRunStableAfter = 30 * time.Minute

// hasVolunteerPairings reports whether this device is the volunteer in any
// helper pairing.
func (r *LocalBackend) hasVolunteerPairings() bool {
	return len(r.helperPairingKeys.IDs(string(helperticket.RoleVolunteer))) > 0
}

// censoredCountries are the countries where the pairings-only route never
// starts on its own. It mirrors censoredCountries in lantern-cloud
// regions/regions.go, as the app's helperCensoredCountries does; keep the
// three in step.
var censoredCountries = map[string]struct{}{
	"AE": {}, "AF": {}, "AZ": {}, "BY": {}, "CN": {}, "CU": {}, "EG": {},
	"ET": {}, "IR": {}, "KP": {}, "MM": {}, "PK": {}, "RU": {}, "SA": {},
	"SY": {}, "TJ": {}, "TM": {}, "UZ": {}, "VN": {}, "YE": {},
}

// pairingRouteCountryAllowed reports whether this device's country is known
// and not censored. A country override wins over the saved country, which
// config updates leave alone while one is set.
func pairingRouteCountryAllowed() bool {
	c := env.GetString(env.Country)
	if c == "" {
		c = settings.GetString(settings.CountryCodeKey)
	}
	c = strings.ToUpper(strings.TrimSpace(c))
	if c == "" {
		return false
	}
	_, censored := censoredCountries[c]
	return !censored
}

// wantPairingRoute reports whether this device should run the pairings-only
// route: it volunteers in a pairing, from a country where that is allowed.
// The pairing keys are kept either way, so a pairing can still be authorized,
// revoked, or served once the user turns Share My Connection on.
func (r *LocalBackend) wantPairingRoute() bool {
	return r.hasVolunteerPairings() && pairingRouteCountryAllowed()
}

// peerShareActive reports whether the peer client runs or is meant to, for
// Share My Connection or for pairings only. The reverse client reads it to
// leave the manual port to the peer client.
func (r *LocalBackend) peerShareActive() bool {
	return peerShareOn() || r.peerForPairings.Load()
}

// syncPairingRoute reconciles the pairings-only route in the background:
// mapping a port and registering take seconds.
func (r *LocalBackend) syncPairingRoute() {
	if r.peerClient == nil || peerShareUnsupported() {
		return
	}
	// At most one worker waits for the lock; it reads the state when it runs,
	// so the timer, network changes and pairing changes coalesce into it.
	if !r.pairingSyncQueued.CompareAndSwap(false, true) {
		return
	}
	if !r.addPeerWork() {
		r.pairingSyncQueued.Store(false)
		return
	}
	go func() {
		defer r.peerWG.Done()
		r.peerToggleMu.Lock()
		defer r.peerToggleMu.Unlock()
		r.pairingSyncQueued.Store(false)
		if r.ctx.Err() != nil {
			return
		}
		r.reconcilePairingRouteLocked()
	}()
}

// reconcilePairingRouteLocked is reconcileSharingOffLocked, starting at once,
// when Share My Connection is off; with sharing on, its toggle governs the
// client and this does nothing. The caller holds peerToggleMu.
func (r *LocalBackend) reconcilePairingRouteLocked() {
	if settings.GetBool(settings.PeerShareEnabledKey) {
		return
	}
	r.reconcileSharingOffLocked(true)
}

// reconcileSharingOffLocked brings the peer client to what sharing being off
// and this device's volunteer pairings ask for: a pairings-only run while it
// has any, nothing otherwise. Every path that turns sharing off ends here. A
// pool run left over from sharing is handed to
// pairings-only on the same port mapping by re-registering, and fails closed:
// if the re-register fails, the client stops rather than leave a pool route
// up. A fresh start runs here only when startNow is set; otherwise it is left
// to syncPairingRoute, which re-checks the setting, so a toggle returns
// promptly. The caller holds peerToggleMu.
func (r *LocalBackend) reconcileSharingOffLocked(startNow bool) {
	if r.peerClient == nil || peerShareUnsupported() {
		return
	}
	// A re-register queued for sharing, by an "on" that took the lock between
	// an "off" cancelling it and this, would rotate a run sharing no longer
	// owns.
	r.cancelPeerRereg()
	want, active := r.wantPairingRoute(), r.peerClient.IsActive()
	if !active {
		// A self-stop clears active before its teardown deregisters and
		// closes the box; Stop waits that out, so pool sessions have ended
		// before sharing-off returns. It returns at once when nothing is
		// tearing down.
		r.drainPeerTeardownLocked()
	}
	if active && want && !r.peerForPairings.Load() {
		r.peerForPairings.Store(true)
		r.peerClient.RetagStatus()
		if r.handOverToPairingsLocked() {
			r.notePairingRunStart()
			r.emitSharingStatus()
			return
		}
		slog.Warn("pairing route re-register failed; restarting it")
		r.stopPeerLocked()
		active = false
	}
	switch {
	case !want:
		if active {
			r.stopPeerLocked()
		}
		// A later pairing starts its backoff afresh.
		r.resetPairingRouteRetry()
	case want && !active && startNow:
		r.startPairingRouteLocked()
	case want && !active:
		r.syncPairingRoute()
	}
}

// handOverToPairingsLocked makes a pool run pairings-only on the same port
// mapping, reporting whether it did. The re-register sends serve_pool=false and
// rotates the credentials, so strangers are cut off. A route already
// registered without the pool ("help others too" was off) has nothing to
// change and keeps its friends' sessions. That is judged from MayServePool,
// never the setting, which a pending or failed re-register leaves ahead of the
// registration. The caller holds peerToggleMu.
func (r *LocalBackend) handOverToPairingsLocked() bool {
	if !r.peerClient.MayServePool() {
		return true
	}
	ctx, cancel := context.WithTimeout(r.ctx, peerToggleTimeout)
	defer cancel()
	return r.peerClient.Reregister(ctx) == nil
}

// startPairingRouteLocked starts a pairings-only run, retrying later if it
// fails. The caller holds peerToggleMu.
func (r *LocalBackend) startPairingRouteLocked() {
	// A stale worker, a timer's from before this backoff say, leaves the
	// attempt to the scheduled retry.
	r.pairingRetryMu.Lock()
	early := time.Now().Before(r.pairingNotBefore)
	r.pairingRetryMu.Unlock()
	if early {
		return
	}
	ctx, cancel := context.WithTimeout(r.ctx, peerToggleTimeout)
	defer cancel()
	// The reverse client holds the manual port, when one is set, that the
	// peer client binds. Without one they don't collide, and pausing would
	// drop the friend's reverse sessions on every retry.
	if peer.ManualPort() != 0 {
		resume := r.pauseReverse(ctx)
		defer resume()
	}
	r.notePairingRouteAttempt()
	r.peerForPairings.Store(true)
	if err := r.peerClient.Start(ctx); err != nil {
		r.peerForPairings.Store(false)
		// Fixed text: the error can quote an API body or URL.
		slog.Warn("pairing route start failed; retrying later")
		r.schedulePairingRouteRetry()
		return
	}
	// The backoff is kept until the run proves stable: see onPeerSelfStop.
	r.notePairingRunStart()
	slog.Info("pairing route started")
}

// drainPeerTeardownLocked waits for an inactive client's in-flight teardown,
// if any. The caller holds peerToggleMu.
func (r *LocalBackend) drainPeerTeardownLocked() {
	ctx, cancel := context.WithTimeout(r.ctx, peerToggleTimeout)
	defer cancel()
	if err := r.peerClient.Stop(ctx); err != nil {
		slog.Warn("waiting for peer teardown returned error", "error", err)
	}
}

// stopPeerLocked stops the peer client. The caller holds peerToggleMu.
func (r *LocalBackend) stopPeerLocked() {
	ctx, cancel := context.WithTimeout(r.ctx, peerToggleTimeout)
	defer cancel()
	if err := r.peerClient.Stop(ctx); err != nil {
		slog.Warn("peer stop returned error", "error", err)
	}
	r.clearPairingRunStart()
	// Cleared before the reverse client restarts, so it sees the manual port
	// free (peerShareActive).
	wasPairings := r.peerForPairings.Swap(false)
	r.restartYieldedReverse()
	// A sharing run's Stop published its own status; a pairings-only run's was
	// kept from the sharing UI.
	if wasPairings {
		r.emitSharingStatus()
	}
}

// notePairingRunStart records when the current pairings-only run began, by a
// start or a hand-off from sharing.
func (r *LocalBackend) notePairingRunStart() {
	r.pairingRetryMu.Lock()
	r.pairingStartedAt = time.Now()
	r.pairingRetryMu.Unlock()
}

// clearPairingRunStart forgets the pairings-only run's start: it ended, or
// became a sharing run.
func (r *LocalBackend) clearPairingRunStart() {
	r.pairingRetryMu.Lock()
	r.pairingStartedAt = time.Time{}
	r.pairingRetryMu.Unlock()
}

// emitSharingStatus tells the sharing UI of a change the peer client didn't
// publish itself: a hand-off between sharing and pairings-only changes what
// PeerStatus reports without a new phase.
func (r *LocalBackend) emitSharingStatus() {
	events.Emit(peer.StatusEvent{Status: r.PeerStatus()})
}

// pairingRunWasStable reports whether the pairings-only run that just stopped
// had stayed up pairingRunStableAfter, long enough to restart the backoff, so a
// run that starts and soon stops itself backs off like a failed start.
func (r *LocalBackend) pairingRunWasStable() bool {
	r.pairingRetryMu.Lock()
	defer r.pairingRetryMu.Unlock()
	return !r.pairingStartedAt.IsZero() && time.Since(r.pairingStartedAt) >= pairingRunStableAfter
}

// schedulePairingRouteRetry tries the pairings-only start again after a
// backoff that doubles with each failure up to pairingRouteRetryMax. Nothing is
// scheduled once the backend is closing.
func (r *LocalBackend) schedulePairingRouteRetry() {
	r.peerWGMu.Lock()
	closing := r.peerClosing
	r.peerWGMu.Unlock()
	if closing {
		return
	}
	r.pairingRetryMu.Lock()
	defer r.pairingRetryMu.Unlock()
	if r.pairingRetryTimer != nil {
		r.pairingRetryTimer.Stop()
	}
	wait := r.pairingRetryWait
	if wait == 0 {
		wait = pairingRouteRetryFirst
	}
	r.pairingRetryWait = min(2*wait, pairingRouteRetryMax)
	r.pairingNotBefore = time.Now().Add(wait)
	r.pairingRetryTimer = time.AfterFunc(wait, r.syncPairingRoute)
}

// clearPairingNotBefore lets the next start run at once, keeping the backoff.
func (r *LocalBackend) clearPairingNotBefore() {
	r.pairingRetryMu.Lock()
	r.pairingNotBefore = time.Time{}
	r.pairingRetryMu.Unlock()
}

// resetPairingRouteRetry cancels a pending retry and restarts the backoff.
func (r *LocalBackend) resetPairingRouteRetry() {
	r.pairingRetryMu.Lock()
	defer r.pairingRetryMu.Unlock()
	if r.pairingRetryTimer != nil {
		r.pairingRetryTimer.Stop()
		r.pairingRetryTimer = nil
	}
	r.pairingRetryWait = 0
	r.pairingNotBefore = time.Time{}
}

// notePairingRouteAttempt records when a pairings-only start was last tried.
func (r *LocalBackend) notePairingRouteAttempt() {
	r.pairingRetryMu.Lock()
	r.pairingLastAttempt = time.Now()
	r.pairingRetryMu.Unlock()
}

// pairingRouteNetworkChanged retries a failed pairings-only start at once, as
// the new network's router may map a port the last one wouldn't, but no more
// often than pairingRouteRetryFirst: network events can come in bursts.
func (r *LocalBackend) pairingRouteNetworkChanged() {
	if r.peerClient == nil || r.peerClient.IsActive() || !r.wantPairingRoute() ||
		settings.GetBool(settings.PeerShareEnabledKey) {
		return
	}
	// The attempt is reserved here, not when it runs, so a burst of events
	// queues one.
	r.pairingRetryMu.Lock()
	recent := time.Since(r.pairingLastAttempt) < pairingRouteRetryFirst
	if !recent {
		r.pairingLastAttempt = time.Now()
	}
	r.pairingRetryMu.Unlock()
	if recent {
		return
	}
	// The backoff starts over on the new network, but a pending retry is left
	// armed in case this attempt turns out a no-op.
	r.pairingRetryMu.Lock()
	r.pairingRetryWait = 0
	r.pairingNotBefore = time.Time{}
	r.pairingRetryMu.Unlock()
	r.syncPairingRoute()
}
