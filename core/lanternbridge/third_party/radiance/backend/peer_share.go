package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/kindling"
	"github.com/getlantern/radiance/peer"
	"github.com/sagernet/sing/common/control"
)

// peerController is the subset of *peer.Client that LocalBackend needs.
// Defined as an interface so tests can swap in a fake without standing up
// real UPnP / sing-box / lantern-cloud dependencies.
type peerController interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	IsActive() bool
	CurrentStatus() peer.Status
	RelaySnapshot() peer.Snapshot
	Reregister(ctx context.Context) error
	MayServePool() bool
	RetagStatus()
}

// peerToggleTimeout caps blocking time on a slow router; UPnP M-SEARCH +
// /v1/peer/register normally complete in single-digit seconds. Also used as
// the deadline for Stop on backend close so a stalled deregister can't hang
// shutdown.
const peerToggleTimeout = 30 * time.Second

// peerShareUnsupported reports platforms that must never serve as a peer. It
// is a var solely so tests can reach the unsupported branch: common.Platform
// is a constant, so the real check cannot be faked at runtime.
//
// iOS is excluded because the backend runs inside the network extension
// there, on a memory budget roughly a tenth of every other platform's, and
// serving adds a second sing-box instance to it. The memory monitor cannot
// absorb the difference: it measures the whole process but can only reclaim
// the VPN's own connections, so peer load would be relieved by evicting the
// user's own traffic, and failing that the extension is killed and the VPN
// goes down with it.
var peerShareUnsupported = common.IsIOS

// newPeerClient constructs the production peer.Client wired against the
// shared kindling HTTP client and the platform device ID. Pulled out of
// NewLocalBackend so the construction site is a one-liner.
func newPeerClient(platformDeviceID string, onSelfStop func(error), pairingsOnly func() bool, physical func() control.Func) (*peer.Client, error) {
	api := peer.NewAPI(kindling.HTTPClient(), common.GetBaseURL(), platformDeviceID)
	client, err := peer.NewClient(peer.Config{
		API:            api,
		RejectionsPath: filepath.Join(settings.GetString(settings.DataPathKey), "peer-rejections.json"),
		OnSelfStop:     onSelfStop,
		PairingsOnly:   pairingsOnly,
		// Mapping a port with the VPN up needs the physical interface.
		PhysicalControl: physical,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create peer client: %w", err)
	}
	return client, nil
}

// applyPeerShare drives peerClient to match the toggle and is the only writer
// of PeerShareEnabledKey. Persisting and acting happen together under
// peerToggleMu, the same lock the self-stop callback takes, so toggles apply
// in order and the setting always ends up describing the runtime state: "on"
// is rolled back if Start fails. Stop errors are logged because a partial
// teardown shouldn't keep the toggle on.
func (r *LocalBackend) applyPeerShare(enabled bool) error {
	_, err := r.applyPeerShareRegistered(enabled)
	return err
}

// applyPeerShareRegistered is applyPeerShare, also reporting whether the
// registration follows the settings as they are, or a re-register for them is
// under way, so a caller that persisted a registration setting first has
// nothing left to re-register. Decided under peerToggleMu.
func (r *LocalBackend) applyPeerShareRegistered(enabled bool) (registered bool, err error) {
	if peerShareUnsupported() {
		// A persisted "on" would otherwise survive every restart with nothing
		// behind it.
		persistErr := persistPeerShare(false)
		if enabled {
			return false, errors.Join(fmt.Errorf("peer share is not supported on %s", common.Platform), persistErr)
		}
		return false, persistErr
	}
	// Construction degrades to a nil client rather than failing (the backend
	// must always come up so a user can report an issue), so the toggle
	// reports the outage instead of panicking.
	if r.peerClient == nil {
		persistErr := persistPeerShare(false)
		if enabled {
			return false, errors.Join(errors.New("peer share unavailable: peer client failed to initialize"), persistErr)
		}
		return false, persistErr
	}
	if !enabled {
		// A re-register retry, and an attempt it has running, were for the
		// session stopping now. Cancelled before taking the toggle lock,
		// which a running attempt holds, so turning off is prompt.
		r.cancelPeerRereg()
	}
	r.peerToggleMu.Lock()
	defer r.peerToggleMu.Unlock()
	toggleCtx, cancel := context.WithTimeout(r.ctx, peerToggleTimeout)
	defer cancel()
	if !enabled {
		persistErr := persistPeerShare(false)
		// Stops the client, or, for a volunteer, keeps serving its pairings
		// on the same port mapping.
		r.reconcileSharingOffLocked(false)
		return false, persistErr
	}
	if err := persistPeerShare(true); err != nil {
		return false, err
	}
	// A second "on" that queued behind an in-flight Start must not fail on
	// "already active" and roll the toggle back under a running peer.
	if r.peerClient.IsActive() {
		// A pairings-only run becomes the shared one.
		if r.peerForPairings.Swap(false) {
			r.peerClient.RetagStatus()
			r.resetPairingRouteRetry()
			r.clearPairingRunStart()
			// Only "help others too" changes its serve_pool=false registration.
			if settings.PeerServesPool() {
				r.reregisterPeer()
			}
			r.emitSharingStatus()
			// The registration now follows this patch's settings, so the
			// caller re-registers nothing more for them.
			return true, nil
		}
		return false, nil
	}
	r.peerForPairings.Store(false)
	r.resetPairingRouteRetry()
	// The reverse client may hold the manual port peer sharing binds. Once
	// resumed it picks its port from the setting persisted above.
	resume := r.pauseReverse(toggleCtx)
	defer resume()
	// Start registers the current settings, so a pending re-register retry,
	// which was for an earlier session, has nothing left to do.
	r.cancelPeerRereg()
	if err := r.peerClient.Start(toggleCtx); err != nil {
		// Surface the underlying Start error so operators can see it in the
		// daemon log (UPnP failure, registration 4xx, etc.) rather than only
		// via the IPC HTTP response.
		slog.Error("peer share start failed", "error", err)
		if rbErr := persistPeerShare(false); rbErr != nil {
			slog.Error("peer share rollback failed after Start error",
				"start_error", err, "rollback_error", rbErr)
		}
		// Sharing is off again; a volunteer still serves its pairings.
		r.reconcileSharingOffLocked(false)
		return true, fmt.Errorf("start peer share: %w", err)
	}
	slog.Info("peer share start succeeded")
	return true, nil
}

// reregisterRetryFirst and reregisterRetryMax bound the backoff between
// re-register attempts. Vars so tests can shorten them.
var (
	reregisterRetryFirst = 30 * time.Second
	reregisterRetryMax   = 5 * time.Minute
)

// reregisterPeer re-registers a running peer in the background after "help
// others too" changes, so the change applies at once rather than at the
// hourly rotation. Re-registering sends the current setting and rotates the
// credentials; closing the old box ends its sessions, so strangers are cut
// off and paired clients reconnect within seconds with their pairing IDs.
// The switch's caption warns of it (help_others_too_note). If lantern-cloud
// is unreachable it retries, backing off from reregisterRetryFirst to
// reregisterRetryMax, until it succeeds, the peer stops, the backend closes,
// or a newer request replaces it: only the latest request's loop runs.
//
// The Unbounded widget needs nothing from here: its syncRooms re-reads the
// setting within roomSyncInterval and restarts the widget when helping others
// turns off, with the same brief drop.
func (r *LocalBackend) reregisterPeer() {
	// A closed backend's peer is stopped or stopping; there is nothing to
	// re-register.
	if r.peerClient == nil || r.ctx.Err() != nil {
		return
	}
	r.peerWGMu.Lock()
	if r.peerClosing {
		r.peerWGMu.Unlock()
		return
	}
	// Superseding cancels the older loop, its backoff and any later attempt,
	// but not an attempt already running: that one could be between its
	// register and its box rebuild. Attempts run under attemptCtx, which
	// only turning sharing off, starting it, or Close cancels.
	if r.peerReregCancel != nil {
		r.peerReregCancel()
	}
	if r.peerReregAttemptCtx == nil {
		r.peerReregAttemptCtx, r.peerReregAttemptCancel = context.WithCancel(r.ctx)
	}
	attemptCtx := r.peerReregAttemptCtx
	ctx, cancel := context.WithCancel(attemptCtx)
	r.peerReregCancel = cancel
	r.peerWG.Add(1)
	r.peerWGMu.Unlock()
	go func() {
		defer r.peerWG.Done()
		defer cancel()
		wait := reregisterRetryFirst
		for attempt := 0; ; attempt++ {
			err := r.reregisterOnce(ctx, attemptCtx)
			// ErrNotActive: the peer stopped, and its next Start registers
			// with the current value.
			if err == nil || errors.Is(err, peer.ErrNotActive) || ctx.Err() != nil {
				return
			}
			// Fixed text: the error can quote an API body or URL.
			if attempt == 0 {
				slog.Warn("peer re-register failed; retrying")
			} else {
				slog.Debug("peer re-register retry failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(2*wait, reregisterRetryMax)
		}
	}()
}

// cancelPeerRereg ends the re-register retry, if any, and the attempt it has
// running: sharing is stopping or starting, or the backend is closing.
func (r *LocalBackend) cancelPeerRereg() {
	r.peerWGMu.Lock()
	defer r.peerWGMu.Unlock()
	if r.peerReregCancel != nil {
		r.peerReregCancel()
		r.peerReregCancel = nil
	}
	if r.peerReregAttemptCancel != nil {
		r.peerReregAttemptCancel()
		r.peerReregAttemptCtx, r.peerReregAttemptCancel = nil, nil
	}
}

// reregisterOnce makes one re-register attempt under the toggle lock, so it
// cannot overlap a Start or Stop. loop is the retry loop's ctx: a superseded
// loop starts no attempt. The attempt itself runs under attemptCtx.
func (r *LocalBackend) reregisterOnce(loop, attemptCtx context.Context) error {
	r.peerToggleMu.Lock()
	defer r.peerToggleMu.Unlock()
	if err := loop.Err(); err != nil {
		return err
	}
	if !r.peerClient.IsActive() {
		return peer.ErrNotActive
	}
	ctx, cancel := context.WithTimeout(attemptCtx, peerToggleTimeout)
	defer cancel()
	return r.peerClient.Reregister(ctx)
}

func persistPeerShare(on bool) error {
	if err := settings.Patch(settings.Settings{settings.PeerShareEnabledKey: on}); err != nil {
		return fmt.Errorf("persist %s: %w", settings.PeerShareEnabledKey, err)
	}
	return nil
}

// onPeerSelfStop clears the persisted toggle when the peer client stopped
// itself, so the setting keeps reflecting runtime state and a restart of the
// app doesn't resume a peer that isn't running. A toggle that restarted the
// client in the meantime wins.
func (r *LocalBackend) onPeerSelfStop(reason error) {
	r.peerToggleMu.Lock()
	defer r.peerToggleMu.Unlock()
	if r.peerClient == nil || r.peerClient.IsActive() {
		return
	}
	if r.peerForPairings.Swap(false) {
		// A pairings-only run never set the toggle; try again later.
		// Fixed text: the reason can quote an API body or URL.
		slog.Warn("pairing route stopped itself; retrying later")
		r.restartYieldedReverse()
		if r.pairingRunWasStable() {
			r.resetPairingRouteRetry()
		}
		r.clearPairingRunStart()
		r.schedulePairingRouteRetry()
		return
	}
	slog.Warn("peer share stopped itself; turning the toggle off", "reason", reason)
	if err := persistPeerShare(false); err != nil {
		slog.Error("clearing peer share toggle after self-stop", "error", err)
	}
	r.restartYieldedReverse()
	// A volunteer still serves its pairings.
	r.reconcileSharingOffLocked(false)
}

// resumePeerShareIfEnabled re-Starts the peer client if the user left the
// toggle on across restarts. Runs in a goroutine because UPnP discovery and
// registration can take several seconds and Start() must return promptly.
// peerWG ensures Close waits for an in-flight resume to settle before
// teardown, so we never leave a registered route or a running box behind.
func (r *LocalBackend) resumePeerShareIfEnabled() {
	if !settings.GetBool(settings.PeerShareEnabledKey) {
		return
	}
	if !r.addPeerWork() {
		return
	}
	go func() {
		defer r.peerWG.Done()
		if r.ctx.Err() != nil {
			return
		}
		if err := r.applyPeerShare(true); err != nil {
			slog.Warn("peer share auto-resume failed", "error", err)
		}
	}()
}

// addPeerWork adds one to peerWG unless the backend is closing, so an Add
// can never race closePeerClient's Wait. It reports whether it added.
func (r *LocalBackend) addPeerWork() bool {
	r.peerWGMu.Lock()
	defer r.peerWGMu.Unlock()
	if r.peerClosing {
		return false
	}
	r.peerWG.Add(1)
	return true
}

// closePeerClient runs at backend shutdown. It waits for any in-flight
// auto-resume Start to finish (so we don't tear down ctx while it's still
// setting things up — that would leave a registered route + open box
// behind) and then stops the peer client with a fresh ctx so Deregister
// and UnmapPort have a live HTTP deadline even though r.ctx is about to
// cancel.
//
// No-op when peerClient is nil (peer-focused unit tests that construct
// partial LocalBackends).
func (r *LocalBackend) closePeerClient() {
	if r.peerClient == nil {
		return
	}
	r.peerWGMu.Lock()
	r.peerClosing = true
	r.peerWGMu.Unlock()
	// A re-register retry may be waiting out its backoff, and a pairings-only
	// start its retry.
	r.cancelPeerRereg()
	r.resetPairingRouteRetry()
	r.peerWG.Wait()
	if !r.peerClient.IsActive() {
		return
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), peerToggleTimeout)
	defer cancel()
	if err := r.peerClient.Stop(stopCtx); err != nil {
		slog.Warn("peer share stop on backend close returned error", "error", err)
	}
}

// PeerStatus returns the current peer-share session state for the IPC
// /peer/status endpoint. A nil peerClient reports the zero Status rather
// than panicking: construction degrades to a nil client, and the IPC
// handler serves this on every GET /peer/status.
func (r *LocalBackend) PeerStatus() peer.Status {
	if r.peerClient == nil {
		return peer.Status{}
	}
	// A pairings-only run, current or last, is not Share My Connection.
	if st := r.peerClient.CurrentStatus(); !st.PairingsOnly {
		return st
	}
	return peer.Status{}
}

// PeerRelaySnapshot returns the bytes the current or most recent direct-sharing
// session has relayed, for the IPC /peer/snapshot endpoint. It is empty while
// the client's last run was pairings-only; a hand-off between the modes keeps
// one session, whose totals then carry across. A nil peerClient reports an
// empty snapshot, as PeerStatus does.
func (r *LocalBackend) PeerRelaySnapshot() peer.Snapshot {
	// A pairings-only run, current or last, is not Share My Connection.
	if r.peerClient == nil || r.peerClient.CurrentStatus().PairingsOnly {
		return peer.Snapshot{Peers: []string{}, PeerBytes: []peer.PeerBytes{}}
	}
	return r.peerClient.RelaySnapshot()
}
