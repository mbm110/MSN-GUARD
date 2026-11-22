package backend

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/broflake/common/helperticket"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/peer"
	"github.com/getlantern/radiance/vpn"
)

// newPairingRouteTestBackend is newPeerTestBackend with a pairing key store
// that syncs the pairings-only route on change, as NewLocalBackend wires it.
func newPairingRouteTestBackend(t *testing.T, fake *fakePeerController) *LocalBackend {
	t.Helper()
	r := newPeerTestBackend(t, fake)
	fake.pairingsOnly = r.peerForPairings.Load
	r.helperPairingKeys = &helper.PairingKeys{}
	r.helperPairingKeys.SetOnChange(r.pairingKeysChanged)
	t.Cleanup(r.closePeerClient)
	return r
}

func pairingKeys(roles ...helperticket.Role) map[string]helper.PairingKey {
	keys := make(map[string]helper.PairingKey, len(roles))
	for i, role := range roles {
		keys[string(rune('a'+i))] = helper.PairingKey{Key: bytes.Repeat([]byte{byte(i + 1)}, 32), Role: string(role)}
	}
	return keys
}

// TestPairingRoute_FollowsVolunteerPairings checks that a volunteer with Share My Connection off starts its route for its pairings,
// pairings-only, and stops it when the last pairing ends.
func TestPairingRoute_FollowsVolunteerPairings(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)

	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.True(t, fake.IsActive())
	assert.True(t, r.peerForPairings.Load(), "the run serves pairings only")
	assert.True(t, r.peerShareActive(), "the reverse client must leave the manual port alone")
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey), "the share toggle stays off")

	r.helperPairingKeys.Set(nil)
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.stopCalls.Load())
	assert.False(t, fake.IsActive())
	assert.False(t, r.peerForPairings.Load())
}

// TestPairingRoute_InviterPairingDoesNotStart checks that only being someone's volunteer starts the route; an inviter pairing doesn't.
func TestPairingRoute_InviterPairingDoesNotStart(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)

	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleInviter))
	waitPeerWork(t, r)
	assert.Zero(t, fake.startCalls.Load())
}

// TestPairingRoute_RetriesAFailedStart checks that a router that won't map a port fails the start; it is tried again later,
// and the share toggle is never touched.
func TestPairingRoute_RetriesAFailedStart(t *testing.T) {
	first := pairingRouteRetryFirst
	pairingRouteRetryFirst = 20 * time.Millisecond
	t.Cleanup(func() { pairingRouteRetryFirst = first })

	fake := &fakePeerController{startErr: errors.New("no upnp")}
	r := newPairingRouteTestBackend(t, fake)

	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	require.Eventually(t, func() bool { return fake.startCalls.Load() >= 2 }, 2*time.Second, 5*time.Millisecond,
		"a failed start is retried")
	// Closing stops the retries, so the state below is settled.
	r.closePeerClient()
	assert.False(t, r.peerForPairings.Load())
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey))
}

// TestPairingRoute_NetworkChangeRetriesNow checks that a network change retries at once rather than waiting out the backoff, but
// not again until pairingRouteRetryFirst has passed since the last attempt.
func TestPairingRoute_NetworkChangeRetriesNow(t *testing.T) {
	first := pairingRouteRetryFirst
	pairingRouteRetryFirst = 200 * time.Millisecond
	t.Cleanup(func() { pairingRouteRetryFirst = first })
	fake := &fakePeerController{startErr: errors.New("no upnp")}
	r := newPairingRouteTestBackend(t, fake)

	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.Equal(t, int64(1), fake.startCalls.Load())

	r.pairingRouteNetworkChanged()
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.startCalls.Load(), "a burst of network events doesn't hammer the router")

	fake.startErr = nil
	r.pairingRetryMu.Lock()
	r.pairingLastAttempt = time.Now().Add(-time.Second)
	r.pairingRetryMu.Unlock()
	r.pairingRouteNetworkChanged()
	waitPeerWork(t, r)
	assert.Equal(t, int64(2), fake.startCalls.Load())
	assert.True(t, r.peerForPairings.Load())
}

// TestPairingRoute_HandsOffWithShareToggle checks that Share My Connection and the pairings-only route are one client on one port
// mapping: turning sharing on takes over a pairings-only run, and turning it
// off hands back, each by re-registering rather than restarting.
func TestPairingRoute_HandsOffWithShareToggle(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.True(t, r.peerForPairings.Load())

	require.NoError(t, r.applyPeerShare(true))
	require.Eventually(t, func() bool { return fake.reregisterCalls.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	assert.Equal(t, int64(1), fake.startCalls.Load(), "the running client is kept")
	assert.False(t, r.peerForPairings.Load())

	require.NoError(t, r.applyPeerShare(false))
	assert.Equal(t, int64(2), fake.reregisterCalls.Load(), "turning sharing off re-registers before it returns")
	waitPeerWork(t, r)
	assert.Zero(t, fake.stopCalls.Load(), "the mapping is kept")
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.True(t, fake.IsActive())
	assert.True(t, r.peerForPairings.Load())
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey))
}

// TestPairingRoute_ShareOffFailsClosed checks that turning sharing off fails closed: if the re-register that drops the pool
// fails, the client stops rather than leaving a pool route up, and the
// pairings-only run starts afresh, registering serve_pool=false from the start.
func TestPairingRoute_ShareOffFailsClosed(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	require.NoError(t, r.applyPeerShare(true))
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	fake.setReregister(func(context.Context, int64) error { return errors.New("lantern-cloud unreachable") })

	require.NoError(t, r.applyPeerShare(false))
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.stopCalls.Load(), "the pool route is taken down")
	assert.Equal(t, int64(2), fake.startCalls.Load(), "a fresh pairings-only run starts")
	assert.True(t, fake.IsActive())
	assert.True(t, r.peerForPairings.Load())
}

// TestPairingRoute_ShareOffWithoutPairingsStops checks that with no volunteer pairing, turning sharing off stops the client as before.
func TestPairingRoute_ShareOffWithoutPairingsStops(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	require.NoError(t, r.applyPeerShare(true))

	require.NoError(t, r.applyPeerShare(false))
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.stopCalls.Load())
	assert.False(t, fake.IsActive())
	assert.False(t, r.peerForPairings.Load())
}

// TestPairingRoute_LeavesSharingAlone checks that with sharing on, its toggle governs the client: pairing changes don't stop it.
func TestPairingRoute_LeavesSharingAlone(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	require.NoError(t, r.applyPeerShare(true))

	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	r.helperPairingKeys.Set(nil)
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.Zero(t, fake.stopCalls.Load())
	assert.False(t, r.peerForPairings.Load())
}

// TestPairingRoute_SelfStopRetries checks that a pairings-only run that stops itself is retried and leaves the share toggle
// as it was.
func TestPairingRoute_SelfStopRetries(t *testing.T) {
	first := pairingRouteRetryFirst
	pairingRouteRetryFirst = 20 * time.Millisecond
	t.Cleanup(func() { pairingRouteRetryFirst = first })

	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.True(t, r.peerForPairings.Load())

	fake.active.Store(false)
	r.onPeerSelfStop(errors.New("route dropped"))
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey))
	require.Eventually(t, func() bool { return fake.startCalls.Load() == 2 && fake.IsActive() }, 2*time.Second, 5*time.Millisecond)
	assert.True(t, r.peerForPairings.Load())
}

// TestPairingRoute_ShareStartFailureFallsBackToPairings checks that a share Start that fails and rolls the toggle back leaves sharing off, so a
// volunteer goes back to serving its pairings.
func TestPairingRoute_ShareStartFailureFallsBackToPairings(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	fake.onStart = func() {
		if settings.GetBool(settings.PeerShareEnabledKey) {
			fake.startErr = errors.New("register 4xx")
		} else {
			fake.startErr = nil
		}
	}
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.NoError(t, r.applyPeerShare(false))
	waitPeerWork(t, r)
	fake.active.Store(false)
	r.peerForPairings.Store(false)

	require.Error(t, r.applyPeerShare(true))
	waitPeerWork(t, r)
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey))
	assert.True(t, fake.IsActive(), "the pairings-only run starts again")
	assert.True(t, r.peerForPairings.Load())
}

// TestPairingRoute_ShareSelfStopFallsBackToPairings checks that a sharing run that stops itself turns the toggle off, and a volunteer goes
// back to serving its pairings.
func TestPairingRoute_ShareSelfStopFallsBackToPairings(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	require.NoError(t, r.applyPeerShare(true))
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)

	fake.active.Store(false)
	r.onPeerSelfStop(errors.New("route dropped"))
	waitPeerWork(t, r)
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey))
	assert.Equal(t, int64(2), fake.startCalls.Load())
	assert.True(t, fake.IsActive())
	assert.True(t, r.peerForPairings.Load())
}

// TestPairingRoute_RedundantChangesDontRotate checks that an "off" while the run is already pairings-only, or a "help others too"
// change then, leaves the run alone: no credential rotation drops the friend.
func TestPairingRoute_RedundantChangesDontRotate(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.True(t, r.peerForPairings.Load())

	require.NoError(t, r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: false}))
	require.NoError(t, r.PatchSettings(settings.Settings{settings.PeerServePoolKey: false}))
	waitPeerWork(t, r)
	assert.Zero(t, fake.reregisterCalls.Load())
	assert.Zero(t, fake.stopCalls.Load())
	assert.Equal(t, int64(1), fake.startCalls.Load())
}

// TestPairingRoute_StatusShowsSharingOff checks that a pairings-only run doesn't show as Share My Connection, which is off.
func TestPairingRoute_StatusShowsSharingOff(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.True(t, fake.IsActive())
	assert.False(t, r.PeerStatus().Active)
}

// TestPairingRoute_HandOffWithoutPoolKeepsSessions checks that with "help others too" off, a sharing run already serves only pairings, so
// handing it to or from pairings-only rotates nothing and keeps the friends'
// sessions; the sharing UI still hears of each hand-off.
func TestPairingRoute_HandOffWithoutPoolKeepsSessions(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	require.NoError(t, settings.Set(settings.PeerServePoolKey, false))
	var statuses atomic.Int64
	sub := events.Subscribe(func(peer.StatusEvent) { statuses.Add(1) })
	t.Cleanup(func() { events.Unsubscribe(sub) })
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)

	require.NoError(t, r.applyPeerShare(true))
	require.NoError(t, r.applyPeerShare(false))
	waitPeerWork(t, r)
	assert.Zero(t, fake.reregisterCalls.Load())
	assert.Zero(t, fake.stopCalls.Load())
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.True(t, r.peerForPairings.Load())
	require.Eventually(t, func() bool { return statuses.Load() >= 2 }, 2*time.Second, 5*time.Millisecond,
		"each hand-off tells the sharing UI")
}

// TestPairingRoute_RelaySnapshotShowsSharingOff checks that a pairings-only run's relay isn't Share My Connection's, and an idle one
// isn't time spent sharing, though its bytes still count for helper activity.
func TestPairingRoute_RelaySnapshotShowsSharingOff(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.NotEmpty(t, fake.RelaySnapshot().Peers)
	assert.Empty(t, r.PeerRelaySnapshot().Peers)
	running, _, bytes := r.sharingCounters()
	assert.False(t, running)
	assert.Equal(t, uint64(1), bytes)

	require.NoError(t, r.applyPeerShare(true))
	assert.NotEmpty(t, r.PeerRelaySnapshot().Peers, "sharing's relay shows")
}

// TestPairingRoute_HandOffJudgesTheRegistration checks that a hand-off is judged by the registration, not the setting: with "help others
// too" just turned off but the route still registered for the pool (its
// re-register pending or failed), turning sharing off still re-registers, and
// fails closed if that fails.
func TestPairingRoute_HandOffJudgesTheRegistration(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	require.NoError(t, r.applyPeerShare(true))
	require.True(t, fake.MayServePool())
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.NoError(t, settings.Set(settings.PeerServePoolKey, false))
	fake.setReregister(func(context.Context, int64) error { return errors.New("lantern-cloud unreachable") })

	require.NoError(t, r.applyPeerShare(false))
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.reregisterCalls.Load(), "a pool registration is re-registered whatever the setting says")
	assert.Equal(t, int64(1), fake.stopCalls.Load(), "and the pool route is taken down when that fails")
	assert.False(t, fake.MayServePool())
}

// TestPairingRoute_BackoffResetsOnlyAfterAStableRun checks that a pairings-only run that soon stops itself backs off like a failed start; one
// that stayed up restarts the backoff.
func TestPairingRoute_BackoffResetsOnlyAfterAStableRun(t *testing.T) {
	first, maxWait, stable := pairingRouteRetryFirst, pairingRouteRetryMax, pairingRunStableAfter
	// Retries far off, so none fires during the test.
	pairingRouteRetryFirst, pairingRouteRetryMax, pairingRunStableAfter = time.Hour, 8*time.Hour, 50*time.Millisecond
	t.Cleanup(func() { pairingRouteRetryFirst, pairingRouteRetryMax, pairingRunStableAfter = first, maxWait, stable })
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	nextWait := func() time.Duration {
		r.pairingRetryMu.Lock()
		defer r.pairingRetryMu.Unlock()
		return r.pairingRetryWait
	}
	selfStop := func() {
		fake.active.Store(false)
		r.onPeerSelfStop(errors.New("route dropped"))
	}
	r.pairingRetryMu.Lock()
	r.pairingRetryWait = 2 * time.Hour
	r.pairingRetryMu.Unlock()

	selfStop()
	assert.Equal(t, 4*time.Hour, nextWait(), "a short-lived run keeps backing off")

	r.peerForPairings.Store(true)
	fake.active.Store(true)
	r.notePairingRunStart()
	time.Sleep(2 * pairingRunStableAfter)
	selfStop()
	assert.Equal(t, 2*time.Hour, nextWait(), "a stable run restarts the backoff from its first step")
}

// TestPairingRoute_ShareOnWithPoolOffInOnePatch checks that turning sharing on over a pairings-only run with "help others too" off in
// the same patch rotates nothing: the registration already matches.
func TestPairingRoute_ShareOnWithPoolOffInOnePatch(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.True(t, r.peerForPairings.Load())

	require.NoError(t, r.PatchSettings(settings.Settings{
		settings.PeerShareEnabledKey: true,
		settings.PeerServePoolKey:    false,
	}))
	waitPeerWork(t, r)
	assert.Zero(t, fake.reregisterCalls.Load())
	assert.False(t, r.peerForPairings.Load())
	assert.True(t, settings.GetBool(settings.PeerShareEnabledKey))
}

// TestPairingRoute_EnteringSharingFollowsTheSetting checks that entering sharing from pairings-only re-registers exactly when "help others
// too" is on, whatever a rotation in flight leaves the registration looking
// like: it's the only case in which serve_pool changes.
func TestPairingRoute_EnteringSharingFollowsTheSetting(t *testing.T) {
	for _, tc := range []struct {
		name       string
		servesPool bool
		want       int64
	}{
		{"help others too on", true, 1},
		{"help others too off", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakePeerController{}
			r := newPairingRouteTestBackend(t, fake)
			require.NoError(t, settings.Set(settings.PeerServePoolKey, tc.servesPool))
			r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
			waitPeerWork(t, r)
			// An hourly rotation in flight: the registration may be anything.
			fake.poolMaybe.Store(true)

			require.NoError(t, r.applyPeerShare(true))
			require.Eventually(t, func() bool { return fake.reregisterCalls.Load() == tc.want }, 2*time.Second, 5*time.Millisecond)
			waitPeerWork(t, r)
			assert.Equal(t, tc.want, fake.reregisterCalls.Load())
		})
	}
}

// TestPairingRoute_FailedStartDoesntShowAsSharingError checks that a failed pairings-only start leaves its error on the client; that isn't a
// Share My Connection failure, so it stays hidden through the retry backoff
// until sharing takes over.
func TestPairingRoute_FailedStartDoesntShowAsSharingError(t *testing.T) {
	fake := &fakePeerController{startErr: errors.New("no upnp")}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.False(t, r.peerForPairings.Load())
	require.Equal(t, peer.PhaseError, fake.CurrentStatus().Phase)
	assert.Equal(t, peer.Status{}, r.PeerStatus())

	fake.startErr = nil
	require.NoError(t, r.applyPeerShare(true))
	assert.True(t, r.PeerStatus().Active, "a sharing run's status shows again")
}

// TestPairingRoute_NetworkBurstQueuesOneAttempt checks that a burst of network events reserves one attempt: the cooldown holds even when
// they arrive while a start is still waiting for the toggle lock.
func TestPairingRoute_NetworkBurstQueuesOneAttempt(t *testing.T) {
	first := pairingRouteRetryFirst
	pairingRouteRetryFirst = time.Hour
	t.Cleanup(func() { pairingRouteRetryFirst = first })
	fake := &fakePeerController{startErr: errors.New("no upnp")}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.Equal(t, int64(1), fake.startCalls.Load())
	r.pairingRetryMu.Lock()
	r.pairingLastAttempt = time.Now().Add(-2 * time.Hour)
	r.pairingRetryMu.Unlock()

	r.peerToggleMu.Lock()
	r.pairingRouteNetworkChanged()
	r.pairingRouteNetworkChanged()
	r.peerToggleMu.Unlock()
	waitPeerWork(t, r)
	assert.Equal(t, int64(2), fake.startCalls.Load(), "one attempt for the burst")
}

// TestPairingRoute_LastPairingEndingResetsTheBackoff checks that when the last
// pairing ends while no route runs, a backoff grown by failed starts doesn't
// carry over to the next pairing.
func TestPairingRoute_LastPairingEndingResetsTheBackoff(t *testing.T) {
	first := pairingRouteRetryFirst
	pairingRouteRetryFirst = time.Hour
	t.Cleanup(func() { pairingRouteRetryFirst = first })
	fake := &fakePeerController{startErr: errors.New("no upnp")}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	r.pairingRetryMu.Lock()
	require.NotZero(t, r.pairingRetryWait)
	r.pairingRetryMu.Unlock()

	r.helperPairingKeys.Set(nil)
	waitPeerWork(t, r)
	r.pairingRetryMu.Lock()
	defer r.pairingRetryMu.Unlock()
	assert.Zero(t, r.pairingRetryWait)
	assert.Nil(t, r.pairingRetryTimer)
}

// TestPairingRoute_ShareOffWaitsForATeardownInFlight checks that turning
// sharing off while a self-stop is still tearing down (the client already
// inactive) waits for it, so pool sessions have ended when the toggle returns,
// with or without volunteer pairings.
func TestPairingRoute_ShareOffWaitsForATeardownInFlight(t *testing.T) {
	for _, pairings := range []bool{false, true} {
		fake := &fakePeerController{}
		r := newPairingRouteTestBackend(t, fake)
		if pairings {
			r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
			waitPeerWork(t, r)
		}
		require.NoError(t, settings.Set(settings.PeerShareEnabledKey, true))
		teardown := make(chan struct{})
		fake.teardown.Store(&teardown)
		fake.active.Store(false)

		done := make(chan error, 1)
		go func() { done <- r.applyPeerShare(false) }()
		select {
		case <-done:
			t.Fatalf("pairings=%v: sharing-off returned before the teardown ended", pairings)
		case <-time.After(100 * time.Millisecond):
		}
		close(teardown)
		require.NoError(t, <-done)
		fake.teardown.Store(nil)
		waitPeerWork(t, r)
	}
}

// TestPairingRoute_QueuedSyncsCoalesce checks that reconciles queued while the
// toggle lock is held (a retry timer, a network change, a pairing change)
// coalesce into one worker, so a failed start isn't retried at once.
func TestPairingRoute_QueuedSyncsCoalesce(t *testing.T) {
	first := pairingRouteRetryFirst
	pairingRouteRetryFirst = time.Hour
	t.Cleanup(func() { pairingRouteRetryFirst = first })
	fake := &fakePeerController{startErr: errors.New("no upnp")}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.Equal(t, int64(1), fake.startCalls.Load())
	// The retry is due, so exactly one of the queued workers attempts it.
	r.clearPairingNotBefore()

	r.peerToggleMu.Lock()
	r.syncPairingRoute()
	r.syncPairingRoute()
	r.syncPairingRoute()
	r.peerToggleMu.Unlock()
	waitPeerWork(t, r)
	assert.Equal(t, int64(2), fake.startCalls.Load(), "one attempt for the queued reconciles")
}

// TestPairingRoute_StaleWorkerWaitsForTheBackoff checks that a worker reaching
// a start before the scheduled retry is due (a stale timer's, say) leaves the
// attempt to that retry, while a network change or a new pairing still tries at
// once.
func TestPairingRoute_StaleWorkerWaitsForTheBackoff(t *testing.T) {
	first := pairingRouteRetryFirst
	pairingRouteRetryFirst = time.Hour
	t.Cleanup(func() { pairingRouteRetryFirst = first })
	fake := &fakePeerController{startErr: errors.New("no upnp")}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.Equal(t, int64(1), fake.startCalls.Load())

	r.syncPairingRoute()
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.startCalls.Load(), "an early worker waits for the scheduled retry")

	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer, helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	assert.Equal(t, int64(2), fake.startCalls.Load(), "a new pairing tries at once")
}

// TestPairingRoute_ShareOffCancelsAQueuedReregister checks that a re-register
// an "on" queued for sharing, still waiting for the toggle lock when an "off"
// hands the run back to pairings-only, never runs: it would rotate the
// credentials and drop the friends' sessions for nothing.
func TestPairingRoute_ShareOffCancelsAQueuedReregister(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.True(t, r.peerForPairings.Load())

	// As an "on" over the pairings-only run left things: sharing owns the run
	// and a re-register waits for the lock.
	r.peerToggleMu.Lock()
	require.NoError(t, settings.Set(settings.PeerShareEnabledKey, true))
	r.peerForPairings.Store(false)
	r.reregisterPeer()
	// Then an "off" gets the lock first.
	require.NoError(t, settings.Set(settings.PeerShareEnabledKey, false))
	r.reconcileSharingOffLocked(false)
	r.peerToggleMu.Unlock()
	waitPeerWork(t, r)

	assert.Zero(t, fake.reregisterCalls.Load())
	assert.True(t, r.peerForPairings.Load())
}

// TestPairingRoute_NotWhereTheCountryIsUnknownOrCensored checks that a volunteer pairing doesn't start the route, and so
// maps no port, while this device's country is unknown or censored. The pairing keys are kept.
func TestPairingRoute_NotWhereTheCountryIsUnknownOrCensored(t *testing.T) {
	for _, country := range []string{"", "CN", "ir"} {
		t.Run("country="+country, func(t *testing.T) {
			fake := &fakePeerController{}
			r := newPairingRouteTestBackend(t, fake)
			require.NoError(t, settings.Set(settings.CountryCodeKey, country))

			r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
			waitPeerWork(t, r)
			r.pairingRouteNetworkChanged()
			waitPeerWork(t, r)
			assert.Zero(t, fake.startCalls.Load())
			assert.False(t, r.peerForPairings.Load())
			assert.True(t, r.hasVolunteerPairings(), "the pairing keys are kept")
		})
	}
}

// TestPairingRoute_FollowsCountryChanges checks that the route stops when the country becomes censored and starts again
// once it is allowed.
func TestPairingRoute_FollowsCountryChanges(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.True(t, fake.IsActive())

	require.NoError(t, settings.Set(settings.CountryCodeKey, "RU"))
	r.CountryCodeChanged()
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.stopCalls.Load())
	assert.False(t, fake.IsActive())
	assert.False(t, r.peerForPairings.Load())

	require.NoError(t, settings.Set(settings.CountryCodeKey, "DE"))
	r.CountryCodeChanged()
	waitPeerWork(t, r)
	assert.Equal(t, int64(2), fake.startCalls.Load())
	assert.True(t, fake.IsActive())
	assert.True(t, r.peerForPairings.Load())
}

// TestPairingRoute_ShareOffInACensoredCountryStops checks that turning sharing off where the country is censored stops the
// client instead of handing it to pairings-only, though it volunteers in a pairing.
func TestPairingRoute_ShareOffInACensoredCountryStops(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	require.NoError(t, settings.Set(settings.CountryCodeKey, "CN"))
	require.NoError(t, r.applyPeerShare(true))
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)

	require.NoError(t, r.applyPeerShare(false))
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.Equal(t, int64(1), fake.stopCalls.Load())
	assert.False(t, fake.IsActive())
	assert.False(t, r.peerForPairings.Load())
}

// TestPairingRoute_PatchedCountryReconciles checks that patching the country through PatchSettings stops the route where
// the new country is censored.
func TestPairingRoute_PatchedCountryReconciles(t *testing.T) {
	fake := &fakePeerController{}
	r := newPairingRouteTestBackend(t, fake)
	r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
	waitPeerWork(t, r)
	require.True(t, fake.IsActive())

	require.NoError(t, r.PatchSettings(settings.Settings{settings.CountryCodeKey: "CN"}))
	waitPeerWork(t, r)
	assert.Equal(t, int64(1), fake.stopCalls.Load())
	assert.False(t, fake.IsActive())
}

// TestPairingRoute_CountryOverrideWins checks that a country override decides over the saved country, both ways.
func TestPairingRoute_CountryOverrideWins(t *testing.T) {
	for _, tc := range []struct {
		saved, override string
		starts          bool
	}{
		{saved: "US", override: "CN", starts: false},
		{saved: "", override: "US", starts: true},
	} {
		t.Run(tc.saved+"/"+tc.override, func(t *testing.T) {
			prev := env.GetString(env.Country)
			env.Set(env.Country.String(), tc.override)
			t.Cleanup(func() { env.Set(env.Country.String(), prev) })
			fake := &fakePeerController{}
			r := newPairingRouteTestBackend(t, fake)
			require.NoError(t, settings.Set(settings.CountryCodeKey, tc.saved))

			r.helperPairingKeys.Set(pairingKeys(helperticket.RoleVolunteer))
			waitPeerWork(t, r)
			assert.Equal(t, tc.starts, fake.IsActive())
		})
	}
}

// TestPairingRouteCountryAllowed checks the country gate the pairings-only route and the widget's direct exit share: only
// a known, uncensored country passes, and an override decides over the saved country.
func TestPairingRouteCountryAllowed(t *testing.T) {
	var censored string
	for c := range censoredCountries {
		censored = c
		break
	}
	for _, tc := range []struct {
		name, saved, override string
		allowed               bool
	}{
		{name: "no country", allowed: false},
		{name: "censored", saved: censored, allowed: false},
		{name: "lowercase and padded", saved: " us ", allowed: true},
		{name: "censored override over US", saved: "US", override: censored, allowed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, settings.InitSettings(t.TempDir()))
			t.Cleanup(settings.Reset)
			prev := env.GetString(env.Country)
			env.Set(env.Country.String(), tc.override)
			t.Cleanup(func() { env.Set(env.Country.String(), prev) })
			require.NoError(t, settings.Set(settings.CountryCodeKey, tc.saved))

			assert.Equal(t, tc.allowed, pairingRouteCountryAllowed())
		})
	}
}

// TestCountryCodeChangedRechecksTheDirectExit checks that a country change, here through PatchSettings, re-checks the
// widget's direct exit at once instead of waiting for the next config.
func TestCountryCodeChangedRechecksTheDirectExit(t *testing.T) {
	var rechecks atomic.Int32
	prev := recheckDirectExit
	recheckDirectExit = func() { rechecks.Add(1) }
	t.Cleanup(func() { recheckDirectExit = prev })
	r := newPairingRouteTestBackend(t, &fakePeerController{})

	require.NoError(t, r.PatchSettings(settings.Settings{settings.CountryCodeKey: "CN"}))
	waitPeerWork(t, r)
	assert.Equal(t, int32(1), rechecks.Load())

	r.CountryCodeChanged()
	assert.Equal(t, int32(2), rechecks.Load())
}

type fakeVPNPlatform struct{ vpn.PlatformInterface }

// TestDirectExitAllowed checks the widget's direct exit gate: a known, uncensored country, and
// where the exit follows the VPN (Android), a platform interface and a connected VPN.
func TestDirectExitAllowed(t *testing.T) {
	prev := directExitNeedsVPN
	t.Cleanup(func() { directExitNeedsVPN = prev })
	r := newPeerTestBackend(t, &fakePeerController{})

	directExitNeedsVPN = func() bool { return false }
	assert.True(t, r.directExitAllowed(), "desktop needs no VPN or platform interface")
	r.vpnClient = vpn.NewVPNClient(t.TempDir(), nil, nil)
	assert.True(t, r.directExitAllowed(), "desktop ignores the VPN status")

	directExitNeedsVPN = func() bool { return true }
	assert.False(t, r.directExitAllowed(), "Android with no platform interface")
	r.vpnClient = vpn.NewVPNClient(t.TempDir(), nil, fakeVPNPlatform{})
	assert.False(t, r.directExitAllowed(), "Android with the VPN disconnected (or, on this host, no shared platform)")

	for _, status := range []vpn.VPNStatus{vpn.Disconnected, vpn.Connecting, vpn.Disconnecting, vpn.Restarting, vpn.ErrorStatus} {
		assert.False(t, directExitVPNReady(true, status), status)
	}
	assert.True(t, directExitVPNReady(true, vpn.Connected))
	assert.False(t, directExitVPNReady(false, vpn.Connected))

	require.NoError(t, settings.Set(settings.CountryCodeKey, "CN"))
	directExitNeedsVPN = func() bool { return false }
	assert.False(t, r.directExitAllowed(), "a censored country")
}

// TestVPNStatusRechecksTheDirectExit checks that on Android each VPN status change re-checks
// the widget's direct exit, and that desktop doesn't listen.
func TestVPNStatusRechecksTheDirectExit(t *testing.T) {
	var rechecks atomic.Int32
	prevRecheck, prevNeeds := recheckDirectExit, directExitNeedsVPN
	recheckDirectExit = func() { rechecks.Add(1) }
	t.Cleanup(func() { recheckDirectExit, directExitNeedsVPN = prevRecheck, prevNeeds })

	directExitNeedsVPN = func() bool { return false }
	newPeerTestBackend(t, &fakePeerController{}).startDirectExitVPNListener()
	directExitNeedsVPN = func() bool { return true }
	newPeerTestBackend(t, &fakePeerController{}).startDirectExitVPNListener()

	events.Emit(vpn.StatusUpdateEvent{Status: vpn.Connected})
	require.Eventually(t, func() bool { return rechecks.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	events.Emit(vpn.StatusUpdateEvent{Status: vpn.Disconnecting})
	require.Eventually(t, func() bool { return rechecks.Load() == 2 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(2), rechecks.Load(), "only the Android backend listens")
}

type boxPlatformSource struct{ p libbox.PlatformInterface }

func (s boxPlatformSource) BoxPlatform() libbox.PlatformInterface { return s.p }

// TestDirectExitPlatformOnlyOnAndroid checks that only Android hands the widget's direct exit a
// platform interface. Elsewhere, macOS's network extension included, the exit boxes keep
// sing-box's own interface monitor.
func TestDirectExitPlatformOnlyOnAndroid(t *testing.T) {
	prev := directExitNeedsVPN
	t.Cleanup(func() { directExitNeedsVPN = prev })
	platform := fakeVPNPlatform{}
	vc := boxPlatformSource{p: platform}

	directExitNeedsVPN = func() bool { return false }
	assert.Nil(t, directExitPlatform(vc), "a platform interface outside Android stays the VPN's")

	directExitNeedsVPN = func() bool { return true }
	assert.Equal(t, platform, directExitPlatform(vc), "Android's exit shares the VPN's platform")
	assert.Nil(t, directExitPlatform(boxPlatformSource{}))
	assert.Nil(t, directExitPlatform(vpn.NewVPNClient(t.TempDir(), nil, platform)), "the VPN shares its platform only on Android")
}
