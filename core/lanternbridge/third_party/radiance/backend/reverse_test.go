package backend

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/getlantern/common"
	lbA "github.com/getlantern/lantern-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/broflake/common/helperticket"

	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/peer"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/vpn"
)

// fakeReverse stands in for the reverse client. With a box, it adds tags as
// reverse outbounds on Start and tears the box down on Stop, as the client's
// first cycle and teardown do. It acts as if a manual port is configured, so
// a Start while peer sharing is on yields it.
type fakeReverse struct {
	starts, stops, networks, pairings atomic.Int32
	running, yielded                  atomic.Bool
	box                               peer.ReverseBox
	tags                              []string
	// hang makes Stop and Release wait for their ctx, as a teardown that
	// overruns does.
	hang atomic.Bool
}

func (f *fakeReverse) Start(context.Context) error {
	f.starts.Add(1)
	if f.box != nil {
		if err := f.box.SetReverseOutbounds(f.tags); err != nil {
			return err
		}
	}
	f.yielded.Store(peerShareOn())
	f.running.Store(true)
	return nil
}

func (f *fakeReverse) Stop(ctx context.Context) {
	f.stops.Add(1)
	if f.hang.Load() {
		<-ctx.Done()
	}
	if f.box != nil {
		_ = f.box.SetReversePortal(nil, "")
	}
	f.running.Store(false)
}

func (f *fakeReverse) Release(ctx context.Context) {
	if f.box != nil {
		_ = f.box.SetReverseOutbounds(nil)
	}
	f.Stop(ctx)
}

func (f *fakeReverse) NetworkChanged()  { f.networks.Add(1) }
func (f *fakeReverse) PairingsChanged() { f.pairings.Add(1) }
func (f *fakeReverse) YieldedManualPort() bool {
	return f.running.Load() && f.yielded.Load()
}

const reverseSettle = 150 * time.Millisecond

func newReverseTestBackend(t *testing.T, unsupported bool) (*LocalBackend, *fakeReverse) {
	t.Helper()
	r, fake := newUnstartedReverseTestBackend(t, t.TempDir(), unsupported)
	r.startReverse()
	return r, fake
}

func newUnstartedReverseTestBackend(t *testing.T, dataDir string, unsupported bool) (*LocalBackend, *fakeReverse) {
	t.Helper()
	prev := reverseUnsupported
	reverseUnsupported = func() bool { return unsupported }
	t.Cleanup(func() { reverseUnsupported = prev })
	r := newPersonalProxiesBackendIn(t, dataDir)
	r.helperPairingKeys = &helper.PairingKeys{}
	fake := &fakeReverse{}
	r.useReverseClient(fake)
	t.Cleanup(r.stopReverse)
	return r, fake
}

func notRunning(f *fakeReverse) func() bool { return func() bool { return !f.running.Load() } }

func emitVPNStatus(s vpn.VPNStatus) { events.Emit(vpn.StatusUpdateEvent{Status: s}) }

func emitReverseFeature(on bool) {
	events.Emit(config.NewConfigEvent{New: &config.Config{Features: map[string]bool{C.UNBOUNDED: true, helperReverseFeature: on}}})
}

func TestReverseRunsWhileTheVPNIsConnectedAndTheFeatureIsOn(t *testing.T) {
	_, fake := newReverseTestBackend(t, false)

	emitReverseFeature(true)
	assert.Never(t, fake.running.Load, reverseSettle, 10*time.Millisecond, "the VPN is down")

	emitVPNStatus(vpn.Connected)
	require.Eventually(t, fake.running.Load, time.Second, 5*time.Millisecond)

	emitVPNStatus(vpn.Restarting)
	assert.Never(t, func() bool { return !fake.running.Load() }, reverseSettle, 10*time.Millisecond,
		"a restart keeps the client, whose state the new tunnel restores")
	emitVPNStatus(vpn.Connected)
	assert.Never(t, func() bool { return fake.starts.Load() != 1 }, reverseSettle, 10*time.Millisecond)

	emitVPNStatus(vpn.Disconnected)
	require.Eventually(t, notRunning(fake), time.Second, 5*time.Millisecond)

	emitVPNStatus(vpn.Connected)
	require.Eventually(t, fake.running.Load, time.Second, 5*time.Millisecond)

	emitReverseFeature(false)
	require.Eventually(t, notRunning(fake), time.Second, 5*time.Millisecond)
	assert.Equal(t, int32(2), fake.starts.Load())
	assert.Equal(t, int32(2), fake.stops.Load())
}

func TestReverseStopsOnAnErrorStatus(t *testing.T) {
	_, fake := newReverseTestBackend(t, false)
	emitReverseFeature(true)
	emitVPNStatus(vpn.Connected)
	require.Eventually(t, fake.running.Load, time.Second, 5*time.Millisecond)
	emitVPNStatus(vpn.ErrorStatus)
	require.Eventually(t, notRunning(fake), time.Second, 5*time.Millisecond)
}

func TestReverseNeverStartsWhereUnsupported(t *testing.T) {
	_, fake := newReverseTestBackend(t, true)
	emitReverseFeature(true)
	emitVPNStatus(vpn.Connected)
	assert.Never(t, func() bool { return fake.starts.Load() > 0 }, reverseSettle, 10*time.Millisecond)
}

func TestReverseStopsWithTheBackend(t *testing.T) {
	r, fake := newReverseTestBackend(t, false)
	emitReverseFeature(true)
	emitVPNStatus(vpn.Connected)
	require.Eventually(t, fake.running.Load, time.Second, 5*time.Millisecond)
	r.stopReverse()
	assert.False(t, fake.running.Load())
}

func TestReverseHearsPairingKeyChanges(t *testing.T) {
	r, fake := newReverseTestBackend(t, false)
	key := bytes.Repeat([]byte{7}, 32)
	r.SetHelperPairingKeys(map[string]helper.PairingKey{"p1": {Key: key, Role: string(helperticket.RoleInviter)}})
	assert.Equal(t, int32(1), fake.pairings.Load())
	r.SetHelperPairingKeys(map[string]helper.PairingKey{"p1": {Key: key, Role: string(helperticket.RoleInviter)}})
	assert.Equal(t, int32(1), fake.pairings.Load(), "an unchanged set is no change")
}

func TestReverseHearsNetworkResets(t *testing.T) {
	r, fake := newReverseTestBackend(t, false)
	r.ResetNetwork()
	r.ResetNetworkForMonitor(nil)
	assert.Equal(t, int32(2), fake.networks.Load())
}

func TestReverseStartsWhenTheVPNIsAlreadyConnected(t *testing.T) {
	dataDir := t.TempDir()
	writeCachedConfig(t, dataDir, &config.Config{Features: map[string]bool{helperReverseFeature: true}})
	r, fake := newUnstartedReverseTestBackend(t, dataDir, false)
	r.startReverseWith(func() vpn.VPNStatus { return vpn.Connected })
	require.Eventually(t, fake.running.Load, time.Second, 5*time.Millisecond)
}

func TestReverseDoesNotStartWhileConnecting(t *testing.T) {
	_, fake := newReverseTestBackend(t, false)
	emitReverseFeature(true)
	emitVPNStatus(vpn.Connecting)
	assert.Never(t, fake.running.Load, reverseSettle, 10*time.Millisecond)
}

const reversePairing = "pairing-b"

func inviterKey(t *testing.T, r *LocalBackend, pairingIDs ...string) {
	t.Helper()
	keys := map[string]helper.PairingKey{}
	for _, id := range pairingIDs {
		keys[id] = helper.PairingKey{Key: bytes.Repeat([]byte{7}, 32), Role: string(helperticket.RoleInviter)}
	}
	r.SetHelperPairingKeys(keys)
}

// newReverseFriendBackend is a backend whose fake reverse client, once
// started, publishes ppFriendB's reverse outbound for reversePairing, with
// ppFriendB selected.
func newReverseFriendBackend(t *testing.T, dataDir string) (*LocalBackend, *fakeReverse) {
	t.Helper()
	r, fake := newUnstartedReverseTestBackend(t, dataDir, false)
	r.reverseFriends = loadReverseFriends(filepath.Join(dataDir, reverseFriendsFileName))
	inviterKey(t, r, reversePairing)
	r.reverseFriends.setTags(map[string]string{reversePairing: ppFriendB})
	fake.box, fake.tags = reverseBox{r: r}, []string{lbA.ReverseHelperTag(ppFriendB)}
	r.startSelectionFallbackListener()
	r.startReverse()
	emitReverseFeature(true)
	emitVPNStatus(vpn.Connected)
	require.Eventually(t, fake.running.Load, time.Second, 5*time.Millisecond)
	r.persistSelection(vpn.PersonalProxySelection(ppFriendB))
	return r, fake
}

// While the VPN is down a reverse-only friend has no outbound, and the paths
// that clear a missing selection run: the Disconnected listener and a config
// update. The friend's pairing has not ended, so the selection stands.
func TestReverseKeepsASelectionWhileTheVPNIsDown(t *testing.T) {
	r, fake := newReverseFriendBackend(t, t.TempDir())
	friend := vpn.PersonalProxySelection(ppFriendB)

	emitVPNStatus(vpn.Disconnected)
	require.Eventually(t, notRunning(fake), time.Second, 5*time.Millisecond)
	assert.Empty(t, r.reverseOutbounds())
	r.applyConfig(cachedConfig(), true)
	r.clearSelectedIfMissing()
	assert.Equal(t, friend, selectedTag(t))
	assert.NoError(t, r.checkConnectSelection(t.Context(), friend))

	emitVPNStatus(vpn.Connected)
	require.Eventually(t, fake.running.Load, time.Second, 5*time.Millisecond)
	assert.Equal(t, friend, selectedTag(t))
}

func TestReverseKeepsASelectionAcrossALaunch(t *testing.T) {
	dataDir := t.TempDir()
	r, _ := newReverseFriendBackend(t, dataDir)
	r.stopReverse()
	require.Empty(t, r.reverseOutbounds())

	next := newPersonalProxiesBackendIn(t, dataDir)
	next.reverseFriends = loadReverseFriends(filepath.Join(dataDir, reverseFriendsFileName))
	next.clearSelectedIfMissing()
	assert.Equal(t, vpn.PersonalProxySelection(ppFriendB), selectedTag(t))
}

// A pairing that ended while the backend was stopped leaves friends in
// reverse-friends.json, which the first, empty, set of pairing keys prunes.
func TestReversePrunesPersistedFriendsOnTheFirstPairingKeys(t *testing.T) {
	dataDir := t.TempDir()
	r, _ := newReverseFriendBackend(t, dataDir)
	r.stopReverse()

	next, _ := newUnstartedReverseTestBackend(t, dataDir, false)
	next.reverseFriends = loadReverseFriends(filepath.Join(dataDir, reverseFriendsFileName))
	require.True(t, next.reverseFriends.has(ppFriendB))
	require.Equal(t, vpn.PersonalProxySelection(ppFriendB), selectedTag(t))

	next.SetHelperPairingKeys(nil)
	require.Eventually(t, func() bool { return !next.reverseFriends.has(ppFriendB) }, time.Second, 5*time.Millisecond)
	assert.Eventually(t, func() bool { return selectedTag(t) == vpn.AutoSelectTag }, time.Second, 5*time.Millisecond)
}

func TestReverseClearsASelectionWhenItsPairingEnds(t *testing.T) {
	r, fake := newReverseFriendBackend(t, t.TempDir())
	emitVPNStatus(vpn.Disconnected)
	require.Eventually(t, notRunning(fake), time.Second, 5*time.Millisecond)

	inviterKey(t, r, "pairing-other")
	require.Eventually(t, func() bool { return selectedTag(t) == vpn.AutoSelectTag }, time.Second, 5*time.Millisecond)
	assert.False(t, r.reverseFriends.has(ppFriendB))
}

// A pairing revoked while its friend's reverse outbound is up is pruned at
// once, but the selection stands on the outbound until the reverse client
// withdraws it, which must then clear the selection.
func TestReverseClearsASelectionWhenItsPairingEndsWhileConnected(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected string
		withdraw func(reverseBox) error
	}{
		{"friend, other pairings left", vpn.PersonalProxySelection(ppFriendB), func(b reverseBox) error { return b.SetReverseOutbounds(nil) }},
		{"friend, last pairing", vpn.PersonalProxySelection(ppFriendB), func(b reverseBox) error { return b.SetReversePortal(nil, "") }},
		{"group, last pairing", vpn.PersonalProxiesTag, func(b reverseBox) error { return b.SetReversePortal(nil, "") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newReverseFriendBackend(t, t.TempDir())
			r.persistSelection(tc.selected)
			inviterKey(t, r, "pairing-other")
			require.Eventually(t, func() bool { return !r.reverseFriends.has(ppFriendB) }, time.Second, 5*time.Millisecond)
			r.clearSelectedIfMissing()
			require.Equal(t, tc.selected, selectedTag(t), "the outbound is still up")

			require.NoError(t, tc.withdraw(reverseBox{r: r}))
			assert.Equal(t, vpn.AutoSelectTag, selectedTag(t))
		})
	}
}

// lantern-cloud's kill switch, and an address loss, take the portal and
// outbounds down while the pairing goes on.
func TestReverseKeepsASelectionThroughAWithdrawal(t *testing.T) {
	r, _ := newReverseFriendBackend(t, t.TempDir())
	box := reverseBox{r: r}
	require.NoError(t, box.SetReverseOutbounds(nil))
	require.NoError(t, box.SetReversePortal(nil, ""))
	r.applyConfig(cachedConfig(), true)
	assert.Equal(t, vpn.PersonalProxySelection(ppFriendB), selectedTag(t))
}

// A tunnel that came up while the friend had no outbound runs on a fallback
// until the outbound returns.
func TestReverseBoxRestoresTheSavedFriendInTheTunnel(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tunnel := &fakeHelperTunnel{live: map[string]string{}, selected: vpn.AutoSelectTag}
	tunnel.attach(r)
	r.reverseFriends = &reverseFriends{byPairing: map[string]string{pairingHash(reversePairing): ppFriendB}}
	friend := vpn.PersonalProxySelection(ppFriendB)
	r.persistSelection(friend)
	require.Equal(t, friend, selectedTag(t))

	require.NoError(t, reverseBox{r: r}.SetReverseOutbounds([]string{lbA.ReverseHelperTag(ppFriendA)}))
	assert.Equal(t, vpn.AutoSelectTag, tunnel.current(), "another friend's outbound")
	require.NoError(t, reverseBox{r: r}.SetReverseOutbounds([]string{lbA.ReverseHelperTag(ppFriendB)}))
	assert.Equal(t, friend, tunnel.current())
}

// A connect to a reverse-only friend comes up before the reverse client has
// published the friend's outbound. The tunnel runs on the fallback meanwhile,
// but the saved selection stays the friend's so the outbound restores it.
func TestReverseConnectKeepsTheFriendUntilItsOutboundIsUp(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{friendless: true, refuseFriend: true}
	tun.attach(r)
	require.NoError(t, r.srvManager.AddServers(directServers("lantern-1"), false))
	r.reverseFriends = &reverseFriends{byPairing: map[string]string{pairingHash(reversePairing): ppFriendB}}
	friend := vpn.PersonalProxySelection(ppFriendB)
	r.persistSelection(friend)
	evts := fallbackEvents(t)

	require.NoError(t, r.ConnectVPN(t.Context(), friend))
	assert.Equal(t, friend, selectedTag(t), "the fallback was saved over the friend")
	assert.NotEqual(t, friend, tun.current())
	assert.Empty(t, evts)

	tun.mu.Lock()
	tun.refuseFriend = false
	tun.mu.Unlock()
	require.NoError(t, reverseBox{r: r}.SetReverseOutbounds([]string{lbA.ReverseHelperTag(ppFriendB)}))
	assert.Equal(t, friend, tun.current())
	assert.Equal(t, friend, selectedTag(t))
}

// newPeerShareReverseBackend is a backend whose reverse client runs, holding
// the manual port, and whose peer client is fake.
func newPeerShareReverseBackend(t *testing.T) (*LocalBackend, *fakeReverse, *fakePeerController) {
	t.Helper()
	r, fake := newReverseTestBackend(t, false)
	peerFake := &fakePeerController{}
	r.peerClient = peerFake
	emitReverseFeature(true)
	emitVPNStatus(vpn.Connected)
	require.Eventually(t, fake.running.Load, time.Second, 5*time.Millisecond)
	require.False(t, fake.YieldedManualPort())
	return r, fake, peerFake
}

func restartedOnOwnPort(f *fakeReverse, starts int32) func() bool {
	return func() bool { return f.starts.Load() == starts && f.YieldedManualPort() }
}

// Peer sharing binds the manual port, so it starts only once the reverse
// client has stopped, and the reverse client comes back on a port of its own.
func TestPeerShareOnStopsTheReverseClientFirst(t *testing.T) {
	r, fake, peerFake := newPeerShareReverseBackend(t)
	peerFake.onStart = func() {
		assert.False(t, fake.running.Load(), "the reverse client stopped before peer sharing started")
		assert.Equal(t, int32(1), fake.stops.Load())
		assert.True(t, peerShareOn())
	}
	require.NoError(t, r.applyPeerShare(true))
	assert.Equal(t, int64(1), peerFake.startCalls.Load())
	require.Eventually(t, restartedOnOwnPort(fake, 2), time.Second, 5*time.Millisecond)

	// Peer sharing off gives the manual port back.
	require.NoError(t, r.applyPeerShare(false))
	require.Eventually(t, func() bool {
		return fake.starts.Load() == 3 && fake.running.Load() && !fake.YieldedManualPort()
	}, time.Second, 5*time.Millisecond)
	assert.Equal(t, int32(2), fake.stops.Load())

	// A client already on the manual port stays put.
	require.NoError(t, r.applyPeerShare(false))
	assert.Never(t, func() bool { return fake.starts.Load() != 3 }, reverseSettle, 10*time.Millisecond)
}

func TestPeerShareRestartsTheReverseClientThroughANetworkChange(t *testing.T) {
	r, fake, peerFake := newPeerShareReverseBackend(t)
	peerFake.onStart = func() { r.ResetNetwork() }
	require.NoError(t, r.applyPeerShare(true))
	require.Eventually(t, restartedOnOwnPort(fake, 2), time.Second, 5*time.Millisecond)
	assert.Equal(t, int32(1), fake.networks.Load())

	peerFake.onStart = nil
	r.ResetNetwork()
	require.NoError(t, r.applyPeerShare(false))
	require.Eventually(t, func() bool {
		return fake.starts.Load() == 3 && fake.running.Load() && !fake.YieldedManualPort()
	}, time.Second, 5*time.Millisecond)
}

// The gate stays authoritative: a client paused for peer sharing does not
// restart once the VPN went down meanwhile.
func TestPeerShareDoesNotRestartTheReverseClientAgainstTheGate(t *testing.T) {
	r, fake, peerFake := newPeerShareReverseBackend(t)
	peerFake.onStart = func() {
		emitVPNStatus(vpn.Disconnected)
		g := r.reverseGate.Load()
		require.Eventually(t, func() bool {
			g.mu.Lock()
			defer g.mu.Unlock()
			return !g.vpnUp
		}, time.Second, 5*time.Millisecond)
	}
	require.NoError(t, r.applyPeerShare(true))
	assert.Never(t, fake.running.Load, reverseSettle, 10*time.Millisecond)
	assert.Equal(t, int32(1), fake.starts.Load())

	emitVPNStatus(vpn.Connected)
	require.Eventually(t, restartedOnOwnPort(fake, 2), time.Second, 5*time.Millisecond)
}

func TestPeerShareStartsWhenTheReverseTeardownOverruns(t *testing.T) {
	prev := reverseStopTimeout
	reverseStopTimeout = 50 * time.Millisecond
	t.Cleanup(func() { reverseStopTimeout = prev })
	r, fake, peerFake := newPeerShareReverseBackend(t)
	fake.hang.Store(true)
	start := time.Now()
	require.NoError(t, r.applyPeerShare(true))
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Equal(t, int64(1), peerFake.startCalls.Load(), "an overrun teardown still starts peer sharing")
	require.Eventually(t, restartedOnOwnPort(fake, 2), time.Second, 5*time.Millisecond)
}

func TestPeerShareOnWithoutAReverseGate(t *testing.T) {
	peerFake := &fakePeerController{}
	r := newPeerTestBackend(t, peerFake)
	r.reverseClient = &fakeReverse{}
	require.NoError(t, r.applyPeerShare(true))
	require.NoError(t, r.applyPeerShare(false))
	assert.Equal(t, int64(1), peerFake.startCalls.Load())
}

func TestPeerShareSelfStopRestartsAYieldedReverseClient(t *testing.T) {
	r, fake, peerFake := newPeerShareReverseBackend(t)
	require.NoError(t, r.applyPeerShare(true))
	require.Eventually(t, restartedOnOwnPort(fake, 2), time.Second, 5*time.Millisecond)

	peerFake.active.Store(false)
	r.onPeerSelfStop(errors.New("router lost the mapping"))
	assert.False(t, peerShareOn())
	require.Eventually(t, func() bool {
		return fake.starts.Load() == 3 && fake.running.Load() && !fake.YieldedManualPort()
	}, time.Second, 5*time.Millisecond)
}

// A personal proxies group whose only members are reverse outbounds goes
// with them while peer sharing pauses the reverse client, and the tunnel
// falls back to auto-select. The saved group is selected again once they
// return.
func TestPeerSharePauseRestoresTheSavedPersonalProxiesGroup(t *testing.T) {
	r, fake := newReverseFriendBackend(t, t.TempDir())
	peerFake := &fakePeerController{}
	r.peerClient = peerFake
	tunnel := &fakeHelperTunnel{live: map[string]string{}}
	tunnel.attach(r)
	r.persistSelection(vpn.PersonalProxiesTag)
	require.NoError(t, r.liveTunnel().SelectServer(vpn.PersonalProxiesTag))

	peerFake.onStart = func() {
		assert.False(t, fake.running.Load())
		assert.Empty(t, r.reverseOutbounds())
		// The tunnel withdrew the emptied group.
		require.NoError(t, tunnel.SelectServer(vpn.AutoSelectTag))
	}
	require.NoError(t, r.applyPeerShare(true))
	require.Eventually(t, restartedOnOwnPort(fake, 2), time.Second, 5*time.Millisecond)
	assert.Equal(t, vpn.PersonalProxiesTag, tunnel.current())
	assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t))
}

// A saved personal proxies group whose only members are reverse outbounds
// stands while they are down, as a saved reverse friend does: through a
// config refresh, and across a launch, where the tunnel starts on
// auto-select without saving it.
func TestReverseKeepsASavedPersonalProxiesGroupWhileItsMembersAreDown(t *testing.T) {
	dataDir := t.TempDir()
	r, fake := newReverseFriendBackend(t, dataDir)
	r.persistSelection(vpn.PersonalProxiesTag)
	emitVPNStatus(vpn.Disconnected)
	require.Eventually(t, notRunning(fake), time.Second, 5*time.Millisecond)
	require.NoError(t, reverseBox{r: r}.SetReversePortal(nil, ""))
	require.Empty(t, r.reverseOutbounds())

	r.applyConfig(cachedConfig(), true)
	r.clearSelectedIfMissing()
	assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t))
	assert.Equal(t, vpn.AutoSelectTag, r.fallbackFor(vpn.PersonalProxySelection(ppFriendB)),
		"a friend does not fall back to a group with no member")
	r.stopReverse()

	next := newPersonalProxiesBackendIn(t, dataDir)
	next.reverseFriends = loadReverseFriends(filepath.Join(dataDir, reverseFriendsFileName))
	next.clearSelectedIfMissing()
	assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t))
	tunnel := &fakeHelperTunnel{}
	tunnel.attach(next)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, next.ConnectVPN(ctx, vpn.PersonalProxiesTag))
	assert.Equal(t, vpn.AutoSelectTag, tunnel.current(), "the tunnel starts without the group")
	assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t), "which stays saved")
	assert.Equal(t, vpn.AutoSelectTag, next.restartBoxOptions().InitialServer)

	require.NoError(t, reverseBox{r: next}.SetReverseOutbounds([]string{lbA.ReverseHelperTag(ppFriendB)}))
	assert.Equal(t, vpn.PersonalProxiesTag, tunnel.current())
}

// A prune that read the pairings before a friend was recorded must not drop
// it: the pairings are read under the lock record takes.
func TestReverseFriendsPruneDoesNotDropALaterRecord(t *testing.T) {
	f := &reverseFriends{byPairing: map[string]string{pairingHash("pairing-a"): ppFriendA}}
	f.setTags(map[string]string{"pairing-b": ppFriendB})
	recorded := make(chan struct{})
	f.prune(func() []string {
		go func() {
			f.record([]string{lbA.ReverseHelperTag(ppFriendB)}, func() []string { return []string{"pairing-a", "pairing-b"} })
			close(recorded)
		}()
		select {
		case <-recorded:
			t.Error("record ran inside the prune")
		case <-time.After(100 * time.Millisecond):
		}
		return []string{"pairing-a"}
	})
	<-recorded
	assert.True(t, f.has(ppFriendA))
	assert.True(t, f.has(ppFriendB))
}

// A status change that lands while the gate seeds its state is applied after
// the seed, not overwritten by it.
func TestReverseGateSeedDoesNotOverwriteANewerStatus(t *testing.T) {
	dataDir := t.TempDir()
	writeCachedConfig(t, dataDir, &config.Config{Features: map[string]bool{helperReverseFeature: true}})
	r, fake := newUnstartedReverseTestBackend(t, dataDir, false)
	r.startReverseWith(func() vpn.VPNStatus {
		g := r.reverseGate.Load()
		applied := make(chan struct{})
		go func() {
			g.setVPNStatus(vpn.Disconnected)
			close(applied)
		}()
		select {
		case <-applied:
		case <-time.After(100 * time.Millisecond):
		}
		return vpn.Connected
	})
	assert.Never(t, fake.running.Load, reverseSettle, 10*time.Millisecond)
	g := r.reverseGate.Load()
	g.mu.Lock()
	defer g.mu.Unlock()
	assert.False(t, g.vpnUp)
}

// After Close neither a queued prune nor a late record saves the friends, so
// neither overwrites a replacement backend's.
func TestReverseFriendsAreNotSavedAfterClose(t *testing.T) {
	dataDir := t.TempDir()
	r, _ := newReverseFriendBackend(t, dataDir)
	r.stopReverse()
	r.selectionMu.Lock()
	r.selectionClosed = true
	r.selectionMu.Unlock()
	saved := func() *reverseFriends { return loadReverseFriends(filepath.Join(dataDir, reverseFriendsFileName)) }
	require.True(t, saved().has(ppFriendB))

	r.helperPairingKeys.Set(map[string]helper.PairingKey{
		"pairing-other": {Key: bytes.Repeat([]byte{7}, 32), Role: string(helperticket.RoleInviter)},
	})
	r.pruneReverseFriends()
	assert.True(t, saved().has(ppFriendB), "a prune after Close saved the friends")

	r.reverseFriends.setTags(map[string]string{"pairing-other": ppFriendA})
	require.NoError(t, reverseBox{r: r}.SetReverseOutbounds([]string{lbA.ReverseHelperTag(ppFriendA)}))
	assert.False(t, saved().has(ppFriendA), "a record after Close saved the friends")
}

// A pairing revoked after the reverse client took its tags, and pruned before
// they were recorded, is not recorded back.
func TestReverseFriendsRecordSkipsARevokedPairing(t *testing.T) {
	f := &reverseFriends{byPairing: map[string]string{}}
	f.setTags(map[string]string{"pairing-b": ppFriendB})
	none := func() []string { return nil }
	f.prune(none)
	f.record([]string{lbA.ReverseHelperTag(ppFriendB)}, none)
	assert.False(t, f.has(ppFriendB))

	f.record([]string{lbA.ReverseHelperTag(ppFriendB)}, func() []string { return []string{"pairing-b"} })
	assert.True(t, f.has(ppFriendB))
}

// A saved group that started empty is selected once a config brings it a
// direct helper, while its reverse members are still down.
func TestReverseSavedGroupIsSelectedWhenAConfigAddsAHelper(t *testing.T) {
	dataDir := t.TempDir()
	r, fake := newReverseFriendBackend(t, dataDir)
	r.persistSelection(vpn.PersonalProxiesTag)
	emitVPNStatus(vpn.Disconnected)
	require.Eventually(t, notRunning(fake), time.Second, 5*time.Millisecond)
	require.NoError(t, reverseBox{r: r}.SetReversePortal(nil, ""))
	r.stopReverse()

	tunnel := &fakeHelperTunnel{}
	tunnel.attach(r)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.ConnectVPN(ctx, vpn.PersonalProxiesTag))
	require.Equal(t, vpn.AutoSelectTag, tunnel.current())

	require.NoError(t, r.updateServers(servers.ServerList{Servers: []*servers.Server{helperWithPort(ppFriendA, 1080)}}, true))
	assert.Equal(t, vpn.PersonalProxiesTag, tunnel.current())
	assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t))
}

// newSavedFriendTunnel is a backend with ppFriendB's selection saved and kept
// as a reverse friend, a rooms consumer, no tickets for it, and a connected
// tunnel on auto-select.
func newSavedFriendTunnel(t *testing.T) (*LocalBackend, *fakeHelperTunnel, *fakeTickets) {
	t.Helper()
	r := newPersonalProxiesBackend(t)
	r.reverseFriends = &reverseFriends{byPairing: map[string]string{pairingHash(ppPairingB): ppFriendB}}
	tickets := withTickets(t, r, nil)
	require.NoError(t, r.srvManager.AddServers(consumerServers(), false))
	r.persistSelection(vpn.PersonalProxySelection(ppFriendB))
	tunnel := &fakeHelperTunnel{live: map[string]string{}, selected: vpn.AutoSelectTag}
	tunnel.attach(r)
	return r, tunnel, tickets
}

// A saved friend reached only by rooms is restored once its tickets arrive.
func TestSavedFriendIsRestoredWhenItsRoomsTicketsArrive(t *testing.T) {
	r, tunnel, tickets := newSavedFriendTunnel(t)
	r.restoreSavedSelection()
	require.Equal(t, vpn.AutoSelectTag, tunnel.current(), "no member without a ticket")

	tickets.reissue(t, r, map[string]string{ppFriendB: ppPairingB})
	assert.Equal(t, vpn.PersonalProxySelection(ppFriendB), tunnel.current())
}

// A helper added while a connect waited reaches the new tunnel only through
// the Connected reconcile, which then restores the saved group.
func TestConnectedReconcileRestoresTheSavedGroup(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	r.reverseFriends = &reverseFriends{byPairing: map[string]string{pairingHash(reversePairing): ppFriendB}}
	r.startHelperReconcileListener()
	r.persistSelection(vpn.PersonalProxiesTag)
	tunnel := &fakeHelperTunnel{}
	tunnel.attach(r)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.ConnectVPN(ctx, vpn.PersonalProxiesTag))
	require.Equal(t, vpn.AutoSelectTag, tunnel.current())

	require.NoError(t, r.srvManager.AddServers(directServers(ppFriendA), false))
	emitVPNStatus(vpn.Connected)
	require.Eventually(t, func() bool { return tunnel.current() == vpn.PersonalProxiesTag }, time.Second, 5*time.Millisecond)
	assert.Equal(t, vpn.PersonalProxiesTag, selectedTag(t))
}

func selectCalls(f *fakeHelperTunnel) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "select:") {
			n++
		}
	}
	return n
}

// While connected the restore runs periodically, so a member that arrived by
// a path that restored nothing is still taken up; once the tunnel matches the
// saved selection it selects nothing more.
func TestSelectionRestoreTickerCatchesAMissedMember(t *testing.T) {
	prev := selectionRestoreInterval
	selectionRestoreInterval = 10 * time.Millisecond
	t.Cleanup(func() { selectionRestoreInterval = prev })
	r := newPersonalProxiesBackend(t)
	r.reverseFriends = &reverseFriends{byPairing: map[string]string{pairingHash(reversePairing): ppFriendB}}
	r.persistSelection(vpn.PersonalProxiesTag)
	tunnel := &fakeHelperTunnel{live: map[string]string{}, selected: vpn.AutoSelectTag}
	tunnel.attach(r)
	r.setSelectionRestoreTicker(true)
	t.Cleanup(func() { r.setSelectionRestoreTicker(false) })

	assert.Never(t, func() bool { return selectCalls(tunnel) > 0 }, 50*time.Millisecond, 5*time.Millisecond, "no member yet")
	require.NoError(t, r.srvManager.AddServers(directServers(ppFriendA), false))
	require.Eventually(t, func() bool { return tunnel.current() == vpn.PersonalProxiesTag }, time.Second, 5*time.Millisecond)
	n := selectCalls(tunnel)
	assert.Never(t, func() bool { return selectCalls(tunnel) != n }, 100*time.Millisecond, 5*time.Millisecond,
		"a tunnel on the saved selection is left alone")

	r.setSelectionRestoreTicker(false)
	require.NoError(t, tunnel.SelectServer(vpn.AutoSelectTag))
	// A fresh variable: the previous Never's last check can still be reading n.
	stopped := selectCalls(tunnel)
	assert.Never(t, func() bool { return selectCalls(tunnel) != stopped }, 50*time.Millisecond, 5*time.Millisecond, "stopped")
}

// The VPN client reports Connected before Connect returns. A restore it, or a
// tick, runs then must not put back the previous selection over the one the
// connect requested.
func TestConnectSelectionWinsOverARestoreBeforeItIsSaved(t *testing.T) {
	for _, requested := range []string{"lantern-1", vpn.AutoSelectTag} {
		t.Run(requested, func(t *testing.T) {
			r := newPersonalProxiesBackend(t)
			require.NoError(t, r.srvManager.AddServers(directServers("lantern-1", ppFriendB), false))
			friend := vpn.PersonalProxySelection(ppFriendB)
			r.persistSelection(friend)
			tunnel := &fakeHelperTunnel{}
			tunnel.attach(r)
			t.Cleanup(func() { r.setSelectionRestoreTicker(false) })
			restored := 0
			tunnel.onConnect = func() {
				r.tunnelConnected()
				r.restoreSavedSelection()
				restored++
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			require.NoError(t, r.ConnectVPN(ctx, requested))
			require.Equal(t, 1, restored)
			assert.Equal(t, requested, tunnel.current())
			assert.Equal(t, requested, selectedTag(t))
			assert.Empty(t, tunnel.SelectedPersonalProxy())

			// Once saved, the restore follows the new selection.
			r.restoreSavedSelection()
			assert.Equal(t, requested, tunnel.current())
		})
	}
}

// A failed connect leaves nothing pending, so restores resume.
func TestFailedConnectDoesNotBlockRestores(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.srvManager.AddServers(directServers("lantern-1", ppFriendB), false))
	tunnel := &fakeHelperTunnel{connectErr: errors.New("tun busy")}
	tunnel.attach(r)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.Error(t, r.ConnectVPN(ctx, "lantern-1"))
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	assert.False(t, r.connectPending)
}

// Auto mode can report the very server a connect pins. The pin is applied
// anyway, so the tunnel ends in manual mode on it.
func TestConnectPinsAServerAutoHappensToBeOn(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.srvManager.AddServers(directServers("lantern-1"), false))
	tunnel := &fakeHelperTunnel{}
	tunnel.attach(r)
	tunnel.onConnect = func() {
		tunnel.mu.Lock()
		tunnel.selected, tunnel.autoChoice = vpn.AutoSelectTag, "lantern-1"
		tunnel.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.ConnectVPN(ctx, "lantern-1"))
	manual, ok := tunnel.ManualSelection()
	assert.True(t, ok, "manual mode")
	assert.Equal(t, "lantern-1", manual)
	assert.Equal(t, "lantern-1", selectedTag(t))
}

// The tunnel can report a reverse outbound as its auto or current selection.
// It resolves to its friend's helper server, or to the friend's personal
// proxy when the manager has none, for both selected-server responses.
func TestReverseOutboundResolvesAsTheSelectedServer(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up()
	direct := helperWithPort(ppFriendA, 1080)
	require.NoError(t, r.srvManager.AddServers(servers.ServerList{Servers: []*servers.Server{direct}}, false))
	revA, revB := lbA.ReverseHelperTag(ppFriendA), lbA.ReverseHelperTag(ppFriendB)
	require.NoError(t, r.vpnClient.SetReverseOutbounds([]string{revA, revB}))

	// GET /server/auto-selected: CurrentAutoSelectedServer, then GetServerByTag.
	autoSelected := func() (*servers.Server, bool) {
		tag, err := r.CurrentAutoSelectedServer()
		require.NoError(t, err)
		return r.GetServerByTag(tag)
	}
	for _, tc := range []struct{ rev, want string }{
		{revA, ppFriendA},
		{revB, vpn.PersonalProxySelection(ppFriendB)},
	} {
		tun.mu.Lock()
		tun.autoChoice, tun.selected = tc.rev, tc.rev
		tun.mu.Unlock()

		srv, found := autoSelected()
		require.True(t, found)
		assert.Equal(t, tc.want, srv.Tag)

		// GET /server/selected in auto mode.
		require.NoError(t, settings.Set(settings.AutoConnectKey, true))
		srv, found, err := r.SelectedServer()
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, tc.want, srv.Tag)

		// GET /server/selected with no saved selection: the tunnel's current one.
		require.NoError(t, settings.Set(settings.AutoConnectKey, false))
		require.NoError(t, settings.Clear(settings.SelectedServerKey))
		srv, found, err = r.SelectedServer()
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, tc.want, srv.Tag)
	}

	require.NoError(t, r.vpnClient.SetReverseOutbounds(nil))
	_, found := autoSelected()
	assert.False(t, found, "a reverse outbound that is not live resolves to nothing")
}

// A managed server whose tag looks like a reverse outbound's is found by its
// own tag, live alias or not.
func TestGetServerByTagPrefersAnExactMatch(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	rev := lbA.ReverseHelperTag(ppFriendA)
	require.NoError(t, r.srvManager.AddServers(servers.ServerList{Servers: []*servers.Server{
		helperWithPort(ppFriendA, 1080),
		{Tag: rev, Type: "socks", Options: option.Outbound{Tag: rev, Type: "socks", Options: &option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "203.0.113.8", ServerPort: 1081},
		}}},
	}}, false))
	for _, live := range [][]string{nil, {rev}} {
		require.NoError(t, r.vpnClient.SetReverseOutbounds(live))
		srv, found := r.GetServerByTag(rev)
		require.True(t, found)
		assert.Equal(t, rev, srv.Tag)
	}
}
