package backend

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/getlantern/broflake/common/helperticket"
	"github.com/getlantern/lantern-box/protocol/samizdatreverse"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/kindling"
	"github.com/getlantern/radiance/peer"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/vpn"
)

// helperReverseFeature is the config feature that lets this device serve its
// paired helpers as a reverse inviter.
const helperReverseFeature = "helper_reverse"

// reverseStopTimeout bounds how long the gate waits for the reverse client's
// teardown; the teardown runs to its own deadline either way. A var so tests
// can shorten it.
var reverseStopTimeout = 10 * time.Second

// reverseUnsupported reports whether this platform must never run the reverse
// client. It is a var solely so tests can fake it.
var reverseUnsupported = common.IsIOS

// reverseController is the subset of *peer.ReverseClient that LocalBackend
// needs.
type reverseController interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context)
	Release(ctx context.Context)
	NetworkChanged()
	PairingsChanged()
	YieldedManualPort() bool
}

func (r *LocalBackend) newReverseClient(deviceID string) *peer.ReverseClient {
	return peer.NewReverseClient(peer.ReverseConfig{
		API:             helper.NewReverseAPI(kindling.HTTPClient(), common.GetBaseURL(), deviceID),
		Keys:            r.helperPairingKeys,
		Box:             reverseBox{r: r},
		OnTags:          r.reverseFriends.setTags,
		PeerShareActive: r.peerShareActive,
		LocalIPControl:  r.vpnClient.PhysicalInterfaceControl,
	})
}

func (r *LocalBackend) newBridgeClient(deviceID string) *helper.BridgeClient {
	return helper.NewBridgeClient(helper.BridgeConfig{
		API:    helper.NewReverseAPI(kindling.HTTPClient(), common.GetBaseURL(), deviceID),
		Keys:   r.helperPairingKeys,
		NewBox: peer.NewBridgeBox,
		Usage:  r.helperUsage,
	})
}

// useReverseClient makes c the backend's reverse client and points pairing key
// changes at it.
func (r *LocalBackend) useReverseClient(c reverseController) {
	r.reverseClient = c
	r.helperPairingKeys.SetOnChange(r.pairingKeysChanged)
}

func (r *LocalBackend) pairingKeysChanged() {
	// A pairing change is new information, so it tries at once.
	r.clearPairingNotBefore()
	r.syncPairingRoute()
	if r.reverseClient != nil {
		r.reverseClient.PairingsChanged()
		go r.pruneReverseFriends()
	}
	if r.bridgeClient != nil {
		r.bridgeClient.PairingsChanged()
	}
}

func (r *LocalBackend) inviterPairingIDs() []string {
	return r.helperPairingKeys.IDs(string(helperticket.RoleInviter))
}

// pruneReverseFriends forgets the reverse friends whose inviter pairing ended,
// and with them a selection that only they kept. After Close it does nothing,
// so it never saves over a replacement backend's friends.
func (r *LocalBackend) pruneReverseFriends() {
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	if r.selectionClosed || !r.reverseFriends.prune(r.inviterPairingIDs) {
		return
	}
	r.clearSelectedIfMissingLocked()
}

// startReverse runs the reverse client while the VPN is connected and the
// config enables helperReverseFeature, until stopReverse or r.ctx ends.
func (r *LocalBackend) startReverse() {
	status := func() vpn.VPNStatus { return "" }
	if r.vpnClient != nil {
		status = r.vpnClient.Status
	}
	r.startReverseWith(status)
}

func (r *LocalBackend) startReverseWith(vpnStatus func() vpn.VPNStatus) {
	if r.reverseClient == nil || reverseUnsupported() {
		return
	}
	ctx, cancel := context.WithCancel(r.ctx)
	g := &reverseGate{
		client: r.reverseClient,
		kick:   make(chan struct{}, 1),
		cancel: cancel,
		exited: make(chan struct{}),
	}
	if prev := r.reverseGate.Swap(g); prev != nil {
		prev.stop()
	}
	events.SubscribeContext(ctx, func(evt vpn.StatusUpdateEvent) { g.setVPNStatus(evt.Status) })
	events.SubscribeContext(ctx, func(evt config.NewConfigEvent) {
		if evt.New != nil {
			g.setFeature(evt.New.Features[helperReverseFeature])
		}
	})
	// Seeded after subscribing, and read and applied under the lock the
	// callbacks take, so neither a change in between nor a later one is lost.
	g.mu.Lock()
	g.applyVPNStatusLocked(vpnStatus())
	if cfg, err := r.confHandler.GetConfig(); err == nil && cfg != nil {
		g.featureOn = cfg.Features[helperReverseFeature]
	}
	g.mu.Unlock()
	g.wake()
	go g.run(ctx)
}

// stopReverse stops the reverse client and waits, at most about
// reverseStopTimeout, for its teardown.
func (r *LocalBackend) stopReverse() {
	if g := r.reverseGate.Swap(nil); g != nil {
		g.stop()
	}
}

func peerShareOn() bool { return settings.GetBool(settings.PeerShareEnabledKey) }

// pauseReverse stops the reverse client, if it runs, and keeps it stopped
// until resume is called. It returns once the client has removed its portal
// and unmapped its port, that wait has timed out, or ctx ends. resume may be
// called more than once.
func (r *LocalBackend) pauseReverse(ctx context.Context) (resume func()) {
	g := r.reverseGate.Load()
	if g == nil {
		return func() {}
	}
	return g.pause(ctx)
}

// restartYieldedReverse restarts the reverse client if it runs on a port of
// its own only because peer sharing held the manual port.
func (r *LocalBackend) restartYieldedReverse() {
	if g := r.reverseGate.Load(); g != nil {
		g.restartYielded()
	}
}

func (r *LocalBackend) reverseNetworkChanged() {
	if r.reverseClient != nil {
		r.reverseClient.NetworkChanged()
	}
}

// reverseGate starts and stops a reverse client on one goroutine, so the event
// and IPC paths that report its inputs never wait on it.
type reverseGate struct {
	client reverseController
	kick   chan struct{}
	cancel context.CancelFunc
	exited chan struct{}

	mu        sync.Mutex
	vpnUp     bool
	featureOn bool
	// paused counts unresumed pauses, which keep the client stopped.
	paused int
	// pauseAcks close once the loop has acted on their pause.
	pauseAcks    []chan struct{}
	restartYield bool
}

func (g *reverseGate) setVPNStatus(s vpn.VPNStatus) {
	g.mu.Lock()
	g.applyVPNStatusLocked(s)
	g.mu.Unlock()
	g.wake()
}

func (g *reverseGate) applyVPNStatusLocked(s vpn.VPNStatus) {
	switch s {
	case vpn.Connected:
		g.vpnUp = true
	case vpn.Connecting, vpn.Restarting:
		// A restart keeps the client: the new tunnel restores its portal and
		// outbounds. Every other way out of Connected already set the VPN down.
	default:
		g.vpnUp = false
	}
}

func (g *reverseGate) setFeature(on bool) { g.set(&g.featureOn, on) }

func (g *reverseGate) set(field *bool, v bool) {
	g.mu.Lock()
	*field = v
	g.mu.Unlock()
	g.wake()
}

func (g *reverseGate) wake() {
	select {
	case g.kick <- struct{}{}:
	default:
	}
}

func (g *reverseGate) pause(ctx context.Context) (resume func()) {
	ack := make(chan struct{})
	g.mu.Lock()
	g.paused++
	g.pauseAcks = append(g.pauseAcks, ack)
	g.mu.Unlock()
	g.wake()
	select {
	case <-ack:
	case <-g.exited:
	case <-ctx.Done():
		slog.Warn("Gave up waiting for the reverse client to stop")
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.paused--
			g.mu.Unlock()
			g.wake()
		})
	}
}

func (g *reverseGate) restartYielded() {
	g.mu.Lock()
	g.restartYield = true
	g.mu.Unlock()
	g.wake()
}

// take returns whether the client should run, whether a restart for the
// manual port was asked for, and the pauses seen, clearing both requests.
func (g *reverseGate) take() (want, restart bool, acks []chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	want = g.vpnUp && g.featureOn && g.paused == 0
	restart, acks = g.restartYield, g.pauseAcks
	g.restartYield, g.pauseAcks = false, nil
	return want, restart, acks
}

func (g *reverseGate) run(ctx context.Context) {
	defer close(g.exited)
	running := false
	for {
		select {
		case <-ctx.Done():
			if running {
				g.stopClient(g.client.Stop)
			}
			return
		case <-g.kick:
		}
		want, restart, acks := g.take()
		if running && (!want || (restart && g.client.YieldedManualPort())) {
			// A later Start waits out the deregister itself.
			g.stopClient(g.client.Release)
			running = false
		}
		if want && !running {
			if err := g.client.Start(ctx); err != nil {
				slog.Warn("Failed to start the reverse client", "error", err)
			} else {
				running = true
			}
		}
		for _, ack := range acks {
			close(ack)
		}
	}
}

func (g *reverseGate) stopClient(stop func(context.Context)) {
	ctx, cancel := context.WithTimeout(context.Background(), reverseStopTimeout)
	defer cancel()
	stop(ctx)
	if ctx.Err() != nil {
		slog.Warn("Reverse client teardown is still running")
	}
}

func (g *reverseGate) stop() {
	g.cancel()
	<-g.exited
}

// reverseBox is the VPN client as the reverse client's box. It records the
// friends of each reverse outbound set it publishes in r.reverseFriends.
//
// A revoked pairing's friend is pruned at once, but its outbound goes only
// when the reverse client next cycles, and until then it keeps a selection of
// the friend standing. So each withdrawal checks the selection again.
type reverseBox struct{ r *LocalBackend }

func (b reverseBox) SetReversePortal(cfg *samizdatreverse.PortalConfig, masqueradeDomain string) error {
	err := b.r.vpnClient.SetReversePortal(cfg, masqueradeDomain)
	if cfg == nil {
		// Removing the portal removes the outbounds, even on an error.
		b.r.selectionMu.Lock()
		defer b.r.selectionMu.Unlock()
		if !b.r.selectionClosed {
			b.r.clearSelectedIfMissingLocked()
		}
	}
	return err
}

func (b reverseBox) SetReverseOutbounds(tags []string) error {
	if err := b.r.vpnClient.SetReverseOutbounds(tags); err != nil {
		return err
	}
	b.r.selectionMu.Lock()
	defer b.r.selectionMu.Unlock()
	if b.r.selectionClosed {
		return nil
	}
	if len(tags) > 0 {
		b.r.reverseFriends.record(tags, b.r.inviterPairingIDs)
		b.r.restoreSavedSelectionLocked()
	}
	b.r.clearSelectedIfMissingLocked()
	return nil
}

func (b reverseBox) RebindReversePortal() error { return b.r.vpnClient.RebindReversePortal() }

func (b reverseBox) ReversePortalListening() bool { return b.r.vpnClient.ReversePortalListening() }

// restoreSavedSelection is restoreSavedSelectionLocked for a caller not
// holding r.selectionMu.
func (r *LocalBackend) restoreSavedSelection() {
	r.selectionMu.Lock()
	defer r.selectionMu.Unlock()
	r.restoreSavedSelectionLocked()
}

// restoreSavedSelectionLocked has the tunnel select the saved personal
// proxies group, or saved friend, once it has a member: a tunnel built while
// it had none, or that lost its last member, fell back from it. The caller
// must hold r.selectionMu.
func (r *LocalBackend) restoreSavedSelectionLocked() {
	if r.selectionClosed || r.connectPending || settings.GetBool(settings.AutoConnectKey) {
		return
	}
	var saved servers.Server
	if err := settings.GetStruct(settings.SelectedServerKey, &saved); err != nil {
		return
	}
	// With no tunnel up there is nothing to restore, and the next connect
	// starts on the saved selection.
	current, err := r.liveTunnel().CurrentSelectedServer()
	if err != nil || current == "" {
		return
	}
	if saved.Tag == vpn.PersonalProxiesTag {
		if manual, ok := r.liveTunnel().ManualSelection(); (ok && manual == vpn.PersonalProxiesTag) || !r.personalProxiesLive() {
			return
		}
	} else {
		friend, ok := vpn.ParsePersonalProxySelection(saved.Tag)
		if !ok || r.liveTunnel().SelectedPersonalProxy() == friend || !r.friendReach(friend).routable() {
			return
		}
	}
	if err := r.liveTunnel().SelectServer(saved.Tag); err != nil && !errors.Is(err, vpn.ErrTunnelNotConnected) {
		// The error can name the friend.
		slog.Warn("Failed to restore the saved selection once it had a member")
	}
}
