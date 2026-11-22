package vpn

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common"
)

// fakeNetwork models the box network manager: UpdateInterfaces re-polls, applying
// a pending interface count that a test sets to simulate a route returning.
type fakeNetwork struct {
	mu        sync.Mutex
	current   int
	pending   int
	updates   atomic.Int32
	resets    atomic.Int32
	updateErr error
}

func (f *fakeNetwork) UpdateInterfaces() error {
	f.updates.Add(1)
	f.mu.Lock()
	f.current = f.pending
	f.mu.Unlock()
	return f.updateErr
}

func (f *fakeNetwork) NetworkInterfaces() []adapter.NetworkInterface {
	f.mu.Lock()
	defer f.mu.Unlock()
	return make([]adapter.NetworkInterface, f.current)
}

func (f *fakeNetwork) ResetNetwork(context.Context) { f.resets.Add(1) }

func (f *fakeNetwork) setPending(n int) {
	f.mu.Lock()
	f.pending = n
	f.mu.Unlock()
}

type blockedRecoveryNetwork struct {
	fakeNetwork
	entered chan struct{}
	release chan struct{}
}

func (n *blockedRecoveryNetwork) UpdateInterfaces() error {
	close(n.entered)
	<-n.release
	return n.fakeNetwork.UpdateInterfaces()
}

func TestNetRecovery_TunnelCloseWaitsForBlockedUpdate(t *testing.T) {
	net := &blockedRecoveryNetwork{
		fakeNetwork: fakeNetwork{pending: 1},
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	rec := newTestRecovery(net, alwaysPaused, time.Millisecond, time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	release := sync.OnceFunc(func() { close(net.release) })
	go rec.run(ctx)
	t.Cleanup(func() {
		cancel()
		release()
		rec.stop()
	})
	rec.pause()
	select {
	case <-net.entered:
	case <-time.After(time.Second):
		t.Fatal("recovery did not start updating interfaces")
	}

	closed := make(chan struct{})
	tn := &tunnel{cancel: cancel, netRecovery: rec, closeTimeout: 20 * time.Millisecond}
	tn.closers = append(tn.closers, closerFunc(func() error {
		close(closed)
		return nil
	}))
	closeResult := make(chan error, 1)
	go func() { closeResult <- tn.close() }()
	select {
	case err := <-closeResult:
		require.ErrorContains(t, err, "timeout waiting for tunnel to close")
	case <-time.After(time.Second):
		t.Fatal("tunnel close did not honor its timeout")
	}
	select {
	case <-closed:
		t.Fatal("box resources closed while recovery was still using them")
	default:
	}

	release()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("box resources did not close after recovery exited")
	}
	require.EqualValues(t, 1, net.resets.Load())
}

func newTestRecovery(net boxNetwork, paused func() bool, base, max time.Duration) *netRecovery {
	return &netRecovery{
		network:       net,
		networkPaused: paused,
		backoff:       common.NewBackoff(base, max),
		armCh:         make(chan struct{}, 1),
		wakeCh:        make(chan struct{}, 1),
		done:          make(chan struct{}),
	}
}

func alwaysPaused() bool { return true }

// stableCount waits until c stops changing across consecutive polls and returns
// its settled value, so a test can baseline a loop that may have one attempt in
// flight.
func stableCount(t *testing.T, c func() int32) int32 {
	t.Helper()
	last := c()
	require.Eventually(t, func() bool {
		got := c()
		if got == last {
			return true
		}
		last = got
		return false
	}, 2*time.Second, 20*time.Millisecond, "count never stabilized")
	return last
}

func TestNetRecovery_ResetsOnceWhenInterfacesReturn(t *testing.T) {
	net := &fakeNetwork{} // starts with no interfaces
	rec := newTestRecovery(net, alwaysPaused, 10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.run(ctx)

	rec.pause()
	require.Eventually(t, func() bool {
		return net.updates.Load() >= 2
	}, 2*time.Second, 20*time.Millisecond, "should keep re-polling while paused with no interfaces")
	require.Zero(t, net.resets.Load(), "must not reset the network while interfaces are still gone")

	net.setPending(2) // route returns
	require.Eventually(t, func() bool {
		return net.resets.Load() == 1
	}, 2*time.Second, 20*time.Millisecond, "should reset once when interfaces refill")
	require.Never(t, func() bool {
		return net.resets.Load() > 1
	}, 300*time.Millisecond, 20*time.Millisecond, "must not keep resetting after recovery")
}

func TestNetRecovery_RecoversAgainWhilePauseRemainsLatched(t *testing.T) {
	ctx, cancel := context.WithCancel(pause.WithDefaultManager(context.Background()))
	mgr := service.FromContext[pause.Manager](ctx)
	net := &fakeNetwork{pending: 1}
	rec := newTestRecovery(net, mgr.IsNetworkPaused, 10*time.Millisecond, 50*time.Millisecond)
	var pauseEvents atomic.Int32
	cb := mgr.RegisterCallback(func(evt int) {
		switch evt {
		case pause.EventNetworkPause:
			pauseEvents.Add(1)
			rec.pause()
		case pause.EventNetworkWake:
			rec.wake()
		}
	})
	go rec.run(ctx)
	t.Cleanup(func() {
		cancel()
		rec.stop()
		mgr.UnregisterCallback(cb)
	})

	mgr.NetworkPause()
	require.Eventually(t, func() bool {
		return net.resets.Load() == 1
	}, 2*time.Second, 20*time.Millisecond)
	require.True(t, mgr.IsNetworkPaused())

	net.setPending(0)
	mgr.NetworkPause()
	require.EqualValues(t, 1, pauseEvents.Load())
	require.Eventually(t, func() bool {
		return len(net.NetworkInterfaces()) == 0
	}, 2*time.Second, 20*time.Millisecond, "polling must continue while the pause remains latched")
	net.setPending(1)
	require.Eventually(t, func() bool {
		return net.resets.Load() == 2
	}, 2*time.Second, 20*time.Millisecond, "a second outage must recover without another pause event")
	require.Never(t, func() bool {
		return net.resets.Load() > 2
	}, 300*time.Millisecond, 20*time.Millisecond, "stable interfaces must not trigger repeated resets")

	mgr.NetworkWake()
	settled := stableCount(t, net.updates.Load)
	require.Never(t, func() bool {
		return net.updates.Load() > settled
	}, 300*time.Millisecond, 20*time.Millisecond, "an actual network wake must stop polling")
}

func TestNetRecovery_StopsWhenUnpaused(t *testing.T) {
	net := &fakeNetwork{}
	var paused atomic.Bool
	paused.Store(true)
	rec := newTestRecovery(net, paused.Load, 10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.run(ctx)

	rec.pause()
	require.Eventually(t, func() bool {
		return net.updates.Load() >= 1
	}, 2*time.Second, 20*time.Millisecond, "should be polling while paused")

	paused.Store(false)
	rec.wake()
	settled := stableCount(t, net.updates.Load)
	require.Never(t, func() bool {
		return net.updates.Load() > settled
	}, 300*time.Millisecond, 20*time.Millisecond, "should stop polling once unpaused")
}

func TestNetRecovery_IgnoresStaleArmWhenNotPaused(t *testing.T) {
	net := &fakeNetwork{pending: 5, current: 5}
	rec := newTestRecovery(net, func() bool { return false }, 10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.run(ctx)

	rec.pause() // a stale seed arming recovery while the manager is not paused
	require.Never(t, func() bool {
		return net.updates.Load() > 0 || net.resets.Load() > 0
	}, 300*time.Millisecond, 20*time.Millisecond, "a stale arm must not touch the network when not paused")
}

func TestNetRecovery_SettlesBeforeFirstAttempt(t *testing.T) {
	net := &fakeNetwork{}
	var paused atomic.Bool
	paused.Store(true)
	// A base long enough that only a wake, not the interval, can end the first wait.
	rec := newTestRecovery(net, paused.Load, time.Hour, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.run(ctx)

	rec.pause()
	paused.Store(false)
	rec.wake()
	require.Never(t, func() bool {
		return net.updates.Load() > 0
	}, 300*time.Millisecond, 20*time.Millisecond, "a pause cleared within the base interval must not re-poll")
}

func TestNetRecovery_UpdateErrorDoesNotBlockRecovery(t *testing.T) {
	net := &fakeNetwork{updateErr: errors.New("no interfaces")}
	rec := newTestRecovery(net, alwaysPaused, 10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.run(ctx)

	rec.pause()
	net.setPending(2)
	require.Eventually(t, func() bool {
		return net.resets.Load() == 1
	}, 2*time.Second, 20*time.Millisecond, "a failing update must not stop recovery detecting the refilled list")
}

func TestNetRecovery_ContextCancelStops(t *testing.T) {
	net := &fakeNetwork{}
	rec := newTestRecovery(net, alwaysPaused, 10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go rec.run(ctx)

	rec.pause()
	require.Eventually(t, func() bool {
		return net.updates.Load() >= 1
	}, 2*time.Second, 20*time.Millisecond, "should be polling before cancel")

	cancel()
	rec.stop()
	select {
	case <-rec.done:
	default:
		t.Fatal("run did not return after context cancel")
	}

	settled := stableCount(t, net.updates.Load)
	require.Never(t, func() bool {
		return net.updates.Load() > settled
	}, 300*time.Millisecond, 20*time.Millisecond, "stopped supervisor should not poll")
}
