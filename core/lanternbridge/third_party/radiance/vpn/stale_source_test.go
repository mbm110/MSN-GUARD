package vpn

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type staleOutcome struct {
	outcome string
	boundOK bool
}

type staleHarness struct {
	m        *staleSourceMachine
	results  []sourceStatus
	checks   []time.Duration
	calls    int
	resets   int
	restarts int
	// failRestart reports the last restart as failed.
	failRestart func(started bool)
	outcomes    []staleOutcome
	t0          time.Time
	logs        *bytes.Buffer
}

// newStaleHarness returns a machine whose checks report results in turn,
// then healthy.
func newStaleHarness(guard *staleSourceGuard, results ...sourceStatus) *staleHarness {
	h := &staleHarness{results: results, t0: time.Unix(1_000_000, 0), logs: &bytes.Buffer{}}
	iface := &control.Interface{Name: "en0", Index: 4}
	h.m = &staleSourceMachine{
		schedule:     staleSourceSchedule,
		recheckDelay: staleSourceRecheckDelay,
		defaultIface: func() *control.Interface { return iface },
		check: func(iface *control.Interface) sourceCheckResult {
			h.calls++
			status := sourceHealthy
			if len(h.results) > 0 {
				status, h.results = h.results[0], h.results[1:]
			}
			res := sourceCheckResult{status: status, iface: iface.Name, index: iface.Index, addrs: []string{".20"}, source: ".20"}
			if status == sourceStale {
				res.source, res.bound, res.boundOK = ".22", "ok", true
			}
			return res
		},
		reset:   func() { h.resets++ },
		restart: func(failed func(bool)) { h.restarts++; h.failRestart = failed },
		guard:   guard,
		record:  func(o string, b bool) { h.outcomes = append(h.outcomes, staleOutcome{o, b}) },
		logger:  slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	return h
}

// runChecks runs up to n due checks, recording when each ran.
func (h *staleHarness) runChecks(n int) {
	for range n {
		due, ok := h.m.nextDue()
		if !ok {
			return
		}
		h.checks = append(h.checks, due.Sub(h.t0))
		h.m.tick(due)
	}
}

func secs(s ...float64) []time.Duration {
	var ds []time.Duration
	for _, v := range s {
		ds = append(ds, time.Duration(v*float64(time.Second)))
	}
	return ds
}

func TestStaleSourceSchedule(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{})
	_, ok := h.m.nextDue()
	require.False(t, ok, "nothing runs before an update")
	h.m.update(h.t0, true)
	h.runChecks(100)
	assert.Equal(t, secs(2, 5, 10, 20, 40, 60), h.checks)
	_, ok = h.m.nextDue()
	assert.False(t, ok, "quiet after the schedule")
	assert.Empty(t, h.outcomes)
}

func TestStaleSourceUpdateRestartsSchedule(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{}, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(2)
	h.m.update(h.t0.Add(7*time.Second), true)
	h.runChecks(1)
	assert.Equal(t, secs(2, 5, 9), h.checks)
	assert.Zero(t, h.resets, "a new update starts the stale count over")
}

func TestStaleSourceNoDefaultInterface(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{})
	h.m.update(h.t0, false)
	_, ok := h.m.nextDue()
	assert.False(t, ok)

	h.m.update(h.t0, true)
	h.m.defaultIface = func() *control.Interface { return nil }
	h.runChecks(100)
	assert.Equal(t, secs(2), h.checks, "the schedule stops once the default interface is gone")
}

func TestStaleSourceOneStaleDoesNotRecover(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{}, sourceStale, sourceHealthy, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(100)
	assert.Zero(t, h.resets)
	assert.Zero(t, h.restarts)
	assert.Empty(t, h.outcomes)
}

func TestStaleSourceUnknownIsIgnored(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{}, sourceUnknown, sourceStale, sourceUnknown, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(4)
	assert.Equal(t, 1, h.resets, "unknown checks neither count nor break a run")
}

func TestStaleSourceResetRecovers(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{}, sourceStale, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(100)
	assert.Equal(t, 1, h.resets)
	assert.Equal(t, secs(2, 5, 8, 10, 20, 40, 60), h.checks, "a recheck 3s after the reset")
	assert.Equal(t, []staleOutcome{{staleOutcomeRecoveredByReset, true}}, h.outcomes)
	assert.Zero(t, h.restarts)
}

func TestStaleSourceEscalatesToRestart(t *testing.T) {
	guard := &staleSourceGuard{}
	h := newStaleHarness(guard, sourceStale, sourceStale, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(3)
	assert.Equal(t, 1, h.resets)
	assert.Equal(t, 1, h.restarts)
	assert.Empty(t, h.outcomes, "the outcome is the next check's")

	// The old tunnel stops checking, so it can't take the restart's outcome
	// before the restart happens.
	_, ok := h.m.nextDue()
	assert.False(t, ok)
	h.m.tick(h.t0.Add(10 * time.Second))
	assert.Equal(t, 3, h.calls)
	assert.Empty(t, h.outcomes)

	// The restarted tunnel's checker, healthy.
	next := newStaleHarness(guard)
	next.t0 = h.t0.Add(10 * time.Second)
	next.m.update(next.t0, true)
	next.runChecks(100)
	assert.Equal(t, []staleOutcome{{staleOutcomeRecoveredByRestart, true}}, next.outcomes)
}

func TestStaleSourceNotRecoveredStopsUntilUpdate(t *testing.T) {
	guard := &staleSourceGuard{}
	h := newStaleHarness(guard, sourceStale, sourceStale, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(3)
	require.Equal(t, 1, h.restarts)

	next := newStaleHarness(guard, sourceStale, sourceStale, sourceStale, sourceStale, sourceStale, sourceStale)
	next.t0 = h.t0.Add(10 * time.Second)
	next.m.update(next.t0, true)
	next.runChecks(100)
	assert.Equal(t, []staleOutcome{{staleOutcomeNotRecovered, true}}, next.outcomes)
	assert.Zero(t, next.resets, "no recovery after a failed restart")
	assert.Zero(t, next.restarts)
	assert.Equal(t, 1, bytes.Count(next.logs.Bytes(), []byte("recovery failed")), "logged once")

	// A new update starts recovering again.
	next.results = []sourceStatus{sourceStale, sourceStale}
	next.m.update(next.t0.Add(time.Minute), true)
	next.runChecks(2)
	assert.Equal(t, 1, next.resets)
}

func TestStaleSourceRestartRateLimited(t *testing.T) {
	guard := &staleSourceGuard{}
	h := newStaleHarness(guard, sourceStale, sourceStale, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(3)
	require.Equal(t, 1, h.restarts)
	// The restart's outcome lapses unseen.
	guard.takePending(h.t0.Add(time.Hour))

	later := newStaleHarness(guard, sourceStale, sourceStale, sourceStale, sourceStale)
	later.t0 = h.t0.Add(5 * time.Minute)
	later.m.update(later.t0, true)
	later.runChecks(100)
	assert.Equal(t, 1, later.resets)
	assert.Zero(t, later.restarts)
	assert.Equal(t, []staleOutcome{{staleOutcomeRestartRateLimited, true}}, later.outcomes)

	after := newStaleHarness(guard, sourceStale, sourceStale, sourceStale)
	after.t0 = h.t0.Add(11 * time.Minute)
	after.m.update(after.t0, true)
	after.runChecks(3)
	assert.Equal(t, 1, after.restarts, "allowed again after 10 minutes")
}

func TestStaleSourceNoRestartPath(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{}, sourceStale, sourceStale, sourceStale)
	h.m.restart = nil
	h.m.update(h.t0, true)
	h.runChecks(100)
	assert.Equal(t, []staleOutcome{{staleOutcomeNotRecovered, true}}, h.outcomes)
}

func TestStaleSourceHealthyEndsEpisode(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{}, sourceStale, sourceStale, sourceHealthy, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(100)
	assert.Equal(t, 1, h.resets, "the stale check after recovery starts a new count")
	assert.Equal(t, []staleOutcome{{staleOutcomeRecoveredByReset, true}}, h.outcomes)
}

func TestStaleSourceLogFields(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{}, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(1)
	line := h.logs.String()
	for _, want := range []string{"iface=en0", "iface_index=4", "addrs=.20", "source=.22", "bound=ok", "since_update_s=2", "step=none", "result=stale"} {
		assert.Contains(t, line, want)
	}
}

func TestLastOctet(t *testing.T) {
	assert.Equal(t, ".22", lastOctet(netip.MustParseAddr("192.0.2.22")))
	assert.Equal(t, "non_ipv4", lastOctet(netip.MustParseAddr("2001:db8::1")))
}

type fakeInterfaceMonitor struct {
	mu        sync.Mutex
	iface     *control.Interface
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
}

func (*fakeInterfaceMonitor) MyInterfaces() []string { return nil }

func (f *fakeInterfaceMonitor) DefaultInterface() *control.Interface {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.iface
}

func (f *fakeInterfaceMonitor) RegisterCallback(cb tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callbacks.PushBack(cb)
}

func (f *fakeInterfaceMonitor) UnregisterCallback(e *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callbacks.Remove(e)
}

func (f *fakeInterfaceMonitor) set(iface *control.Interface) {
	f.mu.Lock()
	f.iface = iface
	callbacks := f.callbacks.Array()
	f.mu.Unlock()
	for _, cb := range callbacks {
		cb(iface, 0)
	}
}

func (f *fakeInterfaceMonitor) registered() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callbacks.Len()
}

func TestStaleSourceCheckerLifecycle(t *testing.T) {
	monitor := &fakeInterfaceMonitor{}
	var checks atomic.Int32
	m := &staleSourceMachine{
		schedule:     []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 15 * time.Millisecond},
		recheckDelay: time.Millisecond,
		defaultIface: monitor.DefaultInterface,
		check: func(iface *control.Interface) sourceCheckResult {
			checks.Add(1)
			return sourceCheckResult{status: sourceHealthy}
		},
		reset:  func() {},
		guard:  &staleSourceGuard{},
		record: func(string, bool) {},
		logger: slog.New(slog.DiscardHandler),
	}
	closer, _ := startStaleSourceChecker(context.Background(), monitor, m)
	require.Equal(t, 1, monitor.registered())

	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, checks.Load(), "nothing runs without a default interface")

	monitor.set(&control.Interface{Name: "en0", Index: 4})
	require.Eventually(t, func() bool { return checks.Load() == 3 }, time.Second, time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	assert.EqualValues(t, 3, checks.Load(), "quiet after the schedule")

	monitor.set(&control.Interface{Name: "en0", Index: 4})
	require.Eventually(t, func() bool { return checks.Load() == 6 }, time.Second, time.Millisecond)

	// Close mid-schedule: it returns, unregisters, and nothing runs after.
	monitor.set(&control.Interface{Name: "en0", Index: 4})
	require.NoError(t, closer.Close())
	n := checks.Load()
	assert.Zero(t, monitor.registered())
	monitor.set(&control.Interface{Name: "en0", Index: 4})
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, n, checks.Load())
}

func TestStaleSourceCheckerStartsWithDefaultInterface(t *testing.T) {
	monitor := &fakeInterfaceMonitor{iface: &control.Interface{Name: "en0", Index: 4}}
	var checks atomic.Int32
	m := &staleSourceMachine{
		schedule:     []time.Duration{time.Millisecond},
		defaultIface: monitor.DefaultInterface,
		check: func(*control.Interface) sourceCheckResult {
			checks.Add(1)
			return sourceCheckResult{status: sourceHealthy}
		},
		guard:  &staleSourceGuard{},
		logger: slog.New(slog.DiscardHandler),
	}
	ctx, cancel := context.WithCancel(context.Background())
	closer, _ := startStaleSourceChecker(ctx, monitor, m)
	require.Eventually(t, func() bool { return checks.Load() == 1 }, time.Second, time.Millisecond)
	// Canceling the tunnel's context ends the goroutine too; Close then returns at once.
	cancel()
	require.NoError(t, closer.Close())
}

func TestStaleSourceRestartNeedsPlatform(t *testing.T) {
	c := NewVPNClient(t.TempDir(), slog.New(slog.DiscardHandler), nil)
	assert.Nil(t, c.staleSourceRestart(&tunnel{}), "the direct restart path needs the backend's BoxOptions")
	tn := c.newTunnel(BoxOptions{}, "")
	assert.Same(t, &c.staleSource, tn.staleSource)
}

func TestExternalResetRestartsStaleSourceSchedule(t *testing.T) {
	tn, router := resetTestTunnel(t)
	var kicks atomic.Int32
	tn.staleSourceUpdate = func() { kicks.Add(1) }
	client := &VPNClient{tunnel: tn}

	client.ResetNetworkForMonitor(nil)
	client.ResetNetworkForMonitor(&resetMonitor{})
	assert.Zero(t, kicks.Load(), "a stale listener starts nothing")

	client.ResetNetworkForMonitor(router.monitor)
	assert.EqualValues(t, 1, kicks.Load())
	client.ResetNetwork()
	assert.EqualValues(t, 2, kicks.Load())

	client.tunnel = nil
	client.ResetNetworkForMonitor(router.monitor)
	client.ResetNetwork()
	assert.EqualValues(t, 2, kicks.Load(), "nothing starts with no tunnel running")
}

// TestStaleSourceOwnResetKeepsSchedule runs a tunnel's real checker wiring
// with a fake check: the checker's own reset doesn't start the schedule
// over, and an external reset does.
func TestStaleSourceOwnResetKeepsSchedule(t *testing.T) {
	prevCheck, prevSchedule, prevRecheck := newSourceCheck, staleSourceSchedule, staleSourceRecheckDelay
	t.Cleanup(func() {
		newSourceCheck, staleSourceSchedule, staleSourceRecheckDelay = prevCheck, prevSchedule, prevRecheck
	})
	var checks atomic.Int32
	newSourceCheck = func(context.Context, defaultInterfaceMonitor) sourceCheckFunc {
		return func(iface *control.Interface) sourceCheckResult {
			checks.Add(1)
			return sourceCheckResult{status: sourceStale, iface: iface.Name, index: iface.Index}
		}
	}
	staleSourceSchedule = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond}
	staleSourceRecheckDelay = 5 * time.Millisecond

	tn, router := resetTestTunnel(t)
	router.monitor.iface = &control.Interface{Name: "en0", Index: 4}
	tn.ctx = context.Background()
	tn.staleSource = &staleSourceGuard{}
	closer := tn.startStaleSourceChecker()
	require.NotNil(t, closer)
	t.Cleanup(func() { _ = closer.Close() })
	client := &VPNClient{tunnel: tn}

	// Stale at 10 and 20ms resets; the recheck at 25ms finds no restart path
	// and gives up; 40 and 50ms finish the schedule.
	require.Eventually(t, func() bool { return checks.Load() == 5 }, time.Second, time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	assert.EqualValues(t, 5, checks.Load(), "the checker's own reset didn't start the schedule over")
	assert.EqualValues(t, 1, router.resets.Load())

	client.ResetNetwork()
	require.Eventually(t, func() bool { return checks.Load() == 10 }, time.Second, time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	assert.EqualValues(t, 10, checks.Load())
	assert.EqualValues(t, 3, router.resets.Load(), "the external reset, then the checker's own")
}

// TestStaleSourceRestartErrors checks which Restart errors count as a
// restart that never started.
func TestStaleSourceRestartErrors(t *testing.T) {
	run := func(c *VPNClient, tn *tunnel) bool {
		got := make(chan bool, 1)
		c.staleSourceRestart(tn)(func(started bool) { got <- started })
		select {
		case started := <-got:
			return started
		case <-time.After(3 * time.Second):
			t.Fatal("no failure reported")
			return false
		}
	}

	// No tunnel connected: Restart returns ErrTunnelNotConnected untouched.
	c := NewVPNClient(t.TempDir(), slog.New(slog.DiscardHandler), &stubPlatform{})
	assert.False(t, run(c, &tunnel{}))

	// The tunnel that asked was replaced: its restart must not take down the new one.
	p := &stubPlatform{}
	c = NewVPNClient(t.TempDir(), slog.New(slog.DiscardHandler), p)
	c.status.Store(Connected)
	c.tunnel = &tunnel{}
	assert.False(t, run(c, &tunnel{}))
	p.mu.Lock()
	assert.False(t, p.restartCalled, "the replacement wasn't restarted")
	p.mu.Unlock()

	// RestartService fails after the platform may have torn the tunnel down.
	c = NewVPNClient(t.TempDir(), slog.New(slog.DiscardHandler), &stubPlatform{restartErr: errors.New("start failed")})
	c.status.Store(Connected)
	c.tunnel = &tunnel{}
	assert.True(t, run(c, c.tunnel))
}

func TestStaleSourceFailedRestartAfterTeardownKeepsRateLimit(t *testing.T) {
	guard := &staleSourceGuard{}
	h := newStaleHarness(guard, sourceStale, sourceStale, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(3)
	require.Equal(t, 1, h.restarts)

	h.failRestart(true)
	assert.Equal(t, []staleOutcome{{staleOutcomeNotRecovered, true}}, h.outcomes)
	pending, _ := guard.takePending(h.t0.Add(9 * time.Second))
	assert.False(t, pending, "a restart that failed awaits no outcome")

	next := newStaleHarness(guard, sourceStale, sourceStale, sourceStale)
	next.t0 = h.t0.Add(time.Minute)
	next.m.update(next.t0, true)
	next.runChecks(3)
	assert.Zero(t, next.restarts)
	assert.Equal(t, []staleOutcome{{staleOutcomeRestartRateLimited, true}}, next.outcomes)
}

func TestStaleSourceFailedRestartRollsBack(t *testing.T) {
	guard := &staleSourceGuard{}
	h := newStaleHarness(guard, sourceStale, sourceStale, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(3)
	require.Equal(t, 1, h.restarts)

	// Restart returned ErrTunnelNotConnected: it never started.
	h.failRestart(false)
	assert.Equal(t, []staleOutcome{{staleOutcomeNotRecovered, true}}, h.outcomes)
	assert.Contains(t, h.logs.String(), "tunnel restart failed")
	pending, _ := guard.takePending(h.t0.Add(9 * time.Second))
	assert.False(t, pending, "a restart that failed awaits no outcome")

	// The rate limit doesn't hold for a restart that never ran.
	next := newStaleHarness(guard, sourceStale, sourceStale, sourceStale)
	next.t0 = h.t0.Add(time.Minute)
	next.m.update(next.t0, true)
	next.runChecks(3)
	assert.Equal(t, 1, next.restarts)
	assert.Empty(t, next.outcomes)

	// Reporting a failure once the outcome is taken changes nothing.
	guard.takePending(next.t0.Add(9 * time.Second))
	next.failRestart(false)
	assert.Empty(t, next.outcomes)
}

func TestStaleSourceInconclusiveAfterResetIsBounded(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{},
		sourceHealthy, sourceHealthy, sourceHealthy, sourceHealthy, sourceStale, sourceStale,
		sourceUnknown, sourceUnknown, sourceUnknown, sourceUnknown)
	h.m.update(h.t0, true)
	h.runChecks(100)
	assert.Equal(t, 1, h.resets)
	assert.Equal(t, secs(2, 5, 10, 20, 40, 60, 63, 66, 69, 72), h.checks, "3 more rechecks after the first")
	assert.Equal(t, []staleOutcome{{staleOutcomeNotRecovered, true}}, h.outcomes)
	assert.Contains(t, h.logs.String(), "checks inconclusive after network reset")
}

// TestStaleSourceRestartThroughPlatform drives a tunnel's checker to a restart
// through a platform interface that, like the extension, closes the tunnel
// and starts a new one. A restart called on the checker's goroutine would
// deadlock: closing the tunnel waits for that goroutine.
func TestStaleSourceRestartThroughPlatform(t *testing.T) {
	prevCheck, prevSchedule, prevRecheck, prevRecord := newSourceCheck, staleSourceSchedule, staleSourceRecheckDelay, staleSourceRecord
	t.Cleanup(func() {
		newSourceCheck, staleSourceSchedule, staleSourceRecheckDelay, staleSourceRecord = prevCheck, prevSchedule, prevRecheck, prevRecord
	})
	// The old tunnel's default interface is stale, the new one's healthy.
	newSourceCheck = func(context.Context, defaultInterfaceMonitor) sourceCheckFunc {
		return func(iface *control.Interface) sourceCheckResult {
			if iface.Index == 4 {
				return sourceCheckResult{status: sourceStale, iface: iface.Name, index: iface.Index}
			}
			return sourceCheckResult{status: sourceHealthy, iface: iface.Name, index: iface.Index}
		}
	}
	staleSourceSchedule = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond}
	staleSourceRecheckDelay = 5 * time.Millisecond
	var (
		mu       sync.Mutex
		outcomes []staleOutcome
	)
	staleSourceRecord = func(o string, b bool) {
		mu.Lock()
		outcomes = append(outcomes, staleOutcome{o, b})
		mu.Unlock()
	}

	p := &stubPlatform{}
	c := NewVPNClient(t.TempDir(), slog.New(slog.DiscardHandler), p)
	startTunnel := func(index int) *tunnel {
		tn, router := resetTestTunnel(t)
		router.monitor.iface = &control.Interface{Name: "en0", Index: index}
		tn.ctx, tn.cancel = context.WithCancel(context.Background())
		tn.staleSource = &c.staleSource
		tn.restartForStaleSource = c.staleSourceRestart(tn)
		tn.closeTimeout = 5 * time.Second
		if closer := tn.startStaleSourceChecker(); closer != nil {
			tn.closers = append(tn.closers, closer)
		}
		return tn
	}
	restarted := make(chan error, 1)
	p.restartFn = func() error {
		err := c.Disconnect()
		if err == nil {
			c.mu.Lock()
			c.setTunnelLocked(startTunnel(5))
			c.setStatus(Connected, nil)
			c.mu.Unlock()
		}
		restarted <- err
		return err
	}
	c.mu.Lock()
	c.setTunnelLocked(startTunnel(4))
	c.status.Store(Connected)
	c.mu.Unlock()

	select {
	case err := <-restarted:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("the restart didn't complete")
	}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(outcomes) > 0
	}, time.Second, time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	assert.Equal(t, []staleOutcome{{staleOutcomeRecoveredByRestart, false}}, outcomes, "only the new tunnel records")
	mu.Unlock()
	require.NoError(t, c.Disconnect())
}

// escalated returns a harness on guard whose machine has asked for a restart.
func escalated(t *testing.T, guard *staleSourceGuard) *staleHarness {
	h := newStaleHarness(guard, sourceStale, sourceStale, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(3)
	require.Equal(t, 1, h.restarts)
	return h
}

func TestStaleSourceUpdateAfterRestartIgnored(t *testing.T) {
	guard := &staleSourceGuard{}
	h := escalated(t, guard)

	// An interface update or an external reset before the restart happens.
	h.results = []sourceStatus{sourceHealthy}
	h.m.update(h.t0.Add(9*time.Second), true)
	_, ok := h.m.nextDue()
	assert.False(t, ok, "the machine that asked for a restart stays stopped")
	h.m.tick(h.t0.Add(11 * time.Second))
	assert.Equal(t, 3, h.calls)
	assert.Empty(t, h.outcomes)
	pending, _ := guard.awaiting(h.t0.Add(11 * time.Second))
	assert.True(t, pending, "the outcome is left to the restarted tunnel")

	// So a restart that then never starts still gives back the rate limit.
	h.failRestart(false)
	assert.Equal(t, []staleOutcome{{staleOutcomeNotRecovered, true}}, h.outcomes)
	next := escalated(t, guard)
	assert.Empty(t, next.outcomes)
}

func TestStaleSourcePendingRestartInconclusive(t *testing.T) {
	guard := &staleSourceGuard{}
	h := escalated(t, guard)

	next := newStaleHarness(guard, sourceUnknown, sourceUnknown, sourceUnknown, sourceUnknown, sourceUnknown, sourceUnknown)
	next.t0 = h.t0.Add(10 * time.Second)
	next.m.update(next.t0, true)
	next.runChecks(100)
	assert.Equal(t, []staleOutcome{{staleOutcomeNotRecovered, true}}, next.outcomes, "bounded, and recorded once")
	assert.Contains(t, next.logs.String(), "checks inconclusive after tunnel restart")
	pending, _ := guard.awaiting(next.t0.Add(time.Minute))
	assert.False(t, pending)
}

func TestStaleSourcePendingRestartScheduleEnds(t *testing.T) {
	guard := &staleSourceGuard{}
	h := escalated(t, guard)

	next := newStaleHarness(guard, sourceUnknown, sourceUnknown)
	next.m.schedule = secs(2, 5)
	next.t0 = h.t0.Add(10 * time.Second)
	next.m.update(next.t0, true)
	next.runChecks(100)
	assert.Equal(t, []staleOutcome{{staleOutcomeNotRecovered, true}}, next.outcomes)
	assert.Contains(t, next.logs.String(), "no conclusive check after tunnel restart")
}

func TestStaleSourcePendingRestartWindowRunsOut(t *testing.T) {
	guard := &staleSourceGuard{}
	h := escalated(t, guard)

	next := newStaleHarness(guard)
	next.t0 = h.t0.Add(3 * time.Minute)
	next.m.update(next.t0, true)
	next.runChecks(100)
	assert.Equal(t, []staleOutcome{{staleOutcomeNotRecovered, true}}, next.outcomes, "not recovered_by_restart")
	assert.Contains(t, next.logs.String(), "restart outcome window ran out")
}

// An update or reset that arrives while a check runs supersedes its result:
// a stale result from before an external reset doesn't escalate.
func TestStaleSourceCheckOvertakenBySignal(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{}, sourceStale, sourceStale, sourceStale, sourceStale, sourceStale)
	check := h.m.check
	var signalDuring int
	h.m.check = func(iface *control.Interface) sourceCheckResult {
		if h.calls+1 == signalDuring {
			h.m.generation.Add(1)
		}
		return check(iface)
	}
	h.m.update(h.t0, true)
	h.runChecks(2)
	require.Equal(t, 1, h.resets)

	// The recheck after the reset is stale, but a reset signal arrives during it.
	signalDuring = 3
	h.runChecks(1)
	assert.Equal(t, 3, h.calls)
	assert.Zero(t, h.restarts, "the overtaken result doesn't escalate")
	assert.Empty(t, h.outcomes)

	// The signal's update starts the episode over: two more stale checks
	// reset again, rather than the next one restarting.
	h.m.update(h.t0.Add(9*time.Second), true)
	h.runChecks(2)
	assert.Equal(t, 2, h.resets)
	assert.Zero(t, h.restarts)
}

// A signal queued before a due tick, its generation already bumped, holds
// the tick off: the goroutine's select can pick the timer first.
func TestStaleSourceTickWaitsForQueuedSignal(t *testing.T) {
	h := newStaleHarness(&staleSourceGuard{}, sourceStale, sourceStale, sourceStale, sourceStale)
	h.m.update(h.t0, true)
	h.runChecks(2)
	require.Equal(t, 1, h.resets)

	h.m.generation.Add(1)
	due, ok := h.m.nextDue()
	require.True(t, ok)
	h.m.tick(due)
	assert.Equal(t, 2, h.calls, "no check while a signal waits")
	assert.Zero(t, h.restarts)
	assert.Empty(t, h.outcomes)

	// Once the update is applied, checks run again from a fresh episode.
	h.m.update(due, true)
	h.runChecks(1)
	assert.Equal(t, 3, h.calls)
	assert.Zero(t, h.restarts)
}
