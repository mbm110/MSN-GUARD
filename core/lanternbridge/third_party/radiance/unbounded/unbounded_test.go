package unbounded

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/broflake/clientcore"
	C "github.com/getlantern/common"
	"github.com/getlantern/lantern-box/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/internal/testutil"
)

// TestMain initializes the settings package once for the whole test
// binary. settings.InitSettings is itself a sync.Once-guarded
// installer (it persists the path to k.filePath), so calling it per
// t.TempDir() leaves the settings layer pointing at a directory the
// testing infra has already cleaned up by the time the second test
// runs — every subsequent settings.Set then fails with ENOENT.
//
// os.Exit bypasses deferred calls, so the tmp-dir cleanup is done
// explicitly: capture m.Run's exit code, RemoveAll, then exit with
// that code. A naked defer + os.Exit would silently leak a directory
// per test invocation.
//
// The widget's HTTP clients dial through the fixed bypass proxy port, so
// the package holds testutil.LockBypassPort while its tests run: another
// package's fake proxy on that port would otherwise take their requests.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "radiance-unbounded-settings-*")
	if err != nil {
		panic(err)
	}
	if err := settings.InitSettings(dir); err != nil {
		os.RemoveAll(dir)
		panic(err)
	}
	unlock := testutil.LockBypassPort()
	code := m.Run()
	unlock()
	os.RemoveAll(dir)
	os.Exit(code)
}

// fakeWidget is a stand-in for the live broflake UI. stopBlock, if
// non-nil, lets a test pin Stop() until the test releases it — used
// to drive the "stop must wait for the worker" assertions.
type fakeWidget struct {
	stopCalled atomic.Int32
	stopBlock  chan struct{}
}

func (w *fakeWidget) Stop() {
	w.stopCalled.Add(1)
	if w.stopBlock != nil {
		<-w.stopBlock
	}
}

// resetManager swaps the package-level manager + widget factory and
// resets the UnboundedKey setting. Cleanup restores everything so
// tests don't bleed into each other.
func resetManager(t *testing.T, build func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error)) {
	t.Helper()
	require.NoError(t, settings.Set(settings.UnboundedKey, false))

	prevManager := manager
	prevNewExit, prevRunExit, prevUnsupported := newDirectExit, runDirectExit, directExitUnsupported
	newDirectExit = func(context.Context) (directExit, error) { return &fakeExit{}, nil }
	runDirectExit = func(ctx context.Context, _ directExit, _ node.ExitConfig) error {
		<-ctx.Done()
		return nil
	}
	directExitUnsupported = func() bool { return false }
	prevWidget := newWidget
	prevInit := initOnce
	// armed: true so direct manager.start calls in tests don't bail on
	// the disarmed gate. Tests that exercise Stop's disarm behavior
	// (TestStopDisarmsManager) flip it explicitly.
	manager = &unboundedManager{armed: true}
	newWidget = build
	initOnce = sync.Once{}
	t.Cleanup(func() {
		// Wait for any still-live worker on the test's manager to
		// exit before swapping the package-level newWidget back.
		// Without this, the worker's read of newWidget (when the
		// fake created it) races with the cleanup's write at test
		// teardown — the race detector flags it even though the
		// worker has already finished its call. Tests that leave a
		// pinned worker (e.g. TestStopCtx_TimesOut) must release
		// it before returning so this wait completes.
		manager.mu.Lock()
		done := manager.done
		manager.mu.Unlock()
		if done != nil {
			<-done
		}
		// A snapshot read leaves a gate evaluation running in the background;
		// let it finish, or it logs into the next test's capture.
		require.Eventually(t, func() bool { return !manager.noteQueued.Load() },
			5*time.Second, time.Millisecond, "a background gate evaluation didn't finish")
		manager = prevManager
		newWidget = prevWidget
		newDirectExit, runDirectExit, directExitUnsupported = prevNewExit, prevRunExit, prevUnsupported
		initOnce = prevInit
		_ = settings.Set(settings.UnboundedKey, false)
	})
}

// waitForRunning polls m.cancel under m.mu until it matches expected,
// primeManager seeds the predicate fields so a direct manager.start()
// in a test will satisfy the shouldStart() check inside the lock: the
// UnboundedKey setting goes true, manager.lastFeatureOn = true, and
// manager.lastCfg = the supplied cfg (or testCfg if nil). Tests that
// exercise the start path directly call this once after resetManager.
//
// The default test cfg populates all four required URL fields so
// cfgUsable passes — a zero-value UnboundedConfig would fail the
// "all fields supplied" gate and start() would bail.
func primeManager(t *testing.T, cfg *C.UnboundedConfig) {
	t.Helper()
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	if cfg == nil {
		cfg = testCfg()
	}
	manager.mu.Lock()
	manager.lastFeatureOn = true
	manager.lastCfg = cfg
	manager.mu.Unlock()
}

// testCfg returns a UnboundedConfig that passes cfgUsable. Use this
// instead of a bare `&C.UnboundedConfig{}` literal in tests; the
// zero-value literal would now fail the runnable predicate.
func testCfg() *C.UnboundedConfig {
	return &C.UnboundedConfig{
		DiscoverySrv:      "https://discovery.test.example",
		DiscoveryEndpoint: "/v1/disco",
		EgressAddr:        "https://egress.test.example",
		EgressEndpoint:    "/v1/egress",
	}
}

// or the deadline expires. The start goroutine sets m.cancel under
// m.mu before kicking off the worker, so this is a sufficient signal
// that a transition has been requested — note that for "true" the
// worker's newWidget call may still be pending.
func waitForRunning(t *testing.T, m *unboundedManager, expected bool, dur time.Duration) {
	t.Helper()
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		running := m.cancel != nil
		m.mu.Unlock()
		if running == expected {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waitForRunning: timed out waiting for running=%v", expected)
}

// waitForCount polls an int32 atomic until it equals want, or the
// deadline expires. Used in place of a flat-sleep when waiting for
// the start goroutine to call newWidget.
func waitForCount(t *testing.T, v *atomic.Int32, want int32, dur time.Duration) {
	t.Helper()
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		if v.Load() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waitForCount: timed out waiting for count=%d, got %d", want, v.Load())
}

func TestShouldStart(t *testing.T) {
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		return &fakeWidget{}, nil
	})

	tests := []struct {
		name    string
		toggle  bool
		feature bool
		cfg     *C.UnboundedConfig
		want    bool
	}{
		{"all off", false, false, nil, false},
		{"toggle only", true, false, nil, false},
		{"feature+cfg, no toggle", false, true, testCfg(), false},
		{"toggle+feature, no cfg", true, true, nil, false},
		{"toggle+cfg, no feature", true, false, testCfg(), false},
		{"all three", true, true, testCfg(), true},
		// Partial cfg (missing required URLs) treated as not-yet-ready
		// — broflake's client defaults would otherwise route real
		// traffic through upstream-maintainer infra, bypassing the
		// server's per-environment endpoint selection.
		{"partial cfg, no egress", true, true,
			&C.UnboundedConfig{
				DiscoverySrv:      "https://d.example",
				DiscoveryEndpoint: "/v1/disco",
			}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, settings.Set(settings.UnboundedKey, tc.toggle))
			manager.mu.Lock()
			manager.lastFeatureOn = tc.feature
			manager.lastCfg = tc.cfg
			got := manager.shouldStart()
			manager.mu.Unlock()
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestApply_DisabledIsNoop: Apply() returns immediately when the
// local toggle is off, regardless of cached server state.
func TestApply_DisabledIsNoop(t *testing.T) {
	starts := atomic.Int32{}
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		starts.Add(1)
		return &fakeWidget{}, nil
	})

	manager.mu.Lock()
	manager.lastFeatureOn = true
	manager.lastCfg = testCfg()
	manager.mu.Unlock()
	require.NoError(t, Apply())

	// Allow any spurious goroutine a beat to land.
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(0), starts.Load(), "Apply() must not start widget when toggle is off")
}

// TestApply_StartsWhenAllConditionsHold: with toggle on + cached
// feature flag + cached config, Apply() spins up exactly one widget.
func TestApply_StartsWhenAllConditionsHold(t *testing.T) {
	fw := &fakeWidget{}
	starts := atomic.Int32{}
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		starts.Add(1)
		return fw, nil
	})

	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	manager.mu.Lock()
	manager.lastFeatureOn = true
	manager.lastCfg = testCfg()
	manager.mu.Unlock()
	require.NoError(t, Apply())

	waitForRunning(t, manager, true, 1*time.Second)
	waitForCount(t, &starts, 1, 1*time.Second)

	// Double-Apply should not start a second widget.
	require.NoError(t, Apply())
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(1), starts.Load())

	// Tear down.
	require.NoError(t, settings.Set(settings.UnboundedKey, false))
	require.NoError(t, Apply())
	waitForRunning(t, manager, false, 1*time.Second)
	assert.Equal(t, int32(1), fw.stopCalled.Load())
}

// TestStop_WaitsForWorker: stop() blocks until the worker's ui.Stop
// returns. Pin ui.Stop with stopBlock and observe stop()'s wait.
func TestStop_WaitsForWorker(t *testing.T) {
	block := make(chan struct{})
	fw := &fakeWidget{stopBlock: block}
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		return fw, nil
	})

	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	manager.mu.Lock()
	manager.lastFeatureOn = true
	manager.lastCfg = testCfg()
	manager.mu.Unlock()
	require.NoError(t, Apply())
	waitForRunning(t, manager, true, 1*time.Second)

	stopReturned := make(chan struct{})
	go func() {
		manager.stop()
		close(stopReturned)
	}()
	select {
	case <-stopReturned:
		t.Fatal("stop() returned before fake widget's Stop unblocked")
	case <-time.After(100 * time.Millisecond):
	}
	close(block)
	select {
	case <-stopReturned:
	case <-time.After(1 * time.Second):
		t.Fatal("stop() did not return after fake widget's Stop unblocked")
	}
	assert.Equal(t, int32(1), fw.stopCalled.Load())
}

// TestStartDuringStop_NoOverlap pins the transitionMu invariant: at
// any instant, at most one broflake widget is between newWidget and
// Stop's return. If stop() merely signalled cancel and returned
// (without holding transitionMu through the wait on done), a
// concurrent start() could observe m.cancel == nil and bring up a
// second widget while the first is still inside ui.Stop. The test
// exercises the manager directly (skipping Apply's predicate check)
// because the property being verified is local to start/stop
// serialization — two widgets alive simultaneously means
// transitionMu failed to serialize.
func TestStartDuringStop_NoOverlap(t *testing.T) {
	var (
		liveCount atomic.Int32
		maxLive   atomic.Int32
		stopGate  = make(chan struct{})
	)
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		v := liveCount.Add(1)
		if v > maxLive.Load() {
			maxLive.Store(v)
		}
		return &countingWidget{onStop: func() {
			<-stopGate
			liveCount.Add(-1)
		}}, nil
	})

	// Prime predicate so direct manager.start calls satisfy
	// shouldStart() inside the lock, then start the first widget.
	primeManager(t, nil)
	manager.start()
	waitForCount(t, &liveCount, 1, 1*time.Second)

	// Kick off a stop — it'll block on stopGate inside the fake's
	// onStop until we release it.
	stopDone := make(chan struct{})
	go func() {
		manager.stop()
		close(stopDone)
	}()

	// Once the stop is in flight (worker has received cancel and
	// entered onStop), launch a concurrent start. transitionMu must
	// hold this until the prior stop returns.
	time.Sleep(50 * time.Millisecond)
	startDone := make(chan struct{})
	go func() {
		manager.start()
		close(startDone)
	}()

	// Neither should have completed yet.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-stopDone:
		t.Fatal("stop returned before stopGate released")
	case <-startDone:
		t.Fatal("start returned before prior stop completed")
	default:
	}

	// Release the first widget's Stop. stop() returns, transitionMu
	// frees, start() acquires it and creates widget #2.
	close(stopGate)
	select {
	case <-stopDone:
	case <-time.After(1 * time.Second):
		t.Fatal("stop did not return after gate release")
	}
	select {
	case <-startDone:
	case <-time.After(1 * time.Second):
		t.Fatal("start did not return after stop completed")
	}

	// Widget #2 should now be live.
	waitForCount(t, &liveCount, 1, 1*time.Second)
	require.Equal(t, int32(1), maxLive.Load(), "two widgets ran concurrently — transitionMu failed")

	// Cleanup: tear down widget #2. stopGate is already closed, so
	// the worker's Stop returns immediately.
	manager.stop()
	waitForCount(t, &liveCount, 0, 1*time.Second)
}

// TestInitSubscription_SeedsCachedConfig: passing a non-nil initial
// config to InitSubscription kicks off the same applyConfig path
// the live event subscriber takes. With all three conditions met,
// the widget should auto-start without a fresh NewConfigEvent.
func TestInitSubscription_SeedsCachedConfig(t *testing.T) {
	starts := atomic.Int32{}
	fw := &fakeWidget{}
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		starts.Add(1)
		return fw, nil
	})

	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	cfg := &config.Config{
		Features:  map[string]bool{C.UNBOUNDED: true},
		Unbounded: testCfg(),
	}
	InitSubscription(cfg)

	waitForRunning(t, manager, true, 1*time.Second)
	waitForCount(t, &starts, 1, 1*time.Second)

	// Cleanup.
	require.NoError(t, settings.Set(settings.UnboundedKey, false))
	require.NoError(t, Apply())
	waitForRunning(t, manager, false, 1*time.Second)
}

// TestInitSubscription_FutureEventStillFires: even with a nil
// initial, the subscription still reacts to a subsequent
// NewConfigEvent — confirms the seed didn't replace the live path.
func TestInitSubscription_FutureEventStillFires(t *testing.T) {
	starts := atomic.Int32{}
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		starts.Add(1)
		return &fakeWidget{}, nil
	})

	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	InitSubscription(nil)
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(0), starts.Load(), "should not start with no cached config")

	// Fire a NewConfigEvent with all three conditions satisfied.
	cfg := config.Config{
		Features:  map[string]bool{C.UNBOUNDED: true},
		Unbounded: testCfg(),
	}
	events.Emit(config.NewConfigEvent{New: &cfg})
	waitForRunning(t, manager, true, 1*time.Second)
	waitForCount(t, &starts, 1, 1*time.Second)

	// Cleanup.
	require.NoError(t, settings.Set(settings.UnboundedKey, false))
	require.NoError(t, Apply())
	waitForRunning(t, manager, false, 1*time.Second)
}

// TestApplyConfig_RestartsOnParamChange: broflake consumes its
// options once in clientcore.NewBroflake. A server-side config
// change while the widget is alive must therefore tear down the
// current worker and bring up a new one — otherwise the running
// proxy stays on stale discovery/egress endpoints. applyConfig
// compares the new cfg against runningCfg (the snapshot the worker
// was started with) and triggers stop+start when they differ,
// provided the three-condition predicate still holds.
func TestApplyConfig_RestartsOnParamChange(t *testing.T) {
	starts := atomic.Int32{}
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		starts.Add(1)
		return &fakeWidget{}, nil
	})

	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	cfgA := testCfg()
	cfgB := testCfg()
	cfgB.DiscoverySrv = "https://b.example/"

	// First config — bring up widget #1.
	applyConfig(config.Config{
		Features:  map[string]bool{C.UNBOUNDED: true},
		Unbounded: cfgA,
	})
	waitForRunning(t, manager, true, 1*time.Second)
	waitForCount(t, &starts, 1, 1*time.Second)

	// Same config — no restart.
	applyConfig(config.Config{
		Features:  map[string]bool{C.UNBOUNDED: true},
		Unbounded: testCfg(), // value-equal to cfgA
	})
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), starts.Load(), "identical config must not restart")

	// Changed config — restart with new params.
	applyConfig(config.Config{
		Features:  map[string]bool{C.UNBOUNDED: true},
		Unbounded: cfgB,
	})
	waitForCount(t, &starts, 2, 2*time.Second)

	// Cleanup.
	require.NoError(t, settings.Set(settings.UnboundedKey, false))
	require.NoError(t, Apply())
	waitForRunning(t, manager, false, 1*time.Second)
}

// TestStopDisarmsManager verifies the public-Stop shutdown
// contract: after Stop returns, NO subsequent start path may revive
// the widget — not Apply, not applyConfig from a late config event,
// not manager.start directly. The armed gate enforces this;
// transitionMu alone is not enough because it just serializes
// transitions, it doesn't decide whether a queued one should still
// proceed after a shutdown. Without this gate, a config event
// firing during Stop's wait-for-worker window would block at
// transitionMu and then start a fresh widget the moment Stop's
// caller returned from LocalBackend.Close, silently keeping
// broflake alive past the documented shutdown contract.
func TestStopDisarmsManager(t *testing.T) {
	starts := atomic.Int32{}
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		starts.Add(1)
		return &fakeWidget{}, nil
	})

	// Bring up a widget so Stop has something to tear down.
	primeManager(t, nil)
	manager.start()
	waitForCount(t, &starts, 1, 1*time.Second)

	require.NoError(t, Stop(context.Background()))
	manager.mu.Lock()
	armed := manager.armed
	manager.mu.Unlock()
	require.False(t, armed, "Stop must disarm the manager")

	// All three start paths must be no-ops now. Predicate is still
	// satisfied (toggle, feature, cfg) — only armed gates the start.
	primeManager(t, nil)

	require.NoError(t, Apply())
	applyConfig(config.Config{
		Features:  map[string]bool{C.UNBOUNDED: true},
		Unbounded: testCfg(),
	})
	manager.start()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), starts.Load(), "no start path may revive the widget post-Stop")

	// A fresh InitSubscription re-arms — Start-after-Close path.
	initOnce = sync.Once{} // simulate re-arm path; InitSubscription's once guards re-subscription
	InitSubscription(&config.Config{
		Features:  map[string]bool{C.UNBOUNDED: true},
		Unbounded: testCfg(),
	})
	waitForCount(t, &starts, 2, 1*time.Second)

	// Cleanup.
	require.NoError(t, Stop(context.Background()))
}

// TestStartAfterStopWaiting_NoRevival: pin Stop in its <-done wait
// (worker can't exit because its Stop is blocked), then race a
// config-event-driven start against the disarm. Confirms that even a
// start queued at transitionMu while Stop is waiting bails out after
// transitionMu releases — the armed re-check inside start catches it.
func TestStartAfterStopWaiting_NoRevival(t *testing.T) {
	block := make(chan struct{})
	starts := atomic.Int32{}
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		starts.Add(1)
		return &fakeWidget{stopBlock: block}, nil
	})

	primeManager(t, nil)
	manager.start()
	waitForCount(t, &starts, 1, 1*time.Second)

	// Stop in a goroutine — it'll set armed=false, signal cancel,
	// then block on <-done waiting for the worker, which is in turn
	// pinned by stopBlock.
	stopDone := make(chan struct{})
	go func() {
		_ = Stop(context.Background())
		close(stopDone)
	}()

	// Give Stop a beat to acquire transitionMu and disarm.
	time.Sleep(50 * time.Millisecond)
	manager.mu.Lock()
	armed := manager.armed
	manager.mu.Unlock()
	require.False(t, armed, "Stop must disarm before waiting on done")

	// Now race a start. It blocks at transitionMu until Stop returns.
	startDone := make(chan struct{})
	go func() {
		manager.start()
		close(startDone)
	}()
	time.Sleep(20 * time.Millisecond)
	select {
	case <-startDone:
		t.Fatal("start completed before Stop unblocked")
	default:
	}

	// Release the worker so Stop returns.
	close(block)
	select {
	case <-stopDone:
	case <-time.After(1 * time.Second):
		t.Fatal("Stop did not return after worker released")
	}
	select {
	case <-startDone:
	case <-time.After(1 * time.Second):
		t.Fatal("start did not return after Stop returned")
	}

	// Critically: starts must still be 1 — the queued start saw
	// armed=false and bailed.
	assert.Equal(t, int32(1), starts.Load(), "start queued during Stop must not revive the widget")
}

// TestStopCtx_TimesOut: Stop(ctx) returns ctx.Err() when the worker
// is still mid-shutdown past the deadline. The worker is left to
// exit on its own schedule afterwards.
func TestStopCtx_TimesOut(t *testing.T) {
	block := make(chan struct{})
	fw := &fakeWidget{stopBlock: block}
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		return fw, nil
	})

	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	manager.mu.Lock()
	manager.lastFeatureOn = true
	manager.lastCfg = testCfg()
	manager.mu.Unlock()
	require.NoError(t, Apply())
	waitForRunning(t, manager, true, 1*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := Stop(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	// Release the worker so the test exits cleanly.
	close(block)
}

// TestConnectionEventBridge pins the observable API this package
// adds: broflake's OnConnectionChangeFunc callback must translate
// (state, workerIdx, addr) into a ConnectionEvent with the matching
// State, the consumer Source, and a freshly-stamped Timestamp.
// broflake hands the callback a nil addr on close, so the close's
// Source is backfilled from the addr its accept carried (see
// connSources) — otherwise downstream consumers (the Flutter globe +
// helped counter) couldn't match the close to its accept. Capture the
// callback that start installs on bfOpt via a fake newWidget, invoke
// accept-then-close on one slot, then assert the events arriving via
// events.Subscribe.
func TestConnectionEventBridge(t *testing.T) {
	var captured atomic.Pointer[clientcore.ConnectionChangeFunc]
	resetManager(t, func(bfOpt *clientcore.BroflakeOptions, _ *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
		cb := bfOpt.OnConnectionChangeFunc
		captured.Store(&cb)
		return &fakeWidget{}, nil
	})

	primeManager(t, nil)
	manager.start()
	// Worker may still be inside the goroutine setup when start
	// returns; wait until newWidget has been called and the callback
	// captured.
	deadline := time.Now().Add(1 * time.Second)
	for captured.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.NotNil(t, captured.Load(), "newWidget was never invoked")
	cb := *captured.Load()
	require.NotNil(t, cb, "OnConnectionChangeFunc must be installed on bfOpt")

	// Buffered so the subscription's delivery goroutine can deposit
	// without blocking before the test reads.
	ch := make(chan ConnectionEvent, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events.SubscribeContext(ctx, func(evt ConnectionEvent) { ch <- evt })

	before := time.Now().UnixMilli()
	cb(1, 7, net.ParseIP("198.51.100.42"))
	cb(-1, 7, nil)
	after := time.Now().UnixMilli()

	// events.Emit dispatches each subscriber on a per-callback
	// goroutine, so the two events can arrive in either order.
	// Assert set-membership keyed by State (unique in this test)
	// rather than positional equality.
	byState := make(map[int]ConnectionEvent, 2)
	for i := 0; i < 2; i++ {
		select {
		case evt := <-ch:
			byState[evt.State] = evt
		case <-time.After(1 * time.Second):
			t.Fatalf("timed out waiting for ConnectionEvent #%d", i+1)
		}
	}

	require.Contains(t, byState, 1, "expected an accept event (State=+1)")
	require.Contains(t, byState, -1, "expected a close event (State=-1)")
	assert.Equal(t, "198.51.100.42", byState[1].Source, "accept Source")
	assert.Equal(t, "198.51.100.42", byState[-1].Source,
		"close Source is backfilled from the accept (broflake delivers a nil addr on close)")
	for state, evt := range byState {
		assert.GreaterOrEqual(t, evt.Timestamp, before, "State=%d Timestamp not before emit", state)
		assert.LessOrEqual(t, evt.Timestamp, after, "State=%d Timestamp not after emit", state)
	}

	// Cleanup.
	require.NoError(t, Stop(context.Background()))
}

// TestInternalStop_TimesOut: internal stop (called by Apply and
// applyConfig) must not block forever when ui.Stop hangs. If it
// did, toggling Unbounded off via PatchSettings or a disabling
// config event would block the caller indefinitely while holding
// transitionMu. Pin ui.Stop with stopBlock past a short
// internalStopTimeout and confirm Apply returns within a sane
// budget.
func TestInternalStop_TimesOut(t *testing.T) {
	prevTimeout := internalStopTimeout
	internalStopTimeout = 50 * time.Millisecond
	t.Cleanup(func() { internalStopTimeout = prevTimeout })

	block := make(chan struct{})
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		return &fakeWidget{stopBlock: block}, nil
	})

	primeManager(t, nil)
	require.NoError(t, Apply())
	waitForRunning(t, manager, true, 1*time.Second)

	// Flip toggle off so Apply's !Enabled branch calls manager.stop.
	// With the worker pinned by stopBlock, internal stop must time
	// out rather than hang. Apply itself returns nil — the timeout
	// is logged but not propagated.
	require.NoError(t, settings.Set(settings.UnboundedKey, false))
	applyReturned := make(chan struct{})
	go func() {
		_ = Apply()
		close(applyReturned)
	}()
	select {
	case <-applyReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Apply blocked past timeout — internal stop is not context-bounded")
	}

	// Release the worker so the test's cleanup wait completes.
	close(block)
}

func TestDonorSTUNConfiguration(t *testing.T) {
	for _, servers := range [][]string{nil, {}, {" ", ""}, {"stun:192.0.2.1:3478", "stun:192.0.2.2:3478"}} {
		t.Run(fmt.Sprint(servers), func(t *testing.T) {
			received := make(chan []string, 1)
			resetManager(t, func(_ *clientcore.BroflakeOptions, rtc *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
				batch, err := rtc.STUNBatch(100)
				received <- batch
				return &fakeWidget{}, err
			})
			defer manager.stop()
			cfg := testCfg()
			cfg.STUNServers = servers
			primeManager(t, cfg)
			manager.start()
			select {
			case batch := <-received:
				require.ElementsMatch(t, C.NormalizeDonorSTUNServers(servers), batch)
				require.NotEmpty(t, batch)
			case <-time.After(time.Second):
				t.Fatal("donor startup blocked")
			}
		})
	}
}

func TestDonorSTUNBatchIsolation(t *testing.T) {
	pool := []string{" stun:192.0.2.1:3478 ", "stun:192.0.2.1:3478", "stun:192.0.2.2:3478"}
	sample := donorSTUNBatch(pool)
	pool[0] = "changed"
	batch, err := sample(100)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"stun:192.0.2.1:3478", "stun:192.0.2.2:3478"}, batch)
	batch[0] = "changed"
	next, err := sample(100)
	require.NoError(t, err)
	require.NotContains(t, next, "changed")
	empty, err := sample(0)
	require.NoError(t, err)
	require.Empty(t, empty)
	one, err := sample(1)
	require.NoError(t, err)
	require.Len(t, one, 1)
}

func TestApplyConfigRestartsOnSTUNChange(t *testing.T) {
	received := make(chan []string, 3)
	resetManager(t, func(_ *clientcore.BroflakeOptions, rtc *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
		batch, err := rtc.STUNBatch(100)
		received <- batch
		return &fakeWidget{}, err
	})
	defer manager.stop()
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	cfg := testCfg()
	cfg.STUNServers = []string{"stun:192.0.2.1:3478"}
	applyConfig(config.Config{Features: map[string]bool{C.UNBOUNDED: true}, Unbounded: cfg})
	select {
	case batch := <-received:
		require.Equal(t, cfg.STUNServers, batch)
	case <-time.After(time.Second):
		t.Fatal("first donor did not start")
	}
	cfg.STUNServers[0] = "stun:192.0.2.2:3478"
	applyConfig(config.Config{Features: map[string]bool{C.UNBOUNDED: true}, Unbounded: cfg})
	select {
	case batch := <-received:
		require.Equal(t, cfg.STUNServers, batch)
	case <-time.After(time.Second):
		t.Fatal("STUN change did not restart donor")
	}
}

func TestApplyConfigDoesNotRestartOnSTUNReorder(t *testing.T) {
	starts := atomic.Int32{}
	resetManager(t, func(_ *clientcore.BroflakeOptions, _ *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
		starts.Add(1)
		return &fakeWidget{}, nil
	})
	defer manager.stop()
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	cfg := testCfg()
	cfg.STUNServers = []string{"stun:192.0.2.1:3478", "stun:192.0.2.2:3478"}
	applyConfig(config.Config{Features: map[string]bool{C.UNBOUNDED: true}, Unbounded: cfg})
	waitForCount(t, &starts, 1, time.Second)
	manager.mu.Lock()
	originalDone := manager.done
	manager.mu.Unlock()
	cfg.STUNServers = []string{"stun:192.0.2.2:3478", " stun:192.0.2.1:3478 ", "stun:192.0.2.2:3478"}
	applyConfig(config.Config{Features: map[string]bool{C.UNBOUNDED: true}, Unbounded: cfg})
	manager.mu.Lock()
	currentDone := manager.done
	manager.mu.Unlock()
	require.Equal(t, originalDone, currentDone)
	require.Equal(t, int32(1), starts.Load())
}

func TestDonorTuningConfiguration(t *testing.T) {
	received := make(chan clientcore.WebRTCOptions, 1)
	resetManager(t, func(_ *clientcore.BroflakeOptions, rtc *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
		received <- *rtc
		return &fakeWidget{}, nil
	})
	defer manager.stop()
	cfg := testCfg()
	cfg.Tuning = map[string]string{
		"ice_max_binding_requests": "40",
		"nat_fail_timeout_ms":      "8000",
		"from_a_newer_server":      "1",
	}
	primeManager(t, cfg)
	manager.start()
	select {
	case rtc := <-received:
		require.Equal(t, clientcore.WebRTCTuning{ICEMaxBindingRequests: 40}, rtc.Tuning)
		require.Equal(t, 8*time.Second, rtc.NATFailTimeout)
	case <-time.After(time.Second):
		t.Fatal("donor startup blocked")
	}
	require.Equal(t, "8000", cfg.Tuning["nat_fail_timeout_ms"], "the config's own map must not be modified")
}

func TestWidgetTuningNATFailTimeout(t *testing.T) {
	tests := []struct {
		raw     string
		want    time.Duration
		ignored bool
	}{
		{raw: "1000", want: time.Second},
		{raw: "15000", want: 15 * time.Second},
		{raw: "30000", want: 30 * time.Second},
		{raw: "999", ignored: true},
		{raw: "30001", ignored: true},
		{raw: "-5000", ignored: true},
		{raw: "8s", ignored: true},
		{raw: "99999999999999", ignored: true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			natFail, _, ignored := widgetTuning(map[string]string{natFailTimeoutKey: tt.raw})
			require.Equal(t, tt.want, natFail)
			if tt.ignored {
				require.Equal(t, []string{fmt.Sprintf("%s=%q", natFailTimeoutKey, tt.raw)}, ignored)
			} else {
				require.Empty(t, ignored)
			}
		})
	}
	natFail, _, ignored := widgetTuning(nil)
	require.Zero(t, natFail)
	require.Empty(t, ignored)
}

func TestWidgetVolunteerSocket(t *testing.T) {
	tests := []struct {
		opts    map[string]string
		want    bool
		ignored bool
	}{
		{opts: nil},
		{opts: map[string]string{volunteerSocketKey: "true"}, want: true},
		{opts: map[string]string{volunteerSocketKey: "1"}, want: true},
		{opts: map[string]string{volunteerSocketKey: "false"}},
		{opts: map[string]string{volunteerSocketKey: "yes"}, ignored: true},
	}
	for _, tt := range tests {
		on, ignored := widgetVolunteerSocket(tt.opts)
		require.Equal(t, tt.want, on, tt.opts)
		require.Equal(t, tt.ignored, len(ignored) > 0, tt.opts)
	}
	// It isn't WebRTC tuning, so widgetTuning neither reads nor reports it.
	_, _, ignored := widgetTuning(map[string]string{volunteerSocketKey: "true"})
	require.Empty(t, ignored)
}

func TestApplyConfigRestartsOnTuningChange(t *testing.T) {
	received := make(chan clientcore.WebRTCTuning, 3)
	resetManager(t, func(_ *clientcore.BroflakeOptions, rtc *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
		received <- rtc.Tuning
		return &fakeWidget{}, nil
	})
	defer manager.stop()
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	cfg := testCfg()
	cfg.Tuning = map[string]string{"ice_max_binding_requests": "40"}
	applyConfig(config.Config{Features: map[string]bool{C.UNBOUNDED: true}, Unbounded: cfg})
	select {
	case tuning := <-received:
		require.Equal(t, uint16(40), tuning.ICEMaxBindingRequests)
	case <-time.After(time.Second):
		t.Fatal("first donor did not start")
	}
	// Mutating the map in place must still restart: applyConfig keeps its own copy.
	cfg.Tuning["ice_max_binding_requests"] = "60"
	applyConfig(config.Config{Features: map[string]bool{C.UNBOUNDED: true}, Unbounded: cfg})
	select {
	case tuning := <-received:
		require.Equal(t, uint16(60), tuning.ICEMaxBindingRequests)
	case <-time.After(time.Second):
		t.Fatal("tuning change did not restart donor")
	}
}

func TestRunHookFollowsTheWorker(t *testing.T) {
	var (
		mu    sync.Mutex
		heard []bool
	)
	hook := func(running bool) {
		mu.Lock()
		defer mu.Unlock()
		heard = append(heard, running)
	}
	heardSoFar := func() []bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(heard)
	}

	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		return &fakeWidget{}, nil
	})
	SetRunHook(hook)
	primeManager(t, nil)
	manager.start()
	waitForRunning(t, manager, true, time.Second)
	manager.start()
	manager.stop()
	waitForRunning(t, manager, false, time.Second)
	manager.stop()
	assert.Equal(t, []bool{true, false}, heardSoFar())

	// A widget that fails to build stops the hook too.
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		return nil, errors.New("no widget")
	})
	SetRunHook(hook)
	primeManager(t, nil)
	mu.Lock()
	heard = nil
	mu.Unlock()
	manager.start()
	require.Eventually(t, func() bool { return len(heardSoFar()) == 2 }, time.Second, 5*time.Millisecond)
	assert.Equal(t, []bool{true, false}, heardSoFar())
}

// Both of the widget's HTTP clients, for freddie and for the egress, go around
// the tunnel. Signaling that resolved through the system resolver couldn't
// reach freddie while the VPN was on, so a volunteer took no new consumers.
func TestWidgetDialsAroundTheTunnel(t *testing.T) {
	type clients struct{ signaling, egress *http.Client }
	received := make(chan clients, 1)
	resetManager(t, func(_ *clientcore.BroflakeOptions, rtc *clientcore.WebRTCOptions, eg *clientcore.EgressOptions) (widget, error) {
		received <- clients{rtc.HTTPClient, eg.HTTPClient}
		return &fakeWidget{}, nil
	})
	defer manager.stop()
	primeManager(t, testCfg())
	manager.start()
	select {
	case c := <-received:
		require.Same(t, bypassHTTPClient, c.egress)
		require.NotNil(t, c.signaling)
		require.Same(t, bypassHTTPClient.Transport, c.signaling.Transport)
		require.NotNil(t, c.signaling.CheckRedirect, "signaling still refuses cross-origin redirects")
	case <-time.After(time.Second):
		t.Fatal("donor startup blocked")
	}
}

func TestBypassHTTPClientDialsWithItsDialer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	// The name doesn't resolve, so only a dial through the client's dialer,
	// which sends every connection to the test server, reaches it.
	var dialer net.Dialer
	client := newBypassHTTPClient(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, srv.Listener.Addr().String())
	})
	require.Zero(t, client.Timeout, "websocket.Dial bounds the dial with its own context")
	resp, err := client.Get("http://egress.invalid/ws")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusTeapot, resp.StatusCode)
}
