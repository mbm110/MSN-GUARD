package unbounded

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/broflake/clientcore"
	C "github.com/getlantern/common"
	"github.com/getlantern/lantern-box/node"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rcommon "github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
)

// fakeExit records what the manager does to the exit.
type fakeExit struct {
	mu      sync.Mutex
	enabled []bool
	closed  bool
}

func (f *fakeExit) Options() *clientcore.ExitOptions { return &clientcore.ExitOptions{} }
func (f *fakeExit) SetEnabled(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = append(f.enabled, on)
}
func (f *fakeExit) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}
func (f *fakeExit) state() (last bool, closed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := len(f.enabled); n > 0 {
		last = f.enabled[n-1]
	}
	return last, f.closed
}

// exitHarness installs a fake exit and a RunExit that records each run until its context ends.
type exitHarness struct {
	exit    *fakeExit
	runs    atomic.Int32
	running atomic.Int32
	mu      sync.Mutex
	cfgs    []node.ExitConfig
	rtcExit atomic.Bool
}

func newExitHarness(t *testing.T) *exitHarness {
	t.Helper()
	h := &exitHarness{exit: &fakeExit{}}
	prevDelay := directExitOffDelay
	t.Cleanup(func() { directExitOffDelay = prevDelay })
	resetManager(t, func(_ *clientcore.BroflakeOptions, rtcOpt *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
		h.rtcExit.Store(rtcOpt.Exit != nil)
		return &fakeWidget{}, nil
	})
	newDirectExit = func(context.Context) (directExit, error) { return h.exit, nil }
	runDirectExit = func(ctx context.Context, _ directExit, cfg node.ExitConfig) error {
		h.mu.Lock()
		h.cfgs = append(h.cfgs, cfg)
		h.mu.Unlock()
		h.runs.Add(1)
		h.running.Add(1)
		defer h.running.Add(-1)
		<-ctx.Done()
		return nil
	}
	// Runs before resetManager's cleanup, which waits for the worker to exit.
	t.Cleanup(func() { manager.stop() })
	return h
}

func (h *exitHarness) lastCfg() node.ExitConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfgs[len(h.cfgs)-1]
}

func directExitConfig(on bool) config.Config {
	return config.Config{
		Unbounded: testCfg(),
		Features:  map[string]bool{C.UNBOUNDED: true, directExitFeature: on},
	}
}

func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	require.Eventually(t, cond, 2*time.Second, 5*time.Millisecond, msg)
}

func TestExitFlagTurnsOnAtOnceAndOffAfterTheDelay(t *testing.T) {
	var f exitFlag
	now := time.Now()
	assert.False(t, f.update(false, now), "an off flag has nothing to stop")
	assert.False(t, f.settle(now))
	assert.False(t, f.update(true, now))
	assert.True(t, f.settle(now))

	assert.True(t, f.update(false, now), "the first config without direct_exit starts the delay")
	assert.False(t, f.update(false, now.Add(time.Minute)), "later ones don't restart it")
	assert.True(t, f.settle(now.Add(directExitOffDelay-time.Second)), "the exit stays on through the delay")
	assert.False(t, f.settle(now.Add(directExitOffDelay)), "and stops once it passes")

	assert.False(t, f.update(true, now))
	assert.True(t, f.update(false, now))
	assert.False(t, f.update(true, now.Add(time.Minute)), "a config with the flag cancels the off")
	assert.True(t, f.settle(now.Add(2*directExitOffDelay)))
}

func TestDirectExitRunsWhileTheFlagIsOn(t *testing.T) {
	h := newExitHarness(t)
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return h.running.Load() == 1 }, "RunExit should start with the flag on")
	assert.True(t, h.rtcExit.Load(), "broflake must get the exit's options")
	last, _ := h.exit.state()
	assert.True(t, last, "the exit must be enabled")

	cfg := h.lastCfg()
	assert.Equal(t, rcommon.GetBaseURL(), cfg.APIURL)
	assert.Equal(t, settings.GetString(settings.DeviceIDKey), cfg.DeviceID)
	assert.NotNil(t, cfg.HTTPClient)
	assert.NotNil(t, cfg.Header)
	assert.NotNil(t, cfg.NewBox)
	assert.NotNil(t, cfg.ServePool)
	assert.NotNil(t, cfg.Reregister)
	assert.NotNil(t, cfg.OnHoldOff)
	assert.Equal(t, uint32(0x2024), cfg.RoutingMark)

	applyConfig(directExitConfig(false))
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(1), h.running.Load(), "a config without the flag keeps the exit through the delay")

	// config-new sends nothing more while the config stays the same, so the delay alone stops it.
	directExitOffDelay = 50 * time.Millisecond
	applyConfig(directExitConfig(true))
	applyConfig(directExitConfig(false))
	eventually(t, func() bool { return h.running.Load() == 0 }, "the delay passing stops RunExit")
	last, _ = h.exit.state()
	assert.False(t, last, "and disable the exit")
	assert.Equal(t, int32(1), h.runs.Load(), "turning the flag off must not restart the widget")
}

func TestDirectExitNeedsAnAllowedCountry(t *testing.T) {
	h := newExitHarness(t)
	SetDirectExitAllowed(func() bool { return false })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	waitForRunning(t, manager, true, 2*time.Second)
	eventually(t, h.rtcExit.Load, "the exit is offered to broflake, off")
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(0), h.runs.Load(), "no registration from a disallowed country")

	SetDirectExitAllowed(func() bool { return true })
	eventually(t, func() bool { return h.running.Load() == 1 }, "allowing the country starts RunExit")
}

func TestDirectExitNeverOnWithoutAnAllowedCheck(t *testing.T) {
	h := newExitHarness(t)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	applyConfig(directExitConfig(true))
	waitForRunning(t, manager, true, 2*time.Second)
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(0), h.runs.Load())
}

func TestDirectExitClosesWithTheWidget(t *testing.T) {
	h := newExitHarness(t)
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return h.running.Load() == 1 }, "RunExit should start")

	require.NoError(t, Stop(context.Background()))
	assert.Equal(t, int32(0), h.running.Load(), "Stop must end RunExit before it returns")
	_, closed := h.exit.state()
	assert.True(t, closed, "Stop must close the exit")
}

func TestNoDirectExitOnUnsupportedPlatforms(t *testing.T) {
	h := newExitHarness(t)
	directExitUnsupported = func() bool { return true }
	var made atomic.Bool
	newDirectExit = func(context.Context) (directExit, error) { made.Store(true); return h.exit, nil }
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	waitForRunning(t, manager, true, 2*time.Second)
	time.Sleep(20 * time.Millisecond)
	assert.False(t, made.Load())
	assert.False(t, h.rtcExit.Load())
	assert.Equal(t, int32(0), h.runs.Load())
}

func TestWidgetRunsWhenTheExitCantBeMade(t *testing.T) {
	h := newExitHarness(t)
	newDirectExit = func(context.Context) (directExit, error) { return nil, errors.New("no quic") }
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	waitForRunning(t, manager, true, 2*time.Second)
	time.Sleep(20 * time.Millisecond)
	assert.False(t, h.rtcExit.Load(), "no exit, so broflake relays as before")
	assert.Equal(t, int32(0), h.runs.Load())
}

func TestExitHoldOffOutlivesAWidgetRun(t *testing.T) {
	h := newExitHarness(t)
	until := time.Now().Add(time.Hour).Truncate(time.Second)
	runDirectExit = func(ctx context.Context, _ directExit, cfg node.ExitConfig) error {
		h.mu.Lock()
		h.cfgs = append(h.cfgs, cfg)
		h.mu.Unlock()
		h.runs.Add(1)
		cfg.OnHoldOff(until)
		<-ctx.Done()
		return nil
	}
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return h.runs.Load() == 1 }, "first run")

	manager.stop()
	manager.start()
	eventually(t, func() bool { return h.runs.Load() == 2 }, "second run")
	assert.True(t, h.lastCfg().NotBefore.Equal(until), "the next run must wait out the hold-off")
}

func TestServePoolChangeReregisters(t *testing.T) {
	h := newExitHarness(t)
	prevInterval := roomSyncInterval
	roomSyncInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		roomSyncInterval = prevInterval
		_ = settings.Set(settings.PeerServePoolKey, true)
	})
	require.NoError(t, settings.Set(settings.PeerServePoolKey, false))
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return h.running.Load() == 1 }, "RunExit should start")
	rereg := h.lastCfg().Reregister

	require.NoError(t, settings.Set(settings.PeerServePoolKey, true))
	select {
	case <-rereg:
	case <-time.After(2 * time.Second):
		t.Fatal("turning helping others on must re-register the exit")
	}
}

func TestExitHeadersAreConfigNews(t *testing.T) {
	prevUser := settings.GetInt64(settings.UserIDKey)
	t.Cleanup(func() { _ = settings.Set(settings.UserIDKey, prevUser) })
	require.NoError(t, settings.Set(settings.UserIDKey, int64(1234567890)))
	h := http.Header{}
	h.Set("X-Lantern-App", "lantern-box")
	h.Set(rcommon.DeviceIDHeader, "set-by-runexit")
	h.Set("Content-Type", "application/json")

	exitHeaders(h)

	assert.Equal(t, rcommon.Name, h.Get(rcommon.AppNameHeader), "lantern-cloud refuses lantern-box's app name in webrtc mode")
	assert.Equal(t, "1234567890", h.Get(rcommon.UserIDHeader), "the same user ID config-new gets, for the flag's stickiness")
	assert.Equal(t, rcommon.Platform, h.Get(rcommon.PlatformHeader))
	assert.Equal(t, "set-by-runexit", h.Get(rcommon.DeviceIDHeader), "RunExit's device ID stays")
	assert.Equal(t, "application/json", h.Get("Content-Type"))
}

func TestRecheckDirectExitFollowsTheAllowedCheck(t *testing.T) {
	h := newExitHarness(t)
	var allowed atomic.Bool
	allowed.Store(true)
	SetDirectExitAllowed(allowed.Load)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return h.running.Load() == 1 }, "RunExit should start from an allowed country")

	allowed.Store(false)
	RecheckDirectExit()
	assert.Equal(t, int32(0), h.running.Load(), "the re-check stops RunExit before it returns")
	last, _ := h.exit.state()
	assert.False(t, last, "and disables the exit")

	allowed.Store(true)
	RecheckDirectExit()
	eventually(t, func() bool { return h.running.Load() == 1 }, "an allowed country starts RunExit again")
	assert.Equal(t, int32(2), h.runs.Load())
}

// exitPlatform is a platform interface for the exit's boxes: enough of one for sing-box to build
// a box with auto_detect_interface on it, counting its default interface monitor's starts.
type exitPlatform struct {
	libbox.PlatformInterface
	monitorStarts atomic.Int32
}

func (*exitPlatform) LocalDNSTransport() libbox.LocalDNSTransport { return nil }
func (*exitPlatform) UseProcFS() bool                             { return false }
func (*exitPlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (*exitPlatform) UnderNetworkExtension() bool                 { return false }
func (*exitPlatform) IncludeAllNetworks() bool                    { return false }
func (*exitPlatform) RegisterMyInterface(string)                  {}
func (*exitPlatform) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	return nil, errors.New("no interfaces")
}
func (p *exitPlatform) StartDefaultInterfaceMonitor(libbox.InterfaceUpdateListener) error {
	p.monitorStarts.Add(1)
	return nil
}
func (*exitPlatform) CloseDefaultInterfaceMonitor(libbox.InterfaceUpdateListener) error { return nil }

// runContexts records the context each RunExit is handed.
func runContexts(t *testing.T) func() []context.Context {
	var mu sync.Mutex
	var ctxs []context.Context
	runDirectExit = func(ctx context.Context, _ directExit, _ node.ExitConfig) error {
		mu.Lock()
		ctxs = append(ctxs, ctx)
		mu.Unlock()
		<-ctx.Done()
		return nil
	}
	return func() []context.Context {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(ctxs)
	}
}

func TestDirectExitRunsOnThePlatformInterface(t *testing.T) {
	newExitHarness(t)
	ctxs := runContexts(t)
	platform := &exitPlatform{}
	SetPlatformInterface(platform)
	var allowed atomic.Bool
	allowed.Store(true)
	SetDirectExitAllowed(allowed.Load)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return len(ctxs()) == 1 }, "RunExit should start")
	allowed.Store(false)
	RecheckDirectExit()
	allowed.Store(true)
	RecheckDirectExit()
	eventually(t, func() bool { return len(ctxs()) == 2 }, "RunExit should start again")

	for _, ctx := range ctxs() {
		assert.Same(t, platform, ctx.Value(exitPlatformKey{}), "each run carries the platform")
		assert.Nil(t, service.FromContext[adapter.PlatformInterface](ctx), "boxes get their own wrapper, not the run's")
	}
	a, b := newExitBoxContext(ctxs()[0]), newExitBoxContext(ctxs()[0])
	wa, wb := service.FromContext[adapter.PlatformInterface](a), service.FromContext[adapter.PlatformInterface](b)
	require.NotNil(t, wa)
	require.NotNil(t, wb)
	assert.NotSame(t, wa, wb, "each exit box gets a fresh wrapper")
}

func TestDirectExitRunsWithoutAPlatformInterface(t *testing.T) {
	newExitHarness(t)
	ctxs := runContexts(t)
	SetDirectExitAllowed(func() bool { return true })
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	applyConfig(directExitConfig(true))
	eventually(t, func() bool { return len(ctxs()) == 1 }, "RunExit should start")
	ctx := ctxs()[0]
	assert.Nil(t, ctx.Value(exitPlatformKey{}))
	assert.Nil(t, service.FromContext[adapter.PlatformInterface](newExitBoxContext(ctx)), "desktop boxes keep sing-box's own monitor")
}
