package unbounded

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/broflake/clientcore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	C "github.com/getlantern/common"

	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
)

func idleWidgets(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
	return &fakeWidget{}, nil
}

// blockedLog records the reasons the manager logs.
type blockedLog struct {
	mu      sync.Mutex
	reasons []string
}

func (l *blockedLog) count(reason string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.reasons {
		if r == reason {
			n++
		}
	}
	return n
}

func (l *blockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.reasons, ",")
}

func captureBlocked(t *testing.T) *blockedLog {
	t.Helper()
	l := &blockedLog{}
	record := func(reason string) {
		l.mu.Lock()
		l.reasons = append(l.reasons, reason)
		l.mu.Unlock()
	}
	prev := blockedHook.Swap(&record)
	t.Cleanup(func() { blockedHook.Store(prev) })
	return l
}

func TestBlocked_Reasons(t *testing.T) {
	incomplete := testCfg()
	incomplete.EgressAddr = ""
	for _, tc := range []struct {
		name    string
		enabled bool
		armed   bool
		cfg     *C.UnboundedConfig
		feature bool
		want    string
	}{
		{"toggle off", false, true, testCfg(), true, BlockedDisabled},
		{"not armed", true, false, testCfg(), true, BlockedNotArmed},
		{"no config", true, true, nil, true, BlockedNoConfig},
		{"feature off", true, true, testCfg(), false, BlockedFeatureOff},
		{"config incomplete", true, true, incomplete, true, BlockedConfigIncomplete},
		{"nothing started it", true, true, testCfg(), true, BlockedNotStarted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetManager(t, idleWidgets)
			require.NoError(t, settings.Set(settings.UnboundedKey, tc.enabled))
			manager.mu.Lock()
			manager.armed = tc.armed
			manager.lastCfg = tc.cfg
			manager.lastFeatureOn = tc.feature
			manager.mu.Unlock()
			assert.Equal(t, tc.want, CurrentSnapshot().Blocked)
		})
	}
}

// A backend that never armed the widget, with sharing on and a usable config,
// reports and logs not_armed, and Apply can't start it.
func TestBlocked_NotArmedIsVisible(t *testing.T) {
	logs := captureBlocked(t)
	resetManager(t, idleWidgets)
	primeManager(t, nil)
	manager.mu.Lock()
	manager.armed = false
	manager.mu.Unlock()

	require.NoError(t, Apply())
	s := CurrentSnapshot()
	assert.False(t, s.Running)
	assert.Equal(t, BlockedNotArmed, s.Blocked)
	assert.Equal(t, 1, logs.count(BlockedNotArmed), logs.String())
}

// The reason is logged once per change, not on every evaluation.
func TestNoteBlocked_LogsOncePerChange(t *testing.T) {
	logs := captureBlocked(t)
	resetManager(t, idleWidgets)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	manager.noteBlocked()
	manager.noteBlocked()
	manager.mu.Lock()
	manager.lastCfg = testCfg()
	manager.mu.Unlock()
	manager.noteBlocked()

	assert.Equal(t, 1, logs.count(BlockedNoConfig), logs.String())
	assert.Equal(t, 1, logs.count(BlockedFeatureOff), logs.String())
}

// Once the widget runs it reports no reason, and a later block is logged
// again even if it's the reason logged before it ran.
func TestBlocked_ClearsWhileRunning(t *testing.T) {
	logs := captureBlocked(t)
	resetManager(t, idleWidgets)
	// Registered after resetManager, so it runs first: a failed assertion
	// mustn't leave resetManager waiting on a worker nothing stopped.
	t.Cleanup(manager.stop)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	manager.noteBlocked() // no_config

	applyConfig(config.Config{Features: map[string]bool{C.UNBOUNDED: true}, Unbounded: testCfg()})
	waitForRunning(t, manager, true, 2*time.Second)
	require.Eventually(t, func() bool { return CurrentSnapshot().Running }, 2*time.Second, 10*time.Millisecond)
	assert.Empty(t, CurrentSnapshot().Blocked)

	manager.stop()
	manager.mu.Lock()
	manager.lastCfg = nil
	manager.mu.Unlock()
	manager.noteBlocked()
	assert.Equal(t, 2, logs.count(BlockedNoConfig), logs.String())
}

// A cold start with no cached config says so, and a config the server turned
// the feature off in says that.
func TestBlocked_LoggedFromStartupAndConfig(t *testing.T) {
	logs := captureBlocked(t)
	resetManager(t, idleWidgets)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	manager.mu.Lock()
	manager.armed = false
	manager.mu.Unlock()

	InitSubscription(nil)
	assert.Equal(t, 1, logs.count(BlockedNoConfig), logs.String())

	applyConfig(config.Config{Features: map[string]bool{C.UNBOUNDED: false}, Unbounded: testCfg()})
	assert.Equal(t, 1, logs.count(BlockedFeatureOff), logs.String())
}

// The reason reaches IPC clients in the snapshot's JSON.
func TestSnapshot_BlockedOnTheWire(t *testing.T) {
	resetManager(t, idleWidgets)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	b, err := json.Marshal(CurrentSnapshot())
	require.NoError(t, err)
	assert.Contains(t, string(b), `"blocked":"no_config"`)
}

// A worker whose stop outlives the timeout is tearing down, not starting: it
// reports why nothing runs, and the reason is logged once it exits.
func TestBlocked_StoppingWorkerIsNotStarting(t *testing.T) {
	prevTimeout := internalStopTimeout
	internalStopTimeout = 50 * time.Millisecond
	t.Cleanup(func() { internalStopTimeout = prevTimeout })
	// Before resetManager, so the logger is restored only after its cleanup
	// has joined the worker, whose exit evaluation logs through it.
	logs := captureBlocked(t)
	block := make(chan struct{})
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		return &fakeWidget{stopBlock: block}, nil
	})
	// Both run before resetManager's wait on the worker, so a failed
	// assertion can't leave it running: release unpins the widget's Stop,
	// then stop cancels the worker.
	t.Cleanup(manager.stop)
	release := sync.OnceFunc(func() { close(block) })
	t.Cleanup(release)
	primeManager(t, nil)
	require.NoError(t, Apply())
	waitForRunning(t, manager, true, time.Second)
	require.Eventually(t, func() bool { return CurrentSnapshot().Running }, time.Second, 10*time.Millisecond)
	manager.mu.Lock()
	done := manager.done
	manager.mu.Unlock()

	require.NoError(t, settings.Set(settings.UnboundedKey, false))
	require.NoError(t, Apply()) // the stop times out on the pinned widget
	assert.Equal(t, BlockedDisabled, CurrentSnapshot().Blocked)

	release()
	// done closes after the worker's exit evaluation, so every log is in.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the worker didn't exit")
	}
	assert.Equal(t, 1, logs.count(BlockedDisabled), "logged once across the timeout and the teardown: %s", logs.String())
}

// A widget that fails to build leaves nothing running with every condition
// met. Only the worker's exit sees that, so it must log not_started.
func TestBlocked_LoggedWhenTheWidgetFailsToBuild(t *testing.T) {
	logs := captureBlocked(t)
	// The build fails only after Apply returns, so Apply's own evaluation
	// sees the widget starting and only the worker's exit can log the failure.
	fail := make(chan struct{})
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		<-fail
		return nil, errors.New("no widget")
	})
	release := sync.OnceFunc(func() { close(fail) })
	t.Cleanup(release) // before resetManager's wait on the worker
	primeManager(t, nil)
	require.NoError(t, Apply())
	assert.Zero(t, logs.count(BlockedNotStarted), "logged before the build failed: %s", logs.String())

	release()
	assert.Eventually(t, func() bool { return logs.count(BlockedNotStarted) == 1 }, time.Second, 10*time.Millisecond, logs.String())
	assert.Equal(t, BlockedNotStarted, CurrentSnapshot().Blocked)
}

// A backend closing stops and disarms the widget, which is logged even when
// the worker exits before stop has finished.
func TestBlocked_PublicStopLogsNotArmed(t *testing.T) {
	logs := captureBlocked(t)
	resetManager(t, idleWidgets)
	t.Cleanup(manager.stop)
	primeManager(t, nil)
	require.NoError(t, Apply())
	require.Eventually(t, func() bool { return CurrentSnapshot().Running }, time.Second, 10*time.Millisecond)

	require.NoError(t, Stop(context.Background()))
	assert.Equal(t, 1, logs.count(BlockedNotArmed), logs.String())
	assert.Equal(t, BlockedNotArmed, CurrentSnapshot().Blocked)
}

// With no worker to exit, only Stop itself can log that it disarmed the widget.
func TestBlocked_PublicStopWithoutWorkerLogsNotArmed(t *testing.T) {
	logs := captureBlocked(t)
	resetManager(t, idleWidgets)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	manager.noteBlocked() // no_config: armed, waiting for config

	require.NoError(t, Stop(context.Background()))
	assert.Equal(t, 1, logs.count(BlockedNotArmed), logs.String())
}

// A backend that never reaches InitSubscription never evaluates the gate
// itself; the app's snapshot polling still gets not_armed logged.
func TestBlocked_SnapshotReadLogsNotArmed(t *testing.T) {
	logs := captureBlocked(t)
	resetManager(t, idleWidgets)
	primeManager(t, nil)
	manager.mu.Lock()
	manager.armed = false
	manager.mu.Unlock()

	assert.Equal(t, BlockedNotArmed, CurrentSnapshot().Blocked)
	assert.Eventually(t, func() bool { return logs.count(BlockedNotArmed) == 1 }, time.Second, 10*time.Millisecond, logs.String())
	CurrentSnapshot()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, logs.count(BlockedNotArmed), "logged once across polls: %s", logs.String())
}

// A stalled log sink mustn't stall snapshot reads: the app polls them, and
// the backend's activity tracker reads them under its own lock.
func TestBlocked_SnapshotReadDoesNotWaitOnLogging(t *testing.T) {
	captureBlocked(t)
	resetManager(t, idleWidgets)
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	stall := make(chan struct{})
	release := sync.OnceFunc(func() { close(stall) })
	t.Cleanup(release)
	entered := make(chan struct{})
	var enter sync.Once
	stalled := func(string) {
		enter.Do(func() { close(entered) })
		<-stall
	}
	blockedHook.Store(&stalled)

	direct := make(chan struct{})
	go func() {
		defer close(direct)
		manager.noteBlocked() // holds noteMu, stuck in the log sink
	}()
	// Before resetManager restores anything: unstall it, then let it finish.
	t.Cleanup(func() {
		release()
		<-direct
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the evaluation never reached the log sink")
	}
	read := make(chan Snapshot, 1)
	go func() { read <- CurrentSnapshot() }()
	select {
	case s := <-read:
		assert.Equal(t, BlockedNoConfig, s.Blocked)
	case <-time.After(time.Second):
		t.Fatal("a snapshot read waited on a stalled log write")
	}
}

// An evaluation that chose no_config but hadn't logged it when the widget
// started must not have the last word: the start's evaluation waits for it,
// then logs that the widget runs.
func TestBlocked_StaleReasonIsNotTheLastLog(t *testing.T) {
	logs := captureBlocked(t)
	record := *blockedHook.Load()
	held := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	holding := func(reason string) {
		if reason == BlockedNoConfig {
			once.Do(func() { close(held); <-release })
		}
		record(reason)
	}
	blockedHook.Store(&holding)
	resetManager(t, idleWidgets)
	t.Cleanup(manager.stop)
	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseOnce) // before resetManager's wait, if an assertion fails
	require.NoError(t, settings.Set(settings.UnboundedKey, true))

	go manager.noteBlocked() // chooses no_config, then waits in the logger
	<-held
	// applyConfig starts the widget, then its own evaluation waits for the
	// held one, so it runs alongside.
	applied := make(chan struct{})
	go func() {
		defer close(applied)
		applyConfig(config.Config{Features: map[string]bool{C.UNBOUNDED: true}, Unbounded: testCfg()})
	}()
	require.Eventually(t, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return manager.running
	}, time.Second, 10*time.Millisecond)

	releaseOnce()
	select {
	case <-applied:
	case <-time.After(time.Second):
		t.Fatal("applyConfig didn't return")
	}
	assert.Eventually(t, func() bool {
		logs.mu.Lock()
		defer logs.mu.Unlock()
		n := len(logs.reasons)
		return n > 0 && logs.reasons[n-1] == ""
	}, time.Second, 10*time.Millisecond, logs.String())
}
