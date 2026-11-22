package memmon

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gateBase is a realistic, non-zero clock origin: the burst window uses a 0
// unix-nano sentinel for "no window yet", which time.Unix(0,0) would collide with.
var gateBase = time.Unix(1_700_000_000, 0).UTC()

type fakeSampler struct {
	mu       sync.Mutex
	pressure float64
	calls    int
}

func (f *fakeSampler) Sample(now time.Time) Sample {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return Sample{Footprint: uint64(f.pressure * float64(testCap)), Cap: testCap, Timestamp: now}
}

func (f *fakeSampler) sampleCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type rejectLog struct {
	mu     sync.Mutex
	states []bool
}

func (r *rejectLog) set(b bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, b)
}

func (r *rejectLog) snapshot() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.states...)
}

func newTestGate(cfg AdmissionConfig, pressure float64) (*AdmissionGate, *fakeSampler, *rejectLog) {
	fs := &fakeSampler{pressure: pressure}
	rl := &rejectLog{}
	return NewAdmissionGate(cfg, fs, rl.set), fs, rl
}

func TestAdmitDisarmedSkipsRead(t *testing.T) {
	g, fs, rl := newTestGate(AdmissionConfig{BurstDialThreshold: -1}, 0.99)
	for range 5 {
		g.RecordDial(gateBase)
	}
	assert.Zero(t, fs.sampleCount(), "disarmed gate never reads memory")
	assert.Empty(t, rl.snapshot(), "disarmed gate never rejects")
}

func TestAdmitArmedBelowEnterNoReject(t *testing.T) {
	g, fs, rl := newTestGate(AdmissionConfig{BurstDialThreshold: -1}, 0.80)
	g.Observe(LevelSoft, 0.80, gateBase)
	g.RecordDial(gateBase)
	assert.Positive(t, fs.sampleCount(), "armed gate reads memory")
	assert.Empty(t, rl.snapshot(), "below StartRejectingPressure does not reject")
}

func TestAdmitArmedRejectsAtEnter(t *testing.T) {
	g, _, rl := newTestGate(AdmissionConfig{BurstDialThreshold: -1}, 0.95)
	g.Observe(LevelSoft, 0.80, gateBase)
	g.RecordDial(gateBase)
	assert.Equal(t, []bool{true}, rl.snapshot(), "pressure at/above StartRejectingPressure latches reject")
}

func TestAdmitSingleFlightRead(t *testing.T) {
	g, fs, _ := newTestGate(AdmissionConfig{BurstDialThreshold: -1, SampleCacheTTL: time.Hour}, 0.80)
	g.Observe(LevelSoft, 0.80, gateBase)
	for range 10 {
		g.RecordDial(gateBase)
	}
	assert.Equal(t, 1, fs.sampleCount(), "a burst within CacheTTL coalesces onto one read")
}

func TestIntakeBurstArmsFromNormal(t *testing.T) {
	g, fs, rl := newTestGate(AdmissionConfig{BurstDialThreshold: 3, BurstDialWindow: time.Second}, 0.95)
	// No Observe: the gate is disarmed by level. The first two dials only count;
	// the third trips the burst trigger, reads fresh, and rejects.
	g.RecordDial(gateBase)
	g.RecordDial(gateBase)
	assert.Zero(t, fs.sampleCount(), "below the burst threshold does not read")
	assert.Empty(t, rl.snapshot())
	g.RecordDial(gateBase)
	assert.Equal(t, 1, fs.sampleCount(), "the burst threshold arms a fresh read")
	assert.Equal(t, []bool{true}, rl.snapshot(), "a burst from Normal can latch reject")
}

func TestExitOnRecoverWithHysteresis(t *testing.T) {
	g, _, rl := newTestGate(AdmissionConfig{BurstDialThreshold: -1}, 0.95)
	g.Observe(LevelSoft, 0.80, gateBase)
	g.RecordDial(gateBase)
	require.Equal(t, []bool{true}, rl.snapshot())

	// Between StopRejectingPressure (0.85) and StartRejectingPressure (0.92): hold, no lift.
	g.Observe(LevelSoft, 0.88, gateBase.Add(time.Second))
	assert.Equal(t, []bool{true}, rl.snapshot(), "pressure in the hysteresis band holds reject")

	// Below StopRejectingPressure: lift.
	g.Observe(LevelSoft, 0.80, gateBase.Add(2*time.Second))
	assert.Equal(t, []bool{true, false}, rl.snapshot(), "receding below StopRejectingPressure lifts reject")
}

func TestFailOpenLiftsWhilePressureHigh(t *testing.T) {
	g, _, rl := newTestGate(AdmissionConfig{BurstDialThreshold: -1, MaxRejectDuration: 10 * time.Second}, 0.97)
	g.Observe(LevelHard, 0.97, gateBase)
	g.RecordDial(gateBase)
	require.Equal(t, []bool{true}, rl.snapshot())

	// Still over StartRejectingPressure and before the hold elapses: stay rejecting.
	g.Observe(LevelHard, 0.97, gateBase.Add(5*time.Second))
	assert.Equal(t, []bool{true}, rl.snapshot(), "before MaxRejectDuration, a high footprint holds reject")

	// Hold elapsed: fail open even though pressure is still high.
	g.Observe(LevelHard, 0.97, gateBase.Add(10*time.Second))
	assert.Equal(t, []bool{true, false}, rl.snapshot(), "MaxRejectDuration fails open so a leak cannot wedge intake")
}

func TestRejectEdgeTriggered(t *testing.T) {
	g, _, rl := newTestGate(AdmissionConfig{BurstDialThreshold: -1, SampleCacheTTL: time.Hour}, 0.95)
	g.Observe(LevelSoft, 0.80, gateBase)
	for range 5 {
		g.RecordDial(gateBase)
	}
	assert.Equal(t, []bool{true}, rl.snapshot(), "reject latches once, not once per dial")

	g.Observe(LevelNormal, 0.50, gateBase.Add(time.Second)) // recover → lift once
	g.Observe(LevelNormal, 0.50, gateBase.Add(2*time.Second))
	assert.Equal(t, []bool{true, false}, rl.snapshot(), "lift latches once, not once per tick")
}

func TestConcurrentAdmitObserve(t *testing.T) {
	g, _, _ := newTestGate(AdmissionConfig{BurstDialThreshold: 4, SampleCacheTTL: 10 * time.Millisecond}, 0.95)
	g.Observe(LevelSoft, 0.80, gateBase)

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			now := gateBase.Add(time.Duration(i) * time.Millisecond)
			g.RecordDial(now)
		})
	}
	for i := range 8 {
		wg.Go(func() {
			now := gateBase.Add(time.Duration(i) * time.Millisecond)
			g.Observe(LevelSoft, 0.90, now)
		})
	}
	wg.Wait()
}
