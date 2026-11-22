package memmon

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCap = 1_000_000

// Threshold values the pressure series in this file are calibrated against.
// Pinned explicitly so the engine-mechanics tests (hysteresis, dwell, settle,
// prediction) stay independent of the production tuning in applyDefaults.
const (
	testSoftEnter = 0.75
	testSoftExit  = 0.65
	testHardEnter = 0.92
	testHardExit  = 0.85
)

// testThresholds returns a Config carrying the classic test thresholds the
// pressure series target. Callers set PredictHorizon/GoMemLimit as needed.
func testThresholds() Config {
	return Config{
		SoftEnter: testSoftEnter,
		SoftExit:  testSoftExit,
		HardEnter: testHardEnter,
		HardExit:  testHardExit,
	}
}

func sampleAt(base time.Time, d time.Duration, pressure float64) Sample {
	return Sample{
		Footprint: uint64(pressure * testCap),
		Cap:       testCap,
		Timestamp: base.Add(d),
	}
}

// drive feeds a pressure series at fixed spacing and returns the Decision stream.
func drive(c *DecisionEngine, base time.Duration, pressures ...float64) []Decision {
	t0 := time.Unix(0, 0).UTC()
	out := make([]Decision, len(pressures))
	for i, p := range pressures {
		out[i] = c.Decide(sampleAt(t0, time.Duration(i)*base, p))
	}
	return out
}

func levelsOf(acts []Decision) []PressureLevel {
	out := make([]PressureLevel, len(acts))
	for i, a := range acts {
		out[i] = a.Level
	}
	return out
}

// noPredict disables the trend predictor so threshold/hysteresis tests are not
// preempted by early escalation.
func noPredict() Config {
	cfg := testThresholds()
	cfg.PredictHorizon = time.Nanosecond
	return cfg
}

func TestLevelProgression(t *testing.T) {
	tests := []struct {
		name         string
		cfg          Config
		spacing      time.Duration
		pressures    []float64
		wantLevels   []PressureLevel
		wantReason   string // asserted at wantReasonAt when non-empty
		wantReasonAt int
	}{
		{
			name:         "climb soft then hard",
			cfg:          noPredict(),
			spacing:      2 * time.Second,
			pressures:    []float64{0.50, 0.70, 0.76, 0.85, 0.93, 0.95},
			wantLevels:   []PressureLevel{LevelNormal, LevelNormal, LevelSoft, LevelSoft, LevelHard, LevelHard},
			wantReason:   reasonHardEnter,
			wantReasonAt: 4,
		},
		{
			// Oscillate within the hysteresis gap (above softExit 0.65, below hardEnter
			// 0.92): the level holds Soft and never thrashes.
			name:       "no thrash in hysteresis gap",
			cfg:        noPredict(),
			spacing:    2 * time.Second,
			pressures:  []float64{0.80, 0.70, 0.80, 0.70, 0.80, 0.72},
			wantLevels: []PressureLevel{LevelSoft, LevelSoft, LevelSoft, LevelSoft, LevelSoft, LevelSoft},
		},
		{
			// Two ticks below softExit are not enough (dwell=3); the third releases to Normal.
			name:       "downgrade requires dwell of 3",
			cfg:        noPredict(),
			spacing:    2 * time.Second,
			pressures:  []float64{0.80, 0.60, 0.60, 0.60},
			wantLevels: []PressureLevel{LevelSoft, LevelSoft, LevelSoft, LevelNormal},
		},
		{
			// One isolated up-tick (still below hardEnter) is below predictMinTicks, so the
			// predictor must not escalate to Hard. Predictor left enabled (default Config).
			name:       "single spike does not false-predict hard",
			cfg:        testThresholds(),
			spacing:    time.Second,
			pressures:  []float64{0.78, 0.78, 0.82, 0.78, 0.78},
			wantLevels: []PressureLevel{LevelSoft, LevelSoft, LevelSoft, LevelSoft, LevelSoft},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewDecisionEngine(tt.cfg)
			acts := drive(c, tt.spacing, tt.pressures...)
			assert.Equal(t, tt.wantLevels, levelsOf(acts), "level progression")
			if tt.wantReason != "" {
				assert.Equal(t, tt.wantReason, acts[tt.wantReasonAt].Reason, "transition reason")
			}
		})
	}
}

func TestPredictsAndDumpsOnHard(t *testing.T) {
	c := NewDecisionEngine(testThresholds()) // default 5s predict horizon
	acts := drive(c, time.Second, 0.78, 0.80, 0.85, 0.90)
	last := acts[len(acts)-1]
	require.Equal(t, LevelHard, last.Level, "sustained ramp escalates to Hard")
	assert.True(t, last.IsPredicted, "escalation was predicted")
	assert.True(t, last.WriteDump, "Hard entry dumps once")
	require.NotNil(t, last.Snapshot)
	// Pressure never reached hardEnter (0.92), so this was prediction, not threshold.
	assert.Equal(t, []LevelChange{
		{Timestamp: time.Unix(0, 0).UTC(), From: LevelNormal, To: LevelSoft, Reason: reasonSoftEnter},
		{Timestamp: time.Unix(3, 0).UTC(), From: LevelSoft, To: LevelHard, Reason: reasonHardPredicted},
	}, last.Snapshot.Levels)
}

func TestCapZeroNoOp(t *testing.T) {
	c := NewDecisionEngine(Config{})
	t0 := time.Unix(0, 0).UTC()
	for i := range 4 {
		a := c.Decide(Sample{Footprint: 9 << 20, Cap: 0, Timestamp: t0.Add(time.Duration(i) * time.Second)})
		assert.Equalf(t, LevelNormal, a.Level, "tick %d with Cap=0: inert Normal", i)
		assert.Falsef(t, a.EvictOldestBatch, "tick %d with Cap=0: no soft eviction", i)
		assert.Falsef(t, a.CloseAllConnections, "tick %d with Cap=0: no force-close", i)
	}
}

func TestGoMemLimitClamp(t *testing.T) {
	// Cap=testCap, GoMemLimit pins soft-enter to 0.90 (> base 0.75), so 0.85
	// stays Normal and only 0.92 enters Soft.
	cfg := testThresholds()
	cfg.GoMemLimit = 0.90 * testCap
	cfg.PredictHorizon = time.Nanosecond
	c := NewDecisionEngine(cfg)
	acts := drive(c, 2*time.Second, 0.85, 0.92)
	assert.Equal(t, LevelNormal, acts[0].Level, "p=0.85 stays Normal under the GOMEMLIMIT clamp")
	assert.NotEqual(t, LevelNormal, acts[1].Level, "p=0.92 enters Soft under the clamp")
}

func TestGoMemLimitClampNeverInert(t *testing.T) {
	// A cap below GOMEMLIMIT must not push soft-enter past hard-enter, which
	// would make Soft unreachable and the monitor permanently inert.
	cfg := testThresholds()
	cfg.GoMemLimit = 2 * testCap
	cfg.PredictHorizon = time.Nanosecond
	c := NewDecisionEngine(cfg)
	assert.LessOrEqual(t, c.effectiveSoftEnter(testCap), c.cfg.HardEnter, "soft-enter capped at hard-enter")
	// The monitor still reacts: a saturated footprint enters Soft then Hard.
	acts := drive(c, 2*time.Second, 0.99, 0.99)
	assert.Equal(t, LevelSoft, acts[0].Level, "saturated footprint enters Soft")
	assert.Equal(t, LevelHard, acts[1].Level, "and escalates to Hard")
}

func TestProductionDefaultsTolerateRestingFootprint(t *testing.T) {
	resting := NewDecisionEngine(Config{})
	for _, a := range drive(resting, time.Second, 0.83, 0.83, 0.83, 0.83, 0.83, 0.83) {
		assert.Equal(t, LevelNormal, a.Level, "resting footprint stays Normal under production defaults")
	}

	climbed := NewDecisionEngine(Config{})
	acts := drive(climbed, time.Second, 0.90, 0.90)
	assert.Equal(t, LevelSoft, acts[0].Level, "a footprint above SoftEnter still enters Soft")
}

func TestHardReclaimEdgeTriggered(t *testing.T) {
	c := NewDecisionEngine(noPredict())
	t0 := time.Unix(0, 0).UTC()

	c.Decide(sampleAt(t0, 0, 0.80))
	enter := c.Decide(sampleAt(t0, time.Second, 0.95))
	hold := c.Decide(sampleAt(t0, time.Second+250*time.Millisecond, 0.95))
	refire := c.Decide(sampleAt(t0, time.Second+hardCooldown, 0.96))

	assert.True(t, enter.CloseAllConnections, "force-close fires on Hard entry")
	assert.True(t, enter.WriteDump, "Hard entry dumps once")
	assert.False(t, hold.CloseAllConnections, "force-close is edge-triggered; no re-fire within cooldown")
	assert.False(t, hold.WriteDump, "the episode dumps only once")
	assert.True(t, refire.CloseAllConnections, "the cooldown permits another close-all")
	assert.False(t, refire.WriteDump, "a re-fire does not dump again in the same episode")
}

func TestSettlePausesEviction(t *testing.T) {
	c := NewDecisionEngine(noPredict())
	// Enter Soft and evict at a flat, threshold-grazing footprint. During the
	// settle window the freed memory is not yet visible, so a flat reading must
	// neither evict again nor escalate to Hard; once settle expires the same
	// reading escalates.
	acts := drive(c, time.Second, 0.93, 0.93, 0.93)
	assert.Equal(t, LevelSoft, acts[0].Level, "first crossing enters Soft")
	assert.True(t, acts[0].EvictOldestBatch, "Soft entry evicts")
	assert.Equal(t, LevelSoft, acts[1].Level, "flat footprint in settle does not escalate")
	assert.False(t, acts[1].EvictOldestBatch, "eviction paused during settle")
	assert.Equal(t, LevelHard, acts[2].Level, "after settle the threshold escalates")
}

func TestNoEvictWhileFalling(t *testing.T) {
	c := NewDecisionEngine(noPredict())
	// Climb into Soft (evicts), then a falling footprint must not evict:
	// pressure is already recovering, so further teardown is wasted.
	acts := drive(c, 2*time.Second, 0.78, 0.85, 0.70)
	require.Equal(t, LevelSoft, acts[1].Level)
	assert.True(t, acts[1].EvictOldestBatch, "a climbing footprint in Soft evicts")
	assert.Equal(t, LevelSoft, acts[2].Level, "still Soft, above softExit")
	assert.False(t, acts[2].EvictOldestBatch, "no eviction while the footprint is falling")
}

func TestAdaptiveInterval(t *testing.T) {
	c := NewDecisionEngine(noPredict())
	acts := drive(c, 2*time.Second, 0.50, 0.80, 0.95)
	assert.Equal(t, defaultBaseInterval, acts[0].NextInterval, "normal interval")
	assert.Equal(t, softInterval, acts[1].NextInterval, "soft interval")
	assert.Equal(t, hardPredictedInterval, acts[2].NextInterval, "hard interval")
}

func TestSnapshotIncludesLevelHistory(t *testing.T) {
	c := NewDecisionEngine(noPredict())
	acts := drive(c, time.Second, 0.78, 0.85, 0.97)
	last := acts[len(acts)-1]
	require.NotNil(t, last.Snapshot, "imminent hard pressure should dump")
	assert.Equal(t, []LevelChange{
		{Timestamp: time.Unix(0, 0).UTC(), From: LevelNormal, To: LevelSoft, Reason: reasonSoftEnter},
		{Timestamp: time.Unix(2, 0).UTC(), From: LevelSoft, To: LevelHard, Reason: reasonHardEnter},
	}, last.Snapshot.Levels)
}
