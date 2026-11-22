package memmon

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// Config holds the sensing/decision tuning. Zero-valued fields take the
// defaults applied by applyDefaults.
type Config struct {
	// LimitProvider is the static byte ceiling for Android/dev (LimitProvider.Cap). On iOS
	// the Cap is dynamic and this is unused.
	LimitProvider LimitProvider
	// GoMemLimit pins the soft-enter threshold so it never maps below a footprint
	// of GOMEMLIMIT (GC acts before eviction). Leave 0 on iOS, where the dynamic
	// available-memory Cap is self-correcting and the clamp is not wanted.
	GoMemLimit uint64

	BaseInterval time.Duration

	// PredictHorizon is the lookahead window for predictive escalation.
	//
	// If the monitor estimates that the threshold will be crossed within this duration,
	// it escalates to Hard before the crossing occurs.
	//
	// A longer horizon causes earlier and more frequent predictive escalation.
	// A shorter horizon requires a steeper, more imminent rise.
	PredictHorizon time.Duration

	// SoftEnter, HardEnter, SoftExit, and HardExit are pressure thresholds in
	// [0,1]. Each level's enter and exit thresholds are separated to provide
	// hysteresis, so a footprint hovering at a boundary does not flap levels.
	SoftEnter, HardEnter, SoftExit, HardExit float64

	DwellSamples int
}

const (
	defaultSoftEnter      = 0.88
	defaultHardEnter      = 0.92
	defaultHardExit       = 0.85
	defaultSoftExit       = 0.80
	defaultBaseInterval   = 1 * time.Second
	defaultPredictHorizon = 5 * time.Second
	defaultDwellSamples   = 3
)

func (c Config) applyDefaults() Config {
	if c.SoftEnter == 0 {
		c.SoftEnter = defaultSoftEnter
	}
	if c.HardEnter == 0 {
		c.HardEnter = defaultHardEnter
	}
	if c.HardExit == 0 {
		c.HardExit = defaultHardExit
	}
	if c.SoftExit == 0 {
		c.SoftExit = defaultSoftExit
	}
	if c.BaseInterval <= 0 {
		c.BaseInterval = defaultBaseInterval
	}
	if c.PredictHorizon <= 0 {
		c.PredictHorizon = defaultPredictHorizon
	}
	if c.DwellSamples <= 0 {
		c.DwellSamples = defaultDwellSamples
	}
	return c
}

// Executor consumes each Decision and performs the reclamation. Implemented by
// the reaction side; now is passed so the executor's own rate-limiting is
// deterministic under test.
type Executor interface {
	Apply(a Decision, now time.Time)
}

// Monitor runs the single serial loop: each tick samples, decides, and applies
// inline on one goroutine. The only expensive reclaim operations are
// edge-triggered and rate-limited by the engine, so the rare inline pause during
// reclamation is acceptable and there is no separate sampler to starve.
type Monitor struct {
	engine       *DecisionEngine
	readSample   func(now time.Time) Sample
	executor     atomic.Pointer[Executor]
	baseInterval time.Duration

	lastLevel   PressureLevel
	lastTickLog time.Time
}

// normalTickLogInterval and elevatedTickLogInterval throttle the per-tick DEBUG
// log so it emits a periodic heartbeat rather than one line per tick. The
// elevated interval is shorter because an active pressure episode is worth finer
// detail, but still far coarser than the sub-second tick cadence.
const (
	normalTickLogInterval   = 10 * time.Second
	elevatedTickLogInterval = 5 * time.Second
)

// New wires a Monitor from the decision config, the per-tick Sampler, and the
// executor.
func New(cfg Config, sampler Sampler, executor Executor) *Monitor {
	engine := NewDecisionEngine(cfg)
	m := &Monitor{
		engine:       engine,
		readSample:   sampler.Sample,
		baseInterval: engine.cfg.BaseInterval,
	}
	m.SetExecutor(executor)
	return m
}

// SetExecutor sets the executor consulted on each tick. A nil executor leaves
// the monitor visibility-only (sample and log, no reclaim). Safe to call
// concurrently with the run loop.
func (m *Monitor) SetExecutor(executor Executor) {
	if executor == nil {
		// Storing &executor would wrap a nil interface in a non-nil *Executor,
		// which Step then dereferences and calls, panicking. Store a nil pointer
		// so the load-side guard skips it.
		m.executor.Store(nil)
		return
	}
	m.executor.Store(&executor)
}

// Run drives the loop until ctx is canceled. It blocks.
func (m *Monitor) Run(ctx context.Context) {
	interval := m.baseInterval
	timer := time.NewTimer(interval)
	defer timer.Stop()
	m.Step(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-timer.C:
			decision := m.Step(now)
			interval = decision.NextInterval
			if interval <= 0 {
				interval = m.baseInterval
			}
			timer.Reset(interval)
		}
	}
}

// Step runs one sample→decide→apply cycle for the tick at now and returns the
// Decision. Run calls it on the timer; tests drive it directly with a synthetic
// clock and Sampler to exercise the loop without a real timer.
func (m *Monitor) Step(now time.Time) Decision {
	sample := m.readSample(now)
	decision := m.engine.Decide(sample)
	m.logTick(now, sample, decision)
	if executor := m.executor.Load(); executor != nil {
		(*executor).Apply(decision, now)
	}
	return decision
}

func (m *Monitor) logTick(now time.Time, s Sample, d Decision) {
	if m.shouldLogTick(now, d.Level) {
		m.lastTickLog = now
		slog.Debug("memory tick",
			"footprint_mb", logMB(s.Footprint),
			"cap_mb", logMB(s.Cap),
			"pressure", logRound2(d.PressureRatio),
			"go_mb", logMB(s.GoBytes),
			"heap_mb", logMB(s.GoStats.HeapObjects),
			"goroutines", s.GoStats.Goroutines,
			"num_gc", s.GoStats.NumGC,
			"pressure_level", d.Level.String(),
			"reason", d.Reason,
			"predicted", d.IsPredicted,
			"next_interval", d.NextInterval,
		)
	}
	if d.Level != m.lastLevel {
		slog.Info("memory pressure level change",
			"from", m.lastLevel.String(),
			"to", d.Level.String(),
			"pressure", logRound2(d.PressureRatio),
			"footprint_mb", logMB(s.Footprint),
			"reason", d.Reason,
		)
		m.lastLevel = d.Level
	}
}

// shouldLogTick rate-limits per-tick DEBUG logs; transitions are logged elsewhere.
func (m *Monitor) shouldLogTick(now time.Time, level PressureLevel) bool {
	if m.lastTickLog.IsZero() {
		return true
	}
	interval := normalTickLogInterval
	if level != LevelNormal {
		interval = elevatedTickLogInterval
	}
	return now.Sub(m.lastTickLog) >= interval
}
