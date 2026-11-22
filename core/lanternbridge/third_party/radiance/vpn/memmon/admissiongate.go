package memmon

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultStartRejectingPressure = 0.92
	defaultStopRejectingPressure  = 0.85
	defaultSampleCacheTTL         = 75 * time.Millisecond
	defaultMaxRejectDuration      = 10 * time.Second
	defaultBurstDialThreshold     = 32
	defaultBurstDialWindow        = 250 * time.Millisecond
)

// AdmissionConfig tunes the AdmissionGate. Zero-valued fields take defaults.
type AdmissionConfig struct {
	// StartRejectingPressure is the pressure at or above which new connections are refused.
	StartRejectingPressure float64
	// StopRejectingPressure is the pressure below which an active rejection lifts. Kept under
	// StartRejectingPressure so a recovering footprint does not re-trip immediately.
	StopRejectingPressure float64
	// SampleCacheTTL is the single-flight window for the fresh footprint read, so a
	// burst of dials costs one syscall rather than one per connection.
	SampleCacheTTL time.Duration
	// MaxRejectDuration lifts a rejection after this long even if pressure stays
	// high, so a non-connection-driven leak cannot wedge intake permanently.
	MaxRejectDuration time.Duration
	// BurstDialThreshold is the dial count within BurstDialWindow that arms a fresh read
	// regardless of level, catching a burst that climbs from below Soft within a
	// single sampler interval. Zero takes the default; a negative value disables
	// the trigger.
	BurstDialThreshold int
	// BurstDialWindow is the rolling window for the BurstDialThreshold trigger.
	BurstDialWindow time.Duration
}

func (c AdmissionConfig) applyDefaults() AdmissionConfig {
	if c.StartRejectingPressure <= 0 {
		c.StartRejectingPressure = defaultStartRejectingPressure
	}
	if c.StopRejectingPressure <= 0 {
		c.StopRejectingPressure = defaultStopRejectingPressure
	}
	if c.SampleCacheTTL <= 0 {
		c.SampleCacheTTL = defaultSampleCacheTTL
	}
	if c.MaxRejectDuration <= 0 {
		c.MaxRejectDuration = defaultMaxRejectDuration
	}
	if c.BurstDialThreshold == 0 {
		c.BurstDialThreshold = defaultBurstDialThreshold
	}
	if c.BurstDialWindow <= 0 {
		c.BurstDialWindow = defaultBurstDialWindow
	}
	return c
}

// Sampler reads one memory Sample. The monitor and the admission gate each hold
// their own Sampler and read them concurrently, so an implementation that reuses
// internal buffers (notably *Sensor) must not be shared between the two.
type Sampler interface {
	Sample(now time.Time) Sample
}

// AdmissionGate decides when to refuse new connections depending on
// memory pressure. It calls setReject when triggered, it does not itself
// reject connections. RecordDial runs on the dial path; Observe runs on the
// monitor tick. setReject must not re-enter the gate.
type AdmissionGate struct {
	cfg       AdmissionConfig
	sampler   Sampler
	setReject func(bool)

	armed atomic.Bool

	connCount atomic.Int64
	winStart  atomic.Int64 // unix nanos of the current window

	mu          sync.Mutex
	cached      Sample
	cachedAt    time.Time
	haveCached  bool
	rejecting   bool
	rejectSince time.Time
}

// NewAdmissionGate builds a gate. sampler is the dedicated footprint sampler;
// setReject toggles reject mode.
func NewAdmissionGate(cfg AdmissionConfig, sampler Sampler, setReject func(bool)) *AdmissionGate {
	return &AdmissionGate{cfg: cfg.applyDefaults(), sampler: sampler, setReject: setReject}
}

// RecordDial records one inbound connection and may latch rejection. The current
// connection always proceeds; rejection takes effect for subsequent dials at the
// routing layer.
func (g *AdmissionGate) RecordDial(now time.Time) {
	burst := g.recordNew(now)
	if !g.armed.Load() && !burst {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.rejecting {
		return
	}
	if p := g.samplePressureLocked(now); p >= g.cfg.StartRejectingPressure {
		g.rejecting = true
		g.rejectSince = now
		g.setReject(true)
		slog.Info("admission gate latched reject",
			"pressure", logRound2(p),
			"threshold", logRound2(g.cfg.StartRejectingPressure),
			"armed", g.armed.Load(),
			"burst", burst,
		)
	}
}

// Observe arms the gate and lifts an active rejection once pressure recedes below
// StopRejectingPressure or MaxRejectDuration elapses.
func (g *AdmissionGate) Observe(level PressureLevel, pressure float64, now time.Time) {
	g.armed.Store(level >= LevelSoft)

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.rejecting && (pressure < g.cfg.StopRejectingPressure || now.Sub(g.rejectSince) >= g.cfg.MaxRejectDuration) {
		g.rejecting = false
		g.setReject(false)
		reason := "recovered"
		if pressure >= g.cfg.StopRejectingPressure {
			reason = "max_duration"
		}
		slog.Info("admission gate cleared reject", "reason", reason, "pressure", logRound2(pressure))
	}
}

// recordNew counts dials in a rolling window and reports whether the burst
// threshold is met. It uses plain atomics — so the window boundary is approximate
// under concurrency, which is acceptable for a burst heuristic.
func (g *AdmissionGate) recordNew(now time.Time) bool {
	if g.cfg.BurstDialThreshold <= 0 {
		return false
	}
	nowN := now.UnixNano()
	start := g.winStart.Load()
	if start == 0 || nowN-start > int64(g.cfg.BurstDialWindow) {
		g.winStart.Store(nowN)
		g.connCount.Store(1)
		return false
	}
	return g.connCount.Add(1) >= int64(g.cfg.BurstDialThreshold)
}

// samplePressureLocked returns the current pressure from a single-flight cached
// fresh read.
func (g *AdmissionGate) samplePressureLocked(now time.Time) float64 {
	if !g.haveCached || now.Sub(g.cachedAt) >= g.cfg.SampleCacheTTL {
		g.cached = g.sampler.Sample(now)
		g.cachedAt = now
		g.haveCached = true
	}
	return g.cached.PressureRatio()
}
