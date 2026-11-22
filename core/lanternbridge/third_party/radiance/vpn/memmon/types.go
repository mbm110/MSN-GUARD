// Package memmon is the adaptive memory monitor for the mobile VPN daemon. It
// samples Go and process memory on a timer, derives a platform-uniform pressure
// ratio, and decides a graded reclamation level (normal/soft/hard) plus a
// preemptive crash-dump signal before the OS out-of-memory killer fires.
//
// The decision engine (DecisionEngine) is pure given its internal state and a stream of
// Samples; the run loop (Monitor) and the reaction executor are separate so each
// is unit-testable in isolation.
package memmon

import (
	"math"
	"time"
)

// PressureLevel is the graded memory-pressure level the decision core derives.
type PressureLevel int8

const (
	// LevelNormal leaves memory management to GC and the scavenger.
	LevelNormal PressureLevel = iota
	// LevelSoft closes the oldest connections first and reclaims gradually.
	LevelSoft
	// LevelHard force-closes all connections and reclaims as much as possible.
	LevelHard
)

func (l PressureLevel) String() string {
	switch l {
	case LevelNormal:
		return "normal"
	case LevelSoft:
		return "soft"
	case LevelHard:
		return "hard"
	default:
		return "unknown"
	}
}

// LimitProvider yields the live byte ceiling the governing memory metric is
// measured against. Implementations are read once per tick.
type LimitProvider interface {
	Cap() uint64
}

// FixedLimit is a fixed byte ceiling, used on Android and the dev fallback
// where no dynamic headroom API exists.
type FixedLimit uint64

// Cap returns the fixed byte ceiling.
func (s FixedLimit) Cap() uint64 { return uint64(s) }

// GoStats is the runtime/metrics-derived Go memory breakdown carried into the
// crash dump. It is sourced without runtime.ReadMemStats, which stops the world.
type GoStats struct {
	TotalSys     uint64 // /memory/classes/total:bytes
	HeapObjects  uint64 // /memory/classes/heap/objects:bytes (live)
	HeapReleased uint64 // /memory/classes/heap/released:bytes
	Stacks       uint64 // /memory/classes/heap/stacks:bytes
	Goroutines   uint64 // /sched/goroutines:goroutines
	NumGC        uint64 // /gc/cycles/total:gc-cycles
}

// Sample is one point-in-time reading. Timestamp is supplied by the run loop rather
// than read from the clock inside the Sensor or DecisionEngine, so both stay deterministic
// under test.
//
// Footprint/Cap drive the pressure ratio (PressureRatio). GoBytes and Available
// are also carried for the crash dump's non-Go breakdown: non-Go ≈ Footprint −
// GoBytes, and Available is the iOS bytes-before-jetsam headroom.
type Sample struct {
	Footprint          uint64 // iOS: phys_footprint; Android: RSS; dev fallback: GoBytes
	Cap                uint64 // iOS: footprint+available (dynamic); else FixedLimit
	GoBytes            uint64 // runtime/metrics: total mapped − heap released
	Available          uint64 // iOS: os_proc_available_memory(); 0 elsewhere
	HasNativeFootprint bool   // Footprint is an OS reading (iOS/Android), not the dev Go-heap fallback
	GoStats            GoStats
	Timestamp          time.Time
}

// PressureRatio is the platform-uniform ratio in [0,1] where 1 is at the OS kill
// cliff. The inverted iOS (headroom) and Android (footprint) signals reconcile
// because the platform difference lives in Footprint/Cap, not the formula.
func (s Sample) PressureRatio() float64 {
	if s.Cap == 0 {
		return 0
	}
	return clampUnit(float64(s.Footprint) / float64(s.Cap))
}

// LevelChange records a level transition for the crash dump's recent history.
type LevelChange struct {
	Timestamp time.Time
	From      PressureLevel
	To        PressureLevel
	Reason    string
}

// Snapshot is the pre-assembled state the crash dump needs, built from the
// core's ring with no allocation on the hot path beyond the copy. It does not
// include the open-connection count.
type Snapshot struct {
	Samples []Sample
	Levels  []LevelChange
}

// Decision is the decision core's entire output for one tick and the type at the
// seam to the executor. The core never touches connections; the executor
// consumes this and acts.
type Decision struct {
	Level               PressureLevel
	Footprint           uint64        // governing metric this tick; carried for the edge-triggered event
	PressureRatio       float64       // normalized [0,1] ratio this tick; carried for the admission gate and telemetry
	EvictOldestBatch    bool          // soft reclaim; false pauses during the post-eviction settle
	CloseAllConnections bool          // hard reclaim, edge-triggered + rate-limited
	NextInterval        time.Duration // adaptive cadence; the loop resets its timer to this
	WriteDump           bool          // OOM imminent (or breaker tripped): dump before reacting
	Snapshot            *Snapshot     // non-nil iff WriteDump
	IsPredicted         bool          // trend drove this rather than a crossed threshold
	Reason              string        // stable telemetry code for the transition or hold state
}

const (
	reasonNormal        = "normal"
	reasonSoftEnter     = "soft_enter"
	reasonSoftHold      = "soft_hold"
	reasonSoftExit      = "soft_exit"
	reasonHardEnter     = "hard_enter"
	reasonHardPredicted = "hard_predicted"
	reasonHardHold      = "hard_hold"
)

// clampUnit clamps a float to [0,1].
func clampUnit(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

// logMB and logRound2 trim values to two decimals purely for log readability;
// they must not feed any decision, only slog calls.
func logMB(b uint64) float64 { return math.Round(float64(b)/(1024*1024)*100) / 100 }

func logRound2(f float64) float64 { return math.Round(f*100) / 100 }
