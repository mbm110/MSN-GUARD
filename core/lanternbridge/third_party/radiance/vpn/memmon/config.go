package memmon

import "time"

// reactionConfig holds executor-side tuning knobs used by tests and defaults.
type reactionConfig struct {
	// SoftDivisor sets the soft-eviction batch to 1/SoftDivisor of the live
	// connections on each acting tick.
	SoftDivisor int
	// SoftBatchMax is an absolute per-tick ceiling on soft evictions.
	SoftBatchMax int
	// FreeOSMinInterval is a single-flight floor between FreeOSMemory calls; it
	// backstops the decision core's own cooldown so a forced STW collection can
	// never run every tick.
	FreeOSMinInterval time.Duration
}

const (
	defaultSoftDivisor       = 4
	defaultSoftBatchMax      = 16
	defaultFreeOSMinInterval = 3 * time.Second
)

func (c reactionConfig) applyDefaults() reactionConfig {
	if c.SoftDivisor <= 0 {
		c.SoftDivisor = defaultSoftDivisor
	}
	if c.SoftBatchMax <= 0 {
		c.SoftBatchMax = defaultSoftBatchMax
	}
	if c.FreeOSMinInterval <= 0 {
		c.FreeOSMinInterval = defaultFreeOSMinInterval
	}
	return c
}
