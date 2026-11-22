package memmon

import "time"

// Sensor reads the native and Go memory signals each tick and assembles a
// Sample. It holds reusable buffers so a tick allocates nothing.
type Sensor struct {
	goMemSampler  *goSampler
	limitProvider LimitProvider
}

// NewSensor returns a Sensor whose static Cap (Android / dev fallback) comes
// from limitProvider. On iOS the Cap is dynamic (footprint+available) and
// limitProvider is unused.
func NewSensor(limitProvider LimitProvider) *Sensor {
	return &Sensor{goMemSampler: newGoSampler(), limitProvider: limitProvider}
}

// Sample reads memory using a caller-provided timestamp so all values collected
// in the same tick share the same time source.
func (s *Sensor) Sample(now time.Time) Sample {
	footprint, available, availableSupported := readNative()
	goBytes, goStats := s.goMemSampler.read()

	var capacity uint64
	hasNativeFootprint := true
	switch {
	case availableSupported: // iOS: dynamic effective kill ceiling
		capacity = footprint + available
	case footprint != 0: // Android: native footprint vs static budget
		capacity = s.staticCap()
	default: // dev/desktop fallback: steer on goBytes
		footprint = goBytes
		capacity = s.staticCap()
		hasNativeFootprint = false
	}
	return Sample{
		Footprint:          footprint,
		Cap:                capacity,
		GoBytes:            goBytes,
		Available:          available,
		GoStats:            goStats,
		Timestamp:          now,
		HasNativeFootprint: hasNativeFootprint,
	}
}

func (s *Sensor) staticCap() uint64 {
	if s.limitProvider == nil {
		return 0
	}
	return s.limitProvider.Cap()
}
