package memmon

import "time"

// ewmaAlpha and the slope/predict tuning below are field-validation starting
// points; they are deliberately not all exposed as Config knobs.
const (
	ewmaAlpha = 0.3 // smoothing for the pressure-slope estimate

	// slopeRiseEps is the smallest slope (pressure/sec) counted as "rising".
	// Below it the signal is treated as flat — the post-eviction settling state
	// relies on this so a freed-but-not-yet-scavenged footprint reads as success.
	slopeRiseEps = 0.002

	predictMinTicks = 2 // consecutive rising ticks before prediction may fire

	ringLen = 8
)

// settleWindow and hardCooldown approximate reclaim-settle time. After an
// eviction the freed memory is not yet visible — relay buffers linger in the
// bufpool and the scavenger releases lazily — so within settleWindow the core
// pauses further eviction and suppresses flat-footprint escalation, letting the
// next reading reflect the drop. hardCooldown likewise spaces forced collections
// so they cannot stack into a death spiral.
const (
	settleWindow = 2 * time.Second
	hardCooldown = 2 * time.Second

	hardPredictedInterval = 100 * time.Millisecond
	softInterval          = 500 * time.Millisecond
)

// DecisionEngine is the pure decision half of the monitor. Decide is deterministic given
// the DecisionEngine's internal state and the Sample stream; it reads no clock and
// performs no I/O, so a test drives it with a scripted sequence.
type DecisionEngine struct {
	cfg Config

	level PressureLevel

	// slope/prediction state
	slope       float64
	prevP       float64
	prevAt      time.Time
	havePrev    bool
	risingTicks int

	// downgrade hysteresis: consecutive ticks below the exit threshold
	downDwell int

	// post-eviction settling: until this time soft eviction is paused and
	// Soft→Hard threshold escalation requires a sustained rise rather than a
	// flat-but-still-high footprint.
	settleUntil time.Time

	// edge-triggered hard reclaim: force-close fires on entry to Hard and then
	// no more often than hardCooldown.
	lastHardFire time.Time
	haveHardFire bool

	dumpedThisEpisode bool

	ring   []Sample
	levels []LevelChange
}

// NewDecisionEngine returns a DecisionEngine with cfg defaults applied.
func NewDecisionEngine(cfg Config) *DecisionEngine {
	return &DecisionEngine{
		cfg:    cfg.applyDefaults(),
		ring:   make([]Sample, 0, ringLen),
		levels: make([]LevelChange, 0, ringLen),
	}
}

// Level reports the current pressure level (for tests and observability).
func (c *DecisionEngine) Level() PressureLevel { return c.level }

// Decide consumes one Sample and returns the Decision for this tick.
func (c *DecisionEngine) Decide(s Sample) Decision {
	p := s.PressureRatio()
	c.updateSlope(p, s.Timestamp)
	c.pushRing(s)

	inSettle := s.Timestamp.Before(c.settleUntil)
	rising := c.slope > slopeRiseEps
	falling := c.slope < -slopeRiseEps

	softEnter := c.effectiveSoftEnter(s.Cap)
	predicted := c.predictsCliff(p)

	from := c.level
	next := c.nextLevel(p, softEnter, predicted, inSettle, rising)

	a := Decision{Level: next, Footprint: s.Footprint, PressureRatio: p, IsPredicted: predicted && next == LevelHard}
	switch next {
	case LevelSoft:
		// Evict only while the footprint is holding or climbing. A falling
		// footprint is already recovering, so closing more connections is wasted
		// teardown; settle likewise pauses eviction until a prior close is visible.
		if !inSettle && !falling {
			a.EvictOldestBatch = true
			c.settleUntil = s.Timestamp.Add(settleWindow)
		}
	case LevelHard:
		a.CloseAllConnections = c.hardReclaim(s.Timestamp)
		if a.CloseAllConnections {
			c.settleUntil = s.Timestamp.Add(settleWindow)
		}
	}

	a.Reason = reasonFor(from, next, a)
	if next != from {
		c.pushLevel(LevelChange{Timestamp: s.Timestamp, From: from, To: next, Reason: a.Reason})
	}
	a.WriteDump = c.shouldDump(next)
	if a.WriteDump {
		a.Snapshot = c.snapshot()
	}
	a.NextInterval = c.intervalFor(next, predicted)

	if next == LevelNormal {
		c.resetEpisode()
	}
	c.level = next
	return a
}

func (c *DecisionEngine) updateSlope(p float64, at time.Time) {
	if c.havePrev {
		if dt := at.Sub(c.prevAt).Seconds(); dt > 0 {
			inst := (p - c.prevP) / dt
			c.slope = ewmaAlpha*inst + (1-ewmaAlpha)*c.slope
		}
	}
	if c.slope > slopeRiseEps {
		c.risingTicks++
	} else {
		c.risingTicks = 0
	}
	c.prevP, c.prevAt, c.havePrev = p, at, true
}

// effectiveSoftEnter raises the soft-enter threshold so it never maps below a
// footprint of GOMEMLIMIT (GC must get its turn before we evict), capped at
// hard-enter so a cap misconfigured below GOMEMLIMIT cannot push the threshold
// past 1.0 and leave the monitor unable to ever enter Soft. Applied only when
// GoMemLimit is set: on iOS the cap is dynamic and self-correcting, so its
// Config leaves GoMemLimit at 0 to skip the clamp.
func (c *DecisionEngine) effectiveSoftEnter(cap uint64) float64 {
	se := c.cfg.SoftEnter
	if c.cfg.GoMemLimit > 0 && cap > 0 {
		if clamp := float64(c.cfg.GoMemLimit) / float64(cap); clamp > se {
			se = min(clamp, c.cfg.HardEnter)
		}
	}
	return se
}

func (c *DecisionEngine) predictsCliff(p float64) bool {
	if c.level < LevelSoft || c.risingTicks < predictMinTicks || c.slope <= slopeRiseEps {
		return false
	}
	ttl := (1 - p) / c.slope
	return ttl < c.cfg.PredictHorizon.Seconds()
}

func (c *DecisionEngine) nextLevel(p, softEnter float64, predicted, inSettle, rising bool) PressureLevel {
	switch c.level {
	case LevelNormal:
		if p >= softEnter {
			c.downDwell = 0
			return LevelSoft
		}
	case LevelSoft:
		escalate := p >= c.cfg.HardEnter || predicted
		// Flat footprint during the post-eviction settle is expected success,
		// not failure: suppress threshold escalation, require a real rise.
		if inSettle && !rising {
			escalate = false
		}
		switch {
		case escalate:
			c.downDwell = 0
			return LevelHard
		case p <= c.cfg.SoftExit:
			if c.advanceDown() {
				return LevelNormal
			}
		default:
			c.downDwell = 0
		}
	case LevelHard:
		if p <= c.cfg.HardExit {
			if c.advanceDown() {
				return LevelSoft
			}
		} else {
			c.downDwell = 0
		}
	}
	return c.level
}

func (c *DecisionEngine) advanceDown() bool {
	c.downDwell++
	if c.downDwell >= c.cfg.DwellSamples {
		c.downDwell = 0
		return true
	}
	return false
}

// hardReclaim decides whether to fire a force-close this tick. It is
// edge-triggered (on entry to Hard) and rate-limited by hardCooldown so forced
// collections cannot stack.
func (c *DecisionEngine) hardReclaim(at time.Time) bool {
	if c.level != LevelHard {
		c.lastHardFire = at
		c.haveHardFire = true
		return true
	}
	if c.haveHardFire && at.Sub(c.lastHardFire) < hardCooldown {
		return false
	}
	c.lastHardFire = at
	c.haveHardFire = true
	return true
}

// shouldDump latches one crash dump per pressure episode, taken on the first
// Hard tick; the latch resets when the level recedes to Normal.
func (c *DecisionEngine) shouldDump(next PressureLevel) bool {
	if next != LevelHard || c.dumpedThisEpisode {
		return false
	}
	c.dumpedThisEpisode = true
	return true
}

func (c *DecisionEngine) resetEpisode() {
	c.dumpedThisEpisode = false
	c.haveHardFire = false
}

func (c *DecisionEngine) intervalFor(level PressureLevel, predicted bool) time.Duration {
	switch {
	case level == LevelHard || predicted:
		return hardPredictedInterval
	case level == LevelSoft:
		return softInterval
	default:
		return c.cfg.BaseInterval
	}
}

func boundedAppend[T any](dst []T, v T, limit int) []T {
	if len(dst) == limit {
		copy(dst, dst[1:])
		dst[limit-1] = v
		return dst
	}
	return append(dst, v)
}

func (c *DecisionEngine) pushRing(s Sample) {
	c.ring = boundedAppend(c.ring, s, ringLen)
}

func (c *DecisionEngine) pushLevel(l LevelChange) {
	c.levels = boundedAppend(c.levels, l, ringLen)
}

func (c *DecisionEngine) snapshot() *Snapshot {
	samples := make([]Sample, len(c.ring))
	copy(samples, c.ring)
	levels := make([]LevelChange, len(c.levels))
	copy(levels, c.levels)
	return &Snapshot{Samples: samples, Levels: levels}
}

func reasonFor(from, to PressureLevel, a Decision) string {
	if to != from {
		switch to {
		case LevelNormal:
			return reasonSoftExit
		case LevelSoft:
			return reasonSoftEnter
		case LevelHard:
			if a.IsPredicted {
				return reasonHardPredicted
			}
			return reasonHardEnter
		}
	}
	switch to {
	case LevelSoft:
		return reasonSoftHold
	case LevelHard:
		return reasonHardHold
	default:
		return reasonNormal
	}
}
