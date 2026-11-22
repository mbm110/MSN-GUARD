package common

import (
	"context"
	"math/rand/v2"
	"time"
)

const defaultBaseWait = 10 * time.Millisecond

// Backoff implements a quadratic backoff strategy with jitter. Should not be used by multiple
// goroutines concurrently.
type Backoff struct {
	n        int // number of consecutive failures
	baseWait time.Duration
	maxWait  time.Duration
}

// NewBackoff creates a new Backoff with the given base wait time and maximum wait time.
// If baseWait is zero or negative, a default value of 10ms is used.
func NewBackoff(baseWait, maxWait time.Duration) *Backoff {
	if baseWait <= 0 {
		baseWait = defaultBaseWait
	}
	return &Backoff{
		baseWait: baseWait,
		maxWait:  maxWait,
	}
}

// Wait pauses for the next backoff interval or returns early if the context is done.
func (b *Backoff) Wait(ctx context.Context) {
	b.WaitOn(ctx, nil)
}

// WaitOn pauses for the next backoff interval, returning early if ctx is done or
// a value is received on wake. An early wake still advances the interval; an
// already-cancelled ctx does not.
func (b *Backoff) WaitOn(ctx context.Context, wake <-chan struct{}) {
	if ctx.Err() != nil {
		return
	}

	wait := b.nextDelay(rand.Float64())
	select {
	case <-ctx.Done():
	case <-wake:
	case <-time.After(wait):
	}
}

// nextDelay counts a failure and returns the interval to wait for it, jittered
// by random (expected in [0, 1]), capped at maxWait.
func (b *Backoff) nextDelay(random float64) time.Duration {
	b.n++
	wait := b.baseWait * time.Duration(b.n*b.n)
	jitter := 0.8 + 0.4*random
	return min(b.maxWait, time.Duration(float64(wait)*jitter))
}

// Reset resets the backoff counter.
func (b *Backoff) Reset() {
	b.n = 0
}
