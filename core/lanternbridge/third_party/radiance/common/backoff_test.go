package common

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBackoffNextDelay(t *testing.T) {
	backoff := NewBackoff(time.Second, time.Minute)
	for _, expected := range []time.Duration{
		1 * time.Second,
		4 * time.Second,
		9 * time.Second,
		16 * time.Second,
		25 * time.Second,
		36 * time.Second,
		49 * time.Second,
		time.Minute,
		time.Minute,
	} {
		require.Equal(t, expected, backoff.nextDelay(0.5))
	}

	backoff.Reset()
	require.Equal(t, time.Second, backoff.nextDelay(0.5))
}

func TestBackoffNextDelayJitter(t *testing.T) {
	require.Equal(t, 800*time.Millisecond, NewBackoff(time.Second, time.Minute).nextDelay(0))
	require.Equal(t, time.Second, NewBackoff(time.Second, time.Minute).nextDelay(0.5))
	require.Equal(t, 1200*time.Millisecond, NewBackoff(time.Second, time.Minute).nextDelay(1))

	// Jitter cannot push a wait past maxWait.
	require.Equal(t, time.Minute, NewBackoff(time.Minute, time.Minute).nextDelay(1))
}

func TestBackoffDefaultBaseWait(t *testing.T) {
	require.Equal(t, defaultBaseWait, NewBackoff(0, time.Minute).nextDelay(0.5))
	require.Equal(t, defaultBaseWait, NewBackoff(-time.Second, time.Minute).nextDelay(0.5))
}

func TestBackoffWaitOnDoneContextDoesNotCountFailure(t *testing.T) {
	backoff := NewBackoff(time.Second, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	backoff.Wait(ctx)
	require.Equal(t, time.Second, backoff.nextDelay(0.5))
}

func TestBackoffWaitOnReturnsOnWake(t *testing.T) {
	// A wait long enough that only the wake channel can end it.
	backoff := NewBackoff(time.Hour, time.Hour)
	wake := make(chan struct{}, 1)
	wake <- struct{}{}

	started := time.Now()
	backoff.WaitOn(context.Background(), wake)
	require.Less(t, time.Since(started), time.Second)
}
