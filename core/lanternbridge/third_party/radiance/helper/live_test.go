package helper

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type liveClock struct{ t time.Time }

func (c *liveClock) now() time.Time          { return c.t }
func (c *liveClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newLiveClock() *liveClock               { return &liveClock{t: time.Unix(1_800_000_000, 0)} }
func liveOf(s LiveSnapshot, id string) *LivePairing {
	for i := range s.Pairings {
		if s.Pairings[i].PairingID == id {
			return &s.Pairings[i]
		}
	}
	return nil
}

// newManualTracker is a tracker that also uses now as its wall clock and has
// no sampler goroutine, so a test's fake clock is only read from the test's
// goroutine.
func newManualTracker(now func() time.Time) *LiveTracker {
	lt := NewLiveTracker(now)
	lt.interval = 0
	lt.wall = now
	return lt
}

func (lt *LiveTracker) sampleNow() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.sampleAllLocked(lt.clockLocked())
}

// Traffic that moved minutes ago, with nobody reading the tracker since, is
// not "connected now": the sampler stamped it when it moved.
func TestLive_SampledTrafficKeepsItsTime(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	var n atomic.Uint64
	lt.Open("peer", "c1", "pA", n.Load)
	n.Add(LiveThreshold)
	clk.advance(time.Second)
	lt.sampleNow() // what the sampler goroutine does each second
	clk.advance(5 * time.Minute)
	p := liveOf(lt.Snapshot(), "pA")
	require.NotNil(t, p, "the connection is still open")
	assert.False(t, p.Connected, "the burst was five minutes ago")
}

// A pairing first evaluated long after its traffic left the window went quiet
// when it left, so its linger is long over too.
func TestLive_QuietFromWhenTrafficLeftTheWindow(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	lt.Add("pA", LiveThreshold)
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected)
	clk.advance(5 * time.Minute)
	assert.Nil(t, liveOf(lt.Snapshot(), "pA"), "no linger five minutes on")
}

// The linger starts when the expiry that took the window below the threshold
// happened, not when the last expired sample did.
func TestLive_QuietFromTheCrossingNotTheLastExpiry(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	var n atomic.Uint64
	lt.Open("peer", "c1", "pA", n.Load)
	n.Add(LiveThreshold)
	lt.sampleNow() // t=0
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected)
	clk.advance(20 * time.Second)
	n.Add(1)
	lt.Close("c1") // t=20: one more byte, then closed
	// The window fell below the threshold at t=60, so the linger ended at
	// t=75.
	clk.advance(60 * time.Second) // t=80
	assert.Nil(t, liveOf(lt.Snapshot(), "pA"), "not connected at t=80")
}

// A pairing evaluated only after its linger ended reports the linger's end
// as when it disconnected, not the evaluation.
func TestLive_DisconnectedSinceTheLingerEnded(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	start := clk.t
	lt.Open("peer", "c1", "pA", nil)
	lt.Add("pA", LiveThreshold)
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected)
	clk.advance(90 * time.Second)
	p := liveOf(lt.Snapshot(), "pA")
	require.NotNil(t, p)
	assert.False(t, p.Connected)
	assert.Equal(t, start.Add(LiveWindow+LiveLinger).UnixMilli(), p.Since)
}

// A burst sampled after the linger ended starts a new connection rather
// than extending the old one.
func TestLive_BurstAfterTheLingerReconnects(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	var n atomic.Uint64
	lt.Open("peer", "c1", "pA", n.Load)
	n.Add(LiveThreshold)
	lt.sampleNow()
	require.True(t, liveOf(lt.Snapshot(), "pA").Connected)
	// The sampler ran each second until 74s; the linger ends at 75s, and
	// the next sample, at 80s, carries a new burst.
	for range 74 {
		clk.advance(time.Second)
		lt.sampleNow()
	}
	clk.advance(6 * time.Second)
	n.Add(LiveThreshold)
	p := liveOf(lt.Snapshot(), "pA")
	assert.True(t, p.Connected)
	assert.Equal(t, clk.t.UnixMilli(), p.Since, "sampled")

	clk.advance(80 * time.Second)
	lt.Add("pA", LiveThreshold)
	p = liveOf(lt.Snapshot(), "pA")
	assert.True(t, p.Connected)
	assert.Equal(t, clk.t.UnixMilli(), p.Since, "added")
}

// Bytes read after a wall-clock sampling gap longer than the window, as
// after the device slept, may have moved before the window, so they do not
// count.
func TestLive_BytesAfterALongGapDoNotCount(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	var n atomic.Uint64
	lt.Open("peer", "c1", "pA", n.Load)
	lt.sampleNow()
	clk.advance(5 * time.Minute)
	n.Add(LiveThreshold)
	assert.False(t, liveOf(lt.Snapshot(), "pA").Connected, "after a long gap")

	clk.advance(30 * time.Second)
	n.Add(LiveThreshold)
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected, "after an ordinary gap")
}

// After a sleep the monotonic clock has moved one tick and the wall clock
// minutes: the bytes read then do not count.
func TestLive_BytesAfterASleepDoNotCount(t *testing.T) {
	mono, wall := newLiveClock(), newLiveClock()
	lt := newManualTracker(mono.now)
	lt.wall = wall.now
	var n atomic.Uint64
	lt.Open("peer", "c1", "pA", n.Load)
	lt.sampleNow()

	mono.advance(time.Second)
	wall.advance(5 * time.Minute)
	n.Add(LiveThreshold)
	assert.False(t, liveOf(lt.Snapshot(), "pA").Connected)
}

// A pairing connected just before the device slept is disconnected on waking,
// dated when its linger ended during the sleep, though the monotonic clock
// barely moved; one with no connection open is dropped.
func TestLive_SleepExpiresTheWindowAndLinger(t *testing.T) {
	for _, open := range []bool{true, false} {
		mono, wall := newLiveClock(), newLiveClock()
		lt := newManualTracker(mono.now)
		lt.wall = wall.now
		start := wall.t
		if open {
			var n atomic.Uint64
			lt.Open("peer", "c1", "pA", n.Load)
			n.Add(LiveThreshold)
			lt.sampleNow()
		} else {
			lt.Add("pA", LiveThreshold)
		}
		require.True(t, liveOf(lt.Snapshot(), "pA").Connected)

		mono.advance(time.Second)
		wall.advance(time.Hour)
		s := lt.Snapshot()
		if !open {
			assert.Nil(t, liveOf(s, "pA"), "nothing open")
			continue
		}
		p := liveOf(s, "pA")
		require.NotNil(t, p)
		assert.False(t, p.Connected)
		assert.Equal(t, start.Add(LiveWindow+LiveLinger).UnixMilli(), p.Since)
	}
}

// Samples keep the clock's monotonic reading, so a backward wall-clock step
// does not move them.
func TestLive_SamplesKeepTheMonotonicClock(t *testing.T) {
	lt := newManualTracker(time.Now)
	lt.Add("pA", 1)
	lt.mu.Lock()
	defer lt.mu.Unlock()
	require.Len(t, lt.pairings["pA"].samples, 1)
	assert.Contains(t, lt.pairings["pA"].samples[0].at.String(), "m=", "monotonic reading kept")
}

// The sampler runs by itself while a connection is open, with no Snapshot
// calls, and stops once none is.
func TestLive_SamplerRunsOnlyWhileConnectionsAreOpen(t *testing.T) {
	lt := NewLiveTracker(nil)
	lt.interval = 5 * time.Millisecond
	var n atomic.Uint64
	lt.Open("peer", "c1", "pA", n.Load)
	n.Add(100)
	require.Eventually(t, func() bool {
		lt.mu.Lock()
		defer lt.mu.Unlock()
		p := lt.pairings["pA"]
		return p != nil && len(p.samples) > 0
	}, 2*time.Second, time.Millisecond, "bytes sampled without a Snapshot")
	lt.Close("c1")
	require.Eventually(t, func() bool {
		lt.mu.Lock()
		defer lt.mu.Unlock()
		return !lt.sampling
	}, 2*time.Second, time.Millisecond, "the sampler exits with no connection open")
	lt.Open("peer", "c2", "pA", n.Load)
	lt.mu.Lock()
	assert.True(t, lt.sampling, "and restarts with the next")
	lt.mu.Unlock()
	lt.Close("c2")
}

func TestLive_BelowThresholdIsNotConnected(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	var n atomic.Uint64
	lt.Open("peer", "c1", "pA", n.Load)
	// A url-test probe's worth of bytes every few seconds stays under 32 KiB
	// in any minute.
	for range 20 {
		n.Add(1000)
		clk.advance(3 * time.Second)
		p := liveOf(lt.Snapshot(), "pA")
		require.NotNil(t, p, "an open connection is listed")
		assert.False(t, p.Connected)
	}
}

func TestLive_ThresholdWindowAndLinger(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	var n atomic.Uint64
	lt.Open("peer", "c1", "pA", n.Load)

	n.Add(LiveThreshold - 1)
	clk.advance(time.Second)
	assert.False(t, liveOf(lt.Snapshot(), "pA").Connected, "one byte short")

	n.Add(1)
	clk.advance(time.Second)
	start := clk.t
	p := liveOf(lt.Snapshot(), "pA")
	assert.True(t, p.Connected, "at the threshold")
	assert.Equal(t, start.UnixMilli(), p.Since)

	// The bytes stay in the window for 60s, so it stays connected without
	// more traffic.
	clk.advance(57 * time.Second)
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected)

	// Out of the window: quiet, but lingers. It went below the threshold at
	// T+61, when the first sample expired, so the linger ends at T+76.
	clk.advance(3 * time.Second) // T+62
	p = liveOf(lt.Snapshot(), "pA")
	assert.True(t, p.Connected, "lingers")
	assert.Equal(t, start.UnixMilli(), p.Since)
	clk.advance(LiveLinger - 2*time.Second) // T+75
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected, "still lingering")
	clk.advance(time.Second)
	p = liveOf(lt.Snapshot(), "pA")
	assert.False(t, p.Connected, "linger over")
	assert.Equal(t, clk.t.UnixMilli(), p.Since)
}

func TestLive_LingerAbsorbsAShortDip(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	lt.Add("pA", LiveThreshold)
	since := clk.t.UnixMilli()
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected)
	clk.advance(61 * time.Second)
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected, "dip below")
	clk.advance(5 * time.Second)
	lt.Add("pA", LiveThreshold)
	clk.advance(LiveLinger)
	p := liveOf(lt.Snapshot(), "pA")
	assert.True(t, p.Connected, "traffic back within the linger")
	assert.Equal(t, since, p.Since, "no flap")
}

func TestLive_MultiplePairingsAreIndependent(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	var a, b atomic.Uint64
	lt.Open("peer", "a", "pA", a.Load)
	lt.Open("unbounded", "b", "pB", b.Load)
	lt.Add("pC", 10)
	a.Add(LiveThreshold)
	b.Add(100)
	clk.advance(time.Second)
	s := lt.Snapshot()
	require.Len(t, s.Pairings, 3)
	assert.Equal(t, []string{"pA", "pB", "pC"}, []string{s.Pairings[0].PairingID, s.Pairings[1].PairingID, s.Pairings[2].PairingID})
	assert.True(t, liveOf(s, "pA").Connected)
	assert.False(t, liveOf(s, "pB").Connected)
	assert.False(t, liveOf(s, "pC").Connected)
}

func TestLive_BytesFromSeveralConnectionsAndAddSum(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	var a, b atomic.Uint64
	lt.Open("peer", "a", "pA", a.Load)
	lt.Open("peer", "b", "pA", b.Load)
	a.Add(LiveThreshold / 4)
	b.Add(LiveThreshold / 4)
	lt.Add("pA", LiveThreshold/4)
	clk.advance(time.Second)
	assert.False(t, liveOf(lt.Snapshot(), "pA").Connected)
	lt.Add("pA", LiveThreshold/4)
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected)
}

func TestLive_CloseCountsFinalBytesAndPrunes(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	var n atomic.Uint64
	lt.Open("peer", "c1", "pA", n.Load)
	n.Add(LiveThreshold)
	lt.Close("c1")
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected, "the closed connection's bytes count")
	clk.advance(LiveWindow + time.Second)
	assert.True(t, liveOf(lt.Snapshot(), "pA").Connected, "lingers")
	clk.advance(LiveLinger)
	assert.Nil(t, liveOf(lt.Snapshot(), "pA"), "a disconnected pairing with nothing open is dropped")
}

func TestLive_CloseOwnerOnlyClosesThatOwner(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	lt.Open("peer", "a", "pA", nil)
	lt.Open("unbounded", 1, "pB", nil)
	lt.CloseOwner("peer")
	s := lt.Snapshot()
	assert.Nil(t, liveOf(s, "pA"))
	assert.NotNil(t, liveOf(s, "pB"))
	lt.Close(1)
	assert.Empty(t, lt.Snapshot().Pairings)
}

func TestLive_IgnoresPoolAndReopen(t *testing.T) {
	clk := newLiveClock()
	lt := newManualTracker(clk.now)
	lt.Open("peer", "a", "", nil)
	lt.Add("", LiveThreshold)
	assert.Empty(t, lt.Snapshot().Pairings, "pool connections are not tracked")

	lt.Open("peer", "a", "pA", nil)
	lt.Open("peer", "a", "pB", nil) // same key reused: the first is closed
	s := lt.Snapshot()
	assert.Nil(t, liveOf(s, "pA"))
	assert.NotNil(t, liveOf(s, "pB"))
}

func TestLive_NilTrackerIsSafe(t *testing.T) {
	var lt *LiveTracker
	lt.Open("peer", "a", "pA", nil)
	lt.Add("pA", 1)
	lt.Close("a")
	lt.CloseOwner("peer")
	assert.Empty(t, lt.Snapshot().Pairings)
}
