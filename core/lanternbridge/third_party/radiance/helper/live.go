package helper

import (
	"sort"
	"sync"
	"time"
)

// Defaults for LiveTracker. A pairing is connected when it moved at least
// LiveThreshold bytes in the last LiveWindow. The threshold is far above what
// a url-test probe or an idle WebRTC slot moves in a minute, so neither shows
// a friend as connected. A connected pairing stays so until it has been below
// the threshold for LiveLinger, so traffic hovering at the threshold does not
// flap.
const (
	LiveThreshold = 32 << 10
	LiveWindow    = 60 * time.Second
	LiveLinger    = 15 * time.Second
	// LiveSampleInterval is how often open connections' byte totals are
	// read while any is open, so traffic is stamped with when it moved
	// rather than when someone next asked.
	LiveSampleInterval = time.Second
)

// DefaultLive is the process's LiveTracker.
var DefaultLive = NewLiveTracker(nil)

// LivePairing is one pairing's live state on the volunteer.
type LivePairing struct {
	PairingID string `json:"pairing_id"`
	// Connected says the friend is relaying real traffic through this device
	// now.
	Connected bool `json:"connected"`
	// Since is when Connected last changed, or when the pairing was first
	// seen if it never has, in Unix milliseconds.
	Since int64 `json:"since"`
}

// LiveSnapshot is the live state of every pairing with an open connection,
// recent traffic, or a connected state. A pairing missing from it is not
// connected.
type LiveSnapshot struct {
	Pairings []LivePairing `json:"pairings"`
}

// LiveTracker works out, per helper pairing, whether the friend is connected
// to this volunteer right now. It is in memory only: pairing IDs and their
// timeline are never written to disk, logged, or sent anywhere but the local
// app.
type LiveTracker struct {
	mu  sync.Mutex
	now func() time.Time
	// wall reads the wall clock, which unlike now's monotonic reading keeps
	// running while the device sleeps.
	wall func() time.Time
	// slept totals the wall clock's forward jumps past now, as while the
	// device slept or after a forward wall-clock step.
	slept     time.Duration
	lastNow   time.Time
	lastWall  time.Time
	threshold uint64
	window    time.Duration
	linger    time.Duration
	// interval is how often the sampler runs; zero disables it, for tests
	// that drive sampling by hand.
	interval time.Duration
	// sampling says the sampler goroutine is running. It runs only while a
	// connection is open, and exits once none is.
	sampling bool
	pairings map[string]*livePairing
	flows    map[any]*liveFlow
}

type liveFlow struct {
	owner   string
	pairing string
	read    func() uint64
	last    uint64
	// lastAt is when the flow was last sampled, on clockLocked's clock.
	lastAt time.Time
}

type liveSample struct {
	at time.Time
	n  uint64
}

type livePairing struct {
	// samples are byte counts per second, oldest first, within the window.
	samples   []liveSample
	flows     int
	connected bool
	since     time.Time
	// quietSince is when a connected pairing fell below the threshold, or
	// zero while it is above it.
	quietSince time.Time
}

// NewLiveTracker returns a tracker with the default threshold, window and
// linger. now nil means time.Now.
func NewLiveTracker(now func() time.Time) *LiveTracker {
	if now == nil {
		now = time.Now
	}
	return &LiveTracker{
		now:       now,
		wall:      func() time.Time { return time.Now().Round(0) },
		threshold: LiveThreshold,
		window:    LiveWindow,
		linger:    LiveLinger,
		interval:  LiveSampleInterval,
		pairings:  make(map[string]*livePairing),
		flows:     make(map[any]*liveFlow),
	}
}

// Open starts following a connection that came through pairing. key
// identifies it for Close, and owner groups it for CloseOwner; opening a key
// already open closes the earlier one. read, if not nil, returns its
// cumulative byte count, sampled every LiveSampleInterval while any
// connection is open, at Snapshot and at Close. An empty pairing is ignored.
func (t *LiveTracker) Open(owner string, key any, pairing string, read func() uint64) {
	if t == nil || pairing == "" || key == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clockLocked()
	if old, ok := t.flows[key]; ok {
		t.closeLocked(key, old, now)
	}
	f := &liveFlow{owner: owner, pairing: pairing, read: read, lastAt: now}
	if read != nil {
		f.last = read()
	}
	t.flows[key] = f
	p := t.pairingLocked(pairing, now)
	p.flows++
	t.evaluateLocked(p, now)
	if !t.sampling && t.interval > 0 {
		t.sampling = true
		go t.sampleLoop(t.interval)
	}
}

func (t *LiveTracker) sampleLoop(interval time.Duration) {
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for range tk.C {
		t.mu.Lock()
		if len(t.flows) == 0 {
			t.sampling = false
			t.mu.Unlock()
			return
		}
		t.sampleAllLocked(t.clockLocked())
		t.mu.Unlock()
	}
}

func (t *LiveTracker) sampleAllLocked(now time.Time) {
	for _, f := range t.flows {
		t.sampleLocked(f, now)
	}
	for _, p := range t.pairings {
		t.evaluateLocked(p, now)
	}
}

// Close stops following the connection key, counting its last bytes.
func (t *LiveTracker) Close(key any) {
	if t == nil || key == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if f, ok := t.flows[key]; ok {
		t.closeLocked(key, f, t.clockLocked())
	}
}

// CloseOwner closes every connection opened with owner, for a source that
// stopped and will report no closes.
func (t *LiveTracker) CloseOwner(owner string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clockLocked()
	for key, f := range t.flows {
		if f.owner == owner {
			t.closeLocked(key, f, now)
		}
	}
}

// Add counts n bytes relayed for pairing now, for a source that reports
// bytes as they move rather than as a running total.
func (t *LiveTracker) Add(pairing string, n uint64) {
	if t == nil || pairing == "" || n == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clockLocked()
	t.addLocked(t.pairingLocked(pairing, now), now, n)
}

// Snapshot samples every open connection and returns each pairing's state,
// sorted by pairing ID.
func (t *LiveTracker) Snapshot() LiveSnapshot {
	s := LiveSnapshot{Pairings: []LivePairing{}}
	if t == nil {
		return s
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clockLocked()
	t.sampleAllLocked(now)
	for id, p := range t.pairings {
		if !p.connected && p.flows == 0 && len(p.samples) == 0 {
			delete(t.pairings, id)
			continue
		}
		since := t.lastWall.Add(-now.Sub(p.since))
		s.Pairings = append(s.Pairings, LivePairing{PairingID: id, Connected: p.connected, Since: since.UnixMilli()})
	}
	sort.Slice(s.Pairings, func(i, j int) bool { return s.Pairings[i].PairingID < s.Pairings[j].PairingID })
	return s
}

// Reset forgets everything, for tests.
func (t *LiveTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.pairings)
	clear(t.flows)
}

// clockLocked returns now plus slept, so windows and lingers age through a
// sleep.
func (t *LiveTracker) clockLocked() time.Time {
	now, wall := t.now(), t.wall()
	if !t.lastNow.IsZero() {
		// A backward wall-clock step gives a negative skew, which is ignored.
		if skew := wall.Sub(t.lastWall) - now.Sub(t.lastNow); skew > liveSleepTolerance {
			t.slept += skew
		}
	}
	t.lastNow, t.lastWall = now, wall
	return now.Add(t.slept)
}

// liveSleepTolerance is how far the wall clock may outrun now between reads
// before the difference counts as sleep. Smaller would count ordinary skew
// between the two clocks as sleep; a shorter sleep barely moves the window.
const liveSleepTolerance = time.Second

func (t *LiveTracker) pairingLocked(id string, now time.Time) *livePairing {
	p := t.pairings[id]
	if p == nil {
		p = &livePairing{since: now}
		t.pairings[id] = p
	}
	return p
}

func (t *LiveTracker) closeLocked(key any, f *liveFlow, now time.Time) {
	t.sampleLocked(f, now)
	delete(t.flows, key)
	if p := t.pairings[f.pairing]; p != nil {
		p.flows--
		t.evaluateLocked(p, now)
	}
}

func (t *LiveTracker) sampleLocked(f *liveFlow, now time.Time) {
	if f.read == nil {
		return
	}
	cur := f.read()
	gap := now.Sub(f.lastAt)
	f.lastAt = now
	if cur <= f.last {
		return
	}
	n := cur - f.last
	f.last = cur
	// After a gap longer than the window, as when the device slept, the
	// bytes may all have moved before the window, so they are not counted.
	if gap > t.window {
		return
	}
	t.addLocked(t.pairingLocked(f.pairing, now), now, n)
}

// addLocked counts n bytes for p at now, after settling p's state up to
// now, so bytes arriving after its linger ended reconnect it rather than
// extend the old connection.
func (t *LiveTracker) addLocked(p *livePairing, now time.Time, n uint64) {
	t.evaluateLocked(p, now)
	p.add(now, n)
	t.evaluateLocked(p, now)
}

func (p *livePairing) add(now time.Time, n uint64) {
	if last := len(p.samples) - 1; last >= 0 && now.Sub(p.samples[last].at) < time.Second {
		p.samples[last].n += n
		return
	}
	p.samples = append(p.samples, liveSample{at: now, n: n})
}

func (t *LiveTracker) evaluateLocked(p *livePairing, now time.Time) {
	cutoff := now.Add(-t.window)
	var total uint64
	for _, s := range p.samples {
		total += s.n
	}
	// If the window was at the threshold and an expiry took it below, the
	// pairing went quiet when that sample expired, not at this later
	// evaluation.
	var crossedAt time.Time
	drop := 0
	for drop < len(p.samples) && !p.samples[drop].at.After(cutoff) {
		before := total
		total -= p.samples[drop].n
		if before >= t.threshold && total < t.threshold {
			crossedAt = p.samples[drop].at.Add(t.window)
		}
		drop++
	}
	if drop > 0 {
		p.samples = append(p.samples[:0], p.samples[drop:]...)
	}
	switch {
	case total >= t.threshold:
		p.quietSince = time.Time{}
		if !p.connected {
			p.connected = true
			p.since = now
		}
	case p.connected:
		if p.quietSince.IsZero() {
			p.quietSince = now
			if !crossedAt.IsZero() && crossedAt.Before(now) {
				p.quietSince = crossedAt
			}
		}
		if now.Sub(p.quietSince) >= t.linger {
			p.connected = false
			// The linger's end, not this possibly later evaluation.
			p.since = p.quietSince.Add(t.linger)
			p.quietSince = time.Time{}
		}
	}
}
