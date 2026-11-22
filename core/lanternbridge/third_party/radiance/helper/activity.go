package helper

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/gofrs/flock"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
)

// Activity is today's sharing on this device: how long it ran and how much it
// relayed, on the device's local calendar. It counts paired and pool traffic
// together, as Advanced stats does, and says nothing about whom it helped.
type Activity struct {
	Day           string `json:"day"`
	ActiveSeconds int64  `json:"active_seconds"`
	RelayedBytes  uint64 `json:"relayed_bytes"`
}

// Sharing reads what sharing is doing now: whether either mode runs, an
// identifier for its counters' current epochs, and their cumulative bytes.
type Sharing func() (running bool, epoch string, bytes uint64)

// ActivityTracker builds today's Activity from periodic samples and keeps it
// in a file, so a restart on the same day carries on. The file holds only
// the Activity: no pairing, peer or count of either.
//
// More than one tracker can share the file: on mobile, the app can build a
// fallback backend while the extension's keeps running. So a tracker keeps
// only what it has counted and not yet saved (pending), and save adds that to
// the file under a cross-process lock. No tracker writes its own view of the
// totals over another's.
type ActivityTracker struct {
	path string
	read Sharing
	now  func() time.Time
	loc  func() *time.Location

	// writeMu serializes this tracker's saves, including the wait for the
	// cross-process lock. saveMu is held across a save's read and write of
	// the file, and by Today, so a reader never sees pending both in the
	// file and in memory. Order: writeMu, the file lock, saveMu, mu.
	writeMu sync.Mutex
	saveMu  sync.Mutex

	mu      sync.Mutex
	zone    *time.Location // loc's last answer; Sample refreshes it
	pending Activity       // counted since the last save, for pending.Day
	// lastEpoch and lastBytes are the counters at the last sample, or at
	// construction. The counters are process-wide, so a tracker built for a
	// backend recreated in the same process must not count what an earlier
	// one already did; in a fresh process they are near zero at
	// construction, so bytes still count from process start.
	lastEpoch string
	lastBytes uint64
	// every is Run's interval and lastTick when the last tick or Flush
	// sampled; Flush counts the time since, at most every.
	every    time.Duration
	lastTick time.Time
	// stopRun ends Run and runDone closes when it has; stopped makes a Run
	// that starts after Stop return at once.
	stopRun context.CancelFunc
	runDone chan struct{}
	stopped bool
}

// NewActivityTracker returns a tracker that saves to path and samples read.
func NewActivityTracker(path string, read Sharing) *ActivityTracker {
	t := &ActivityTracker{path: path, read: read, now: time.Now, loc: LocalZone}
	_, t.lastEpoch, t.lastBytes = read()
	return t
}

// readActivity reads the file, or the zero Activity if there is none. A save
// replaces the file by renaming, so a read sees one whole version.
func readActivity(path string) Activity {
	var a Activity
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &a)
	}
	return a
}

// combine is the day's totals from the file's and the pending ones, and
// whether the pending ones are in them. Each part counts only if its day is
// not stale (see isNewDay). The later of the days that count is the day: the
// file's counts join it only when they are for that day, and pending counts
// that count always join it, even when they are for an earlier day (a clock
// stepped back across midnight), since days only move forward. With neither,
// it is today with nothing.
func combine(file, pending Activity, today, tomorrow string) (Activity, bool) {
	fileOK := file.Day != "" && !isNewDay(file.Day, today, tomorrow)
	pendingOK := pending.Day != "" && !isNewDay(pending.Day, today, tomorrow)
	out := Activity{Day: today}
	switch {
	case fileOK && pendingOK:
		out.Day = max(file.Day, pending.Day)
	case fileOK:
		out.Day = file.Day
	case pendingOK:
		out.Day = pending.Day
	}
	if fileOK && file.Day == out.Day {
		out.ActiveSeconds += file.ActiveSeconds
		out.RelayedBytes += file.RelayedBytes
	}
	if pendingOK {
		out.ActiveSeconds += pending.ActiveSeconds
		out.RelayedBytes += pending.RelayedBytes
	}
	return out, pendingOK
}

// LocalZone is the device's time zone. Go hard-wires time.Local to UTC on
// Android and iOS, so the zone comes from common.LocalTimeZone, which asks
// the host app; time.Local is the fallback when that is unknown.
func LocalZone() *time.Location {
	return zoneOrLocal(common.LocalTimeZone())
}

func zoneOrLocal(name string) *time.Location {
	if name == "" {
		return time.Local
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.Local
	}
	return loc
}

// days returns today and tomorrow in zone.
func (t *ActivityTracker) days(zone *time.Location) (today, tomorrow string) {
	now := t.now().In(zone)
	return now.Format("2006-01-02"), now.AddDate(0, 0, 1).Format("2006-01-02")
}

// isNewDay reports whether today replaces day. Days are YYYY-MM-DD, so they
// compare as strings. A later day replaces it; so does one more than a day
// earlier, which means day was saved while the clock ran ahead. A clock that
// stepped back across midnight, by less than a day, keeps the later day.
func isNewDay(day, today, tomorrow string) bool {
	return today > day || day > tomorrow
}

// cachedZone returns the zone Sample last resolved, resolving it, outside
// t.mu, only if no sample has run. Resolving can walk the zone database, and
// the app polls Today often.
func (t *ActivityTracker) cachedZone() *time.Location {
	t.mu.Lock()
	zone := t.zone
	t.mu.Unlock()
	if zone != nil {
		return zone
	}
	zone = t.loc()
	t.mu.Lock()
	if t.zone == nil {
		t.zone = zone
	}
	t.mu.Unlock()
	return zone
}

// Today returns today's totals: the file's, which every tracker on it has
// added to, plus this tracker's pending ones. The file is read without the
// cross-process lock, since a save replaces it whole, by renaming; saveMu
// keeps this tracker's own save from landing between the two reads.
func (t *ActivityTracker) Today() Activity {
	today, tomorrow := t.days(t.cachedZone())
	t.saveMu.Lock()
	defer t.saveMu.Unlock()
	file := readActivity(t.path)
	t.mu.Lock()
	pending := t.pending
	t.mu.Unlock()
	a, _ := combine(file, pending, today, tomorrow)
	return a
}

// Sample adds one interval: elapsed counts as active if sharing runs now, and
// the bytes relayed since the last sample are added unless the counters were
// reset in between. It holds the lock across read, which only copies two
// snapshots, so concurrent samples cannot count the same bytes twice.
func (t *ActivityTracker) Sample(elapsed time.Duration) {
	zone := t.loc() // outside the lock: it can load many zones
	today, tomorrow := t.days(zone)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.zone = zone
	running, epoch, bytes := t.read()
	if isNewDay(t.pending.Day, today, tomorrow) {
		// Unsaved counts for an earlier day are dropped with that day.
		t.pending = Activity{Day: today}
	}
	if running {
		t.pending.ActiveSeconds += int64(elapsed.Round(time.Second) / time.Second)
	}
	if epoch == t.lastEpoch && bytes >= t.lastBytes {
		t.pending.RelayedBytes += bytes - t.lastBytes
	}
	t.lastEpoch, t.lastBytes = epoch, bytes
}

// Run samples every interval until ctx ends or Stop is called, saving after
// a sample that changed something. A device that never shares writes nothing
// but the first sample of each day. It takes no sample when it ends: the
// backend's Close stops it and then calls Flush, while sharing still runs.
func (t *ActivityTracker) Run(ctx context.Context, every time.Duration) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	t.every, t.lastTick = every, time.Now()
	t.stopRun, t.runDone = cancel, done
	t.mu.Unlock()
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.Flush()
		}
	}
}

// Stop ends Run and waits for it, so no tick saves after Stop returns. A Run
// that starts afterwards returns at once.
func (t *ActivityTracker) Stop() {
	t.mu.Lock()
	t.stopped = true
	stop, done := t.stopRun, t.runDone
	t.mu.Unlock()
	if stop != nil {
		stop()
		<-done
	}
}

// Flush samples the time since the last tick or Flush, capped at one
// interval because time the device slept is not time it shared, and saves.
// Ticks and flushes each claim the span since the one before, so no interval
// counts twice. Before Run starts it counts bytes only.
func (t *ActivityTracker) Flush() {
	t.mu.Lock()
	now := time.Now()
	var elapsed time.Duration
	if !t.lastTick.IsZero() {
		elapsed = min(now.Sub(t.lastTick), t.every)
	}
	t.lastTick = now
	t.mu.Unlock()
	t.Sample(elapsed)
	t.save()
}

// activityLockWait bounds how long save waits for the cross-process lock. A
// healthy holder keeps it for one read-modify-write; one that holds it longer
// is suspended (iOS freezes apps mid-write), as for the settings file. A var
// so tests can shorten it.
var activityLockWait = 500 * time.Millisecond

// save adds the pending counts to the file. It holds an exclusive lock on a
// sibling lock file across reading the file, rolling its day forward by the
// usual rules, adding, and writing it back, so trackers in other processes
// never lose each other's counts. It waits at most activityLockWait for that
// lock; without it, the counts stay pending for the next save. What it wrote
// is then taken off pending. It writes nothing when the file would not change.
//
// writeMu serializes this tracker's saves across the lock wait; saveMu is
// held only for the read and write, so Today never waits on the lock.
func (t *ActivityTracker) save() {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.mu.Lock()
	empty := t.pending.Day == ""
	t.mu.Unlock()
	if empty {
		return
	}
	// Fixed text only: these errors quote the file's path, which can name
	// the device's user.
	lock := flock.New(t.path + ".lock")
	ctx, cancel := context.WithTimeout(context.Background(), activityLockWait)
	locked, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	cancel()
	if err != nil || !locked {
		slog.Debug("helper: activity file lock unavailable; saving later")
		return
	}
	defer func() { _ = lock.Unlock() }()

	today, tomorrow := t.days(t.cachedZone())
	t.saveMu.Lock()
	defer t.saveMu.Unlock()
	t.mu.Lock()
	pending := t.pending
	t.mu.Unlock()
	file := readActivity(t.path)
	merged, counted := combine(file, pending, today, tomorrow)
	if merged != file {
		data, err := json.Marshal(merged)
		if err != nil {
			return
		}
		// Private: only the backend reads the file; the app asks over IPC.
		if atomicfile.WriteFile(t.path, data, fileperm.Private) != nil {
			slog.Debug("helper: saving activity failed")
			return
		}
	}
	if !counted {
		return
	}
	t.mu.Lock()
	if t.pending.Day == pending.Day {
		t.pending.ActiveSeconds -= pending.ActiveSeconds
		t.pending.RelayedBytes -= pending.RelayedBytes
	}
	t.mu.Unlock()
}
