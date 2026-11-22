package helper

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
)

type fakeSharing struct {
	running bool
	epoch   string
	bytes   uint64
}

func (f *fakeSharing) read() (bool, string, uint64) { return f.running, f.epoch, f.bytes }

func TestActivityCountsTimeAndBytesWhileSharing(t *testing.T) {
	sh := &fakeSharing{running: true, epoch: "e1"}
	now := time.Date(2026, 10, 23, 10, 0, 0, 0, time.Local)
	tr := NewActivityTracker(filepath.Join(t.TempDir(), "a.json"), sh.read)
	tr.now = func() time.Time { return now }

	tr.Sample(time.Minute) // primes the byte baseline
	sh.bytes = 1000
	tr.Sample(time.Minute)
	sh.running = false
	sh.bytes = 1500
	tr.Sample(time.Minute)
	got := tr.Today()
	assert.Equal(t, "2026-10-23", got.Day)
	assert.Equal(t, int64(120), got.ActiveSeconds, "only samples taken while sharing count")
	assert.Equal(t, uint64(1500), got.RelayedBytes)

	sh.epoch, sh.bytes = "e2", 10 // a restarted counter
	tr.Sample(time.Minute)
	assert.Equal(t, uint64(1500), tr.Today().RelayedBytes, "a new epoch re-baselines rather than adding")

	now = now.Add(24 * time.Hour)
	assert.Equal(t, Activity{Day: "2026-10-24"}, tr.Today(), "a new day starts at zero")
}

func TestActivitySavesOnlyOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	sh := &fakeSharing{epoch: "e"}
	now := time.Date(2026, 10, 23, 10, 0, 0, 0, time.Local)
	tr := NewActivityTracker(path, sh.read)
	tr.now = func() time.Time { return now }
	tr.Sample(time.Minute)
	tr.save()
	info, err := os.Stat(path)
	require.NoError(t, err, "the first sample of a day starts the file")
	first := info.ModTime()
	require.NoError(t, os.Chtimes(path, first.Add(-time.Hour), first.Add(-time.Hour)))
	for range 5 {
		tr.Sample(time.Minute) // not sharing: nothing changes
		tr.save()
	}
	info, err = os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, first.Add(-time.Hour).Unix(), info.ModTime().Unix(), "idle samples write nothing")
	sh.running = true
	tr.Sample(time.Minute)
	tr.save()
	info, err = os.Stat(path)
	require.NoError(t, err)
	assert.NotEqual(t, first.Add(-time.Hour).Unix(), info.ModTime().Unix(), "a change is saved")
}

func TestActivitySurvivesARestartTheSameDay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	sh := &fakeSharing{running: true, epoch: "e"}
	tr := NewActivityTracker(path, sh.read)
	tr.Sample(30 * time.Second)
	tr.save()
	again := NewActivityTracker(path, sh.read)
	assert.Equal(t, int64(30), again.Today().ActiveSeconds)
	require.FileExists(t, path)
}

// The file is on-device state: it holds the day and the two totals, and
// nothing else.
func TestActivityFileHoldsOnlyTheTotals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	sh := &fakeSharing{running: true, epoch: "e"}
	tr := NewActivityTracker(path, sh.read)
	tr.Sample(time.Minute)
	tr.save()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(data, &fields))
	assert.ElementsMatch(t, []string{"day", "active_seconds", "relayed_bytes"}, slices.Collect(maps.Keys(fields)))
	info, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

// Android and iOS hard-wire time.Local to UTC, so the day follows the
// device's zone as radiance resolves it, not time.Local. (time.Local is not
// reassigned here: the runtime's timers read it, so that races.)
func TestActivityDayFollowsTheDeviceZone(t *testing.T) {
	tehran, err := time.LoadLocation("Asia/Tehran")
	require.NoError(t, err)

	sh := &fakeSharing{running: true, epoch: "e"}
	tr := NewActivityTracker(filepath.Join(t.TempDir(), "a.json"), sh.read)
	tr.loc = func() *time.Location { return tehran }
	tr.now = func() time.Time { return time.Date(2026, 10, 23, 21, 0, 0, 0, time.UTC) } // 00:30 on the 24th in Tehran
	tr.Sample(time.Minute)
	assert.Equal(t, "2026-10-24", tr.Today().Day)
}

func TestLocalZoneUsesTheDeviceZone(t *testing.T) {
	prevTZ := settings.GetString(settings.TimeZoneKey)
	require.NoError(t, settings.Set(settings.TimeZoneKey, "Asia/Tehran"))
	t.Cleanup(func() { _ = settings.Set(settings.TimeZoneKey, prevTZ) })
	assert.Equal(t, "Asia/Tehran", LocalZone().String())

	assert.Equal(t, time.Local, zoneOrLocal(""), "an unknown zone falls back to time.Local")
	assert.Equal(t, time.Local, zoneOrLocal("Not/AZone"))
}

// A clock that steps back across midnight keeps today's totals rather than
// starting the earlier day over.
func TestActivityIgnoresAClockSteppingBack(t *testing.T) {
	sh := &fakeSharing{running: true, epoch: "e"}
	now := time.Date(2026, 10, 24, 0, 0, 30, 0, time.UTC)
	tr := NewActivityTracker(filepath.Join(t.TempDir(), "a.json"), sh.read)
	tr.loc = func() *time.Location { return time.UTC }
	tr.now = func() time.Time { return now }
	tr.Sample(time.Minute)
	now = now.Add(-time.Minute) // 23:59:30 on the 23rd
	assert.Equal(t, Activity{Day: "2026-10-24", ActiveSeconds: 60}, tr.Today())
	tr.Sample(time.Minute)
	assert.Equal(t, Activity{Day: "2026-10-24", ActiveSeconds: 120}, tr.Today())
}

// The baseline is taken at construction, where a fresh process's counters
// are zero, so bytes count from the first sample on, not from the second.
func TestActivityCountsBytesFromConstruction(t *testing.T) {
	sh := &fakeSharing{running: true, epoch: "e"}
	tr := NewActivityTracker(filepath.Join(t.TempDir(), "a.json"), sh.read)
	sh.bytes = 700
	tr.Sample(time.Minute)
	assert.Equal(t, uint64(700), tr.Today().RelayedBytes)
}

// A backend rebuilt in the same process (the mobile fallback) gets a new
// tracker on the same file while the process-wide counters are already
// non-zero. It must not add them again.
func TestActivitySecondTrackerInAProcessAddsNothingTwice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	sh := &fakeSharing{running: true, epoch: "e"}
	first := NewActivityTracker(path, sh.read)
	sh.bytes = 500
	first.Sample(time.Minute)
	first.save()

	second := NewActivityTracker(path, sh.read)
	second.Sample(time.Minute)
	assert.Equal(t, uint64(500), second.Today().RelayedBytes, "counters that have not moved add nothing")
	sh.bytes = 800
	second.Sample(time.Minute)
	assert.Equal(t, uint64(800), second.Today().RelayedBytes)
}

// A day saved while the clock ran ahead is dropped once the clock is
// corrected by more than a day, rather than holding until the calendar
// catches up.
func TestActivityDropsADayFarInTheFuture(t *testing.T) {
	sh := &fakeSharing{running: true, epoch: "e"}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	tr := NewActivityTracker(filepath.Join(t.TempDir(), "a.json"), sh.read)
	tr.loc = func() *time.Location { return time.UTC }
	tr.now = func() time.Time { return now }
	tr.Sample(time.Minute)
	now = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, Activity{Day: "2026-10-23"}, tr.Today())
	tr.Sample(time.Minute)
	assert.Equal(t, Activity{Day: "2026-10-23", ActiveSeconds: 60}, tr.Today())
}

// Flush counts the time since the last tick or flush, at most one interval,
// and saves; a second Flush right after adds nothing more.
func TestActivityFlushCountsTheLastPartialInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	sh := &fakeSharing{running: true, epoch: "e"}
	tr := NewActivityTracker(path, sh.read)
	tr.every = time.Minute
	tr.lastTick = time.Now().Add(-40 * time.Second)
	sh.bytes = 42
	tr.Flush()
	tr.Flush()
	saved := NewActivityTracker(path, sh.read).Today()
	assert.Equal(t, int64(40), saved.ActiveSeconds)
	assert.Equal(t, uint64(42), saved.RelayedBytes)

	tr.lastTick = time.Now().Add(-3 * time.Hour) // the device slept
	tr.Flush()
	assert.Equal(t, int64(100), tr.Today().ActiveSeconds, "capped at one interval")
}

// Run stops without sampling: Close flushes, and a tick and a flush never
// count the same interval twice.
func TestActivityRunStopsWithoutSampling(t *testing.T) {
	sh := &fakeSharing{running: true, epoch: "e"}
	tr := NewActivityTracker(filepath.Join(t.TempDir(), "a.json"), sh.read)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.Run(ctx, time.Hour); close(done) }()
	cancel()
	<-done
	tr.Flush()
	assert.LessOrEqual(t, tr.Today().ActiveSeconds, int64(1))
}

// Two trackers on one file, as when the app builds a fallback backend while
// the extension's runs, add up rather than overwrite each other.
func TestActivityTrackersOnOneFileAddUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	a := &fakeSharing{running: true, epoch: "a"}
	b := &fakeSharing{running: true, epoch: "b"}
	ta, tb := NewActivityTracker(path, a.read), NewActivityTracker(path, b.read)
	a.bytes, b.bytes = 100, 7
	ta.Sample(time.Minute)
	tb.Sample(30 * time.Second)
	ta.save()
	tb.save()
	ta.Sample(time.Minute)
	ta.save()
	want := Activity{Day: tb.Today().Day, ActiveSeconds: 150, RelayedBytes: 107}
	assert.Equal(t, want, ta.Today())
	assert.Equal(t, want, tb.Today())
	assert.Equal(t, want, NewActivityTracker(path, a.read).Today())
}

// A tracker with nothing new to add never lowers what another has saved,
// even when it saves last.
func TestActivityAStaleFlushKeepsNewerTotals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	sh := &fakeSharing{running: true, epoch: "e"}
	stale := NewActivityTracker(path, sh.read)
	fresh := NewActivityTracker(path, sh.read)
	fresh.Sample(time.Minute)
	fresh.save()
	stale.Flush()
	assert.Equal(t, int64(60), NewActivityTracker(path, sh.read).Today().ActiveSeconds)
}

// Stop ends Run and waits for it, so nothing saves after Stop and the
// Flush that follows it.
func TestActivityStopEndsRunBeforeItReturns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	sh := &fakeSharing{running: true, epoch: "e"}
	tr := NewActivityTracker(path, sh.read)
	done := make(chan struct{})
	go func() { tr.Run(context.Background(), time.Millisecond); close(done) }()
	require.Eventually(t, func() bool { _, err := os.Stat(path); return err == nil }, time.Second, time.Millisecond)
	tr.Stop()
	select {
	case <-done:
	default:
		t.Fatal("Run still running after Stop returned")
	}
	tr.Flush()
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "no save after Stop and Flush")

	again := NewActivityTracker(path, sh.read)
	again.Stop()
	finished := make(chan struct{})
	go func() { again.Run(context.Background(), time.Millisecond); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("a Run after Stop must return at once")
	}
}

// A lock held elsewhere (an iOS app suspended mid-save, say) bounds the wait:
// save gives up, keeping its counts for the next save, and Today never waits
// on the lock at all.
func TestActivitySaveGivesUpOnAHeldLock(t *testing.T) {
	prev := activityLockWait
	activityLockWait = 100 * time.Millisecond
	t.Cleanup(func() { activityLockWait = prev })
	path := filepath.Join(t.TempDir(), "a.json")
	held := flock.New(path + ".lock")
	require.NoError(t, held.Lock())
	sh := &fakeSharing{running: true, epoch: "e"}
	tr := NewActivityTracker(path, sh.read)
	tr.Sample(time.Minute)

	saved := make(chan struct{})
	start := time.Now()
	go func() { tr.save(); close(saved) }()
	todayDone := make(chan Activity, 1)
	go func() { todayDone <- tr.Today() }()
	select {
	case a := <-todayDone:
		assert.Equal(t, int64(60), a.ActiveSeconds)
	case <-time.After(50 * time.Millisecond):
		t.Fatal("Today waited on the file lock")
	}
	<-saved
	assert.Less(t, time.Since(start), time.Second)
	assert.NoFileExists(t, path)
	assert.Equal(t, int64(60), tr.Today().ActiveSeconds, "the counts are kept")

	require.NoError(t, held.Unlock())
	tr.save()
	assert.Equal(t, int64(60), NewActivityTracker(path, sh.read).Today().ActiveSeconds)
}

// After a save for day D, a clock stepped back across midnight and a new
// tracker count toward D-1. Those counts join D, the later day kept, rather
// than being dropped.
func TestActivityCountsAfterAStepBackJoinTheSavedDay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.json")
	sh := &fakeSharing{running: true, epoch: "e"}
	utc := func() *time.Location { return time.UTC }
	now := time.Date(2026, 10, 24, 0, 0, 30, 0, time.UTC)
	first := NewActivityTracker(path, sh.read)
	first.loc, first.now = utc, func() time.Time { return now }
	first.Sample(time.Minute)
	first.save()

	now = time.Date(2026, 10, 23, 23, 59, 30, 0, time.UTC)
	second := NewActivityTracker(path, sh.read)
	second.loc, second.now = utc, func() time.Time { return now }
	second.Sample(time.Minute)
	second.save()
	assert.Equal(t, Activity{Day: "2026-10-24", ActiveSeconds: 120}, second.Today())
	assert.Equal(t, Activity{Day: "2026-10-24", ActiveSeconds: 120}, readActivity(path))
}
