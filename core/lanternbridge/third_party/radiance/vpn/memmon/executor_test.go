package memmon

import (
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeReclaimer struct {
	conns     []ConnectionRef
	closed    []uuid.UUID
	closeAllN int
	freeOSCnt int
	openCount int
	dialed    int
}

// OldestConnections returns the fake's oldest-first prefix so limit handling exercises executor
// behavior, not sorting.
func (f *fakeReclaimer) OldestConnections(limit int) ([]ConnectionRef, int) {
	if limit <= 0 {
		return nil, len(f.conns)
	}
	return f.conns[:min(limit, len(f.conns))], len(f.conns)
}
func (f *fakeReclaimer) CloseConn(id uuid.UUID)      { f.closed = append(f.closed, id) }
func (f *fakeReclaimer) CloseAllConnections()        { f.closeAllN++ }
func (f *fakeReclaimer) FreeOSMemory()               { f.freeOSCnt++ }
func (f *fakeReclaimer) OpenConnectionCount() int    { return f.openCount }
func (f *fakeReclaimer) TotalDialedConnections() int { return f.dialed }

func refs(n int) []ConnectionRef {
	out := make([]ConnectionRef, n)
	base := time.Unix(0, 0)
	for i := range out {
		out[i] = ConnectionRef{ID: uuid.Must(uuid.NewV4()), CreatedAt: base.Add(time.Duration(i) * time.Second)}
	}
	return out
}

func idsOf(cs []ConnectionRef) []uuid.UUID {
	out := make([]uuid.UUID, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}

func newTestExec(r Reclaimer, cfg reactionConfig) *executor {
	return newExecutor(r, "", "", "", nil, cfg).(*executor)
}

func TestSoftEvictFixedBatch(t *testing.T) {
	r := &fakeReclaimer{conns: refs(20)}
	e := newTestExec(r, reactionConfig{SoftDivisor: 4, SoftBatchMax: 16, FreeOSMinInterval: time.Hour})

	e.Apply(Decision{Level: LevelSoft, EvictOldestBatch: true}, time.Unix(0, 0))

	require.Len(t, r.closed, 5)
	assert.Equal(t, idsOf(r.conns[:5]), r.closed, "evicts the oldest quarter of connections")
}

func TestSoftEvictHitsBatchCap(t *testing.T) {
	r := &fakeReclaimer{conns: refs(100)}
	e := newTestExec(r, reactionConfig{SoftDivisor: 4}) // defaults: cap 16

	e.Apply(Decision{Level: LevelSoft, EvictOldestBatch: true}, time.Unix(0, 0))

	assert.Len(t, r.closed, defaultSoftBatchMax, "capped at SoftBatchMax")
}

func TestSettleGatePausesEviction(t *testing.T) {
	r := &fakeReclaimer{conns: refs(8)}
	e := newTestExec(r, reactionConfig{FreeOSMinInterval: time.Hour})

	// Intensity 0 is the DecisionEngine's settle signal: stay in Soft but evict nothing.
	e.Apply(Decision{Level: LevelSoft}, time.Unix(0, 0))

	assert.Empty(t, r.closed, "no eviction while settle pauses the soft batch")
	assert.Zero(t, r.freeOSCnt, "no forced GC on a paused soft tick")
}

func TestHardForceCloseAll(t *testing.T) {
	r := &fakeReclaimer{conns: refs(5)}
	e := newTestExec(r, reactionConfig{FreeOSMinInterval: time.Hour})

	e.Apply(Decision{Level: LevelHard, CloseAllConnections: true}, time.Unix(0, 0))
	assert.Equal(t, 1, r.closeAllN, "force-close-all fires once")
	assert.Equal(t, 1, r.freeOSCnt, "FreeOSMemory fires with the hard reclaim")

	// Lingering Hard without the edge flag must not act.
	e.Apply(Decision{Level: LevelHard}, time.Unix(1, 0))
	assert.Equal(t, 1, r.closeAllN, "no re-close on a lingering Hard tick without CloseAllConnections")
}

func TestSoftScavengeRateLimited(t *testing.T) {
	r := &fakeReclaimer{conns: refs(20)}
	e := newTestExec(r, reactionConfig{SoftDivisor: 4, FreeOSMinInterval: 3 * time.Second})
	start := time.Unix(0, 0)

	e.Apply(Decision{Level: LevelSoft, EvictOldestBatch: true}, start)
	e.Apply(Decision{Level: LevelSoft, EvictOldestBatch: true}, start.Add(time.Second)) // inside the window
	assert.Equal(t, 1, r.freeOSCnt, "soft scavenge within the window is rate-limited")

	e.Apply(Decision{Level: LevelSoft, EvictOldestBatch: true}, start.Add(4*time.Second)) // past the window
	assert.Equal(t, 2, r.freeOSCnt, "soft scavenge fires again past the window")
}

func TestHardReclaimScavengeBypassesSoftRateLimit(t *testing.T) {
	r := &fakeReclaimer{conns: refs(20)}
	e := newTestExec(r, reactionConfig{SoftDivisor: 4, FreeOSMinInterval: 3 * time.Second})
	start := time.Unix(0, 0)

	// A soft scavenge spends the rate-limit budget.
	e.Apply(Decision{Level: LevelSoft, EvictOldestBatch: true}, start)
	require.Equal(t, 1, r.freeOSCnt)

	// A Hard close-all one second later, well inside FreeOSMinInterval, must still
	// scavenge: the core already edge-triggers and hardCooldown-spaces it.
	e.Apply(Decision{Level: LevelHard, CloseAllConnections: true}, start.Add(time.Second))
	assert.Equal(t, 2, r.freeOSCnt, "hard reclaim scavenges even within the soft rate-limit window")
}
