package vpn

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/vpn/memmon"
)

const gateTestCap = 1_000_000

// stubSampler is a fixed-pressure memmon sample source: it satisfies the gate's
// sampler interface without reading real process memory.
type stubSampler struct{ pressure float64 }

func (s stubSampler) Sample(now time.Time) memmon.Sample {
	return memmon.Sample{Footprint: uint64(s.pressure * gateTestCap), Cap: gateTestCap, Timestamp: now}
}

// joinClosable joins a tracked record whose closer folds it back out of the
// tracker on Close, mirroring the real tcpConn/udpConn wrappers so the tracker's
// close paths exercise the live eviction path. chain is ordered as resolveChain
// builds it: leaf first, matched outbound last.
func joinClosable(ct *connTracker, outbound string, createdAt time.Time, chain ...string) *record {
	r := newRec(outbound)
	r.createdAt = createdAt
	r.chain = chain
	r.closer = closerFunc(func() error { ct.leave(r); return nil })
	ct.join(r)
	return r
}

func refIDs(refs []memmon.ConnectionRef) []uuid.UUID {
	ids := make([]uuid.UUID, len(refs))
	for i, r := range refs {
		ids[i] = r.ID
	}
	return ids
}

// newTestClashModeManager returns a clash mode manager in auto mode, outside any box.
func newTestClashModeManager(t *testing.T) *clashModeManager {
	t.Helper()
	ctx := service.ContextWith[adapter.DNSRouter](context.Background(), stubDNSRouter{})
	modes, err := newClashModeManager(ctx, sblog.NewNOPFactory().Logger(), AutoSelectTag)
	require.NoError(t, err)
	return modes
}

func TestMemmonReclaimer(t *testing.T) {
	ct := newConnTracker()
	r := &memoryReclaimer{tracker: ct}
	base := time.Unix(1_700_000_000, 0)

	// Joined out of creation order; OldestConnections must return oldest-first.
	c2 := joinClosable(ct, "vpn-b", base.Add(2*time.Second))
	c1 := joinClosable(ct, "vpn-a", base.Add(1*time.Second))
	c3 := joinClosable(ct, "vpn-c", base.Add(3*time.Second))

	oldest, total := r.OldestConnections(10)
	assert.Equal(t, []uuid.UUID{c1.id, c2.id, c3.id}, refIDs(oldest), "oldest-first by CreatedAt")
	assert.Equal(t, 3, total, "total counts every active connection, not just the returned ones")

	oldest, total = r.OldestConnections(2)
	assert.Equal(t, []uuid.UUID{c1.id, c2.id}, refIDs(oldest), "limit keeps the oldest, dropping newer")
	assert.Equal(t, 3, total, "total is independent of the limit")

	oldest, total = r.OldestConnections(0)
	assert.Empty(t, oldest, "a non-positive limit selects nothing")
	assert.Equal(t, 3, total)

	require.Equal(t, 3, r.OpenConnectionCount())
	assert.Equal(t, 3, r.TotalDialedConnections())

	r.CloseConn(c1.id)
	assert.Equal(t, 2, r.OpenConnectionCount(), "closing one conn folds it out via leave")

	r.CloseAllConnections()
	assert.Zero(t, r.OpenConnectionCount(), "CloseAllConnections drains the tracker")
}

func TestClashModeManagerRejectMasksMode(t *testing.T) {
	modes := newTestClashModeManager(t)
	require.Equal(t, AutoSelectTag, modes.clashMode.Mode(), "the initial mode")

	modes.setRejectMode(true)
	assert.Equal(t, rejectMode, modes.clashMode.Mode(), "reject masks the live mode so routing rule 0 matches")

	modes.setRejectMode(false)
	assert.Equal(t, AutoSelectTag, modes.clashMode.Mode(), "lifting reject restores the live mode")
}

func TestAdmissionGateDrivesReject(t *testing.T) {
	modes := newTestClashModeManager(t)
	ct := newConnTracker()
	gate := memmon.NewAdmissionGate(
		memmon.AdmissionConfig{BurstDialThreshold: -1},
		stubSampler{pressure: 0.95},
		modes.setRejectMode,
	)
	ct.SetAdmissionGate(gate)

	now := time.Unix(1_700_000_000, 0)

	// The dial path reads the gate the same way RoutedConnection does; while
	// disarmed it must not reject.
	g, _ := ct.admissionGate.Load().(dialAdmissionGate)
	require.NotNil(t, g, "SetAdmissionGate stores the gate for the dial path")
	g.RecordDial(now)
	require.Equal(t, AutoSelectTag, modes.clashMode.Mode(), "a disarmed gate does not reject")

	// A pressure observation arms the gate; the next dial latches reject through
	// the clash mode manager.
	gate.Observe(memmon.LevelSoft, 0.95, now)
	g.RecordDial(now)
	assert.Equal(t, rejectMode, modes.clashMode.Mode(), "an armed gate over EnterLimit rejects via setRejectMode")

	// Recovery below ExitLimit lifts it.
	gate.Observe(memmon.LevelNormal, 0.50, now.Add(time.Second))
	assert.Equal(t, AutoSelectTag, modes.clashMode.Mode(), "receding pressure lifts reject")
}

// adjustableSampler is a synthetic, mutable pressure source. A test mutates
// pressure between steps from a single goroutine, so it needs no locking.
type adjustableSampler struct {
	capBytes uint64
	pressure float64
}

func (s *adjustableSampler) Sample(now time.Time) memmon.Sample {
	return memmon.Sample{Footprint: uint64(s.pressure * float64(s.capBytes)), Cap: s.capBytes, Timestamp: now}
}

func TestMemoryMonitorE2E(t *testing.T) {
	modes := newTestClashModeManager(t)
	ct := newConnTracker()

	base := time.Unix(1_700_000_000, 0)
	joinClosable(ct, "vpn-a", base.Add(time.Second))
	joinClosable(ct, "vpn-b", base.Add(2*time.Second))

	// A single Sampler feeds both the monitor and the gate, which is safe here because
	// the synthetic source has no reused buffers and stepping is single-threaded.
	src := &adjustableSampler{capBytes: 1 << 30}
	gate := memmon.NewAdmissionGate(memmon.AdmissionConfig{}, src, modes.setRejectMode)
	ct.SetAdmissionGate(gate)
	exec := memmon.NewExecutor(&memoryReclaimer{tracker: ct}, t.TempDir(), "test", "test", gate)
	mon := memmon.New(memmon.Config{}, src, exec)

	step := func(p float64, at time.Time) {
		src.pressure = p
		mon.Step(at)
	}

	// Below the soft band: the monitor leaves the gate disarmed, so a dial admits.
	step(0.50, base)
	gate.RecordDial(base)
	require.NotEqual(t, rejectMode, modes.clashMode.Mode(), "a disarmed gate does not reject")

	// Into the soft band: the monitor arms the gate and soft-evicts the oldest.
	t1 := base.Add(time.Second)
	step(0.95, t1)
	assert.Equal(t, 1, len(ct.Connections()), "soft eviction closes exactly the oldest connection")

	// A dial now reads fresh pressure over EnterLimit and latches reject.
	t2 := t1.Add(time.Second)
	gate.RecordDial(t2)
	assert.Equal(t, rejectMode, modes.clashMode.Mode(), "an armed gate over EnterLimit rejects via setRejectMode")

	// Pressure recedes below the gate's exit limit: the next observation lifts it.
	step(0.40, t2.Add(time.Second))
	assert.NotEqual(t, rejectMode, modes.clashMode.Mode(), "receding pressure lifts reject")
}
