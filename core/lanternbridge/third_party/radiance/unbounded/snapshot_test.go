package unbounded

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/broflake/clientcore"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/helper"
	"github.com/stretchr/testify/require"
)

func TestSnapshotRestoresPeersAndRejectsCancelledCallbacks(t *testing.T) {
	m := &unboundedManager{running: true}
	ctx, cancel := context.WithCancel(context.Background())
	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	m.recordConnection(ctx, 1, 1, "192.0.2.1")
	s := m.snapshot()
	require.Equal(t, uint64(1), s.Arrivals)
	require.Equal(t, []string{"192.0.2.1", "192.0.2.1"}, s.Peers)
	s.Peers[0] = "changed"
	require.Equal(t, "192.0.2.1", m.snapshot().Peers[0])
	m.recordConnection(ctx, -1, 0, "")
	require.Len(t, m.snapshot().Peers, 1)
	m.recordConnection(ctx, -1, 1, "")
	m.recordConnection(ctx, 1, 1, "192.0.2.1")
	require.Equal(t, uint64(2), m.snapshot().Arrivals)
	cancel()
	m.recordConnection(ctx, 1, 2, "192.0.2.2")
	require.Len(t, m.snapshot().Peers, 1)
	m.running = false
	require.Empty(t, m.snapshot().Peers)
}

func TestSnapshotReportsActualLifecycle(t *testing.T) {
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		return &fakeWidget{}, nil
	})
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	require.NoError(t, Apply())
	require.True(t, CurrentSnapshot().Enabled)
	require.False(t, CurrentSnapshot().Running)
	manager.mu.Lock()
	manager.lastFeatureOn = true
	manager.lastCfg = testCfg()
	manager.mu.Unlock()
	require.NoError(t, Apply())
	require.Eventually(t, func() bool { return CurrentSnapshot().Running }, time.Second, time.Millisecond)
	require.NoError(t, Stop(context.Background()))
	require.True(t, CurrentSnapshot().Enabled)
	require.False(t, CurrentSnapshot().Running)
	require.Empty(t, CurrentSnapshot().Peers)
}

func newBytesManager(now *time.Time) (*unboundedManager, *slotTable) {
	slots := &slotTable{}
	return &unboundedManager{running: true, slots: slots, now: func() time.Time { return *now }}, slots
}

func peerBytesByIP(s Snapshot) map[string]PeerBytes {
	out := make(map[string]PeerBytes)
	for _, p := range s.PeerBytes {
		out[p.IP] = p
	}
	return out
}

func TestSnapshotAttributesBytesToPeerIPs(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	ctx := context.Background()
	down, up := chunkCounter(slots, true), chunkCounter(slots, false)

	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	m.recordConnection(ctx, 1, 1, "192.0.2.2")
	m.recordConnection(ctx, 1, 2, "192.0.2.1")
	down(100, 0)
	down(50, 2)
	up(7, 0)
	down(30, 1)
	up(3, 1)
	// No known IP for slot 9, so these count only toward the totals.
	down(1000, 9)
	up(1, 9)
	down(-5, 0)

	s := m.snapshot()
	require.Equal(t, uint64(1180), s.BytesDown)
	require.Equal(t, uint64(11), s.BytesUp)
	require.Equal(t, []PeerBytes{
		{IP: "192.0.2.1", Down: 150, Up: 7},
		{IP: "192.0.2.2", Down: 30, Up: 3},
	}, s.PeerBytes)

	down(10, 1)
	s = m.snapshot()
	require.Equal(t, uint64(1190), s.BytesDown)
	require.Equal(t, uint64(40), peerBytesByIP(s)["192.0.2.2"].Down)
}

func TestSnapshotSlotReuseByDifferentIP(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	ctx := context.Background()
	down := chunkCounter(slots, true)

	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	down(100, 0)
	m.recordConnection(ctx, -1, 0, "192.0.2.1")
	// Chunks between close and the next accept are late batches from the closed peer.
	down(5, 0)
	m.recordConnection(ctx, 1, 0, "192.0.2.2")
	down(40, 0)
	// An accept without a preceding close still hands the slot over cleanly.
	m.recordConnection(ctx, 1, 0, "192.0.2.3")
	down(2, 0)

	s := m.snapshot()
	require.Equal(t, uint64(147), s.BytesDown)
	got := peerBytesByIP(s)
	require.Equal(t, uint64(105), got["192.0.2.1"].Down)
	require.Equal(t, uint64(40), got["192.0.2.2"].Down)
	require.Equal(t, uint64(2), got["192.0.2.3"].Down)
	require.Equal(t, 0, m.peerBytes["192.0.2.2"].active)
	require.Equal(t, 1, m.peerBytes["192.0.2.3"].active)
}

func TestSnapshotRetainsEndedPeersFor60s(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	ctx := context.Background()
	down := chunkCounter(slots, true)

	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	m.recordConnection(ctx, 1, 1, "192.0.2.1")
	m.recordConnection(ctx, 1, 2, "192.0.2.2")
	down(10, 0)
	down(20, 2)
	m.recordConnection(ctx, -1, 0, "")
	m.recordConnection(ctx, -1, 2, "")

	now = now.Add(2 * peerRetention)
	// 192.0.2.1 still holds slot 1, so it's kept regardless of age.
	require.Len(t, m.snapshot().PeerBytes, 1)
	m.recordConnection(ctx, -1, 1, "")

	now = now.Add(peerRetention)
	s := m.snapshot()
	require.Equal(t, []PeerBytes{{IP: "192.0.2.1", Down: 10}}, s.PeerBytes)
	now = now.Add(time.Second)
	s = m.snapshot()
	require.Empty(t, s.PeerBytes)
	require.Equal(t, uint64(30), s.BytesDown)

	// A returning IP starts a fresh entry.
	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	down(4, 0)
	require.Equal(t, []PeerBytes{{IP: "192.0.2.1", Down: 4}}, m.snapshot().PeerBytes)
}

func TestSnapshotStopKeepsFinalPeerBytes(t *testing.T) {
	resetManager(t, func(*clientcore.BroflakeOptions, *clientcore.WebRTCOptions, *clientcore.EgressOptions) (widget, error) {
		return &fakeWidget{}, nil
	})
	now := time.Unix(1000, 0)
	manager.now = func() time.Time { return now }
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	manager.mu.Lock()
	manager.lastFeatureOn = true
	manager.lastCfg = testCfg()
	manager.mu.Unlock()
	require.NoError(t, Apply())
	require.Eventually(t, func() bool { return CurrentSnapshot().Running }, time.Second, time.Millisecond)

	manager.mu.Lock()
	slots := manager.slots
	manager.mu.Unlock()
	ctx, stopCtx := context.WithCancel(context.Background())
	manager.recordConnection(ctx, 1, 0, "192.0.2.1")
	down := chunkCounter(slots, true)
	down(64, 0)

	require.NoError(t, Stop(context.Background()))
	stopCtx()
	s := CurrentSnapshot()
	require.False(t, s.Running)
	require.Empty(t, s.Peers)
	require.Equal(t, uint64(64), s.BytesDown)
	require.Equal(t, []PeerBytes{{IP: "192.0.2.1", Down: 64}}, s.PeerBytes)

	// broflake tears down asynchronously, so chunks can arrive after Stop.
	down(36, 0)
	require.Equal(t, []PeerBytes{{IP: "192.0.2.1", Down: 100}}, CurrentSnapshot().PeerBytes)

	now = now.Add(peerRetention + time.Second)
	s = CurrentSnapshot()
	require.Empty(t, s.PeerBytes)
	require.Equal(t, uint64(100), s.BytesDown)
	manager.mu.Lock()
	require.Empty(t, manager.retired)
	manager.mu.Unlock()
	// Once the retired run expires its table is closed.
	down(1000, 0)
	require.Equal(t, uint64(100), CurrentSnapshot().BytesDown)
}

func TestSnapshotJSONShape(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	ctx := context.Background()
	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	chunkCounter(slots, true)(12, 0)
	chunkCounter(slots, false)(3, 0)

	raw, err := json.Marshal(m.snapshot())
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	require.ElementsMatch(t, []string{"epoch", "arrivals", "enabled", "running", "peers", "bytesDown", "bytesUp", "peerBytes"}, keys(got))
	require.Equal(t, float64(12), got["bytesDown"])
	require.Equal(t, float64(3), got["bytesUp"])
	require.Equal(t, []any{map[string]any{"ip": "192.0.2.1", "down": float64(12), "up": float64(3)}}, got["peerBytes"])

	raw, err = json.Marshal((&unboundedManager{}).snapshot())
	require.NoError(t, err)
	require.Contains(t, string(raw), `"peerBytes":[]`)

	// Payloads from older backends without byte fields still decode.
	var old Snapshot
	require.NoError(t, json.Unmarshal([]byte(`{"epoch":"1","arrivals":2,"enabled":true,"running":true,"peers":[]}`), &old))
	require.Zero(t, old.BytesDown)
	require.Empty(t, old.PeerBytes)
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSnapshotConcurrentChunksAreCountedOnce(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	ctx := context.Background()
	down := chunkCounter(slots, true)
	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	m.recordConnection(ctx, 1, 1, "192.0.2.2")

	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				down(1, w)
			}
		}(w)
	}
	for i := 0; i < 50; i++ {
		m.snapshot()
	}
	wg.Wait()
	s := m.snapshot()
	require.Equal(t, uint64(2000), s.BytesDown)
	require.Equal(t, []PeerBytes{{IP: "192.0.2.1", Down: 1000}, {IP: "192.0.2.2", Down: 1000}}, s.PeerBytes)
}

func TestSnapshotCreditsLateUpstreamBatchToClosedPeer(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	ctx := context.Background()
	up := chunkCounter(slots, false)

	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	up(10, 0)
	m.snapshot()
	m.recordConnection(ctx, -1, 0, "")
	m.snapshot()
	// broflake flushes the closed peer's pending upstream batch after the close.
	up(7, 0)
	now = now.Add(time.Second)
	require.Equal(t, []PeerBytes{{IP: "192.0.2.1", Up: 17}}, m.snapshot().PeerBytes)

	m.recordConnection(ctx, 1, 0, "192.0.2.2")
	up(3, 0)
	s := m.snapshot()
	require.Equal(t, uint64(20), s.BytesUp)
	got := peerBytesByIP(s)
	require.Equal(t, uint64(17), got["192.0.2.1"].Up)
	require.Equal(t, uint64(3), got["192.0.2.2"].Up)
}

func TestSlotTableCloseWaitsForInFlightAdds(t *testing.T) {
	slots := &slotTable{}
	slots.mu.RLock()
	closed := make(chan struct{})
	go func() {
		slots.close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("close returned while an add was in flight")
	case <-time.After(20 * time.Millisecond):
	}
	slots.slot(0).down.Add(5)
	slots.mu.RUnlock()
	<-closed
	slots.add(0, 100, true)
	require.Equal(t, uint64(5), slots.slot(0).down.Load())
}

type flushingWidget struct{ onStop func() }

func (w *flushingWidget) Stop() { w.onStop() }

func TestSnapshotCountsUpstreamFlushedWhileStopping(t *testing.T) {
	var upstream clientcore.ChunkFunc
	resetManager(t, func(bf *clientcore.BroflakeOptions, _ *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
		upstream = bf.OnUpstreamChunkFunc
		return &flushingWidget{onStop: func() { upstream(9, 0) }}, nil
	})
	now := time.Unix(1000, 0)
	manager.now = func() time.Time { return now }
	require.NoError(t, settings.Set(settings.UnboundedKey, true))
	manager.mu.Lock()
	manager.lastFeatureOn = true
	manager.lastCfg = testCfg()
	manager.mu.Unlock()
	require.NoError(t, Apply())
	require.Eventually(t, func() bool { return CurrentSnapshot().Running }, time.Second, time.Millisecond)

	manager.recordConnection(context.Background(), 1, 0, "192.0.2.1")
	upstream(4, 0)
	require.NoError(t, Stop(context.Background()))
	s := CurrentSnapshot()
	require.Equal(t, uint64(13), s.BytesUp)
	require.Equal(t, []PeerBytes{{IP: "192.0.2.1", Up: 13}}, s.PeerBytes)
}

func TestSnapshotCreditsRetiredRunBytesToItsOwners(t *testing.T) {
	now := time.Unix(1000, 0)
	m, oldSlots := newBytesManager(&now)
	ctx := context.Background()
	oldUp := chunkCounter(oldSlots, false)
	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	m.recordConnection(ctx, 1, 1, "192.0.2.2")
	m.recordConnection(ctx, -1, 1, "")
	m.mu.Lock()
	m.releaseAllPeers()
	newSlots := &slotTable{}
	m.slots = newSlots
	m.peers = make(map[int]string)
	m.mu.Unlock()

	newUp := chunkCounter(newSlots, false)
	m.recordConnection(ctx, 1, 0, "192.0.2.3")
	oldUp(5, 0)
	oldUp(2, 1)
	newUp(3, 0)
	s := m.snapshot()
	require.Equal(t, uint64(10), s.BytesUp)
	require.Equal(t, []PeerBytes{
		{IP: "192.0.2.1", Up: 5},
		{IP: "192.0.2.2", Up: 2},
		{IP: "192.0.2.3", Up: 3},
	}, s.PeerBytes)
}

func TestSnapshotPendingBytesStayWithPrunedLifetime(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	ctx := context.Background()
	up := chunkCounter(slots, false)

	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	up(5, 0)
	m.recordConnection(ctx, -1, 0, "")
	now = now.Add(peerRetention + time.Second)
	// A late batch is still pending when the same IP returns, with no
	// snapshot taken in between.
	up(7, 0)
	m.recordConnection(ctx, 1, 1, "192.0.2.1")
	s := m.snapshot()
	require.Equal(t, uint64(12), s.BytesUp)
	require.Equal(t, []PeerBytes{{IP: "192.0.2.1"}}, s.PeerBytes)
}

func TestRetiredRunsExpireWithoutPolling(t *testing.T) {
	now := time.Unix(1000, 0)
	m, _ := newBytesManager(&now)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseAllPeers()
	m.slots = &slotTable{}
	now = now.Add(peerRetention + time.Second)
	m.releaseAllPeers()
	require.Len(t, m.retired, 1)
}

func TestSnapshotLateBytesAfterPruneSkipReturningIP(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	ctx := context.Background()
	up := chunkCounter(slots, false)

	m.recordConnection(ctx, 1, 0, "192.0.2.1")
	m.recordConnection(ctx, -1, 0, "")
	now = now.Add(peerRetention + time.Second)
	m.recordConnection(ctx, 1, 1, "192.0.2.1")
	// Arrives after the prune that started the IP's new lifetime.
	up(7, 0)
	s := m.snapshot()
	require.Equal(t, uint64(7), s.BytesUp)
	require.Equal(t, []PeerBytes{{IP: "192.0.2.1"}}, s.PeerBytes)
}

func TestPairedSlotBytesAccrueToUsage(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	m.live = helper.NewLiveTracker(nil)
	u := &helper.Usage{}
	m.usage = u
	u.SetFlush(m.foldPending)
	ctx := context.Background()
	down, up := chunkCounter(slots, true), chunkCounter(slots, false)

	m.recordConnection(ctx, 1, 0, "198.51.100.7")
	m.recordPairing(ctx, slots, 1, 0, testPairing)
	m.recordConnection(ctx, 1, 1, "198.51.100.8")
	m.recordPairing(ctx, slots, 1, 1, "")
	down(100, 0)
	up(20, 0)
	down(999, 1)

	require.Equal(t, []helper.PairedBytes{{PairingID: testPairing, Bytes: 120}}, u.Take(),
		"a take folds the slots first; pool bytes are not paired")
	require.Nil(t, u.Take())

	down(5, 0)
	_ = m.snapshot()
	require.Equal(t, []helper.PairedBytes{{PairingID: testPairing, Bytes: 5}}, u.Take(), "a snapshot's fold accrues too")
	require.Equal(t, uint64(1104), m.snapshot().BytesDown, "the widget's own totals are unchanged")
}

func TestPairedUsageIsPerSlotNotPerIP(t *testing.T) {
	for _, pairedFirst := range []bool{true, false} {
		now := time.Unix(1000, 0)
		m, slots := newBytesManager(&now)
		m.live = helper.NewLiveTracker(nil)
		u := &helper.Usage{}
		m.usage = u
		u.SetFlush(m.foldPending)
		ctx := context.Background()
		down := chunkCounter(slots, true)

		paired, pool := 0, 1
		if !pairedFirst {
			paired, pool = 1, 0
		}
		for _, slot := range []int{0, 1} {
			m.recordConnection(ctx, 1, slot, "198.51.100.7")
			if slot == paired {
				m.recordPairing(ctx, slots, 1, slot, testPairing)
			} else {
				m.recordPairing(ctx, slots, 1, slot, "")
			}
		}
		down(100, paired)
		down(999, pool)
		require.Equal(t, []helper.PairedBytes{{PairingID: testPairing, Bytes: 100}}, u.Take(),
			"paired first: %v", pairedFirst)

		m.recordConnection(ctx, -1, paired, "")
		m.recordPairing(ctx, slots, -1, paired, "")
		down(7, paired)
		down(999, pool)
		require.Equal(t, []helper.PairedBytes{{PairingID: testPairing, Bytes: 7}}, u.Take(),
			"late bytes on a closed paired slot keep its pairing, paired first: %v", pairedFirst)

		m.recordConnection(ctx, 1, paired, "198.51.100.9")
		m.recordPairing(ctx, slots, 1, paired, "")
		down(50, paired)
		require.Nil(t, u.Take(), "a pool consumer reusing the slot is not paired")
	}
}

func TestPairedUsageCreditsRetiredRunBytes(t *testing.T) {
	now := time.Unix(1000, 0)
	m, oldSlots := newBytesManager(&now)
	m.live = helper.NewLiveTracker(nil)
	u := &helper.Usage{}
	m.usage = u
	u.SetFlush(m.foldPending)
	ctx := context.Background()
	oldDown := chunkCounter(oldSlots, true)

	m.recordConnection(ctx, 1, 0, "198.51.100.7")
	m.recordPairing(ctx, oldSlots, 1, 0, testPairing)
	oldDown(10, 0)
	m.mu.Lock()
	m.releaseAllPeers()
	newSlots := &slotTable{}
	m.slots = newSlots
	m.peers = make(map[int]string)
	m.mu.Unlock()

	oldDown(4, 0)
	m.recordConnection(ctx, 1, 0, "198.51.100.8")
	m.recordPairing(ctx, newSlots, 1, 0, "")
	chunkCounter(newSlots, true)(999, 0)
	require.Equal(t, []helper.PairedBytes{{PairingID: testPairing, Bytes: 14}}, u.Take())
}

func TestPairedTrafficWithoutUsage(t *testing.T) {
	now := time.Unix(1000, 0)
	m, slots := newBytesManager(&now)
	m.live = helper.NewLiveTracker(nil)
	ctx := context.Background()
	m.recordConnection(ctx, 1, 0, "198.51.100.7")
	m.recordPairing(ctx, slots, 1, 0, testPairing)
	chunkCounter(slots, true)(10, 0)
	require.NotPanics(t, m.foldPending)
	require.Equal(t, uint64(10), m.snapshot().BytesDown)
}
