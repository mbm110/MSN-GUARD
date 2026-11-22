package peer

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/lantern-box/tracker/peerconn"

	"github.com/getlantern/radiance/helper"
)

func counter(down, up int) *peerconn.Counter {
	c := &peerconn.Counter{}
	c.AddDown(down)
	c.AddUp(up)
	return c
}

// Open connections are read live; a close folds its final count so the totals
// keep it, and a client's connections add up under its IP.
func TestRelayStats_CountsLiveAndClosedConnections(t *testing.T) {
	var r relayStats
	r.begin()
	a, b := counter(100, 10), counter(50, 5)
	r.record(1, "203.0.113.7:1000", a)
	r.record(1, "203.0.113.7:1001", b)
	other := counter(7, 3)
	r.record(1, "198.51.100.9:2000", other)

	a.AddDown(900)
	s := r.snapshot(true)
	assert.Equal(t, uint64(1057), s.BytesDown)
	assert.Equal(t, uint64(18), s.BytesUp)
	assert.Equal(t, []string{"198.51.100.9:2000", "203.0.113.7:1000", "203.0.113.7:1001"}, s.Peers)
	assert.Equal(t, []PeerBytes{
		{IP: "198.51.100.9", Down: 7, Up: 3},
		{IP: "203.0.113.7", Down: 1050, Up: 15},
	}, s.PeerBytes)

	r.record(-1, "203.0.113.7:1000", a)
	a.AddDown(1) // the counter is no longer read once its close is folded
	s = r.snapshot(true)
	assert.Equal(t, uint64(1057), s.BytesDown, "a closed connection's bytes stay counted")
	assert.Equal(t, []PeerBytes{
		{IP: "198.51.100.9", Down: 7, Up: 3},
		{IP: "203.0.113.7", Down: 1050, Up: 15},
	}, s.PeerBytes)
	assert.NotContains(t, s.Peers, "203.0.113.7:1000")
}

// samizdat multiplexes streams over one TCP conn, so two open streams can share
// a source; each keeps its own count, and closing one leaves the other live.
func TestRelayStats_StreamsSharingASource(t *testing.T) {
	var r relayStats
	r.begin()
	a, b := counter(100, 1), counter(200, 2)
	r.record(1, "203.0.113.7:1000", a)
	r.record(1, "203.0.113.7:1000", b)
	assert.Equal(t, uint64(300), r.snapshot(true).BytesDown)

	r.record(-1, "203.0.113.7:1000", a)
	b.AddDown(50)
	s := r.snapshot(true)
	assert.Equal(t, uint64(350), s.BytesDown, "the open stream is still read live")
	assert.Equal(t, []PeerBytes{{IP: "203.0.113.7", Down: 350, Up: 3}}, s.PeerBytes)
	assert.Equal(t, []string{"203.0.113.7:1000"}, s.Peers)
}

// An ordinary stream and an api.iantem.io stream share a source, and the
// ordinary one closes first. Matched by counter, its close is not mistaken for
// the verifier's, so it leaves the snapshot and stops being held.
func TestClient_OrdinaryCloseBeforeVerifierOnSharedSource(t *testing.T) {
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	c := newTestClient(t, fwd, &fakeBoxService{}, newStubServer(t))
	ctx := context.Background()
	require.NoError(t, c.Start(ctx))
	defer func() { require.NoError(t, c.Stop(ctx)) }()

	const src = "5.119.14.105:10304"
	ordinary, verifier := counter(300, 30), counter(9, 9)
	peerconn.Notify(peerconn.Event{State: +1, Source: src, Destination: "google.com:443", Bytes: ordinary})
	peerconn.Notify(peerconn.Event{State: +1, Source: src, Destination: "api.iantem.io:443", Bytes: verifier})
	peerconn.Notify(peerconn.Event{State: -1, Source: src, Bytes: ordinary})
	assert.Equal(t, 0, c.ActiveClients())
	assert.Empty(t, c.RelaySnapshot().Peers)
	peerconn.Notify(peerconn.Event{State: -1, Source: src, Bytes: verifier})
	assert.Equal(t, 0, c.ActiveClients())
	s := c.RelaySnapshot()
	assert.Equal(t, uint64(300), s.BytesDown, "only the ordinary stream counts")
	c.relay.mu.Lock()
	assert.Empty(t, c.relay.conns)
	c.relay.mu.Unlock()
}

// A departed client stays in the snapshot long enough for the app's poller to
// see its final count, then drops out; session totals keep its bytes.
func TestRelayStats_PrunesDepartedClientsAfterRetention(t *testing.T) {
	now := time.Unix(1_000, 0)
	r := relayStats{now: func() time.Time { return now }}
	r.begin()
	c := counter(40, 4)
	r.record(1, "203.0.113.7:1000", c)
	r.record(-1, "203.0.113.7:1000", c)

	now = now.Add(relayRetention)
	assert.Len(t, r.snapshot(true).PeerBytes, 1)
	now = now.Add(time.Second)
	s := r.snapshot(true)
	assert.Empty(t, s.PeerBytes)
	assert.Equal(t, uint64(40), s.BytesDown)
}

// With no one polling, departed clients are still pruned as new ones arrive,
// so memory does not grow with lifetime client churn.
func TestRelayStats_PrunesWithoutSnapshots(t *testing.T) {
	now := time.Unix(1_000, 0)
	r := relayStats{now: func() time.Time { return now }}
	r.begin()
	old := counter(10, 1)
	r.record(1, "203.0.113.7:1000", old)
	r.record(-1, "203.0.113.7:1000", old)
	now = now.Add(relayRetention + time.Second)
	r.record(1, "198.51.100.9:2000", counter(5, 0))
	r.mu.Lock()
	_, kept := r.ips["203.0.113.7"]
	r.mu.Unlock()
	assert.False(t, kept)
	assert.Equal(t, uint64(15), r.snapshot(true).BytesDown)
}

// Stop drops the close events of connections still open, so a stopped
// session's open connections are retired by time: still read live for the
// retention window, then folded into the totals, which never go backwards.
func TestRelayStats_RetiresOpenConnectionsAfterStop(t *testing.T) {
	now := time.Unix(1_000, 0)
	r := relayStats{now: func() time.Time { return now }}
	r.begin()
	c := counter(100, 10)
	r.record(1, "203.0.113.7:1000", c)
	r.end()
	c.AddDown(20) // bytes moved while the box closed
	assert.Equal(t, uint64(120), r.snapshot(false).BytesDown)

	now = now.Add(relayRetention + time.Second)
	s := r.snapshot(false)
	assert.Equal(t, uint64(120), s.BytesDown, "folded, not lost")
	assert.Equal(t, uint64(10), s.BytesUp)
	assert.Empty(t, s.PeerBytes)
	r.mu.Lock()
	assert.Empty(t, r.conns, "the counter is no longer held")
	r.mu.Unlock()
}

// A listener callback from the previous session can pass its drain check,
// stall, and resume after Stop→Start. Its generation is stale, so its counter
// is not counted in the new session or held by it.
func TestRelayStats_IgnoresCallbacksFromAnEarlierSession(t *testing.T) {
	var r relayStats
	old := r.begin()
	r.end()
	current := r.begin()
	require.NotEqual(t, old, current)

	stale := counter(500, 50)
	r.recordFor(old, 1, "203.0.113.7:1000", stale)
	r.recordFor(current, 1, "198.51.100.9:2000", counter(7, 3))
	s := r.snapshot(true)
	assert.Equal(t, uint64(7), s.BytesDown)
	assert.Equal(t, []string{"198.51.100.9:2000"}, s.Peers)
	r.mu.Lock()
	_, held := r.conns[stale]
	r.mu.Unlock()
	assert.False(t, held)
}

// Like Unbounded's, the epoch is fixed for the process and totals carry
// across sessions, so a Stop and Start between two of the app's polls loses
// none of the stopped session's bytes; its open connections fold in at begin.
func TestRelayStats_TotalsCarryAcrossSessions(t *testing.T) {
	now := time.Unix(1_000, 0)
	r := relayStats{now: func() time.Time { return now }}
	gen := r.begin()
	first := r.snapshot(true).Epoch
	c := counter(10, 1)
	r.recordFor(gen, 1, "203.0.113.7:1000", c)
	r.end()
	assert.Empty(t, r.snapshot(false).Peers, "a stopped session lists no peers")

	c.AddDown(5) // relayed after the last poll, while the box closed
	now = now.Add(time.Second)
	gen = r.begin()
	s := r.snapshot(true)
	assert.Equal(t, first, s.Epoch)
	assert.Equal(t, uint64(15), s.BytesDown, "nothing lost across the restart")
	assert.Equal(t, []PeerBytes{{IP: "203.0.113.7", Down: 15, Up: 1}}, s.PeerBytes)

	r.recordFor(gen, 1, "198.51.100.9:2000", counter(7, 0))
	assert.Equal(t, uint64(22), r.snapshot(true).BytesDown)
}

// closeBox can return before the old box finishes closing, so a stopped
// session's connections can keep moving bytes after the next begin. Their
// counters stay readable, though no longer listed as peers, until retention
// ends, and are then folded into the totals with nothing lost.
func TestRelayStats_DrainingCountersSurviveARestart(t *testing.T) {
	now := time.Unix(1_000, 0)
	r := relayStats{now: func() time.Time { return now }}
	gen := r.begin()
	old := counter(10, 1)
	r.recordFor(gen, 1, "203.0.113.7:1000", old)
	r.end()
	r.begin()

	old.AddDown(5) // still draining in the old box
	s := r.snapshot(true)
	assert.Equal(t, uint64(15), s.BytesDown)
	assert.Empty(t, s.Peers, "a retired connection is not a current peer")
	assert.Equal(t, []PeerBytes{{IP: "203.0.113.7", Down: 15, Up: 1}}, s.PeerBytes)

	now = now.Add(relayRetention + time.Second)
	s = r.snapshot(true)
	assert.Equal(t, uint64(15), s.BytesDown, "folded at retention, never backwards")
	r.mu.Lock()
	assert.Empty(t, r.conns, "the counter is released")
	r.mu.Unlock()
	old.AddDown(100) // after the fold the counter is no longer read
	assert.Equal(t, uint64(15), r.snapshot(true).BytesDown)
}

// A verifier accept can pass the drain check, stall, and resume after Stop,
// where isVerifierConn no longer recognizes it. end advances the generation,
// so the late event is not counted in the stopped session.
func TestRelayStats_IgnoresEventsAfterEnd(t *testing.T) {
	var r relayStats
	gen := r.begin()
	r.end()
	r.recordFor(gen, 1, "35.233.177.182:33792", counter(500, 50))
	s := r.snapshot(false)
	assert.Zero(t, s.BytesDown)
	assert.Empty(t, s.PeerBytes)
}

// Connections without a counter, and closes with no recorded accept, are
// ignored rather than miscounted.
func TestRelayStats_IgnoresUncountedAndUnmatchedEvents(t *testing.T) {
	var r relayStats
	r.begin()
	r.record(1, "203.0.113.7:1000", nil)
	r.record(-1, "203.0.113.7:1001", counter(5, 5))
	s := r.snapshot(true)
	assert.Zero(t, s.BytesDown)
	assert.Empty(t, s.PeerBytes)
}

// End to end through a started client: counted connections show up in
// RelaySnapshot, and lantern-cloud's verifier does not.
func TestClient_RelaySnapshot(t *testing.T) {
	fwd := &fakeForwarder{externalIP: "203.0.113.42"}
	c := newTestClient(t, fwd, &fakeBoxService{}, newStubServer(t))
	ctx := context.Background()
	require.NoError(t, c.Start(ctx))

	client := counter(0, 0)
	peerconn.Notify(peerconn.Event{State: +1, Source: "5.119.14.105:10304", Destination: "google.com:443", Bytes: client})
	peerconn.Notify(peerconn.Event{State: +1, Source: "35.233.177.182:33792", Destination: "api.iantem.io:443", Bytes: counter(500, 50)})
	client.AddDown(1200)
	client.AddUp(300)

	s := c.RelaySnapshot()
	assert.True(t, s.Running)
	assert.NotEmpty(t, s.Epoch)
	assert.Equal(t, uint64(1200), s.BytesDown)
	assert.Equal(t, uint64(300), s.BytesUp)
	assert.Equal(t, []string{"5.119.14.105:10304"}, s.Peers)
	assert.Equal(t, []PeerBytes{{IP: "5.119.14.105", Down: 1200, Up: 300}}, s.PeerBytes)

	require.NoError(t, c.Stop(ctx))
	s = c.RelaySnapshot()
	assert.False(t, s.Running)
	assert.Equal(t, uint64(1200), s.BytesDown, "a poll after Stop still sees the final bytes")
}

const (
	usagePairingA = "11111111-1111-4111-8111-111111111111"
	usagePairingB = "22222222-2222-4222-8222-222222222222"
)

func TestRelayStats_UsageAddsUpPairedAndTotal(t *testing.T) {
	var r relayStats
	gen := r.begin()
	pool, a, b := counter(100, 10), counter(50, 5), counter(7, 3)
	r.recordPairingFor(gen, 1, "203.0.113.7:1000", "", pool)
	r.recordPairingFor(gen, 1, "203.0.113.8:1000", usagePairingA, a)
	r.recordPairingFor(gen, 1, "203.0.113.9:1000", usagePairingB, b)

	assert.Equal(t, RelayUsage{RelayedBytes: 175, PairedBytes: []helper.PairedBytes{
		{PairingID: usagePairingA, Bytes: 55}, {PairingID: usagePairingB, Bytes: 10}}}, r.takeUsage())

	a.AddDown(45)
	r.recordPairingFor(gen, -1, "203.0.113.8:1000", usagePairingA, a)
	a.AddDown(1000) // a closed connection is no longer read
	pool.AddUp(1)
	assert.Equal(t, RelayUsage{RelayedBytes: 46, PairedBytes: []helper.PairedBytes{
		{PairingID: usagePairingA, Bytes: 45}}}, r.takeUsage())
	assert.Equal(t, RelayUsage{}, r.takeUsage(), "nothing new, nothing to report")
	assert.Equal(t, uint64(202), r.snapshot(true).BytesDown, "taking usage leaves the snapshot's totals alone")
}

func TestRelayStats_RestoredUsageIsReportedAgain(t *testing.T) {
	var r relayStats
	gen := r.begin()
	a := counter(1000, 24)
	r.recordPairingFor(gen, 1, "203.0.113.8:1000", usagePairingA, a)
	failed := r.takeUsage()
	a.AddUp(1)
	r.restoreUsage(failed)
	assert.Equal(t, RelayUsage{RelayedBytes: 1025, PairedBytes: []helper.PairedBytes{
		{PairingID: usagePairingA, Bytes: 1025}}}, r.takeUsage())
}

func TestRelayStats_LateAttributionCreditsThePairing(t *testing.T) {
	var r relayStats
	gen := r.begin()
	a := counter(300, 0)
	r.recordPairingFor(gen, 1, "203.0.113.8:1000", "", a)
	r.setPairing(a, usagePairingA)
	assert.Equal(t, RelayUsage{RelayedBytes: 300, PairedBytes: []helper.PairedBytes{
		{PairingID: usagePairingA, Bytes: 300}}}, r.takeUsage(),
		"bytes not yet reported go to the pairing the connection turned out to belong to")
}

func TestRelayStats_UsageSurvivesSessionEnd(t *testing.T) {
	now := time.Unix(1000, 0)
	r := relayStats{now: func() time.Time { return now }}
	gen := r.begin()
	a := counter(10, 0)
	r.recordPairingFor(gen, 1, "203.0.113.8:1000", usagePairingA, a)
	r.end()
	now = now.Add(relayRetention + time.Second)
	_ = r.snapshot(false) // prunes the ended session's connections
	assert.Equal(t, RelayUsage{RelayedBytes: 10, PairedBytes: []helper.PairedBytes{
		{PairingID: usagePairingA, Bytes: 10}}}, r.takeUsage())
}

func TestRelayStats_UsageCreditsEachConnectionsOwnPairing(t *testing.T) {
	for _, other := range []string{"", usagePairingB} {
		var r relayStats
		gen := r.begin()
		a, o := counter(40, 2), counter(500, 9)
		r.recordPairingFor(gen, 1, "203.0.113.8:1000", usagePairingA, a)
		r.recordPairingFor(gen, 1, "203.0.113.8:2000", other, o)
		want := []helper.PairedBytes{{PairingID: usagePairingA, Bytes: 42}}
		if other != "" {
			want = append(want, helper.PairedBytes{PairingID: other, Bytes: 509})
		}
		assert.Equal(t, RelayUsage{RelayedBytes: 551, PairedBytes: want}, r.takeUsage(),
			"same IP, other pairing %q: each connection credits only its own pairing", other)
	}
}
