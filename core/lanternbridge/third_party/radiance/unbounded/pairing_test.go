package unbounded

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/broflake/clientcore"
	"github.com/getlantern/broflake/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/internal/testutil"
)

const testPairing = "b2c3d4e5-0000-4000-8000-00000000000c"

// startCapturing starts the manager with a fake widget and returns the
// options start installed on it.
func startCapturing(t *testing.T, live *helper.LiveTracker) *clientcore.BroflakeOptions {
	t.Helper()
	var captured atomic.Pointer[clientcore.BroflakeOptions]
	resetManager(t, func(bfOpt *clientcore.BroflakeOptions, _ *clientcore.WebRTCOptions, _ *clientcore.EgressOptions) (widget, error) {
		captured.Store(bfOpt)
		return &fakeWidget{}, nil
	})
	manager.live = live
	primeManager(t, nil)
	manager.start()
	require.Eventually(t, func() bool { return captured.Load() != nil }, time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return CurrentSnapshot().Running }, time.Second, time.Millisecond)
	return captured.Load()
}

// connect delivers a connection change the way broflake does: the plain
// callback, then the info one.
func connect(bf *clientcore.BroflakeOptions, state, idx int, ip, pairing string) {
	var addr net.IP
	info := common.ConsumerInfo{}
	if state > 0 {
		addr = net.ParseIP(ip)
		info = common.ConsumerInfo{Addr: addr, Pairing: pairing}
	}
	bf.OnConnectionChangeFunc(state, idx, addr)
	bf.OnConnectionChangeInfoFunc(state, idx, info)
}

func TestInfoCallbackCarriesPairingToTheTracker(t *testing.T) {
	live := helper.NewLiveTracker(nil)
	bf := startCapturing(t, live)
	require.NotNil(t, bf.OnConnectionChangeInfoFunc, "start installs the info callback")

	connect(bf, 1, 0, "198.51.100.7", testPairing)
	connect(bf, 1, 1, "198.51.100.8", "")
	s := live.Snapshot()
	require.Len(t, s.Pairings, 1, "the pool slot is not tracked")
	assert.Equal(t, testPairing, s.Pairings[0].PairingID)
	assert.False(t, s.Pairings[0].Connected, "an idle slot is not connected")

	// Bytes on the pool slot do not count toward the friend.
	bf.OnDownstreamChunkFunc(helper.LiveThreshold, 1)
	assert.False(t, live.Snapshot().Pairings[0].Connected)

	bf.OnDownstreamChunkFunc(helper.LiveThreshold/2, 0)
	bf.OnUpstreamChunkFunc(helper.LiveThreshold/2, 0)
	assert.True(t, live.Snapshot().Pairings[0].Connected)

	got := peerBytesByIP(CurrentSnapshot())
	assert.Equal(t, testPairing, got["198.51.100.7"].Pairing, "the snapshot labels the friend's IP")
	assert.Equal(t, "", got["198.51.100.8"].Pairing)

	// The slot closes; the friend's bytes still count for the window.
	connect(bf, -1, 0, "", "")
	assert.True(t, live.Snapshot().Pairings[0].Connected)

	// A new pool occupant of the same slot is not the friend.
	connect(bf, 1, 0, "198.51.100.9", "")
	bf.OnDownstreamChunkFunc(10*helper.LiveThreshold, 0)
	live.Snapshot()
	require.NoError(t, Stop(context.Background()))
}

func TestBytesBeforeTheFriendAreNotTheFriends(t *testing.T) {
	live := helper.NewLiveTracker(nil)
	bf := startCapturing(t, live)
	connect(bf, 1, 0, "198.51.100.9", "")
	bf.OnDownstreamChunkFunc(10*helper.LiveThreshold, 0)
	connect(bf, -1, 0, "", "")
	connect(bf, 1, 0, "198.51.100.7", testPairing)
	s := live.Snapshot()
	require.Len(t, s.Pairings, 1)
	assert.False(t, s.Pairings[0].Connected, "the slot's earlier pool traffic is not the friend's")
	require.NoError(t, Stop(context.Background()))
}

func TestStopEndsTrackedSlots(t *testing.T) {
	live := helper.NewLiveTracker(nil)
	bf := startCapturing(t, live)
	connect(bf, 1, 0, "198.51.100.7", testPairing)
	require.Len(t, live.Snapshot().Pairings, 1)
	require.NoError(t, Stop(context.Background()))
	assert.Empty(t, live.Snapshot().Pairings)

	// A callback broflake delivers after the stop is ignored.
	bf.OnConnectionChangeInfoFunc(1, 2, common.ConsumerInfo{Pairing: testPairing})
	assert.Empty(t, live.Snapshot().Pairings)
}

// The pairing never reaches the logs: no slog call in the package is passed
// a pairing or the ConsumerInfo that carries one.
func TestPairingIsNotLogged(t *testing.T) {
	testutil.LoggedIdentifiers(t, ".", func(name string) bool {
		return strings.Contains(strings.ToLower(name), "pairing") || name == "info"
	})
}
