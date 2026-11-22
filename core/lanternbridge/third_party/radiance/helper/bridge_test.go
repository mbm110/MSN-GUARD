package helper

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/broflake/common/helperticket"
	lbO "github.com/getlantern/lantern-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/helper/reverse"
)

const (
	bridgePairingA = "7a1c2b0e-8a7d-4c1e-9f00-00000000000a"
	bridgePairingB = "7a1c2b0e-8a7d-4c1e-9f00-00000000000b"
	bridgeConfig1  = `{"route":{"final":"direct"}}`
	bridgeConfig2  = `{"route":{"final":"direct","rules":[]}}`
	testPoll       = 150 * time.Second
)

var bridgeEpoch = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

type fakeBridgeKeys struct {
	mu   sync.Mutex
	keys map[string]PairingKey
}

func (k *fakeBridgeKeys) Get(id string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	pk, ok := k.keys[id]
	return bytes.Clone(pk.Key), ok
}

func (k *fakeBridgeKeys) IDs(role string) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var ids []string
	for id, pk := range k.keys {
		if pk.Role == role {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

func volunteerKey(b byte) PairingKey {
	return PairingKey{Key: bytes.Repeat([]byte{b}, 32), Role: string(helperticket.RoleVolunteer)}
}

type fakeBridgeBox struct {
	config  string
	count   func(tag string, n int64)
	mu      sync.Mutex
	started bool
	closed  bool
	sets    []map[string]*lbO.SamizdatBridgeInboundOptions
}

func (f *fakeBridgeBox) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = true
	return nil
}

func (f *fakeBridgeBox) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeBridgeBox) SetBridges(m map[string]*lbO.SamizdatBridgeInboundOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, maps.Clone(m))
	return nil
}

func (f *fakeBridgeBox) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeBridgeBox) last() map[string]*lbO.SamizdatBridgeInboundOptions {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sets) == 0 {
		return nil
	}
	return f.sets[len(f.sets)-1]
}

// bridgeAPI serves /helper/reverse/routes from whatever reply holds.
type bridgeAPI struct {
	mu     sync.Mutex
	status int
	resp   ReverseRoutesResponse
	calls  atomic.Int32
	block  chan struct{}
}

func (a *bridgeAPI) set(status int, resp ReverseRoutesResponse) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status, a.resp = status, resp
}

type bridgeHarness struct {
	t      *testing.T
	api    *bridgeAPI
	keys   *fakeBridgeKeys
	usage  *Usage
	now    time.Time
	nowMu  sync.Mutex
	boxes  []*fakeBridgeBox
	boxMu  sync.Mutex
	client *BridgeClient
}

func newBridgeHarness(t *testing.T) *bridgeHarness {
	h := &bridgeHarness{
		t:     t,
		api:   &bridgeAPI{status: http.StatusOK},
		keys:  &fakeBridgeKeys{keys: map[string]PairingKey{bridgePairingA: volunteerKey(1), bridgePairingB: volunteerKey(2)}},
		usage: &Usage{},
		now:   bridgeEpoch,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.api.calls.Add(1)
		if r.URL.Path != "/v1/helper/reverse/routes" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		if h.api.block != nil {
			select {
			case <-h.api.block:
			case <-r.Context().Done():
			}
		}
		h.api.mu.Lock()
		status, resp := h.api.status, h.api.resp
		h.api.mu.Unlock()
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	h.client = NewBridgeClient(BridgeConfig{
		API:  NewReverseAPI(srv.Client(), srv.URL+"/v1", testReverseDevice),
		Keys: h.keys,
		NewBox: func(_ context.Context, cfg string, count func(string, int64)) (BridgeBox, error) {
			box := &fakeBridgeBox{config: cfg, count: count}
			h.boxMu.Lock()
			h.boxes = append(h.boxes, box)
			h.boxMu.Unlock()
			return box, nil
		},
		Usage:        h.usage,
		Now:          h.clock,
		PollInterval: testPoll,
	})
	return h
}

func (h *bridgeHarness) clock() time.Time {
	h.nowMu.Lock()
	defer h.nowMu.Unlock()
	return h.now
}

func (h *bridgeHarness) advance(d time.Duration) {
	h.nowMu.Lock()
	defer h.nowMu.Unlock()
	h.now = h.now.Add(d)
}

func (h *bridgeHarness) allBoxes() []*fakeBridgeBox {
	h.boxMu.Lock()
	defer h.boxMu.Unlock()
	return slices.Clone(h.boxes)
}

func (h *bridgeHarness) cycle() time.Duration {
	return h.client.cycle(context.Background())
}

func testRoute(issued time.Time) reverse.Route {
	r := reverse.Route{
		Addrs: []netip.AddrPort{
			netip.MustParseAddrPort("203.0.113.7:4443"),
			netip.MustParseAddrPort("[2001:db8::7]:4443"),
		},
		CoverDomain: "cover.example",
		IssuedAt:    issued,
	}
	for i := range r.PublicKey {
		r.PublicKey[i] = byte(i)
		r.CertSPKISHA256[i] = byte(0xff - i)
	}
	return r
}

func (h *bridgeHarness) seal(pairingID string, r reverse.Route) ReverseBlob {
	h.t.Helper()
	key, ok := h.keys.Get(pairingID)
	require.True(h.t, ok)
	blob, err := reverse.Seal(key, pairingID, r)
	require.NoError(h.t, err)
	return ReverseBlob{PairingID: pairingID, Blob: blob, Version: reverse.BlobVersion}
}

func (h *bridgeHarness) wantOptions(pairingID string, r reverse.Route) *lbO.SamizdatBridgeInboundOptions {
	key, _ := h.keys.Get(pairingID)
	sid := reverse.ShortID(key, reverse.Epoch(h.clock()))
	return &lbO.SamizdatBridgeInboundOptions{
		Addrs:          []string{"203.0.113.7:4443", "[2001:db8::7]:4443"},
		PublicKey:      hex.EncodeToString(r.PublicKey[:]),
		ShortID:        hex.EncodeToString(sid[:]),
		ServerName:     r.CoverDomain,
		CertSPKISHA256: hex.EncodeToString(r.CertSPKISHA256[:]),
	}
}

func TestBridgeRouteBecomesOneBridge(t *testing.T) {
	h := newBridgeHarness(t)
	r := testRoute(h.clock())
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, r)}, BridgeConfig: bridgeConfig1})

	assert.Equal(t, testPoll, h.cycle())

	boxes := h.allBoxes()
	require.Len(t, boxes, 1)
	assert.Equal(t, bridgeConfig1, boxes[0].config)
	assert.True(t, boxes[0].started)
	assert.Equal(t, map[string]*lbO.SamizdatBridgeInboundOptions{
		BridgeTag(bridgePairingA): h.wantOptions(bridgePairingA, r),
	}, boxes[0].last())
}

func TestBridgeTagIsAStablePseudonym(t *testing.T) {
	tag := BridgeTag(bridgePairingA)
	assert.Regexp(t, `^bridge-[0-9a-f]{12}$`, tag)
	assert.Equal(t, tag, BridgeTag(bridgePairingA))
	assert.NotEqual(t, tag, BridgeTag(bridgePairingB))
	assert.NotContains(t, tag, bridgePairingA)
}

func TestBridgeSkipsUnusableRoutesWithoutLoggingThem(t *testing.T) {
	var logs bytes.Buffer
	h := newBridgeHarness(t)
	h.client.cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	const unknown, inviter = "7a1c2b0e-0000-0000-0000-0000000000cc", "7a1c2b0e-0000-0000-0000-0000000000dd"
	h.keys.keys[inviter] = PairingKey{Key: bytes.Repeat([]byte{4}, 32), Role: string(helperticket.RoleInviter)}
	now := h.clock()
	good := h.seal(bridgePairingA, testRoute(now))
	stale := h.seal(bridgePairingB, testRoute(now.Add(-reverse.MaxBlobAge-time.Minute)))
	tampered := h.seal(bridgePairingB, testRoute(now))
	tampered.Blob[len(tampered.Blob)-1] ^= 1
	h.keys.keys[unknown] = volunteerKey(3)
	forUnknown := h.seal(unknown, testRoute(now))
	delete(h.keys.keys, unknown)
	forInviter := h.seal(inviter, testRoute(now))
	h.api.set(http.StatusOK, ReverseRoutesResponse{
		Routes:       []ReverseBlob{good, stale, tampered, forUnknown, forInviter},
		BridgeConfig: bridgeConfig1,
	})

	h.cycle()

	boxes := h.allBoxes()
	require.Len(t, boxes, 1)
	assert.Equal(t, []string{BridgeTag(bridgePairingA)}, slices.Collect(maps.Keys(boxes[0].last())))
	out := logs.String()
	assert.Contains(t, out, "bridge: skipped reverse routes")
	opts := h.wantOptions(bridgePairingA, testRoute(now))
	for _, secret := range []string{bridgePairingA, bridgePairingB, unknown, inviter, BridgeTag(bridgePairingA),
		"203.0.113.7", "2001:db8::7", "cover.example", opts.ShortID, opts.PublicKey, opts.CertSPKISHA256} {
		assert.NotContains(t, out, secret)
	}
}

func TestBridgeFollowsRouteChanges(t *testing.T) {
	h := newBridgeHarness(t)
	r := testRoute(h.clock())
	a, b := h.seal(bridgePairingA, r), h.seal(bridgePairingB, r)
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{a, b}, BridgeConfig: bridgeConfig1})
	h.cycle()
	require.Len(t, h.allBoxes(), 1)
	box := h.allBoxes()[0]
	assert.Len(t, box.last(), 2)

	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{a}, BridgeConfig: bridgeConfig1})
	h.cycle()
	assert.Len(t, h.allBoxes(), 1, "a route change reuses the box")
	assert.Equal(t, []string{BridgeTag(bridgePairingA)}, slices.Collect(maps.Keys(box.last())))
	assert.False(t, box.isClosed())

	h.api.set(http.StatusOK, ReverseRoutesResponse{BridgeConfig: bridgeConfig1})
	h.cycle()
	assert.True(t, box.isClosed(), "no routes closes the box")
	assert.Len(t, h.allBoxes(), 1)
}

func TestBridgeRebuildsTheBoxWhenTheConfigChanges(t *testing.T) {
	h := newBridgeHarness(t)
	r := testRoute(h.clock())
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, r)}, BridgeConfig: bridgeConfig1})
	h.cycle()
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, r)}, BridgeConfig: bridgeConfig2})
	h.cycle()

	boxes := h.allBoxes()
	require.Len(t, boxes, 2)
	assert.True(t, boxes[0].isClosed())
	assert.False(t, boxes[1].isClosed())
	assert.Equal(t, bridgeConfig2, boxes[1].config)
	assert.Len(t, boxes[1].last(), 1)
}

func TestBridgeRunsNothingWithoutABridgeConfig(t *testing.T) {
	h := newBridgeHarness(t)
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, testRoute(h.clock()))}})
	h.cycle()
	assert.Empty(t, h.allBoxes())
}

func TestBridgeShortIDFollowsTheEpoch(t *testing.T) {
	h := newBridgeHarness(t)
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, testRoute(h.clock()))}, BridgeConfig: bridgeConfig1})
	h.cycle()
	box := h.allBoxes()[0]
	first := box.last()[BridgeTag(bridgePairingA)].ShortID

	h.advance(reverse.EpochLength)
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, testRoute(h.clock()))}, BridgeConfig: bridgeConfig1})
	h.cycle()
	next := box.last()[BridgeTag(bridgePairingA)].ShortID
	assert.NotEqual(t, first, next)
	assert.Equal(t, h.wantOptions(bridgePairingA, testRoute(h.clock())).ShortID, next)
}

func TestBridgeSkipsTheAPIWithoutVolunteerPairings(t *testing.T) {
	h := newBridgeHarness(t)
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, testRoute(h.clock()))}, BridgeConfig: bridgeConfig1})
	h.cycle()
	box := h.allBoxes()[0]

	h.keys.mu.Lock()
	clear(h.keys.keys)
	h.keys.mu.Unlock()
	calls := h.api.calls.Load()
	assert.Equal(t, testPoll, h.cycle())
	assert.Equal(t, calls, h.api.calls.Load())
	assert.True(t, box.isClosed())
}

func TestBridgeBacksOffWhileBusyAndIdlesWhileDisabled(t *testing.T) {
	h := newBridgeHarness(t)
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, testRoute(h.clock()))}, BridgeConfig: bridgeConfig1})
	h.cycle()
	box := h.allBoxes()[0]

	h.api.set(http.StatusServiceUnavailable, ReverseRoutesResponse{})
	wait := h.cycle()
	assert.Equal(t, 2*testPoll, wait)
	calls := h.api.calls.Load()
	h.advance(wait / 2)
	assert.Equal(t, wait/2, h.cycle(), "a cycle inside the back-off waits out the rest")
	assert.Equal(t, calls, h.api.calls.Load())
	h.advance(wait / 2)
	h.api.set(http.StatusTooManyRequests, ReverseRoutesResponse{})
	wait = h.cycle()
	assert.Equal(t, 4*testPoll, wait)
	h.advance(wait)
	wait = h.cycle()
	assert.Equal(t, maxBridgeBackoff, wait)
	assert.False(t, box.isClosed(), "a busy server keeps the bridges")

	h.advance(wait)
	h.api.set(http.StatusInternalServerError, ReverseRoutesResponse{})
	assert.Equal(t, testPoll, h.cycle())

	h.api.set(http.StatusNotFound, ReverseRoutesResponse{})
	assert.Equal(t, bridgeDisabledWait, h.cycle())
	assert.True(t, box.isClosed())

	h.advance(bridgeDisabledWait)
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, testRoute(h.clock()))}, BridgeConfig: bridgeConfig1})
	assert.Equal(t, testPoll, h.cycle())
	h.api.set(http.StatusServiceUnavailable, ReverseRoutesResponse{})
	assert.Equal(t, 2*testPoll, h.cycle(), "a success resets the backoff")
}

// Restarting the client, as the widget does, does not cut short its
// hold-off on lantern-cloud.
func TestBridgeRestartKeepsTheHoldOff(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			h := newBridgeHarness(t)
			h.api.set(status, ReverseRoutesResponse{})
			h.cycle()
			require.EqualValues(t, 1, h.api.calls.Load())

			h.client.SetRunning(context.Background(), true)
			h.client.SetRunning(context.Background(), false)
			h.client.SetRunning(context.Background(), true)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				h.client.Stop(ctx)
			})
			time.Sleep(100 * time.Millisecond)
			assert.EqualValues(t, 1, h.api.calls.Load())
		})
	}
}

func TestBridgeCountsBytesUnderThePairing(t *testing.T) {
	h := newBridgeHarness(t)
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, testRoute(h.clock()))}, BridgeConfig: bridgeConfig1})
	h.cycle()
	box := h.allBoxes()[0]

	box.count(BridgeTag(bridgePairingA), 100)
	box.count(BridgeTag(bridgePairingA), 23)
	box.count("bridge-000000000000", 7)
	box.count(BridgeTag(bridgePairingA), -1)

	// A bridge removed while a connection drains is still credited.
	h.api.set(http.StatusOK, ReverseRoutesResponse{BridgeConfig: bridgeConfig1})
	h.cycle()
	box.count(BridgeTag(bridgePairingA), 2)

	assert.Equal(t, []PairedBytes{{PairingID: bridgePairingA, Bytes: 125}}, h.usage.Take())
}

func TestBridgeSetRunningFollowsTheWidget(t *testing.T) {
	h := newBridgeHarness(t)
	h.client.cfg.PollInterval = 10 * time.Millisecond
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, testRoute(h.clock()))}, BridgeConfig: bridgeConfig1})

	h.client.SetRunning(context.Background(), true)
	h.client.SetRunning(context.Background(), true)
	require.Eventually(t, func() bool { return len(h.allBoxes()) == 1 && h.allBoxes()[0].last() != nil }, 5*time.Second, 5*time.Millisecond)

	h.client.SetRunning(context.Background(), false)
	require.Eventually(t, func() bool { return h.allBoxes()[0].isClosed() }, 5*time.Second, 5*time.Millisecond)

	// Restarting builds a fresh box.
	h.client.SetRunning(context.Background(), true)
	require.Eventually(t, func() bool { return len(h.allBoxes()) == 2 }, 5*time.Second, 5*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.client.Stop(ctx)
	assert.True(t, h.allBoxes()[1].isClosed(), "Stop waits for the box to close")
}

// A run whose context ended does not keep a later start from running.
func TestBridgeRestartsAfterItsContextEnds(t *testing.T) {
	h := newBridgeHarness(t)
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, testRoute(h.clock()))}, BridgeConfig: bridgeConfig1})
	ctx, cancel := context.WithCancel(context.Background())
	h.client.SetRunning(ctx, true)
	require.Eventually(t, func() bool { return len(h.allBoxes()) == 1 }, 5*time.Second, 5*time.Millisecond)
	cancel()
	require.Eventually(t, func() bool { return h.allBoxes()[0].isClosed() }, 5*time.Second, 5*time.Millisecond)

	h.client.SetRunning(context.Background(), true)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h.client.Stop(ctx)
	})
	require.Eventually(t, func() bool { return len(h.allBoxes()) == 2 }, 5*time.Second, 5*time.Millisecond)
}

// A volunteer pairing added between polls is polled for at once, unless
// lantern-cloud asked the client to back off.
func TestBridgePollsForANewPairingAtOnce(t *testing.T) {
	for _, busy := range []bool{false, true} {
		t.Run(fmt.Sprintf("busy=%v", busy), func(t *testing.T) {
			h := newBridgeHarness(t)
			h.revoke(bridgePairingB)
			r := testRoute(h.clock())
			if busy {
				h.api.set(http.StatusServiceUnavailable, ReverseRoutesResponse{})
			} else {
				h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, r)}, BridgeConfig: bridgeConfig1})
			}
			// Each PairingsChanged waits for the poll before it to finish, so
			// it never interrupts one in flight, which is retried at once.
			cycled := make(chan struct{}, 8)
			h.client.cycled = func() {
				select {
				case cycled <- struct{}{}:
				default:
				}
			}
			waitCycle := func() {
				t.Helper()
				select {
				case <-cycled:
				case <-time.After(5 * time.Second):
					t.Fatal("the client never finished a poll")
				}
			}
			h.client.SetRunning(context.Background(), true)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				h.client.Stop(ctx)
			})
			waitCycle()
			require.Equal(t, int32(1), h.api.calls.Load())

			h.keys.mu.Lock()
			h.keys.keys[bridgePairingB] = volunteerKey(2)
			h.keys.mu.Unlock()
			h.client.PairingsChanged()
			if busy {
				time.Sleep(100 * time.Millisecond)
				assert.Equal(t, int32(1), h.api.calls.Load(), "a backed-off client waits")
				return
			}
			waitCycle()
			require.Equal(t, int32(2), h.api.calls.Load())

			h.client.PairingsChanged()
			time.Sleep(100 * time.Millisecond)
			assert.Equal(t, int32(2), h.api.calls.Load(), "pairings already polled for wait for the next poll")
		})
	}
}

func TestBridgeSetRunningNeverBlocksOnTheAPI(t *testing.T) {
	h := newBridgeHarness(t)
	h.api.block = make(chan struct{})
	defer close(h.api.block)

	h.client.SetRunning(context.Background(), true)
	require.Eventually(t, func() bool { return h.api.calls.Load() == 1 }, 5*time.Second, 5*time.Millisecond)
	returned := make(chan struct{})
	go func() {
		h.client.SetRunning(context.Background(), false)
		h.client.SetRunning(context.Background(), true)
		h.client.SetRunning(context.Background(), false)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("SetRunning blocked on a poll in flight")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.client.Stop(ctx)
	assert.NoError(t, ctx.Err(), "stopping cancels the poll in flight")
}

func (h *bridgeHarness) revoke(pairingID string) {
	h.keys.mu.Lock()
	defer h.keys.mu.Unlock()
	delete(h.keys.keys, pairingID)
}

// A revoked pairing's bridge closes on the next cycle even while
// lantern-cloud fails or is backed off from, and the rest keep running.
func TestBridgeDropsARevokedPairingWhileTheAPIFails(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			h := newBridgeHarness(t)
			r := testRoute(h.clock())
			h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, r), h.seal(bridgePairingB, r)}, BridgeConfig: bridgeConfig1})
			h.cycle()
			box := h.allBoxes()[0]
			require.Len(t, box.last(), 2)

			h.api.set(status, ReverseRoutesResponse{})
			h.revoke(bridgePairingA)
			h.cycle()
			assert.Equal(t, map[string]*lbO.SamizdatBridgeInboundOptions{
				BridgeTag(bridgePairingB): h.wantOptions(bridgePairingB, r),
			}, box.last())
			assert.False(t, box.isClosed())

			h.revoke(bridgePairingB)
			h.cycle()
			assert.True(t, box.isClosed())
		})
	}
}

func TestBridgePairingsChangedDropsWithoutTheAPI(t *testing.T) {
	h := newBridgeHarness(t)
	r := testRoute(h.clock())
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, r), h.seal(bridgePairingB, r)}, BridgeConfig: bridgeConfig1})
	h.client.SetRunning(context.Background(), true)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h.client.Stop(ctx)
	})
	require.Eventually(t, func() bool { return len(h.allBoxes()) == 1 && len(h.allBoxes()[0].last()) == 2 }, 5*time.Second, 5*time.Millisecond)
	calls := h.api.calls.Load()

	h.revoke(bridgePairingA)
	h.client.PairingsChanged()
	box := h.allBoxes()[0]
	require.Eventually(t, func() bool { return len(box.last()) == 1 }, 5*time.Second, 5*time.Millisecond)
	assert.Contains(t, box.last(), BridgeTag(bridgePairingB))
	assert.Equal(t, calls, h.api.calls.Load())
}

// A revocation closes its bridge at once even while a poll is stuck.
func TestBridgeRevocationDoesNotWaitForAPollInFlight(t *testing.T) {
	h := newBridgeHarness(t)
	r := testRoute(h.clock())
	h.api.set(http.StatusOK, ReverseRoutesResponse{Routes: []ReverseBlob{h.seal(bridgePairingA, r), h.seal(bridgePairingB, r)}, BridgeConfig: bridgeConfig1})
	h.cycle()
	box := h.allBoxes()[0]
	require.Len(t, box.last(), 2)

	block := make(chan struct{})
	h.api.block = block
	calls := h.api.calls.Load()
	h.client.SetRunning(context.Background(), true)
	t.Cleanup(func() {
		close(block)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h.client.Stop(ctx)
	})
	require.Eventually(t, func() bool { return h.api.calls.Load() > calls }, 5*time.Second, 5*time.Millisecond)

	h.revoke(bridgePairingA)
	h.client.PairingsChanged()
	require.Eventually(t, func() bool { return len(box.last()) == 1 }, time.Second, 5*time.Millisecond)
	assert.Contains(t, box.last(), BridgeTag(bridgePairingB))
	assert.False(t, box.isClosed())
}

func TestPairingWatchCancelsOnlyAfterItsSnapshot(t *testing.T) {
	var w PairingWatch
	snap := w.Snapshot()
	ctx, release := w.Watch(context.Background(), snap)
	assert.NoError(t, ctx.Err())
	w.Changed()
	assert.Error(t, ctx.Err(), "a change cancels the call in flight")
	release()

	ctx, release = w.Watch(context.Background(), snap)
	assert.Error(t, ctx.Err(), "a change since the snapshot cancels at once")
	release()

	ctx, release = w.Watch(context.Background(), w.Snapshot())
	release()
	w.Changed()
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "release cancels its own ctx")
}
