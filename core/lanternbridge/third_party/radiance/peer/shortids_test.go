package peer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
)

const testBaseShortID = "0011223344556677"

// launchCfgWithShortID is minimalValidLaunchCfg with the base short ID a real
// launch config carries.
func launchCfgWithShortID() string {
	return strings.Replace(minimalValidLaunchCfg,
		`{"type":"samizdat","tag":"samizdat-in"}`,
		`{"type":"samizdat","tag":"samizdat-in","short_ids":["`+testBaseShortID+`"]}`, 1)
}

// pairingState is the client's stored pairing set and whether one is known.
func pairingState(c *Client) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.pairingShortIDs...), c.pairingKnown
}

func TestMergeShortIDs(t *testing.T) {
	assert.Equal(t,
		[]string{testBaseShortID, "1111111111111111", "aaaaaaaaaaaaaaaa"},
		mergeShortIDs([]string{testBaseShortID},
			[]string{"1111111111111111", "bad", "1111111111111111", testBaseShortID, "AAAAAAAAAAAAAAAA", "zzzzzzzzzzzzzzzz"}),
		"base first; invalid, duplicate and base-equal pairing IDs dropped; hex lowercased")
	assert.Equal(t, []string{testBaseShortID}, mergeShortIDs([]string{testBaseShortID}, nil))
}

func TestInboundShortIDs(t *testing.T) {
	assert.Equal(t, []string{testBaseShortID}, inboundShortIDs(launchCfgWithShortID()))
	assert.Empty(t, inboundShortIDs(minimalValidLaunchCfg))
	assert.Empty(t, inboundShortIDs("not json"))
}

func TestClient_StartAddsRegisterPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = time.Hour })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	assert.Equal(t, []string{testBaseShortID, "1111111111111111"}, b.lastShortIDs())
	assert.Equal(t, []string{testBaseShortID, "1111111111111111"}, b.shortIDsAtStart(),
		"the box must hold the pairing IDs before it starts serving")
}

func TestClient_StartIgnoresUnknownRegisterPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = time.Hour })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	assert.Nil(t, b.lastShortIDs(), "a set the server does not vouch for is not applied")
}

func TestClient_WithoutBaseShortIDLeavesInboundAlone(t *testing.T) {
	srv := newStubServer(t) // minimalValidLaunchCfg has no short_ids
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = time.Hour })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	assert.Nil(t, b.lastShortIDs(), "never replace the set without the base ID the verifier uses")
}

func TestClient_HeartbeatReplacesPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.heartbeatShortIDs.Store(&[]string{"2222222222222222"})
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = 20 * time.Millisecond })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID, "2222222222222222"})
	}, 2*time.Second, 10*time.Millisecond)

	// An ended pairing drops out at the next heartbeat; the base ID stays.
	srv.heartbeatShortIDs.Store(&[]string{})
	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID})
	}, 2*time.Second, 10*time.Millisecond)
}

func TestClient_KnownEmptyHeartbeatRevokesPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	srv.heartbeatShortIDs.Store(&[]string{})
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = 20 * time.Millisecond })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID})
	}, 2*time.Second, 10*time.Millisecond, "an authoritative empty set means no pairings")
	ids, known := pairingState(c)
	assert.True(t, known)
	assert.Empty(t, ids)
}

func TestClient_UnknownHeartbeatKeepsPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.heartbeatShortIDs.Store(&[]string{"2222222222222222"})
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = 20 * time.Millisecond })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID, "2222222222222222"})
	}, 2*time.Second, 10*time.Millisecond)

	// The server now answers without the fields, as one without the ticket
	// key or with an unreadable body does.
	srv.heartbeatShortIDs.Store(nil)
	updates := len(b.shortIDUpdates())
	after := srv.heartbeatCount.Load()
	require.Eventually(t, func() bool { return srv.heartbeatCount.Load() >= after+3 }, 2*time.Second, 10*time.Millisecond)

	got := b.shortIDUpdates()
	for _, set := range got[updates:] {
		assert.Equal(t, []string{testBaseShortID, "2222222222222222"}, set,
			"a heartbeat that does not vouch for a set must never revoke")
	}
	assert.Equal(t, []string{testBaseShortID, "2222222222222222"}, b.lastShortIDs())
	ids, known := pairingState(c)
	assert.True(t, known)
	assert.Equal(t, []string{"2222222222222222"}, ids)
}

func TestClient_FailedHeartbeatKeepsPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	srv.heartbeatStatus = http.StatusInternalServerError
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = 20 * time.Millisecond })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	require.Eventually(t, func() bool { return srv.heartbeatCount.Load() >= 3 }, 2*time.Second, 10*time.Millisecond)
	assert.Equal(t, [][]string{{testBaseShortID, "1111111111111111"}}, b.shortIDUpdates(),
		"a failed heartbeat says nothing about pairings, so the last set stays")
}

func TestClient_HeartbeatTransportErrorKeepsPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	srv.heartbeatShortIDs.Store(&[]string{})
	// Each heartbeat outlives its timeout, so the client sees a transport
	// error, never the authoritative empty set the server would send.
	srv.onHeartbeat = func() { time.Sleep(100 * time.Millisecond) }
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) {
		cfg.HeartbeatInterval = 20 * time.Millisecond
		cfg.HeartbeatTimeout = 5 * time.Millisecond
	})
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	require.Eventually(t, func() bool { return srv.heartbeatCount.Load() >= 3 }, 2*time.Second, 10*time.Millisecond)
	assert.Equal(t, [][]string{{testBaseShortID, "1111111111111111"}}, b.shortIDUpdates())
}

func TestClient_FailedShortIDUpdateIsRetried(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = 20 * time.Millisecond })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	b.setUpdateErr(errors.New("refused"))
	srv.heartbeatShortIDs.Store(&[]string{"2222222222222222"})
	waitHeartbeats(t, srv, 3)
	assert.Equal(t, []string{testBaseShortID, "1111111111111111"}, b.lastShortIDs(),
		"a refused set leaves the inbound as it was")
	ids, known := pairingState(c)
	assert.True(t, known)
	assert.Equal(t, []string{"2222222222222222"}, ids, "the record is the server's newest set")

	b.setUpdateErr(nil)
	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID, "2222222222222222"})
	}, 2*time.Second, 10*time.Millisecond)
}

func TestClient_PairingRevisionOrdering(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	srv.registerResp.PairingShortIDsRevision = 100
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = 20 * time.Millisecond })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	withRegister := [][]string{{testBaseShortID, "1111111111111111"}}

	srv.heartbeatRevision.Store(50)
	srv.heartbeatShortIDs.Store(&[]string{"2222222222222222"})
	waitHeartbeats(t, srv, 3)
	assert.Equal(t, withRegister, b.shortIDUpdates(), "an older revision is ignored")

	srv.heartbeatRevision.Store(200)
	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID, "2222222222222222"})
	}, 2*time.Second, 10*time.Millisecond, "a newer revision wins")
}

// The server sends known and its revision together, so a known set without
// a revision is not trusted, at register or heartbeat.
func TestClient_KnownSetWithoutRevisionIsIgnored(t *testing.T) {
	srv := newStubServer(t)
	srv.noRevisions = true
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	srv.heartbeatShortIDs.Store(&[]string{"2222222222222222"})
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = 20 * time.Millisecond })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	waitHeartbeats(t, srv, 3)
	assert.Empty(t, b.shortIDUpdates())
	_, known := pairingState(c)
	assert.False(t, known)
}

// rotatedBoxHas reports whether any box built by a rotation, not by Start,
// was already accepting want when it started.
func rotatedBoxHas(port *portBoxes, want []string) bool {
	port.mu.Lock()
	defer port.mu.Unlock()
	for _, b := range port.boxes[min(1, len(port.boxes)):] {
		if b.started.Load() && slices.Equal(b.shortIDsAtStart(), want) {
			return true
		}
	}
	return false
}

func TestClient_FailedPushIsRetriedOnUnknownHeartbeat(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	// Heartbeats answer without the fields, so none vouches for a set.
	b := &fakeBoxService{updateErr: errors.New("refused")}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = 20 * time.Millisecond })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	assert.Nil(t, b.lastShortIDs(), "the push at Start failed")

	b.setUpdateErr(nil)
	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID, "1111111111111111"})
	}, 2*time.Second, 10*time.Millisecond, "a heartbeat pushes the recorded set the box does not hold")
	after := srv.heartbeatCount.Load()
	require.Eventually(t, func() bool { return srv.heartbeatCount.Load() >= after+3 }, 2*time.Second, 10*time.Millisecond)
	assert.Len(t, b.shortIDUpdates(), 1, "once the box holds the set it is not pushed again")
}

func TestClient_RotationReappliesPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"3333333333333333"}
	srv.registerResp.PairingShortIDsKnown = true
	port := &portBoxes{}
	c := newTestClient(t, &fakeForwarder{externalIP: "203.0.113.42"}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.CredRotationInterval = 50 * time.Millisecond
		cfg.HeartbeatInterval = time.Hour
		cfg.BuildBoxService = port.build
	})
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	require.Eventually(t, func() bool {
		return rotatedBoxHas(port, []string{testBaseShortID, "3333333333333333"})
	}, 2*time.Second, 10*time.Millisecond, "a rotated box must hold the pairing IDs before it starts")
}

func TestClient_RotationKeepsLastKnownPairingShortIDs(t *testing.T) {
	srv := newStubServer(t)
	var registers atomic.Int64
	srv.registerRespFn = func() RegisterResponse {
		resp := RegisterResponse{
			RouteID:                  "00000000-0000-0000-0000-000000000123",
			ServerConfig:             launchCfgWithShortID(),
			HeartbeatIntervalSeconds: 60,
		}
		if registers.Add(1) == 1 {
			resp.PairingShortIDs = []string{"3333333333333333"}
			resp.PairingShortIDsKnown = true
		}
		return resp
	}
	port := &portBoxes{}
	c := newTestClient(t, &fakeForwarder{externalIP: "203.0.113.42"}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.CredRotationInterval = 50 * time.Millisecond
		cfg.HeartbeatInterval = time.Hour
		cfg.BuildBoxService = port.build
	})
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	require.Eventually(t, func() bool {
		return rotatedBoxHas(port, []string{testBaseShortID, "3333333333333333"})
	}, 2*time.Second, 10*time.Millisecond, "a rotation whose register does not vouch for a set keeps the last known one")
}

// hookBox runs onStart before starting and onClose, once, on its first
// close.
type hookBox struct {
	*fakeBoxService
	onStart func()
	once    sync.Once
	onClose func()
}

func (b *hookBox) Start() error {
	if b.onStart != nil {
		b.onStart()
	}
	return b.fakeBoxService.Start()
}

func (b *hookBox) Close() error {
	if b.onClose != nil {
		b.once.Do(b.onClose)
	}
	return b.fakeBoxService.Close()
}

// rotationWithHooks starts a client whose first register carries pairing
// set first at revision 10 and whose later ones carry rotated at revision
// 100, rotates once, and returns the box the rotation built. hook, when set,
// wraps the box the given build (1 for Start's, 2 for the rotation's) returns.
func rotationWithHooks(t *testing.T, first, rotated []string, build int, hook func(c *Client, b *hookBox)) (*Client, *fakeBoxService) {
	t.Helper()
	srv := newStubServer(t)
	var registers atomic.Int64
	srv.registerRespFn = func() RegisterResponse {
		resp := RegisterResponse{
			RouteID:                  "00000000-0000-0000-0000-000000000123",
			ServerConfig:             launchCfgWithShortID(),
			HeartbeatIntervalSeconds: 60,
			PairingShortIDs:          rotated,
			PairingShortIDsKnown:     true,
			PairingShortIDsRevision:  100,
		}
		if registers.Add(1) == 1 {
			resp.PairingShortIDs, resp.PairingShortIDsRevision = first, 10
		}
		return resp
	}
	var (
		c     *Client
		mu    sync.Mutex
		boxes []*fakeBoxService
	)
	c = newTestClient(t, &fakeForwarder{externalIP: "203.0.113.42"}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.CredRotationInterval = time.Hour
		cfg.HeartbeatInterval = time.Hour
		cfg.BuildBoxService = func(_ context.Context, options string) (boxService, error) {
			mu.Lock()
			defer mu.Unlock()
			b := &fakeBoxService{gotConfig: options}
			boxes = append(boxes, b)
			if len(boxes) == build && hook != nil {
				h := &hookBox{fakeBoxService: b}
				hook(c, h)
				return h, nil
			}
			return b, nil
		}
	})
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	require.NoError(t, c.rotateCreds(context.Background()))
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, boxes, 2)
	return c, boxes[1]
}

func TestClient_RotationTakesRegisterSetBeforeStart(t *testing.T) {
	c, rotated := rotationWithHooks(t, []string{"3333333333333333"}, []string{"5555555555555555"}, 0, nil)
	assert.Equal(t, []string{testBaseShortID, "5555555555555555"}, rotated.shortIDsAtStart())
	ids, _ := pairingState(c)
	assert.Equal(t, []string{"5555555555555555"}, ids)
}

// A heartbeat with a newer revision than the rotation's register, landing
// while the new box is built or after it starts but before the swap, wins.
func TestClient_RotationKeepsNewerHeartbeatSet(t *testing.T) {
	both := []string{"3333333333333333", "5555555555555555"}
	newer := func(c *Client) { c.applyPairingShortIDs([]string{"5555555555555555"}, true, 200) }
	for name, tc := range map[string]struct {
		build int
		hook  func(c *Client, b *hookBox)
		start []string
	}{
		"while the old box closes": {
			build: 1, hook: func(c *Client, b *hookBox) { b.onClose = func() { newer(c) } },
			start: []string{testBaseShortID, "5555555555555555"},
		},
		"after the new box starts": {
			build: 2, hook: func(c *Client, b *hookBox) { b.onStart = func() { newer(c) } },
			start: []string{testBaseShortID, "3333333333333333", "5555555555555555"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, rotated := rotationWithHooks(t, both, both, tc.build, tc.hook)
			assert.Equal(t, tc.start, rotated.shortIDsAtStart())
			assert.Equal(t, []string{testBaseShortID, "5555555555555555"}, rotated.lastShortIDs(),
				"the register's older set must not outlive a newer heartbeat that revoked a pairing")
			ids, _ := pairingState(c)
			assert.Equal(t, []string{"5555555555555555"}, ids)
		})
	}
}

// Expiry that clears the set after the rotation pushed it onto its new box,
// but before the swap, leaves the new box with its base ID only.
func TestClient_RotationReconcilesSetExpiredBeforeSwap(t *testing.T) {
	srv := newStubServer(t)
	var registers atomic.Int64
	srv.registerRespFn = func() RegisterResponse {
		resp := RegisterResponse{
			RouteID:                  "00000000-0000-0000-0000-000000000123",
			ServerConfig:             launchCfgWithShortID(),
			HeartbeatIntervalSeconds: 60,
		}
		if registers.Add(1) == 1 {
			resp.PairingShortIDs = []string{"3333333333333333"}
			resp.PairingShortIDsKnown = true
		}
		return resp
	}
	clock := &testClock{}
	clock.set(time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
	var (
		c     *Client
		mu    sync.Mutex
		boxes []*fakeBoxService
	)
	c = newTestClient(t, &fakeForwarder{externalIP: "203.0.113.42"}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.CredRotationInterval = time.Hour
		cfg.HeartbeatInterval = time.Hour
		cfg.Now = clock.now
		cfg.BuildBoxService = func(_ context.Context, options string) (boxService, error) {
			mu.Lock()
			defer mu.Unlock()
			b := &fakeBoxService{gotConfig: options}
			boxes = append(boxes, b)
			if len(boxes) == 1 {
				return b, nil
			}
			// A heartbeat expires the set after the push before Start.
			return &hookBox{fakeBoxService: b, onStart: func() {
				clock.advance(pairingMaxUnconfirmed)
				c.expireUnconfirmedPairing()
			}}, nil
		}
	})
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	require.NoError(t, c.rotateCreds(context.Background()))

	mu.Lock()
	require.Len(t, boxes, 2)
	rotated := boxes[1]
	mu.Unlock()
	assert.Equal(t, []string{testBaseShortID, "3333333333333333"}, rotated.shortIDsAtStart(),
		"the retained set was pushed before Start")
	assert.Equal(t, []string{testBaseShortID}, rotated.lastShortIDs(),
		"the expired IDs must not stay accepted on the new box")
	_, known := pairingState(c)
	assert.False(t, known)
	c.mu.Lock()
	applied := c.pairingApplied
	c.mu.Unlock()
	assert.True(t, applied)
}

// A failed push of the base ID after expiry is retried by a heartbeat that
// does not vouch for a set.
func TestClient_FailedBaseOnlyPushIsRetried(t *testing.T) {
	c, b, srv, clock := expiryClient(t)
	b.setUpdateErr(errors.New("refused"))
	clock.advance(pairingMaxUnconfirmed)
	waitHeartbeats(t, srv, 3)
	assert.Equal(t, []string{testBaseShortID, "1111111111111111"}, b.lastShortIDs())
	// Simulate the swap path's failure: the record is gone but the box
	// still holds the set.
	c.mu.Lock()
	c.pairingKnown, c.pairingShortIDs, c.pairingApplied = false, nil, false
	c.mu.Unlock()
	b.setUpdateErr(nil)
	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID})
	}, 2*time.Second, 10*time.Millisecond)
}

// A heartbeat whose set is older than the rotation's register, landing
// after the register (here, while the old box closes), is ignored.
func TestClient_RotationIgnoresOlderHeartbeatBeforeSwap(t *testing.T) {
	c, rotated := rotationWithHooks(t, []string{"3333333333333333"}, []string{"5555555555555555"}, 1,
		func(c *Client, b *hookBox) {
			b.onClose = func() { c.applyPairingShortIDs([]string{"3333333333333333"}, true, 50) }
		})
	assert.Equal(t, [][]string{{testBaseShortID, "5555555555555555"}}, rotated.shortIDUpdates())
	ids, _ := pairingState(c)
	assert.Equal(t, []string{"5555555555555555"}, ids)
}

// A heartbeat computed before the rotation's register but answered after
// the swap is ignored.
func TestClient_InFlightHeartbeatDoesNotOverwriteRotation(t *testing.T) {
	srv := newStubServer(t)
	var registers atomic.Int64
	srv.registerRespFn = func() RegisterResponse {
		resp := RegisterResponse{
			RouteID:                  "00000000-0000-0000-0000-000000000123",
			ServerConfig:             launchCfgWithShortID(),
			HeartbeatIntervalSeconds: 60,
			PairingShortIDs:          []string{"5555555555555555"},
			PairingShortIDsKnown:     true,
			PairingShortIDsRevision:  100,
		}
		if registers.Add(1) == 1 {
			resp.PairingShortIDs, resp.PairingShortIDsRevision = []string{"3333333333333333"}, 10
		}
		return resp
	}
	srv.heartbeatShortIDs.Store(&[]string{"3333333333333333"})
	srv.heartbeatRevision.Store(20)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var heartbeats atomic.Int64
	srv.onHeartbeat = func() {
		if heartbeats.Add(1) == 1 {
			// The first heartbeat, which carries the 3333 pairing, is
			// answered only after the rotation that ends it.
			close(entered)
			<-release
		}
	}
	var (
		mu    sync.Mutex
		boxes []*fakeBoxService
	)
	c := newTestClient(t, &fakeForwarder{externalIP: "203.0.113.42"}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.CredRotationInterval = time.Hour
		cfg.HeartbeatInterval = 20 * time.Millisecond
		cfg.BuildBoxService = func(_ context.Context, options string) (boxService, error) {
			mu.Lock()
			defer mu.Unlock()
			b := &fakeBoxService{gotConfig: options}
			boxes = append(boxes, b)
			return b, nil
		}
	})
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	<-entered
	require.NoError(t, c.rotateCreds(context.Background()))
	srv.heartbeatShortIDs.Store(&[]string{"5555555555555555"})
	srv.heartbeatRevision.Store(150)
	releaseOnce.Do(func() { close(release) })
	require.Eventually(t, func() bool { return heartbeats.Load() >= 3 }, 2*time.Second, 10*time.Millisecond)

	mu.Lock()
	require.Len(t, boxes, 2)
	rotated := boxes[1]
	mu.Unlock()
	for _, set := range rotated.shortIDUpdates() {
		assert.Equal(t, []string{testBaseShortID, "5555555555555555"}, set,
			"a heartbeat computed before the rotation must not restore the pairing it ended")
	}
	ids, known := pairingState(c)
	assert.True(t, known)
	assert.Equal(t, []string{"5555555555555555"}, ids)
}

// testClock is a settable clock for Config.Now.
type testClock struct{ ns atomic.Int64 }

func (c *testClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *testClock) set(t time.Time)         { c.ns.Store(t.UnixNano()) }
func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// expiryClient starts a client whose register vouches for the 1111 pairing
// at clock time t0, with heartbeats that vouch for nothing.
func expiryClient(t *testing.T) (*Client, *fakeBoxService, *stubServer, *testClock) {
	t.Helper()
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	clock := &testClock{}
	clock.set(time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) {
		cfg.HeartbeatInterval = 20 * time.Millisecond
		cfg.Now = clock.now
	})
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	return c, b, srv, clock
}

// waitHeartbeats waits for n more heartbeats to complete their handling.
func waitHeartbeats(t *testing.T, srv *stubServer, n int64) {
	t.Helper()
	// One beyond n, so the nth has been handled, not merely sent.
	after := srv.heartbeatCount.Load()
	require.Eventually(t, func() bool { return srv.heartbeatCount.Load() >= after+n+1 }, 2*time.Second, 5*time.Millisecond)
}

func TestClient_UnconfirmedPairingShortIDsExpire(t *testing.T) {
	c, b, srv, clock := expiryClient(t)
	withPairing := []string{testBaseShortID, "1111111111111111"}
	require.Equal(t, withPairing, b.lastShortIDs())

	clock.advance(pairingMaxUnconfirmed - time.Minute)
	waitHeartbeats(t, srv, 3)
	assert.Equal(t, withPairing, b.lastShortIDs(), "kept until 48 hours pass unconfirmed")
	_, known := pairingState(c)
	assert.True(t, known)

	clock.advance(time.Minute)
	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID})
	}, 2*time.Second, 5*time.Millisecond, "dropped once 48 hours pass without the server vouching for it")
	ids, known := pairingState(c)
	assert.False(t, known)
	assert.Empty(t, ids)
	waitHeartbeats(t, srv, 3)
	assert.Equal(t, []string{testBaseShortID}, b.lastShortIDs(), "a dropped set is not restored by unconfirmed heartbeats")
}

func TestClient_ConfirmedHeartbeatExtendsPairingShortIDs(t *testing.T) {
	c, b, srv, clock := expiryClient(t)
	withPairing := []string{testBaseShortID, "1111111111111111"}

	clock.advance(47 * time.Hour)
	srv.heartbeatShortIDs.Store(&[]string{"1111111111111111"})
	waitHeartbeats(t, srv, 2)
	srv.heartbeatShortIDs.Store(nil)

	clock.advance(2 * time.Hour) // 49h after Start, 2h after the confirmation
	waitHeartbeats(t, srv, 3)
	assert.Equal(t, withPairing, b.lastShortIDs(), "a confirmation at 47h extends the set")
	_, known := pairingState(c)
	assert.True(t, known)

	clock.advance(pairingMaxUnconfirmed)
	require.Eventually(t, func() bool {
		return slices.Equal(b.lastShortIDs(), []string{testBaseShortID})
	}, 2*time.Second, 5*time.Millisecond)
}

func TestClient_RotationKeepsPairingConfirmationTime(t *testing.T) {
	srv := newStubServer(t)
	var registers atomic.Int64
	srv.registerRespFn = func() RegisterResponse {
		resp := RegisterResponse{
			RouteID:                  "00000000-0000-0000-0000-000000000123",
			ServerConfig:             launchCfgWithShortID(),
			HeartbeatIntervalSeconds: 60,
		}
		if registers.Add(1) == 1 {
			resp.PairingShortIDs = []string{"3333333333333333"}
			resp.PairingShortIDsKnown = true
		}
		return resp
	}
	clock := &testClock{}
	start := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	clock.set(start)
	c := newTestClient(t, &fakeForwarder{externalIP: "203.0.113.42"}, &fakeBoxService{}, srv, func(cfg *Config) {
		cfg.CredRotationInterval = time.Hour
		cfg.HeartbeatInterval = time.Hour
		cfg.Now = clock.now
		cfg.BuildBoxService = func(_ context.Context, _ string) (boxService, error) { return &fakeBoxService{}, nil }
	})
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	clock.advance(30 * time.Hour)
	require.NoError(t, c.rotateCreds(context.Background()))
	c.mu.Lock()
	confirmed := c.pairingConfirmedAt
	c.mu.Unlock()
	assert.True(t, confirmed.Equal(start), "a rotation that reuses the record must not refresh its confirmation")
}

// realSamizdatOptions is a launch config the real lantern-box samizdat inbound
// accepts, listening on a free loopback port.
func realSamizdatOptions(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	priv := make([]byte, 32)
	_, err = rand.Read(priv)
	require.NoError(t, err)
	b, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{
		"type": "samizdat", "tag": "samizdat-in", "listen": "127.0.0.1", "listen_port": 0,
		"private_key":       hex.EncodeToString(priv),
		"short_ids":         []string{testBaseShortID},
		"cert_pem":          string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"key_pem":           string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		"masquerade_domain": "example.com",
	}}})
	require.NoError(t, err)
	return string(b)
}

// TestSamizdatInbound_RealBox checks the seam the fakes stand in for: a
// sing-box built by defaultBuildBoxService exposes lantern-box's samizdat
// inbound, and its UpdateShortIDs is reachable.
func TestSamizdatInbound_RealBox(t *testing.T) {
	b, err := defaultBuildBoxService(context.Background(), realSamizdatOptions(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	u, ok := samizdatInbound(b)
	require.True(t, ok, "the box's samizdat-in inbound must expose UpdateShortIDs")
	require.NoError(t, u.UpdateShortIDs([]string{testBaseShortID, "4444444444444444"}))
	require.Error(t, u.UpdateShortIDs(nil), "lantern-box's own validation runs: an empty set is refused")
}

// With "help others too" off the base ID stays on the box: lantern-cloud's
// reaper re-verifies live peers with it, and a peer that fails three times is
// deprecated, paired friends included.
func TestClient_ServePoolOffKeepsTheBaseShortID(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.Set(settings.PeerServePoolKey, false))
	srv := newStubServer(t)
	srv.registerResp.ServerConfig = launchCfgWithShortID()
	srv.registerResp.PairingShortIDs = []string{"1111111111111111"}
	srv.registerResp.PairingShortIDsKnown = true
	b := &fakeBoxService{}
	c := newTestClient(t, &fakeForwarder{}, b, srv, func(cfg *Config) { cfg.HeartbeatInterval = time.Hour })
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	c.applyPairingShortIDs([]string{"2222222222222222"}, true, 1<<62)
	assert.Equal(t, []string{testBaseShortID, "2222222222222222"}, b.lastShortIDs())
}
