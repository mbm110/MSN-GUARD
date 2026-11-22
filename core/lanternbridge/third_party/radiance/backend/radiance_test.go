package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/getlantern/common"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/helper"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/peer"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/unbounded"
	"github.com/getlantern/radiance/vpn"

	lbA "github.com/getlantern/lantern-box/adapter"
)

// newCachedConfigBackend returns a backend loading its config and servers
// from dataDir, as at startup.
func newCachedConfigBackend(t *testing.T, dataDir string) *LocalBackend {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := config.NewConfigHandler(ctx, config.Options{
		DataPath: dataDir,
		Logger:   log.NoOpLogger(),
	})
	srvMgr, err := servers.NewManager(dataDir, log.NoOpLogger())
	require.NoError(t, err)
	return &LocalBackend{
		ctx:         ctx,
		confHandler: ch,
		srvManager:  srvMgr,
		vpnClient:   vpn.NewVPNClient(dataDir, log.NoOpLogger(), nil),
	}
}

func writeCachedConfig(t *testing.T, dataDir string, cfg *config.Config) {
	t.Helper()
	buf, err := singjson.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, internal.ConfigFileName), buf, 0o600))
}

func TestApplyCurrentConfigLoadsCachedServers(t *testing.T) {
	t.Setenv("RADIANCE_COUNTRY", "US")
	dataDir := t.TempDir()
	writeCachedConfig(t, dataDir, cachedConfig())
	r := newCachedConfigBackend(t, dataDir)

	r.applyCurrentConfig()

	server, found := r.GetServerByTag("cached-out")
	require.True(t, found)
	assert.True(t, server.IsLantern)
	assert.Equal(t, "shadowsocks", server.Type)
	assert.Equal(t, "Shanghai", server.Location.City)
	assert.Equal(t, "CN", server.Location.CountryCode)
}

func TestConfigAppliedEventFollowsServerUpdate(t *testing.T) {
	t.Setenv("RADIANCE_COUNTRY", "US")
	dataDir := t.TempDir()
	writeCachedConfig(t, dataDir, cachedConfig())
	r := newCachedConfigBackend(t, dataDir)
	// The debug hook runs inside Emit, so it sees the state at the moment of the emit;
	// a subscriber would run later, after applyConfig returned.
	var emitted, found bool
	events.SetEmitDebugLogger(func(eventType reflect.Type, _ int) {
		if eventType == reflect.TypeFor[ConfigAppliedEvent]() {
			emitted = true
			_, found = r.GetServerByTag("cached-out")
		}
	})
	t.Cleanup(func() { events.SetEmitDebugLogger(nil) })

	r.applyCurrentConfig()

	require.True(t, emitted, "no ConfigAppliedEvent")
	assert.True(t, found, "servers must be applied before ConfigAppliedEvent")
}

func TestApplyCurrentConfigKeepsHardDemotedServers(t *testing.T) {
	t.Setenv("RADIANCE_COUNTRY", "US")
	dataDir := t.TempDir()
	cfg := cachedConfig()
	writeCachedConfig(t, dataDir, cfg)
	r := newCachedConfigBackend(t, dataDir)
	r.applyCurrentConfig()
	require.NoError(t, r.srvManager.UpdateSelectionHistory(map[string]servers.SelectionHistory{
		"cached-out": {HardDemoted: true},
	}))

	// Restart: the cached config was already applied when it was received.
	r = newCachedConfigBackend(t, dataDir)
	r.applyCurrentConfig()
	server, found := r.GetServerByTag("cached-out")
	require.True(t, found, "applying the cached config at startup must not evict")
	require.NotNil(t, server.SelectionHistory)
	assert.True(t, server.SelectionHistory.HardDemoted)

	r.applyConfig(cfg, true)
	_, found = r.GetServerByTag("cached-out")
	assert.False(t, found, "a newly received config still evicts hard-demoted servers")
}

func cachedConfig() *config.Config {
	return &config.Config{
		Country: "CN",
		OutboundLocations: C.OutboundLocations{
			"cached-out": {
				Country:     "China",
				City:        "Shanghai",
				CountryCode: "CN",
			},
		},
		Options: option.Options{
			Outbounds: []option.Outbound{{
				Tag:  "cached-out",
				Type: "shadowsocks",
				Options: &option.ShadowsocksOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: 443,
					},
					Method:   "chacha20-ietf-poly1305",
					Password: "password",
				},
			}},
		},
	}
}

// TestNewLocalBackendToleratesInvalidOnDiskState guards the init hardening:
// invalid-but-readable on-disk state must not make NewLocalBackend fatal, so a
// user can always report an issue. Every fixture is readable, so a returned
// error can only come from parsing — a non-IO failure that must stay non-fatal.
func TestNewLocalBackendToleratesInvalidOnDiskState(t *testing.T) {
	dataDir := t.TempDir()
	logDir := t.TempDir()
	t.Cleanup(func() {
		assert.NoError(t, debug.SetCrashOutput(nil, debug.CrashOptions{}))
	})
	// setupDirectories honors these env vars over the Options paths; pin them so
	// the resolved data dir is exactly where the invalid files are staged.
	t.Setenv("RADIANCE_DATA_PATH", dataDir)
	t.Setenv("RADIANCE_LOG_PATH", logDir)

	invalidFiles := map[string][]byte{
		"settings.json":              []byte(`{invalid json}`),
		internal.ConfigFileName:      []byte(`{"options":{"outbounds":[{"type":"future-proto"}]}}`),
		internal.ServersFileName:     []byte(`[{"tag":"bad","type":"future-proto","outbound":{"tag":"bad","type":"future-proto"}}]`),
		internal.SplitTunnelFileName: []byte(`{"version":3,"rules":[{"unknown_field":true}]}`),
	}
	for name, content := range invalidFiles {
		require.NoError(t, os.WriteFile(filepath.Join(dataDir, name), content, 0o600))
	}

	backend, err := NewLocalBackend(context.Background(), Options{DataDir: dataDir, LogDir: logDir, LogLevel: "error"})
	require.NoError(t, err, "invalid but readable on-disk state must not make initialization fatal")
	require.NotNil(t, backend)
	t.Cleanup(backend.Close)
}

func TestExhaustionGate_AllowRateLimitsBelowGap(t *testing.T) {
	prev := defaultExhaustionRefetchGap
	defaultExhaustionRefetchGap = 50 * time.Millisecond
	t.Cleanup(func() { defaultExhaustionRefetchGap = prev })

	var g exhaustionGate
	require.True(t, g.allow(), "first allow must pass on a zero gate")
	assert.False(t, g.allow(), "second allow inside the gap must be rate-limited")
	assert.False(t, g.allow(), "third allow inside the gap must still be rate-limited")

	time.Sleep(defaultExhaustionRefetchGap + 10*time.Millisecond)
	assert.True(t, g.allow(), "allow after the gap elapses must pass again")
	assert.False(t, g.allow(), "post-recovery allow must re-arm the gate")
}

func newTestServer(tag string, isLantern, hardDemoted bool, updatedAt time.Time) *servers.Server {
	srv := &servers.Server{
		Tag:       tag,
		IsLantern: isLantern,
	}
	if hardDemoted || !updatedAt.IsZero() {
		srv.SelectionHistory = &servers.SelectionHistory{
			HardDemoted: hardDemoted,
			UpdatedAt:   updatedAt,
		}
	}
	return srv
}

func TestLanternServersToEvict(t *testing.T) {
	baseTime := time.Unix(0, 0).UTC()

	tests := []struct {
		name     string
		existing []*servers.Server
		offered  []string
		limit    int
		selected string
		want     []string
	}{
		{
			name: "evicts only hard-demoted lantern servers",
			existing: []*servers.Server{
				newTestServer("demoted", true, true, baseTime),
				newTestServer("working", true, false, baseTime),
				newTestServer("users-demoted", false, true, baseTime),
			},
			limit: 60,
			want:  []string{"demoted"},
		},
		{
			name: "hard-demoted lantern server is evicted even when offered",
			existing: []*servers.Server{
				newTestServer("demoted", true, true, baseTime),
			},
			offered: []string{"demoted"},
			limit:   60,
			want:    []string{"demoted"},
		},
		{
			name: "offered hard-demoted server does not take a retention slot",
			existing: []*servers.Server{
				newTestServer("demoted", true, true, baseTime),
				newTestServer("old", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("new", true, false, baseTime.Add(2*time.Hour)),
			},
			offered: []string{"demoted", "fresh"},
			limit:   3,
			want:    []string{"demoted"},
		},
		{
			name: "offered tag held by a non-lantern server does not take a retention slot",
			existing: []*servers.Server{
				newTestServer("user", false, false, baseTime),
				newTestServer("old", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("new", true, false, baseTime.Add(2*time.Hour)),
			},
			offered: []string{"user", "fresh"},
			limit:   3,
		},
		{
			name: "under the limit nothing is evicted",
			existing: []*servers.Server{
				newTestServer("a", true, false, baseTime),
				newTestServer("b", true, false, baseTime),
			},
			offered: []string{"c", "d"},
			limit:   60,
		},
		{
			name: "over the limit evicts oldest working servers and keeps the newest",
			existing: []*servers.Server{
				newTestServer("old", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("mid", true, false, baseTime.Add(2*time.Hour)),
				newTestServer("new", true, false, baseTime.Add(3*time.Hour)),
			},
			offered: []string{"fresh"},
			limit:   3,
			want:    []string{"old"},
		},
		{
			name: "offered servers at the limit evict all servers no longer offered",
			existing: []*servers.Server{
				newTestServer("a", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("b", true, false, baseTime.Add(2*time.Hour)),
			},
			offered: []string{"c", "d", "e"},
			limit:   3,
			want:    []string{"a", "b"},
		},
		{
			name: "re-offered servers are kept and servers no longer offered are evicted",
			existing: []*servers.Server{
				newTestServer("offered-oldest", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("dropped-old", true, false, baseTime.Add(2*time.Hour)),
				newTestServer("dropped-new", true, false, baseTime.Add(3*time.Hour)),
				newTestServer("offered-newest", true, false, baseTime.Add(4*time.Hour)),
			},
			offered: []string{"offered-oldest", "offered-newest", "fresh"},
			limit:   4,
			want:    []string{"dropped-old"},
		},
		{
			name: "offered servers over the limit are all kept",
			existing: []*servers.Server{
				newTestServer("a", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("b", true, false, baseTime.Add(2*time.Hour)),
				newTestServer("dropped", true, false, baseTime.Add(3*time.Hour)),
			},
			offered: []string{"a", "b", "c"},
			limit:   2,
			want:    []string{"dropped"},
		},
		{
			name: "selected working server is exempt but counts toward the limit",
			existing: []*servers.Server{
				newTestServer("old-selected", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("a", true, false, baseTime.Add(2*time.Hour)),
				newTestServer("b", true, false, baseTime.Add(3*time.Hour)),
				newTestServer("c", true, false, baseTime.Add(4*time.Hour)),
			},
			offered:  []string{"fresh"},
			limit:    3,
			selected: "old-selected",
			want:     []string{"a", "b"},
		},
		{
			name: "offered selected server counts toward the limit once",
			existing: []*servers.Server{
				newTestServer("selected", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("a", true, false, baseTime.Add(2*time.Hour)),
				newTestServer("b", true, false, baseTime.Add(3*time.Hour)),
			},
			offered:  []string{"selected", "fresh"},
			limit:    3,
			selected: "selected",
			want:     []string{"a"},
		},
		{
			name: "selected server is kept when over the limit",
			existing: []*servers.Server{
				newTestServer("selected", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("a", true, false, baseTime.Add(2*time.Hour)),
			},
			offered:  []string{"b", "c"},
			limit:    2,
			selected: "selected",
			want:     []string{"a"},
		},
		{
			name: "selected server is still evicted when hard-demoted",
			existing: []*servers.Server{
				newTestServer("selected-demoted", true, true, baseTime),
				newTestServer("working", true, false, baseTime),
			},
			offered:  []string{"selected-demoted"},
			limit:    60,
			selected: "selected-demoted",
			want:     []string{"selected-demoted"},
		},
		{
			name: "helpers are never evicted",
			existing: []*servers.Server{
				newTestServer("helper-0123456789ab", true, false, time.Time{}),
				newTestServer("helper-ba9876543210", true, true, baseTime),
				newTestServer("a", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("b", true, false, baseTime.Add(2*time.Hour)),
			},
			offered:  []string{"helper-0123456789ab", "c", "d"},
			limit:    3,
			selected: "personal-proxies",
			want:     []string{"a"},
		},
		{
			name: "offered new helpers take no retention slot",
			existing: []*servers.Server{
				newTestServer("a", true, false, baseTime.Add(1*time.Hour)),
				newTestServer("b", true, false, baseTime.Add(2*time.Hour)),
			},
			offered: []string{"helper-0123456789ab", "helper-ba9876543210", "c"},
			limit:   3,
		},
		{
			name: "server with no selection history sorts oldest",
			existing: []*servers.Server{
				newTestServer("no-history", true, false, time.Time{}),
				newTestServer("probed", true, false, baseTime.Add(5*time.Hour)),
			},
			offered: []string{"fresh"},
			limit:   2,
			want:    []string{"no-history"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			offered := make(map[string]struct{}, len(tt.offered))
			for _, tag := range tt.offered {
				offered[tag] = struct{}{}
			}
			got := lanternServersToEvict(tt.existing, offered, tt.limit, tt.selected)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestEndedHelpersAreThoseTheConfigNoLongerCarries(t *testing.T) {
	existing := []*servers.Server{
		newTestServer("helper-0123456789ab", true, false, time.Time{}),
		newTestServer("helper-ba9876543210", true, false, time.Time{}),
		newTestServer("helper-00000000000d", true, true, time.Unix(9, 0)),
		newTestServer("helper-0000000000aa", false, false, time.Time{}),
		newTestServer("a", true, false, time.Time{}),
	}
	got := endedHelpers(existing, map[string]struct{}{"helper-0123456789ab": {}})
	assert.ElementsMatch(t, []string{"helper-ba9876543210", "helper-00000000000d"}, got,
		"Lantern helpers the config dropped; a user server is not the config's to end")
}

// Reverse outbounds belong to the reverse client, not to the config.
func TestEndedHelpersExcludeReverseOutbounds(t *testing.T) {
	rev := lbA.ReverseHelperTag("helper-0123456789ab")
	existing := []*servers.Server{newTestServer(rev, true, false, time.Time{})}
	assert.Empty(t, endedHelpers(existing, map[string]struct{}{}))
}

func TestAppendManagedServerOptionsIncludesRetainedLanternServers(t *testing.T) {
	options := option.Options{
		Outbounds: []option.Outbound{
			{Tag: "current", Type: "shadowsocks"},
			{Tag: "retained-current", Type: "shadowsocks"},
		},
		Endpoints: []option.Endpoint{
			{Tag: "current-endpoint", Type: "wireguard"},
		},
	}
	managed := []*servers.Server{
		{
			Tag:       "retained-current",
			Type:      "hysteria2",
			IsLantern: true,
			Options:   option.Outbound{Tag: "retained-current", Type: "hysteria2"},
		},
		{
			Tag:       "server-alias-for-current",
			Type:      "hysteria2",
			IsLantern: true,
			Options:   option.Outbound{Tag: "current", Type: "hysteria2"},
		},
		{
			Tag:       "retained-missing",
			Type:      "shadowsocks",
			IsLantern: true,
			Options:   option.Outbound{Tag: "retained-missing", Type: "shadowsocks"},
		},
		{
			Tag:       "user-missing",
			Type:      "trojan",
			IsLantern: false,
			Options:   option.Outbound{Tag: "user-missing", Type: "trojan"},
		},
		{
			Tag:       "missing-option-tag",
			Type:      "shadowsocks",
			IsLantern: true,
			Options:   option.Outbound{Type: "shadowsocks"},
		},
		{
			Tag:       "retained-endpoint",
			Type:      "wireguard",
			IsLantern: true,
			Options:   option.Endpoint{Tag: "retained-endpoint", Type: "wireguard"},
		},
		{
			Tag:       "server-alias-for-current-endpoint",
			Type:      "wireguard",
			IsLantern: true,
			Options:   option.Endpoint{Tag: "current-endpoint", Type: "wireguard"},
		},
		{
			Tag:       "metadata-only",
			IsLantern: true,
		},
	}

	appendManagedServerOptions(&options, managed)

	assert.Equal(t, []string{
		"current",
		"retained-current",
		"retained-missing",
		"user-missing",
	}, outboundTags(options.Outbounds))
	assert.Equal(t, "shadowsocks", options.Outbounds[1].Type, "current config should win duplicate tags")
	assert.Equal(t, []string{
		"current-endpoint",
		"retained-endpoint",
	}, endpointTags(options.Endpoints))
}

func outboundTags(outbounds []option.Outbound) []string {
	tags := make([]string, 0, len(outbounds))
	for _, out := range outbounds {
		tags = append(tags, out.Tag)
	}
	return tags
}

func endpointTags(endpoints []option.Endpoint) []string {
	tags := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		tags = append(tags, endpoint.Tag)
	}
	return tags
}

type fakePeerController struct {
	startCalls atomic.Int64
	stopCalls  atomic.Int64
	startErr   error
	active     atomic.Bool
	// servePoolAtStart is peer_serve_pool as the first Start saw it, which
	// is what that Start's registration sends.
	servePoolAtStart atomic.Value // any
	reregisterCalls  atomic.Int64
	// reregisterFn, when set, answers Reregister; it gets the call's number,
	// from 1.
	reregisterFn atomic.Pointer[func(context.Context, int64) error]
	// onStart, if set, runs at the top of each Start.
	onStart func()
	// pairingsOnly, if set, is the client's Config.PairingsOnly.
	pairingsOnly func() bool
	// poolMaybe models the real client's MayServePool.
	poolMaybe atomic.Bool
	// status models the real client's CurrentStatus: the last Start's error
	// phase, kept until the next Start, or serving while active.
	status atomic.Pointer[peer.Status]
	// teardown, if set, is a self-stop's teardown in flight: Stop waits for
	// it to close.
	teardown atomic.Pointer[chan struct{}]
}

// registrationPool is the serve_pool a registration now would send, as the
// real client decides it.
func (f *fakePeerController) registrationPool() bool {
	return settings.PeerServesPool() && (f.pairingsOnly == nil || !f.pairingsOnly())
}

func (f *fakePeerController) MayServePool() bool { return f.poolMaybe.Load() }

func (f *fakePeerController) Start(_ context.Context) error {
	if f.onStart != nil {
		f.onStart()
	}
	// Counted even when refused, so a test can catch a redundant Start.
	n := f.startCalls.Add(1)
	if f.active.Load() {
		return errors.New("peer client already active")
	}
	if n == 1 {
		f.servePoolAtStart.Store(fmt.Sprint(settings.Get(settings.PeerServePoolKey)))
	}
	if f.startErr != nil {
		// As the real client's rollback: no box serves.
		f.poolMaybe.Store(false)
		f.setStatus(peer.Status{Phase: peer.PhaseError, Error: f.startErr.Error()})
		return f.startErr
	}
	f.poolMaybe.Store(f.registrationPool())
	f.active.Store(true)
	f.setStatus(peer.Status{Phase: peer.PhaseServing, Active: true})
	return nil
}

func (f *fakePeerController) Stop(_ context.Context) error {
	// As the real client: Stop waits for a teardown in flight.
	if ch := f.teardown.Load(); ch != nil {
		<-*ch
	}
	// Only a Stop that stops a session counts: on an idle client the real
	// one does nothing.
	if f.active.Swap(false) {
		f.stopCalls.Add(1)
		f.poolMaybe.Store(false)
		f.setStatus(peer.Status{Phase: peer.PhaseIdle})
	}
	return nil
}

func (f *fakePeerController) Reregister(ctx context.Context) error {
	if !f.active.Load() {
		return peer.ErrNotActive
	}
	n := f.reregisterCalls.Add(1)
	// As the real client: a pool registration may register the pool even if
	// it fails; a pool-free one can't add it.
	pool := f.registrationPool()
	if pool {
		f.poolMaybe.Store(true)
	}
	if fn := f.reregisterFn.Load(); fn != nil {
		if err := (*fn)(ctx, n); err != nil {
			return err
		}
	}
	if !pool {
		f.poolMaybe.Store(false)
	}
	return nil
}

func (f *fakePeerController) setReregister(fn func(context.Context, int64) error) {
	f.reregisterFn.Store(&fn)
}

func (f *fakePeerController) IsActive() bool { return f.active.Load() }
func (f *fakePeerController) CurrentStatus() peer.Status {
	if st := f.status.Load(); st != nil {
		return *st
	}
	// No Start recorded one: a test that set active directly.
	return peer.Status{Active: f.active.Load()}
}

// setStatus records the client's status as the real one would, tagged with
// the run's mode.
func (f *fakePeerController) setStatus(st peer.Status) {
	st.PairingsOnly = f.pairingsOnly != nil && f.pairingsOnly()
	f.status.Store(&st)
}

func (f *fakePeerController) RetagStatus() {
	if st := f.status.Load(); st != nil {
		f.setStatus(*st)
	}
}
func (f *fakePeerController) RelaySnapshot() peer.Snapshot {
	if !f.active.Load() {
		return peer.Snapshot{}
	}
	return peer.Snapshot{Running: true, Peers: []string{"friend"}, BytesUp: 1}
}

// newPeerTestBackend wires a minimal LocalBackend with only the fields
// applyPeerShare touches. settings is initialized to a fresh tempdir per test
// so the rollback path doesn't leak across runs.
func newPeerTestBackend(t *testing.T, fake *fakePeerController) *LocalBackend {
	t.Helper()
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	// A country where the pairings-only route may run.
	require.NoError(t, settings.Set(settings.CountryCodeKey, "US"))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &LocalBackend{ctx: ctx, peerClient: fake}
}

func TestPatchSettings_RejectsInvalidSplitTunnelPolicy(t *testing.T) {
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := &LocalBackend{ctx: ctx}

	err := r.PatchSettings(settings.Settings{settings.SplitTunnelPolicyKey: "bogus"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid")
	assert.NotContains(t, err.Error(), "bogus", "the error must not echo the client-supplied value")
	assert.Empty(t, settings.GetString(settings.SplitTunnelPolicyKey),
		"an invalid policy must not be persisted")
}

func TestApplyPeerShare_StartsOnEnable(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)

	require.NoError(t, r.applyPeerShare(true))
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.Equal(t, int64(0), fake.stopCalls.Load())
	assert.True(t, fake.IsActive())
}

func TestApplyPeerShare_StopsOnDisable(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	fake.active.Store(true)

	require.NoError(t, r.applyPeerShare(false))
	assert.Equal(t, int64(0), fake.startCalls.Load())
	assert.Equal(t, int64(1), fake.stopCalls.Load())
	assert.False(t, fake.IsActive())
}

// On a Start failure we surface the error so the Dart side can roll back
// its UI, AND we flip the persisted setting back to false so the user-visible
// state matches reality on the next read.
func TestApplyPeerShare_StartFailureRollsBackSetting(t *testing.T) {
	fake := &fakePeerController{startErr: errors.New("no upnp")}
	r := newPeerTestBackend(t, fake)

	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))
	require.True(t, settings.GetBool(settings.PeerShareEnabledKey))

	err := r.applyPeerShare(true)
	require.Error(t, err)
	assert.ErrorContains(t, err, "no upnp")
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey),
		"setting must roll back to false after a Start failure")
	assert.False(t, fake.IsActive())
}

// The toggle is persisted "on" but the client stopped itself (the production
// case: a heartbeat 404 after a failed rotation). The next "on" changes no
// setting, and must still start the client.
func TestPatchSettings_ToggleOnRestartsStoppedPeer(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))

	require.NoError(t, r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: true}))
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.True(t, fake.IsActive())

	require.NoError(t, r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: true}))
	assert.Equal(t, int64(1), fake.startCalls.Load(), "a running peer is not restarted")
}

// A PATCH that turns peer share on alongside another change still restarts a
// stopped peer, even though the peer key itself is unchanged.
func TestPatchSettings_ToggleOnWithOtherChangesRestartsStoppedPeer(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))

	require.NoError(t, r.PatchSettings(settings.Settings{
		settings.PeerShareEnabledKey: true,
		settings.LocaleKey:           "fa-IR",
	}))
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.Equal(t, "fa-IR", settings.GetString(settings.LocaleKey))
}

// applyPeerShare persists the toggle it applies, so a self-stop that cleared
// it before this Start doesn't leave a running peer with the toggle off.
func TestApplyPeerShare_StartPersistsToggle(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: false}))

	require.NoError(t, r.applyPeerShare(true))
	assert.True(t, fake.IsActive())
	assert.True(t, settings.GetBool(settings.PeerShareEnabledKey))
}

// An explicit "off" is applied even when the stored value already reads off,
// which it does while an earlier "on" is still on its way to applyPeerShare.
func TestPatchSettings_UnchangedOffStillStopsPeer(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: false}))

	require.NoError(t, r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: false}))
	assert.Equal(t, int64(1), fake.stopCalls.Load())
	assert.False(t, fake.IsActive())
}

// A non-boolean toggle is rejected rather than read as "off".
func TestPatchSettings_NonBoolToggleRejected(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))

	for _, v := range []any{"true", nil, 1} {
		require.Error(t, r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: v}), "%v", v)
	}
	assert.Zero(t, fake.stopCalls.Load())
	assert.True(t, fake.IsActive())
	assert.True(t, settings.GetBool(settings.PeerShareEnabledKey))
}

// A PATCH that turns sharing on and limits it to helper pairings registers
// with serve_pool=false from the first registration.
func TestPatchSettings_ServePoolPersistedBeforeSharingStarts(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)

	require.NoError(t, r.PatchSettings(settings.Settings{
		settings.PeerShareEnabledKey: true,
		settings.PeerServePoolKey:    false,
	}))
	require.Equal(t, int64(1), fake.startCalls.Load())
	assert.Equal(t, "false", fake.servePoolAtStart.Load(),
		"the first registration must already see peer_serve_pool=false")
	assert.False(t, settings.GetBool(settings.PeerServePoolKey))
}

// An invalid setting in the same PATCH is rejected before the toggle applies.
func TestPatchSettings_InvalidPatchDoesNotToggle(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)

	err := r.PatchSettings(settings.Settings{
		settings.PeerShareEnabledKey:  true,
		settings.SplitTunnelPolicyKey: "bogus",
	})
	require.Error(t, err)
	assert.Zero(t, fake.startCalls.Load())
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey))
}

// An "off" queued behind an "on" that is still starting must win: the setting
// ends off and the peer stopped, in the order the toggles arrived.
func TestPatchSettings_OffQueuedBehindStartingOnWins(t *testing.T) {
	fake := &blockingStartPeer{release: make(chan struct{}), entered: make(chan struct{})}
	r := newPeerTestBackend(t, &fake.fakePeerController)
	r.peerClient = fake

	onDone := make(chan error, 1)
	go func() { onDone <- r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: true}) }()
	<-fake.entered
	offDone := make(chan error, 1)
	go func() { offDone <- r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: false}) }()
	time.Sleep(50 * time.Millisecond) // let the off queue on peerToggleMu
	close(fake.release)
	require.NoError(t, <-onDone)
	require.NoError(t, <-offDone)

	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey))
	assert.False(t, fake.IsActive())
}

type blockingStartPeer struct {
	fakePeerController
	release, entered chan struct{}
}

func (b *blockingStartPeer) Start(ctx context.Context) error {
	close(b.entered)
	<-b.release
	return b.fakePeerController.Start(ctx)
}

// A second "on" that queued behind a Start must not fail with "already
// active" and roll the toggle back under a running peer.
func TestApplyPeerShare_EnableWhenActiveKeepsToggle(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))
	fake.active.Store(true)

	require.NoError(t, r.applyPeerShare(true))
	assert.Zero(t, fake.startCalls.Load())
	assert.True(t, settings.GetBool(settings.PeerShareEnabledKey))
}

func TestOnPeerSelfStop_ClearsToggleUnlessRestarted(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))

	fake.active.Store(true)
	r.onPeerSelfStop(errors.New("route gone"))
	assert.True(t, settings.GetBool(settings.PeerShareEnabledKey), "a peer restarted since the self-stop keeps the toggle")

	fake.active.Store(false)
	r.onPeerSelfStop(errors.New("route gone"))
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey))
}

func TestPeerStatus_Accessor(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	fake.active.Store(true)

	got := r.PeerStatus()
	assert.True(t, got.Active)
}

func TestResumePeerShare_NoopWhenSettingOff(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)

	r.resumePeerShareIfEnabled()
	r.peerWG.Wait()
	assert.Equal(t, int64(0), fake.startCalls.Load())
}

func TestResumePeerShare_StartsWhenSettingOn(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))

	r.resumePeerShareIfEnabled()
	r.peerWG.Wait()
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.True(t, fake.IsActive())
}

// Close must wait for an in-flight auto-resume Start before tearing down,
// then call Stop on the active session — otherwise we leave a registered
// route + open box behind on shutdown.
func TestClose_WaitsForResumeAndStopsActivePeer(t *testing.T) {
	startGate := make(chan struct{})
	fake := &slowStartFake{gate: startGate}
	r := newCloseableTestBackend(t, fake)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))

	r.resumePeerShareIfEnabled()

	closeReturned := make(chan struct{})
	go func() {
		r.Close()
		close(closeReturned)
	}()

	// Close must NOT return while the resume goroutine is still in Start.
	select {
	case <-closeReturned:
		t.Fatal("Close returned before in-flight resume Start completed")
	case <-time.After(50 * time.Millisecond):
	}

	// Release Start. It returns nil → peer becomes active. Close must then
	// observe IsActive() and call Stop.
	close(startGate)
	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after resume Start unblocked")
	}
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.Equal(t, int64(1), fake.stopCalls.Load())
}

// slowStartFake blocks on gate until the test releases it, simulating a
// long UPnP discovery so we can race Close against Start.
type slowStartFake struct {
	startCalls atomic.Int64
	stopCalls  atomic.Int64
	active     atomic.Bool
	gate       chan struct{}
}

func (f *slowStartFake) Start(ctx context.Context) error {
	f.startCalls.Add(1)
	select {
	case <-f.gate:
	case <-ctx.Done():
		return ctx.Err()
	}
	f.active.Store(true)
	return nil
}
func (f *slowStartFake) Stop(_ context.Context) error {
	f.stopCalls.Add(1)
	f.active.Store(false)
	return nil
}
func (f *slowStartFake) IsActive() bool                   { return f.active.Load() }
func (f *slowStartFake) CurrentStatus() peer.Status       { return peer.Status{Active: f.active.Load()} }
func (f *slowStartFake) RelaySnapshot() peer.Snapshot     { return peer.Snapshot{} }
func (f *slowStartFake) Reregister(context.Context) error { return nil }
func (f *slowStartFake) MayServePool() bool               { return true }
func (f *slowStartFake) RetagStatus()                     {}

// newCloseableTestBackend mirrors newPeerTestBackend but provides the fields
// Close needs (closeOnce, cancel) so we can exercise the shutdown path
// end-to-end. vpnClient is left nil, which Close tolerates by design.
func newCloseableTestBackend(t *testing.T, fake peerController) *LocalBackend {
	t.Helper()
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(settings.Reset)
	ctx, cancel := context.WithCancel(context.Background())
	return &LocalBackend{
		ctx:        ctx,
		cancel:     cancel,
		peerClient: fake,
		closeOnce:  sync.Once{},
	}
}

// Verify the PatchSettings dispatch actually routes PeerShareEnabledKey to
// applyPeerShare. A typo on the diff key would silently break the toggle.
func TestPatchSettings_PeerShareDispatches(t *testing.T) {
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)

	require.NoError(t, r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: true}))
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.True(t, fake.IsActive())

	require.NoError(t, r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: false}))
	assert.Equal(t, int64(1), fake.stopCalls.Load())
	assert.False(t, fake.IsActive())
}

// Verify PatchSettings routes UnboundedKey to unbounded.Apply via the
// SetApplyHookForTest hook. A typo on the diff key or a removal of
// the Apply call would silently leave the Unbounded toggle persisted
// but inert. The hook fires regardless of the Enabled() gate inside
// Apply, so this catches the dispatch even though we don't prime the
// rest of the manager state.
func TestPatchSettings_UnboundedDispatches(t *testing.T) {
	r := newPeerTestBackend(t, &fakePeerController{})

	var applyCalls atomic.Int32
	unbounded.SetApplyHookForTest(func() { applyCalls.Add(1) })
	t.Cleanup(func() { unbounded.SetApplyHookForTest(nil) })

	require.NoError(t, r.PatchSettings(settings.Settings{settings.UnboundedKey: true}))
	assert.Equal(t, int32(1), applyCalls.Load(), "PatchSettings({UnboundedKey: true}) must dispatch to unbounded.Apply")

	require.NoError(t, r.PatchSettings(settings.Settings{settings.UnboundedKey: false}))
	assert.Equal(t, int32(2), applyCalls.Load(), "PatchSettings({UnboundedKey: false}) must dispatch to unbounded.Apply")

	// A PATCH without UnboundedKey must NOT trigger Apply — confirms
	// the diff check is in place rather than always firing.
	require.NoError(t, r.PatchSettings(settings.Settings{settings.PeerShareEnabledKey: false}))
	assert.Equal(t, int32(2), applyCalls.Load(), "PatchSettings without UnboundedKey must not dispatch to unbounded.Apply")
}

// Construction degrades to a nil peerClient rather than failing, so that a
// peer-client problem can never cost the user the ability to report an issue.
// Everything reachable from IPC must tolerate that.

func TestPeerStatus_NilClientReturnsZeroStatus(t *testing.T) {
	r := newPeerTestBackend(t, nil)
	r.peerClient = nil

	var got peer.Status
	require.NotPanics(t, func() { got = r.PeerStatus() },
		"the IPC /peer/status handler calls this on every request")
	assert.Equal(t, peer.Status{}, got)
}

func TestApplyPeerShare_NilClientReportsUnavailableAndRollsBack(t *testing.T) {
	r := newPeerTestBackend(t, nil)
	r.peerClient = nil
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))

	err := r.applyPeerShare(true)

	require.Error(t, err, "enabling with no peer client must report the outage, not panic")
	assert.ErrorContains(t, err, "peer share unavailable")
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey),
		"the setting must roll back so a persisted \"on\" doesn't survive with nothing behind it")
}

// withPeerShareUnsupported forces the platform gate on for one test. The real
// predicate reads common.Platform, a constant, so the branch is unreachable on
// the host that runs these tests.
func withPeerShareUnsupported(t *testing.T) {
	t.Helper()
	prev := peerShareUnsupported
	peerShareUnsupported = func() bool { return true }
	t.Cleanup(func() { peerShareUnsupported = prev })
}

func TestApplyPeerShare_UnsupportedPlatformRefusesAndRollsBack(t *testing.T) {
	withPeerShareUnsupported(t)
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))

	err := r.applyPeerShare(true)

	require.Error(t, err, "enabling on an unsupported platform must report, not silently no-op")
	assert.ErrorContains(t, err, "not supported")
	assert.Zero(t, fake.startCalls.Load(), "the peer must never start on an unsupported platform")
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey),
		"the setting must roll back so a persisted \"on\" doesn't survive every restart")
}

func TestApplyPeerShare_UnsupportedPlatformDisableIsNoop(t *testing.T) {
	withPeerShareUnsupported(t)
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)

	assert.NoError(t, r.applyPeerShare(false), "turning it off where it never ran is not an error")
	assert.Zero(t, fake.stopCalls.Load(), "nothing was started, so nothing needs stopping")
}

// TestResumePeerShare_UnsupportedPlatformDoesNotStart covers the auto-resume
// path, which reaches Start through applyPeerShare rather than directly: a
// setting persisted before the platform was excluded, or synced from another
// device, would otherwise start a peer on every launch.
func TestResumePeerShare_UnsupportedPlatformDoesNotStart(t *testing.T) {
	withPeerShareUnsupported(t)
	fake := &fakePeerController{}
	r := newPeerTestBackend(t, fake)
	require.NoError(t, settings.Patch(settings.Settings{settings.PeerShareEnabledKey: true}))

	r.resumePeerShareIfEnabled()
	r.peerWG.Wait()

	assert.Zero(t, fake.startCalls.Load(), "auto-resume must not start a peer on an unsupported platform")
	assert.False(t, settings.GetBool(settings.PeerShareEnabledKey),
		"the stale setting is cleared on the way through")
}

func TestApplyPeerShare_NilClientDisableIsNoop(t *testing.T) {
	r := newPeerTestBackend(t, nil)
	r.peerClient = nil

	require.NotPanics(t, func() {
		assert.NoError(t, r.applyPeerShare(false),
			"turning it off when it was never on is not an error")
	})
}

func TestConnectVPN_ShedsConcurrentCalls(t *testing.T) {
	r := &LocalBackend{}

	// Simulate an in-flight connect holding the guard. TryLock is the first thing
	// ConnectVPN does, so contended calls return before touching any dependency.
	require.True(t, r.connectMu.TryLock())

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = r.ConnectVPN(context.Background(), vpn.AutoSelectTag)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.ErrorIsf(t, err, ErrConnectInProgress, "call %d should be shed", i)
	}

	// The reject path must not release the guard; only the holder unlocks it.
	r.connectMu.Unlock()
	assert.True(t, r.connectMu.TryLock())
}

func TestBuildIssueReportMetadataFallsBackToSettings(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))
	require.NoError(t, settings.Set(settings.CountryCodeKey, "IR"))
	require.NoError(t, settings.Set(settings.DeviceIDKey, "device-123"))
	require.NoError(t, settings.Set(settings.SplitTunnelKey, true))

	meta := (*LocalBackend)(nil).buildIssueReportMetadata()

	assert.Equal(t, "IR", meta.country)
	assert.Equal(t, "device-123", meta.deviceID, "device ID must survive a backendless report")
	assert.True(t, meta.splitTunnelEnabled, "split-tunnel state must survive a backendless report")
	assert.NotNil(t, meta.reporter, "a reporter is always needed to upload the report")
}

func TestServerListFromConfig_ExcludesNonSelectable(t *testing.T) {
	cfg := &config.Config{
		Options: option.Options{
			Outbounds: []option.Outbound{
				{Tag: "proxy-1", Type: "shadowsocks"},
				{Tag: "testing-out", Type: "testing"},
			},
			Endpoints: []option.Endpoint{
				{Tag: "ep-1", Type: "wireguard"},
				{Tag: "infra-ep", Type: "wireguard"},
			},
		},
		NonSelectableOutbounds: []string{"testing-out", "infra-ep"},
	}

	list := serverListFromConfig(cfg)

	gotTags := make([]string, 0, len(list.Servers))
	for _, s := range list.Servers {
		gotTags = append(gotTags, s.Tag)
	}
	assert.ElementsMatch(t, []string{"proxy-1", "ep-1"}, gotTags,
		"non-selectable outbounds and endpoints must be excluded from the managed server list")
}

func TestNonSelectableOutboundsFromConfig(t *testing.T) {
	cfg := &config.Config{
		Options: option.Options{
			Outbounds: []option.Outbound{
				{Tag: "proxy-1", Type: "shadowsocks"},
				{Tag: "testing-out", Type: "testing"},
			},
			Endpoints: []option.Endpoint{
				{Tag: "infra-ep", Type: "wireguard"},
			},
		},
		NonSelectableOutbounds: []string{"testing-out", "infra-ep"},
	}

	list := nonSelectableOutboundsFromConfig(cfg)

	gotTags := make([]string, 0, len(list.Servers))
	for _, s := range list.Servers {
		gotTags = append(gotTags, s.Tag)
	}
	assert.ElementsMatch(t, []string{"testing-out"}, gotTags,
		"only non-selectable outbounds are returned; selectable outbounds and non-selectable endpoints are excluded")
	require.Len(t, list.Outbounds(), 1, "the returned server must decode as an outbound for the tunnel")
}

func TestLanternServerTags(t *testing.T) {
	cfg := &config.Config{
		Options: option.Options{
			Outbounds: []option.Outbound{{Tag: "out-1"}, {Tag: "out-2"}},
			Endpoints: []option.Endpoint{{Tag: "ep-1"}},
		},
	}

	t.Run("config outbounds and endpoints are all lantern", func(t *testing.T) {
		assert.ElementsMatch(t, []string{"out-1", "out-2", "ep-1"}, lanternServerTags(cfg, nil))
	})

	t.Run("managed servers included only when lantern", func(t *testing.T) {
		managed := []*servers.Server{
			{Tag: "lan-1", IsLantern: true},
			{Tag: "user-1", IsLantern: false},
		}
		assert.Equal(t, []string{"lan-1"}, lanternServerTags(nil, managed))
	})

	t.Run("config and managed lantern tags are unioned and deduped", func(t *testing.T) {
		managed := []*servers.Server{
			{Tag: "out-1", IsLantern: true}, // duplicate of a config tag
			{Tag: "lan-2", IsLantern: true},
			{Tag: "user-1", IsLantern: false},
		}
		got := lanternServerTags(cfg, managed)
		assert.ElementsMatch(t, []string{"out-1", "out-2", "ep-1", "lan-2"}, got)
		assert.Len(t, got, 4, "the tag shared by config and managed must appear once")
	})

	t.Run("empty tags are skipped", func(t *testing.T) {
		emptyCfg := &config.Config{Options: option.Options{Outbounds: []option.Outbound{{Tag: ""}}}}
		assert.Empty(t, lanternServerTags(emptyCfg, []*servers.Server{{Tag: "", IsLantern: true}}))
	})

	t.Run("nil config and managed yields no tags", func(t *testing.T) {
		assert.Empty(t, lanternServerTags(nil, nil))
	})
}

// TestAwaitConnectable covers the gate that holds a too-early connect until
// there is something to dial.
//
// A connect that arrives before the first config must wait for one instead of
// failing. On iOS the process that reports "no outbounds" is the same process
// hosting the config fetch, and its failure handler tears that process down —
// a first-run deadlock on any slow network (getlantern/engineering#3814).
func TestAwaitConnectable(t *testing.T) {
	// newBackend builds a backend with only what awaitConnectable reads. A
	// cached config on disk is how a returning user already has one at connect.
	newBackend := func(t *testing.T, cached bool) *LocalBackend {
		t.Helper()
		dataDir := t.TempDir()
		if cached {
			buf, err := singjson.Marshal(cachedConfig())
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dataDir, internal.ConfigFileName), buf, 0o600))
		}
		settings.Reset()
		t.Cleanup(settings.Reset)
		require.NoError(t, settings.InitSettings(dataDir))
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		srvMgr, err := servers.NewManager(dataDir, log.NoOpLogger())
		require.NoError(t, err)
		return &LocalBackend{
			ctx:         ctx,
			confHandler: config.NewConfigHandler(ctx, config.Options{DataPath: dataDir, Logger: log.NoOpLogger()}),
			srvManager:  srvMgr,
		}
	}

	// The censored-network shape: the fetch completes, just not instantly.
	t.Run("returns as soon as a config lands", func(t *testing.T) {
		r := newBackend(t, false)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		go func() {
			time.Sleep(150 * time.Millisecond)
			events.Emit(config.NewConfigEvent{New: cachedConfig()})
		}()

		start := time.Now()
		require.NoError(t, r.awaitConnectable(ctx, vpn.AutoSelectTag))
		assert.Less(t, time.Since(start), 3*time.Second, "must return on the config, not on the deadline")
	})

	// events.Emit runs each callback on its own goroutine and SubscribeOnce gates
	// on a plain atomic load, not a CAS, so simultaneous configs can both reach
	// the subscription. Closing the ready channel twice would panic the process.
	t.Run("survives several configs landing at once", func(t *testing.T) {
		r := newBackend(t, false)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var emitters sync.WaitGroup
		emitters.Add(1)
		go func() {
			defer emitters.Done()
			// Ordering, not a timing assertion: the emits have to land after
			// awaitConnectable has subscribed.
			time.Sleep(150 * time.Millisecond)
			var burst sync.WaitGroup
			for range 8 {
				burst.Add(1)
				go func() {
					defer burst.Done()
					events.Emit(config.NewConfigEvent{New: cachedConfig()})
				}()
			}
			burst.Wait()
		}()
		t.Cleanup(emitters.Wait)

		require.NoError(t, r.awaitConnectable(ctx, vpn.AutoSelectTag))
	})

	t.Run("gives up on the caller's deadline rather than blocking forever", func(t *testing.T) {
		r := newBackend(t, false)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := r.awaitConnectable(ctx, vpn.AutoSelectTag)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	// A cached config on disk is enough to connect: NewConfigHandler loads it
	// synchronously, so a returning user's tunnel comes up on it without waiting
	// for any fetch. The already-expired context proves nothing waited, and the
	// box options prove the tunnel actually gets the cached outbounds.
	t.Run("connects straight off the cached config on disk", func(t *testing.T) {
		r := newBackend(t, true)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		require.NoError(t, r.awaitConnectable(ctx, vpn.AutoSelectTag))

		tags := make([]string, 0, len(r.getBoxOptions().Options.Outbounds))
		for _, out := range r.getBoxOptions().Options.Outbounds {
			tags = append(tags, out.Tag)
		}
		assert.Contains(t, tags, "cached-out", "the tunnel must be built from the cached config")
	})

	// A user with their own server can dial it without a Lantern config, so the
	// gate must not hold that connect hostage to a fetch it does not need.
	t.Run("does not wait when the user has a server of their own", func(t *testing.T) {
		r := newBackend(t, false)
		require.NoError(t, r.srvManager.AddServers(
			servers.ServerList{Servers: []*servers.Server{{Tag: "mine", Type: "shadowsocks"}}}, true))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		assert.NoError(t, r.awaitConnectable(ctx, vpn.AutoSelectTag), "auto-select can use the managed server")
		assert.NoError(t, r.awaitConnectable(ctx, "mine"), "an explicit tag resolves without a config")
	})
}

func TestSetCountryCodeFromConfigFollowsCorrections(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))

	setCountryCodeFromConfig(&config.Config{Country: "US"})
	assert.Equal(t, "US", settings.GetString(settings.CountryCodeKey))

	setCountryCodeFromConfig(&config.Config{Country: "IR"})
	assert.Equal(t, "IR", settings.GetString(settings.CountryCodeKey), "a later config corrects the country")

	setCountryCodeFromConfig(&config.Config{})
	assert.Equal(t, "IR", settings.GetString(settings.CountryCodeKey), "a config without a country keeps the last one")
}

func TestPatchSettings_ServePoolChangeReregistersARunningPeer(t *testing.T) {
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	require.NoError(t, b.PatchSettings(settings.Settings{settings.PeerServePoolKey: false}))
	b.peerWG.Wait()
	assert.Equal(t, int64(1), fake.reregisterCalls.Load())

	require.NoError(t, b.PatchSettings(settings.Settings{settings.PeerServePoolKey: false}))
	b.peerWG.Wait()
	assert.Equal(t, int64(1), fake.reregisterCalls.Load(), "an unchanged value re-registers nothing")
}

func TestPatchSettings_ServePoolChangeLeavesAStoppedPeerAlone(t *testing.T) {
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	require.NoError(t, b.PatchSettings(settings.Settings{settings.PeerServePoolKey: false}))
	b.peerWG.Wait()
	assert.Zero(t, fake.reregisterCalls.Load())
}

// A patch that also turns sharing on registers once, through Start, with the
// new value already persisted.
func TestPatchSettings_ServePoolWithToggleOnDoesNotReregister(t *testing.T) {
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	require.NoError(t, b.PatchSettings(settings.Settings{
		settings.PeerShareEnabledKey: true, settings.PeerServePoolKey: false}))
	b.peerWG.Wait()
	assert.Equal(t, int64(1), fake.startCalls.Load())
	assert.Zero(t, fake.reregisterCalls.Load())
}

// A patch that turns sharing on for a peer already running starts nothing,
// so its serve-pool change still has to re-register.
func TestPatchSettings_ServePoolWithToggleOnForARunningPeerReregisters(t *testing.T) {
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	require.NoError(t, b.PatchSettings(settings.Settings{
		settings.PeerShareEnabledKey: true, settings.PeerServePoolKey: false}))
	b.peerWG.Wait()
	assert.Zero(t, fake.startCalls.Load())
	assert.Equal(t, int64(1), fake.reregisterCalls.Load())
}

func TestReregisterPeer_SkipsAClosedBackend(t *testing.T) {
	fake := &fakePeerController{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &LocalBackend{ctx: ctx, peerClient: fake}
	fake.active.Store(true)
	b.reregisterPeer()
	b.peerWG.Wait()
	assert.Zero(t, fake.reregisterCalls.Load())
}

// Once closePeerClient has begun waiting, a re-register starts nothing, even
// before Close cancels the backend's context.
func TestReregisterPeer_AfterCloseStartsNothing(t *testing.T) {
	fake := &fakePeerController{}
	b := newCloseableTestBackend(t, fake)
	fake.active.Store(true)
	b.closePeerClient()
	fake.active.Store(true)
	b.reregisterPeer()
	b.peerWG.Wait()
	assert.Zero(t, fake.reregisterCalls.Load())
}

// setReregisterBackoff shortens or lengthens the re-register retry for a test.
func setReregisterBackoff(t *testing.T, first, longest time.Duration) {
	prevFirst, prevMax := reregisterRetryFirst, reregisterRetryMax
	reregisterRetryFirst, reregisterRetryMax = first, longest
	t.Cleanup(func() { reregisterRetryFirst, reregisterRetryMax = prevFirst, prevMax })
}

// waitPeerWork waits for the backend's background peer work, failing the
// test if it does not finish.
func waitPeerWork(t *testing.T, b *LocalBackend) {
	t.Helper()
	done := make(chan struct{})
	go func() { b.peerWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("peer work did not finish")
	}
}

var errUnreachable = errors.New("lantern-cloud unreachable")

func TestReregisterPeer_RetriesUntilItSucceeds(t *testing.T) {
	setReregisterBackoff(t, time.Millisecond, 4*time.Millisecond)
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	fake.setReregister(func(_ context.Context, n int64) error {
		if n < 3 {
			return errUnreachable
		}
		return nil
	})
	b.reregisterPeer()
	waitPeerWork(t, b)
	assert.Equal(t, int64(3), fake.reregisterCalls.Load())
}

func TestReregisterPeer_StopsWhenThePeerStops(t *testing.T) {
	setReregisterBackoff(t, time.Millisecond, time.Millisecond)
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	fake.setReregister(func(context.Context, int64) error { return peer.ErrNotActive })
	b.reregisterPeer()
	waitPeerWork(t, b)
	assert.Equal(t, int64(1), fake.reregisterCalls.Load())
}

// Close cancels a retry waiting out its backoff, so it neither hangs Close nor
// outlives the backend.
func TestReregisterPeer_CloseEndsTheRetry(t *testing.T) {
	setReregisterBackoff(t, time.Hour, time.Hour)
	fake := &fakePeerController{}
	b := newCloseableTestBackend(t, fake)
	fake.active.Store(true)
	fake.setReregister(func(context.Context, int64) error { return errUnreachable })
	b.reregisterPeer()
	require.Eventually(t, func() bool { return fake.reregisterCalls.Load() == 1 }, time.Second, time.Millisecond)
	closed := make(chan struct{})
	go func() { b.closePeerClient(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited out the backoff")
	}
	assert.Equal(t, int64(1), fake.reregisterCalls.Load())
}

// Only the latest request's retry keeps running: a newer toggle cancels the
// older loop, which would otherwise sit in its hour-long backoff.
func TestReregisterPeer_ANewerRequestSupersedesTheRetry(t *testing.T) {
	setReregisterBackoff(t, time.Hour, time.Hour)
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	fake.setReregister(func(context.Context, int64) error { return errUnreachable })
	b.reregisterPeer()
	require.Eventually(t, func() bool { return fake.reregisterCalls.Load() == 1 }, time.Second, time.Millisecond)
	fake.setReregister(func(context.Context, int64) error { return nil })
	b.reregisterPeer()
	waitPeerWork(t, b)
	assert.Equal(t, int64(2), fake.reregisterCalls.Load())
}

// Turning sharing off ends a pending retry: the session it was for is gone,
// and a new session's Start has registered the current setting already.
func TestReregisterPeer_StopAndStartEndTheRetry(t *testing.T) {
	setReregisterBackoff(t, 50*time.Millisecond, 50*time.Millisecond)
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	fake.setReregister(func(context.Context, int64) error { return errUnreachable })
	b.reregisterPeer()
	require.Eventually(t, func() bool { return fake.reregisterCalls.Load() == 1 }, time.Second, time.Millisecond)
	require.NoError(t, b.applyPeerShare(false))
	require.NoError(t, b.applyPeerShare(true))
	waitPeerWork(t, b)
	assert.Never(t, func() bool { return fake.reregisterCalls.Load() > 1 }, 200*time.Millisecond, 5*time.Millisecond,
		"the stale retry never reaches the new session")
}

// Close stops the activity ticker and flushes before it returns, so the file
// does not change afterwards.
func TestClose_NoActivitySaveAfterItReturns(t *testing.T) {
	fake := &fakePeerController{}
	b := newCloseableTestBackend(t, fake)
	path := filepath.Join(t.TempDir(), "helper-activity.json")
	b.helperActivity = helper.NewActivityTracker(path, func() (bool, string, uint64) { return true, "e", 0 })
	go b.helperActivity.Run(b.ctx, time.Millisecond)
	require.Eventually(t, func() bool { _, err := os.Stat(path); return err == nil }, time.Second, time.Millisecond)
	b.Close()
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))
}

// A newer toggle supersedes the retry loop, not the attempt already running:
// cancelling that could abort a rotation between its register and its box
// rebuild and stop sharing.
func TestReregisterPeer_ANewerRequestLetsTheRunningAttemptFinish(t *testing.T) {
	setReregisterBackoff(t, time.Hour, time.Hour)
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	fake.setReregister(func(ctx context.Context, n int64) error {
		if n == 1 {
			started <- ctx
			<-release
		}
		return nil
	})
	b.reregisterPeer()
	first := <-started
	b.reregisterPeer()
	assert.Never(t, func() bool { return first.Err() != nil }, 30*time.Millisecond, time.Millisecond,
		"the running attempt is not cancelled")
	close(release)
	waitPeerWork(t, b)
	assert.Equal(t, int64(2), fake.reregisterCalls.Load(), "the newer request's attempt runs after it")
}

// Turning sharing off cancels a running attempt at once rather than waiting
// for it under the toggle lock.
func TestReregisterPeer_TurningOffCancelsTheRunningAttempt(t *testing.T) {
	setReregisterBackoff(t, time.Hour, time.Hour)
	fake := &fakePeerController{}
	b := newPeerTestBackend(t, fake)
	fake.active.Store(true)
	started := make(chan struct{})
	fake.setReregister(func(ctx context.Context, n int64) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	b.reregisterPeer()
	<-started
	done := make(chan error, 1)
	go func() { done <- b.applyPeerShare(false) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("turning sharing off waited for the attempt")
	}
	waitPeerWork(t, b)
}

func newPersonalProxiesBackend(t *testing.T) *LocalBackend {
	t.Helper()
	return newPersonalProxiesBackendIn(t, t.TempDir())
}

func newPersonalProxiesBackendIn(t *testing.T, dataDir string) *LocalBackend {
	t.Helper()
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(dataDir))
	// A connect writes the tunnel's files under the data path.
	require.NoError(t, settings.Set(settings.DataPathKey, dataDir))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srvMgr, err := servers.NewManager(dataDir, log.NoOpLogger())
	require.NoError(t, err)
	return &LocalBackend{
		ctx:         ctx,
		confHandler: config.NewConfigHandler(ctx, config.Options{DataPath: dataDir, Logger: log.NoOpLogger()}),
		srvManager:  srvMgr,
		vpnClient:   vpn.NewVPNClient(dataDir, log.NoOpLogger(), nil),
	}
}

func addDirectServer(t *testing.T, r *LocalBackend, tag string) {
	t.Helper()
	require.NoError(t, r.srvManager.AddServers(servers.ServerList{Servers: []*servers.Server{{
		Tag: tag, Type: "direct", IsLantern: true,
		Options: option.Outbound{Tag: tag, Type: "direct", Options: &option.DirectOutboundOptions{}},
	}}}, false))
}

func TestPersonalProxiesServerExistsWhileAHelperDoes(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	addDirectServer(t, r, "lantern-1")
	_, found := r.GetServerByTag(vpn.PersonalProxiesTag)
	assert.False(t, found, "no helper outbound, no group")
	assert.False(t, r.connectable(vpn.PersonalProxiesTag))

	addDirectServer(t, r, "helper-0123456789ab")
	srv, found := r.GetServerByTag(vpn.PersonalProxiesTag)
	require.True(t, found)
	assert.Equal(t, vpn.PersonalProxiesTag, srv.Tag)
	assert.False(t, srv.IsLantern)
	assert.Nil(t, srv.Options)
	assert.True(t, r.connectable(vpn.PersonalProxiesTag))
	for _, s := range r.AllServers() {
		assert.NotEqual(t, vpn.PersonalProxiesTag, s.Tag, "never listed among servers")
	}
}

func TestPersonalProxiesServerExistsWhileAReverseOutboundDoes(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	addDirectServer(t, r, "lantern-1")
	require.NoError(t, r.vpnClient.SetReverseOutbounds([]string{lbA.ReverseHelperTag("helper-0123456789ab")}))
	_, found := r.GetServerByTag(vpn.PersonalProxiesTag)
	assert.True(t, found)
	require.NoError(t, r.vpnClient.SetReverseOutbounds(nil))
	_, found = r.GetServerByTag(vpn.PersonalProxiesTag)
	assert.False(t, found)
}

func TestPersonalProxiesSelectionLastsWhileAHelperDoes(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	addDirectServer(t, r, "helper-0123456789ab")
	r.persistSelection(vpn.PersonalProxiesTag)
	assert.False(t, settings.GetBool(settings.AutoConnectKey))

	sel, exists, err := r.SelectedServer()
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, vpn.PersonalProxiesTag, sel.Tag)

	r.clearSelectedIfMissing()
	assert.False(t, settings.GetBool(settings.AutoConnectKey), "kept while a helper remains")

	_, err = r.srvManager.RemoveServers([]string{"helper-0123456789ab"})
	require.NoError(t, err)
	r.clearSelectedIfMissing()
	assert.True(t, settings.GetBool(settings.AutoConnectKey), "falls back to Smart Location")
}

func directServers(tags ...string) servers.ServerList {
	var list servers.ServerList
	for _, tag := range tags {
		list.Servers = append(list.Servers, &servers.Server{
			Tag: tag, Type: "direct", IsLantern: true,
			Options: option.Outbound{Tag: tag, Type: "direct", Options: &option.DirectOutboundOptions{}},
		})
	}
	return list
}

// Helper outbounds arrive in the config, so they are Lantern servers, but
// they are the user's pairings rather than offers to rotate out. With the
// personal proxies group selected, evicting them all would drop the user's
// choice back to Smart Location.
func TestConfigEvictionKeepsHelpersAndThePersonalProxiesSelection(t *testing.T) {
	const h1, h2 = "helper-0123456789ab", "helper-ba9876543210"
	r := newPersonalProxiesBackend(t)
	retained := []string{h1, h2}
	for i := range maxRetainedLanternServers + 5 {
		retained = append(retained, fmt.Sprintf("lantern-%d", i))
	}
	require.NoError(t, r.srvManager.AddServers(directServers(retained...), false))
	r.persistSelection(vpn.PersonalProxiesTag)

	incoming := []string{h1, h2} // a config keeps carrying its pairings' helpers
	for i := range 10 {
		incoming = append(incoming, fmt.Sprintf("new-%d", i))
	}
	require.NoError(t, r.updateServers(directServers(incoming...), true))

	for _, tag := range []string{h1, h2} {
		_, found := r.srvManager.GetServerByTag(tag)
		assert.True(t, found, "helper %s must not be evicted", tag)
	}
	assert.Len(t, r.srvManager.AllServers(), maxRetainedLanternServers+2,
		"other retained servers are still evicted down to the limit; the helpers sit outside it")
	assert.False(t, settings.GetBool(settings.AutoConnectKey), "the personal proxies selection is kept")
	sel, exists, err := r.SelectedServer()
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, vpn.PersonalProxiesTag, sel.Tag)
}

func helperWithPort(tag string, port uint16) *servers.Server {
	return &servers.Server{
		Tag: tag, Type: "socks", IsLantern: true,
		Options: option.Outbound{Tag: tag, Type: "socks", Options: &option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "203.0.113.7", ServerPort: port},
		}},
	}
}

func storedPort(t *testing.T, r *LocalBackend, tag string) uint16 {
	t.Helper()
	srv, found := r.srvManager.GetServerByTag(tag)
	require.True(t, found, tag)
	return srv.Options.(option.Outbound).Options.(*option.SOCKSOutboundOptions).ServerPort
}

// A helper's tag is stable per pairing and route, but the credentials in its
// options rotate (the samizdat short ID changes daily), so a config carrying
// a known helper tag with new options must replace the stored server.
func TestConfigUpdateRefreshesAHelperWhoseOptionsChanged(t *testing.T) {
	const h = "helper-0123456789ab"
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.updateServers(servers.ServerList{Servers: []*servers.Server{helperWithPort(h, 1080)}}, true))
	require.Equal(t, uint16(1080), storedPort(t, r, h))
	before, _ := r.srvManager.GetServerByTag(h)
	before.SelectionHistory = &servers.SelectionHistory{UpdatedAt: time.Unix(100, 0).UTC()}
	require.NoError(t, r.srvManager.AddServers(servers.ServerList{Servers: []*servers.Server{before}}, true))

	require.NoError(t, r.updateServers(servers.ServerList{Servers: []*servers.Server{helperWithPort(h, 1081)}}, true))
	assert.Equal(t, uint16(1081), storedPort(t, r, h), "the new options are stored")
	after, _ := r.srvManager.GetServerByTag(h)
	require.NotNil(t, after.SelectionHistory, "the server's history is kept")
	assert.Equal(t, time.Unix(100, 0).UTC(), after.SelectionHistory.UpdatedAt)

	// Non-helper servers keep the first offer, as before.
	require.NoError(t, r.updateServers(servers.ServerList{Servers: []*servers.Server{helperWithPort("lantern-x", 1080)}}, true))
	require.NoError(t, r.updateServers(servers.ServerList{Servers: []*servers.Server{helperWithPort("lantern-x", 1081)}}, true))
	assert.Equal(t, uint16(1080), storedPort(t, r, "lantern-x"))
}

func TestConfigUpdateLeavesAnUnchangedHelperAlone(t *testing.T) {
	const h = "helper-0123456789ab"
	dataDir := t.TempDir()
	r := newPersonalProxiesBackendIn(t, dataDir)
	require.NoError(t, r.updateServers(servers.ServerList{Servers: []*servers.Server{helperWithPort(h, 1080)}}, true))
	serversFile := filepath.Join(dataDir, internal.ServersFileName)
	stamp := time.Unix(1, 0)
	require.NoError(t, os.Chtimes(serversFile, stamp, stamp))

	require.NoError(t, r.updateServers(servers.ServerList{Servers: []*servers.Server{helperWithPort(h, 1080)}}, true))
	info, err := os.Stat(serversFile)
	require.NoError(t, err)
	assert.True(t, info.ModTime().Equal(stamp), "identical options are not rewritten")
	assert.Equal(t, uint16(1080), storedPort(t, r, h))
}

func TestImportRefusesThePersonalProxiesTag(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	_, err := r.AddServersByJSON(`{"outbounds":[{"type":"socks","tag":"personal-proxies","server":"203.0.113.7","server_port":1080}]}`)
	require.ErrorIs(t, err, servers.ErrReservedTag)
	require.ErrorIs(t, r.AddServers(servers.ServerList{Servers: []*servers.Server{helperWithPort(vpn.PersonalProxiesTag, 1080)}}),
		servers.ErrReservedTag)
	assert.Empty(t, r.AllServers())
	_, found := r.GetServerByTag(vpn.PersonalProxiesTag)
	assert.False(t, found)
}

// A config that no longer carries a helper ended its pairing: the helper is
// removed, and with the last one the personal proxies group and a selection
// of it. That holds for the cached config applied at startup too: the process
// can stop after a new config is saved but before it is applied, and later
// fetches of the same config bring no update. Only helpers are withdrawn on
// that path; a retained Lantern server is not evicted.
func TestConfigWithoutAHelperEndsItsPairing(t *testing.T) {
	const h = "helper-0123456789ab"
	for _, tc := range []struct {
		name  string
		fresh bool
	}{
		{"fresh config", true},
		{"cached config at startup, saved before a crash", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPersonalProxiesBackend(t)
			tun := &fakeHelperTunnel{}
			tun.attach(r)
			tun.up(directServers("lantern-1", "lantern-old", h).Servers...)
			// The servers the previous config left.
			require.NoError(t, r.updateServers(directServers("lantern-1", "lantern-old", h), true))
			r.persistSelection(vpn.PersonalProxiesTag)
			require.False(t, settings.GetBool(settings.AutoConnectKey))

			// The new config, applied fresh or (after a restart) from the cache.
			require.NoError(t, r.updateServers(directServers("lantern-1"), tc.fresh))
			_, helperKept := r.srvManager.GetServerByTag(h)
			_, offered := r.GetServerByTag(vpn.PersonalProxiesTag)
			_, retained := r.srvManager.GetServerByTag("lantern-old")
			assert.False(t, helperKept)
			assert.False(t, offered)
			assert.True(t, retained, "a Lantern server the config dropped is retained, not evicted")
			assert.True(t, settings.GetBool(settings.AutoConnectKey),
				"a selection of the withdrawn group falls back to auto-select")
			assert.False(t, tun.holds(h), "and the helper leaves the tunnel")
		})
	}
}

// The IPC AddServers path takes a server's tag and its outbound separately.
// The server's tag is the effective one: an outbound tagged with a reserved
// tag under another name is stored and handed to the tunnel under that name.
func TestAddServersUsesTheServerTag(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	srv := helperWithPort("mine", 1080)
	srv.IsLantern = false
	srv.Options = helperWithPort(vpn.AutoSelectTag, 1080).Options
	list := servers.ServerList{Servers: []*servers.Server{srv}}
	require.NoError(t, r.AddServers(list))
	assert.Equal(t, "mine", list.Outbounds()[0].Tag, "what reaches the tunnel")
	stored, found := r.GetServerByTag("mine")
	require.True(t, found)
	assert.Equal(t, "mine", stored.Options.(option.Outbound).Tag)
	_, found = r.GetServerByTag(vpn.AutoSelectTag)
	assert.False(t, found)

	require.ErrorIs(t, r.AddServers(servers.ServerList{Servers: []*servers.Server{helperWithPort(vpn.AutoSelectTag, 1080)}}),
		servers.ErrReservedTag, "a reserved server tag is still refused")
}

// The app renames a private server by fetching it over IPC (as JSON), removing
// it, and adding it back with only its tag changed: its outbound still carries
// the old tag. The rename must keep the server, under the new tag throughout.
func TestRenamingAServerKeepsIt(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	original := helperWithPort("old", 1080)
	original.IsLantern = false
	require.NoError(t, r.AddServers(servers.ServerList{Servers: []*servers.Server{original}}))

	stored, found := r.GetServerByTag("old")
	require.True(t, found)
	wire, err := json.Marshal(stored)
	require.NoError(t, err)
	var source servers.Server
	require.NoError(t, json.Unmarshal(wire, &source))

	require.NoError(t, r.RemoveServers([]string{"old"}))
	source.Tag = "new"
	list := servers.ServerList{Servers: []*servers.Server{&source}}
	require.NoError(t, r.AddServers(list))

	assert.Equal(t, "new", list.Outbounds()[0].Tag, "what reaches the tunnel")
	renamed, found := r.GetServerByTag("new")
	require.True(t, found)
	assert.Equal(t, "new", renamed.Options.(option.Outbound).Tag)
	assert.Equal(t, uint16(1080), renamed.Options.(option.Outbound).Options.(*option.SOCKSOutboundOptions).ServerPort)
	_, found = r.GetServerByTag("old")
	assert.False(t, found)
}

func lanternServersWithHistory(n int) servers.ServerList {
	list := directServers()
	for i := range n {
		srv := directServers(fmt.Sprintf("lantern-%d", i)).Servers[0]
		srv.SelectionHistory = &servers.SelectionHistory{UpdatedAt: time.Unix(int64(1000+i), 0).UTC()}
		list.Servers = append(list.Servers, srv)
	}
	return list
}

// A new pairing's helper takes no retention slot, so it does not push out a
// Lantern server.
func TestNewHelperDoesNotEvictALanternServer(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.srvManager.AddServers(lanternServersWithHistory(maxRetainedLanternServers), false))
	require.NoError(t, r.updateServers(directServers("helper-0123456789ab"), true))
	assert.Len(t, r.AllServers(), maxRetainedLanternServers+1, "nothing was evicted")
}

// A connect that selected the group, which a config update withdrew while
// the tunnel came up, persists auto-select rather than leaving the old choice.
func TestConnectedSelectionFallsBackWhenWithdrawnDuringConnect(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.updateServers(directServers("lantern-1"), true))
	r.persistSelection("lantern-1")
	r.persistConnectedSelection(vpn.PersonalProxiesTag)
	assert.True(t, settings.GetBool(settings.AutoConnectKey))

	require.NoError(t, r.updateServers(directServers("lantern-1", "helper-0123456789ab"), true))
	r.persistConnectedSelection(vpn.PersonalProxiesTag)
	assert.False(t, settings.GetBool(settings.AutoConnectKey))
	sel, _, err := r.SelectedServer()
	require.NoError(t, err)
	assert.Equal(t, vpn.PersonalProxiesTag, sel.Tag)
}

// fakeHelperTunnel stands in for the running tunnel in backend tests, which
// have no tunnel. live maps each outbound tag to its options' fingerprint,
// and is nil while no tunnel is up. UpdateOutbounds only adds and updates, as
// the real update does when its guards keep old outbounds; ReconcileHelpers
// does what the real one does. calls records each call in order.
type fakeHelperTunnel struct {
	mu       sync.Mutex
	live     map[string]string
	removed  [][]string
	calls    []string
	fail     bool
	gate     func() // if set, runs before each reconciliation
	onSelect func() // if set, runs as each selection is applied
	// onRestart, if set, runs as a restart begins, before it rebuilds.
	onRestart func()
	// platformRestart, if set, replaces a restart's rebuild: the tunnel is
	// torn down and reports Restarting while it runs, as a platform restart
	// that reconnects through the backend does.
	platformRestart func()
	restarting      bool
	// onConnect, if set, runs once a connect is up, before it returns, as
	// the VPN client's Connected event does.
	onConnect func()
	// connectErr, if set, fails every connect.
	connectErr error
	// autoChoice is the server auto mode reports having chosen.
	autoChoice string
	// selected is the selection the tunnel last applied.
	selected string
	// friend is the friend whose group the tunnel has selected, or "".
	friend string
	// friendless starts a connect or restart that selects a friend on the
	// personal proxies group, as a tunnel built while the friend had no
	// member does; refuseFriend refuses every selection of a friend.
	friendless, refuseFriend bool
	// refuseGroup refuses a selection of the personal proxies group.
	refuseGroup bool
	// rebuild makes a restart hold only the outbounds in its options, and a
	// selection of a friend require the friend's outbound.
	rebuild bool
}

// startOn applies initial as a tunnel built with it would. The caller must
// hold f.mu.
func (f *fakeHelperTunnel) startOn(initial string) {
	f.selected, f.friend = initial, ""
	if friend, ok := vpn.ParsePersonalProxySelection(initial); ok {
		if f.friendless {
			f.selected = vpn.PersonalProxiesTag
		} else {
			f.friend = friend
		}
	}
}

func (f *fakeHelperTunnel) Connect(_ context.Context, boxOptions vpn.BoxOptions) error {
	f.mu.Lock()
	f.calls = append(f.calls, "connect:"+boxOptions.InitialServer)
	if f.connectErr != nil {
		f.mu.Unlock()
		return f.connectErr
	}
	if f.live == nil {
		f.live = make(map[string]string)
	}
	f.startOn(boxOptions.InitialServer)
	f.mu.Unlock()
	if f.onConnect != nil {
		f.onConnect()
	}
	return nil
}

func (f *fakeHelperTunnel) SelectedPersonalProxy() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.live == nil {
		return ""
	}
	return f.friend
}

var _ liveTunnel = (*fakeHelperTunnel)(nil)

func (f *fakeHelperTunnel) CurrentAutoSelectedServer() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.autoChoice, nil
}

func (f *fakeHelperTunnel) AnnouncedAutoSelectedServer() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.autoChoice
}

func (f *fakeHelperTunnel) CurrentSelectedServer() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.live == nil {
		return "", nil
	}
	if f.selected == vpn.AutoSelectTag && f.autoChoice != "" {
		return f.autoChoice, nil
	}
	return f.selected, nil
}

func (f *fakeHelperTunnel) ManualSelection() (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.live == nil || f.selected == "" || f.selected == vpn.AutoSelectTag {
		return "", false
	}
	return f.selected, true
}

func (f *fakeHelperTunnel) attach(r *LocalBackend) { r.live = f }

func fingerprint(srv *servers.Server) string {
	if out, ok := srv.Options.(option.Outbound); ok {
		if socks, ok := out.Options.(*option.SOCKSOutboundOptions); ok {
			return fmt.Sprint(socks.ServerPort)
		}
	}
	return srv.Type
}

func (f *fakeHelperTunnel) UpdateOutbounds(list servers.ServerList) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "update")
	if f.live == nil {
		return vpn.ErrTunnelNotConnected
	}
	for _, srv := range list.Servers {
		f.live[srv.Tag] = fingerprint(srv)
	}
	return nil
}

func (f *fakeHelperTunnel) RemoveOutbounds(tags []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "remove")
	if f.live == nil {
		return vpn.ErrTunnelNotConnected
	}
	for _, tag := range tags {
		delete(f.live, tag)
	}
	return nil
}

func (f *fakeHelperTunnel) SelectServer(tag string) error {
	if f.onSelect != nil {
		f.onSelect()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "select:"+tag)
	if f.live == nil {
		return vpn.ErrTunnelNotConnected
	}
	friend, isFriend := vpn.ParsePersonalProxySelection(tag)
	if isFriend && f.refuseFriend {
		return vpn.ErrPersonalProxyUnavailable
	}
	if tag == vpn.PersonalProxiesTag && f.refuseGroup {
		return vpn.ErrPersonalProxiesUnavailable
	}
	if _, held := f.live[friend]; isFriend && f.rebuild && !held {
		return vpn.ErrPersonalProxyUnavailable
	}
	f.selected, f.friend = tag, friend
	return nil
}

func (f *fakeHelperTunnel) Restart(boxOptions vpn.BoxOptions) error {
	if f.onRestart != nil {
		f.onRestart()
	}
	f.mu.Lock()
	f.calls = append(f.calls, "restart:"+boxOptions.InitialServer)
	if f.live != nil && f.platformRestart != nil {
		f.live, f.restarting = nil, true
		f.mu.Unlock()
		f.platformRestart()
		f.mu.Lock()
		f.restarting = false
		f.mu.Unlock()
		return nil
	}
	defer f.mu.Unlock()
	if f.live == nil {
		return vpn.ErrTunnelNotConnected
	}
	if f.rebuild {
		f.live = make(map[string]string)
		for _, out := range boxOptions.Options.Outbounds {
			f.live[out.Tag] = out.Type
		}
	}
	f.startOn(boxOptions.InitialServer)
	return nil
}

func (f *fakeHelperTunnel) Status() vpn.VPNStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.restarting:
		return vpn.Restarting
	case f.live != nil:
		return vpn.Connected
	}
	return vpn.Disconnected
}

func (f *fakeHelperTunnel) current() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.selected
}

func (f *fakeHelperTunnel) ReconcileHelpers(helpers servers.ServerList) error {
	if f.gate != nil {
		f.gate()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "reconcile")
	if f.live == nil {
		return vpn.ErrTunnelNotConnected
	}
	if f.fail {
		return errors.New("tunnel busy")
	}
	keep := helpers.Tags()
	var stale []string
	for tag := range f.live {
		if lbA.IsHelperTag(tag) && !slices.Contains(keep, tag) {
			stale = append(stale, tag)
		}
	}
	if len(stale) > 0 {
		slices.Sort(stale)
		f.removed = append(f.removed, stale)
		for _, tag := range stale {
			delete(f.live, tag)
		}
	}
	for _, srv := range helpers.Servers {
		f.live[srv.Tag] = fingerprint(srv)
	}
	return nil
}

// up brings a tunnel up holding servers, as a connect or restart installs the
// options it captured.
func (f *fakeHelperTunnel) up(list ...*servers.Server) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live = make(map[string]string)
	for _, srv := range list {
		f.live[srv.Tag] = fingerprint(srv)
	}
}

func (f *fakeHelperTunnel) holds(tag string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.live[tag]
	return ok
}

func (f *fakeHelperTunnel) options(tag string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live[tag]
}

func (f *fakeHelperTunnel) removals() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.removed)
}

func (f *fakeHelperTunnel) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// A config that ends every pairing of a helpers-only device leaves an empty
// managed list, which the tunnel's update skips; the backend takes the ended
// helpers out of the tunnel itself, whether the config is fresh or cached.
func TestConfigRemovesEndedHelpersFromTheTunnel(t *testing.T) {
	const h1, h2 = "helper-0123456789ab", "helper-ba9876543210"
	for _, fresh := range []bool{true, false} {
		r := newPersonalProxiesBackend(t)
		tun := &fakeHelperTunnel{}
		tun.attach(r)
		tun.up(directServers(h1, h2).Servers...)
		require.NoError(t, r.updateServers(directServers(h1, h2), true))
		require.NoError(t, r.updateServers(servers.ServerList{}, fresh))
		assert.Equal(t, [][]string{{h1, h2}}, tun.removals(), "fresh=%v", fresh)
		assert.Empty(t, r.AllServers())
	}
}

// A failed removal is reported and the next config retries it, since the
// tunnel is reconciled with the manager each time; a helper whose pairing
// came back is kept.
func TestEndedHelperRemovalIsRetried(t *testing.T) {
	const h1, h2 = "helper-0123456789ab", "helper-ba9876543210"
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up(directServers("lantern-1", h1, h2).Servers...)
	require.NoError(t, r.updateServers(directServers("lantern-1", h1, h2), true))

	tun.fail = true
	require.Error(t, r.updateServers(directServers("lantern-1"), true), "the failed removal is reported")
	assert.True(t, tun.holds(h1))

	// h2's pairing comes back before the retry: only h1 is removed.
	tun.fail = false
	require.NoError(t, r.updateServers(directServers("lantern-1", h2), true))
	assert.Equal(t, [][]string{{h1}}, tun.removals())
	assert.True(t, tun.holds(h2))

	require.NoError(t, r.updateServers(directServers("lantern-1", h2), true))
	assert.Len(t, tun.removals(), 1, "nothing more to remove")
}

// A selection cannot interleave with a config update that withdraws it: it
// waits for the update, then finds the group gone and changes nothing.
func TestSelectionWaitsForAWithdrawingConfigUpdate(t *testing.T) {
	const h = "helper-0123456789ab"
	r := newPersonalProxiesBackend(t)
	require.NoError(t, r.updateServers(directServers("lantern-1", h), true))
	r.persistSelection("lantern-1")

	inRemoval, release := make(chan struct{}), make(chan struct{})
	tun := &fakeHelperTunnel{gate: func() {
		close(inRemoval)
		<-release
	}}
	tun.attach(r)
	tun.up(directServers("lantern-1", h).Servers...)
	updated := make(chan error, 1)
	go func() { updated <- r.updateServers(directServers("lantern-1"), true) }()
	<-inRemoval

	selected := make(chan error, 1)
	go func() { selected <- r.SelectServer(vpn.PersonalProxiesTag) }()
	select {
	case err := <-selected:
		t.Fatalf("selection ran during the withdrawal: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-updated)
	require.ErrorIs(t, <-selected, vpn.ErrPersonalProxiesUnavailable)
	sel, _, err := r.SelectedServer()
	require.NoError(t, err)
	assert.Equal(t, "lantern-1", sel.Tag, "the persisted choice is untouched")
}

// A connect or restart builds its tunnel from options it captured before
// taking the VPN lock. A config update in between that ends a pairing finds
// no tunnel (connect) or takes the helper out of the old one (restart); the
// tunnel that then comes up still holds it, and is reconciled with the
// manager once it reports Connected. A helper whose pairing remains is kept.
func TestTunnelsBuiltFromStaleOptionsLoseEndedHelpers(t *testing.T) {
	const ended, kept = "helper-0123456789ab", "helper-ba9876543210"
	for _, tc := range []struct {
		name      string
		upAtStart bool
	}{
		{"connect during the update", false},
		{"restart during the update", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPersonalProxiesBackend(t)
			r.startHelperReconcileListener()
			tun := &fakeHelperTunnel{}
			tun.attach(r)
			if tc.upAtStart {
				tun.up(directServers("lantern-1", ended, kept).Servers...)
			}
			require.NoError(t, r.updateServers(directServers("lantern-1", ended, kept), true))

			snapshot := r.AllServers() // the options the connect or restart captures
			lockTaken := make(chan struct{})
			connected := make(chan struct{})
			go func() {
				defer close(connected)
				<-lockTaken
				tun.up(snapshot...)
				events.Emit(vpn.StatusUpdateEvent{Status: vpn.Connected})
			}()

			// The pairing ends before the connect or restart installs its options.
			require.NoError(t, r.updateServers(directServers("lantern-1", kept), true))
			close(lockTaken)
			<-connected

			require.Eventually(t, func() bool { return !tun.holds(ended) }, 5*time.Second, 10*time.Millisecond,
				"the new tunnel loses the ended helper")
			assert.True(t, tun.holds(kept), "a helper whose pairing remains is kept")
			assert.True(t, tun.holds("lantern-1"))
		})
	}
}

// A config that withdraws an individually selected helper falls back to
// auto-select before the tunnel update removes the helper, so the manual
// selector never picks an arbitrary member meanwhile.
func TestWithdrawnSelectedHelperFallsBackBeforeTheUpdate(t *testing.T) {
	const h = "helper-0123456789ab"
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up(directServers("lantern-1", h).Servers...)
	require.NoError(t, r.updateServers(directServers("lantern-1", h), true))
	r.persistSelection(h)
	require.False(t, settings.GetBool(settings.AutoConnectKey))

	before := len(tun.callLog())
	require.NoError(t, r.updateServers(directServers("lantern-1"), true))
	calls := tun.callLog()[before:]
	selectAt, updateAt := slices.Index(calls, "select:auto"), slices.Index(calls, "update")
	require.NotEqual(t, -1, selectAt, "%v", calls)
	require.NotEqual(t, -1, updateAt, "%v", calls)
	assert.Less(t, selectAt, updateAt, "auto-select first: %v", calls)
	assert.True(t, settings.GetBool(settings.AutoConnectKey))
	assert.False(t, tun.holds(h))
}

// A config update that fails after the manager dropped a selected helper
// (here, saving the removal) still falls back to auto-select, so the
// persisted choice and the tunnel's agree.
func TestFailedConfigUpdateStillClearsAWithdrawnSelection(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions don't block writes on Windows or as root")
	}
	const h = "helper-0123456789ab"
	r := newPersonalProxiesBackend(t)
	serversDir := t.TempDir()
	srvMgr, err := servers.NewManager(serversDir, log.NoOpLogger())
	require.NoError(t, err)
	r.srvManager = srvMgr
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up(directServers("lantern-1", h).Servers...)
	require.NoError(t, r.updateServers(directServers("lantern-1", h), true))
	r.persistSelection(vpn.PersonalProxiesTag)
	require.False(t, settings.GetBool(settings.AutoConnectKey))

	require.NoError(t, os.Chmod(serversDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(serversDir, 0o700) })
	require.Error(t, r.updateServers(directServers("lantern-1"), true), "saving the removal fails")

	assert.True(t, settings.GetBool(settings.AutoConnectKey), "the withdrawn selection falls back")
	assert.Contains(t, tun.callLog(), "select:auto")
	assert.False(t, tun.holds(h), "and the helper leaves the tunnel")
}

// A tunnel built from options captured before a config update reflects none
// of that update's helper changes; on Connected it gains the new helper, the
// rotated credentials and loses the ended helper.
func TestConnectedTunnelGetsHelperChangesMadeWhileItCameUp(t *testing.T) {
	const rotated, added, ended = "helper-0123456789ab", "helper-ba9876543210", "helper-00000000000e"
	r := newPersonalProxiesBackend(t)
	r.startHelperReconcileListener()
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	require.NoError(t, r.updateServers(servers.ServerList{Servers: []*servers.Server{
		helperWithPort("lantern-1", 1080), helperWithPort(rotated, 1080), helperWithPort(ended, 1080),
	}}, true))
	snapshot := r.AllServers() // the options a connect captures

	// While the tunnel comes up: rotated's credentials change, added is
	// paired and ended's pairing ends.
	require.NoError(t, r.updateServers(servers.ServerList{Servers: []*servers.Server{
		helperWithPort("lantern-1", 1080), helperWithPort(rotated, 1081), helperWithPort(added, 1080),
	}}, true))

	tun.up(snapshot...)
	events.Emit(vpn.StatusUpdateEvent{Status: vpn.Connected})
	require.Eventually(t, func() bool { return tun.holds(added) && !tun.holds(ended) },
		5*time.Second, 10*time.Millisecond, "the new tunnel gains the new helper and loses the ended one")
	assert.Equal(t, "1081", tun.options(rotated), "with the rotated credentials")
	assert.Equal(t, "1080", tun.options("lantern-1"))
}

// Removing servers whose removal fails to save has already taken them out of
// the manager in memory. Removing the last helper that way still falls back
// from a selection of the personal proxies group and takes the helper out of
// the tunnel, as a successful removal does.
func TestFailedRemovalStillWithdrawsTheHelper(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions don't block writes on Windows or as root")
	}
	const h = "helper-0123456789ab"
	r := newPersonalProxiesBackend(t)
	serversDir := t.TempDir()
	srvMgr, err := servers.NewManager(serversDir, log.NoOpLogger())
	require.NoError(t, err)
	r.srvManager = srvMgr
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up(directServers("lantern-1", h).Servers...)
	require.NoError(t, r.updateServers(directServers("lantern-1", h), true))
	r.persistSelection(vpn.PersonalProxiesTag)
	require.False(t, settings.GetBool(settings.AutoConnectKey))

	require.NoError(t, os.Chmod(serversDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(serversDir, 0o700) })
	require.Error(t, r.RemoveServers([]string{h}), "saving the removal fails")

	assert.True(t, settings.GetBool(settings.AutoConnectKey), "the withdrawn selection falls back")
	calls := tun.callLog()
	selectAt, removeAt := slices.Index(calls, "select:auto"), slices.Index(calls, "remove")
	require.NotEqual(t, -1, selectAt, "%v", calls)
	require.NotEqual(t, -1, removeAt, "%v", calls)
	assert.Less(t, selectAt, removeAt, "auto-select first: %v", calls)
	assert.False(t, tun.holds(h), "and the helper leaves the tunnel")
	assert.True(t, tun.holds("lantern-1"))

	require.NoError(t, os.Chmod(serversDir, 0o700))
	before := len(tun.callLog())
	require.NoError(t, r.RemoveServers([]string{"never-existed"}))
	assert.Len(t, tun.callLog(), before, "removing an unknown tag touches nothing")
}

// Adds do not take the selection lock, so a server can be added between a
// removal's start and the manager's delete. RemoveServers cleans up after
// what the manager actually removed, so that server leaves the tunnel too.
func TestRemovalCleansUpAServerAddedConcurrently(t *testing.T) {
	r := newPersonalProxiesBackend(t)
	tun := &fakeHelperTunnel{}
	tun.attach(r)
	tun.up(directServers("lantern-1").Servers...)
	require.NoError(t, r.updateServers(directServers("lantern-1"), true))

	late := helperWithPort("late", 1080)
	late.IsLantern = false
	r.beforeManagerRemove = func() {
		require.NoError(t, r.srvManager.AddServers(servers.ServerList{Servers: []*servers.Server{late}}, false))
		require.NoError(t, tun.UpdateOutbounds(servers.ServerList{Servers: []*servers.Server{late}}))
	}
	require.NoError(t, r.RemoveServers([]string{"late"}))

	_, held := r.srvManager.GetServerByTag("late")
	assert.False(t, held)
	assert.False(t, tun.holds("late"), "the removed server leaves the tunnel")
	assert.True(t, tun.holds("lantern-1"))
}

func TestServerListFromConfig_AutoSelectOptions(t *testing.T) {
	list := serverListFromConfig(&config.Config{
		AutoSelectOptions: json.RawMessage(`{"probe_timeouts_ms": {"hysteria2x": 3000}}`),
	})
	require.NotNil(t, list.AutoSelectOptions)
	assert.Equal(t, map[string]uint32{"hysteria2x": 3000}, map[string]uint32(list.AutoSelectOptions.ProbeTimeoutsMs))

	list = serverListFromConfig(&config.Config{})
	require.NotNil(t, list.AutoSelectOptions, "a config without the field must still clear earlier timeouts")
	assert.Empty(t, list.AutoSelectOptions.ProbeTimeoutsMs)
}
