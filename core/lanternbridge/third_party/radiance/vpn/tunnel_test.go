package vpn

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	lsync "github.com/getlantern/common/sync"
	box "github.com/getlantern/lantern-box"
	lbA "github.com/getlantern/lantern-box/adapter"
	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"
	"github.com/getlantern/lantern-box/tracker/clientcontext"
	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	sblog "github.com/sagernet/sing-box/log"
	O "github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/servers"
)

func useTempCrashLog(t *testing.T) string {
	t.Helper()
	t.Cleanup(settings.Reset)
	dir := t.TempDir()
	require.NoError(t, settings.InitSettings(dir))
	require.NoError(t, settings.Set(settings.LogPathKey, dir))
	return filepath.Join(dir, internal.CrashLogFileName)
}

func readCrashLog(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

func TestRecoverToError_LineBreaks(t *testing.T) {
	crashLog := useTempCrashLog(t)
	err := func() (err error) {
		defer recoverToError(&err, "testing")
		panic("first\r\nsecond")
	}()
	require.EqualError(t, err, `panic testing: first\r\nsecond`)
	assert.Contains(t, readCrashLog(t, crashLog), "recovered panic testing: first\r\nsecond")
}

func TestTunnelStart_Panic(t *testing.T) {
	crashLog := useTempCrashLog(t)
	tun := &tunnel{dataPath: t.TempDir()}
	t.Cleanup(func() { assert.NoError(t, tun.close()) })
	options := O.Options{
		Log: &O.LogOptions{Disabled: true},
		Outbounds: []O.Outbound{{
			// Mismatched options panic inside the registered outbound factory.
			Type: C.TypeDirect, Tag: "panic", Options: &O.HTTPOutboundOptions{},
		}},
	}
	err := tun.start(t.Context(), options, nil, false)
	require.ErrorContains(t, err, "panic creating box instance")
	require.ErrorContains(t, err, "initializing tunnel")
	assert.NotContains(t, err.Error(), "\n")
	crash := readCrashLog(t, crashLog)
	assert.Contains(t, crash, "recovered panic creating box instance")
	assert.Contains(t, crash, "adapter/outbound/registry.go:")
	assert.Contains(t, crash, "vpn/tunnel.go:")
	require.NotNil(t, tun.ctx)
	assert.ErrorIs(t, tun.ctx.Err(), context.Canceled)
	assert.Nil(t, tun.boxInstance)
	assert.Empty(t, tun.closers)
}

// TestTunnelDevicePauseWake covers the non-iOS path: devicePause pauses the
// manager and deviceWake resumes it. The iOS timer branch depends on
// common.IsIOS() and is not exercised off-device.
func TestTunnelDevicePauseWake(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	mgr := service.FromContext[pause.Manager](ctx)
	require.NotNil(t, mgr)

	tn := &tunnel{pauseManager: mgr}
	tn.devicePause()
	require.True(t, mgr.IsDevicePaused())
	tn.deviceWake()
	require.False(t, mgr.IsDevicePaused())
}

func TestTunnelLifecycleNilManager(t *testing.T) {
	tn := &tunnel{}
	require.NotPanics(t, func() {
		tn.devicePause()
		tn.deviceWake()
		tn.resetNetwork()
	})
}

type errCloser struct{ err error }

func (c errCloser) Close() error { return c.err }

func TestTunnelClose(t *testing.T) {
	t.Run("no resources", func(t *testing.T) {
		tun := &tunnel{}
		err := tun.close()
		assert.NoError(t, err)
		assert.Nil(t, tun.closers)
		assert.Nil(t, tun.boxInstance)
	})

	t.Run("cancels context", func(t *testing.T) {
		tun := &tunnel{}
		ctx, cancel := context.WithCancel(context.Background())
		tun.cancel = cancel

		err := tun.close()
		assert.NoError(t, err)
		assert.Error(t, ctx.Err(), "context should be cancelled after close")
	})

	t.Run("propagates closer errors", func(t *testing.T) {
		tun := &tunnel{}
		tun.closers = append(tun.closers, errCloser{err: assert.AnError})

		err := tun.close()
		assert.ErrorIs(t, err, assert.AnError)
	})

	// On the timeout branch close() returns while the closer goroutine is still
	// running; a follow-up close() (as on a restart) must not race or panic on
	// the abandoned goroutine's slice, and the slow closer must still finish.
	t.Run("timeout abandons slow closer without corrupting a restart", func(t *testing.T) {
		release := make(chan struct{})
		finished := make(chan struct{})
		tun := &tunnel{closeTimeout: 50 * time.Millisecond}
		tun.closers = append(tun.closers, closerFunc(func() error {
			<-release
			close(finished)
			return nil
		}))

		err := tun.close()
		require.Error(t, err, "close must report the timeout")
		assert.Nil(t, tun.closers, "shared closers must be cleared before returning")
		assert.Nil(t, tun.boxInstance)

		assert.NoError(t, tun.close(), "a second close must find no closers")

		close(release)
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("abandoned closer never finished")
		}
	})
}

func TestSelectMode_NotConnected(t *testing.T) {
	// A tunnel without an active libbox service is not running.
	tun := &tunnel{}
	err := tun.selectMode(AutoSelectTag)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tunnel not running")
}

type stubDNSRouter struct{ adapter.DNSRouter }

func (stubDNSRouter) ClearCache() {}

// newModeTestTunnel returns a tunnel in auto mode that passes selectMode's running check.
func newModeTestTunnel(t *testing.T) *tunnel {
	t.Helper()
	return &tunnel{boxInstance: &sbox.Box{}, clashModeManager: newTestClashModeManager(t), connTracker: newConnTracker()}
}

func TestSelectMode_ClosesOnlyOutgoingModeFlows(t *testing.T) {
	for _, rejecting := range []bool{false, true} {
		t.Run(fmt.Sprintf("rejecting=%t", rejecting), func(t *testing.T) {
			tun := newModeTestTunnel(t)
			tun.clashModeManager.setRejectMode(rejecting)
			ct := tun.connTracker
			auto := joinClosable(ct, "srv-a", time.Now(), "srv-a", AutoSelectTag)
			manual := joinClosable(ct, "srv-b", time.Now(), "srv-b", ManualSelectTag)

			require.NoError(t, tun.selectMode(AutoSelectTag))
			assert.False(t, auto.closed.Load(), "selecting the current mode must close nothing")

			require.NoError(t, tun.selectMode(ManualSelectTag))
			assert.True(t, auto.closed.Load(), "switching away from auto must close its flows")
			assert.False(t, manual.closed.Load())
		})
	}
}

func TestRemoveDuplicates(t *testing.T) {
	ctx := box.BaseContext()
	out1 := O.Outbound{Type: "http", Tag: "http-1", Options: &O.HTTPOutboundOptions{
		ServerOptions: O.ServerOptions{Server: "10.0.0.1", ServerPort: 8080},
	}}
	out2 := O.Outbound{Type: "http", Tag: "http-2", Options: &O.HTTPOutboundOptions{}}
	socks := O.Outbound{Type: "socks", Tag: "socks-1", Options: &O.SOCKSOutboundOptions{}}
	ep1 := O.Endpoint{Type: "wireguard", Tag: "wg-1", Options: &O.WireGuardEndpointOptions{}}

	// The map is built as at tunnel start, so this also checks that startup
	// entries and incoming servers are marshaled the same way.
	t.Run("drops duplicates against current map", func(t *testing.T) {
		curr := makeOutboundOptsMap(ctx, O.Options{Outbounds: []O.Outbound{out1}, Endpoints: []O.Endpoint{ep1}})

		list := servers.ServerList{
			Servers: []*servers.Server{
				{Tag: out1.Tag, Type: out1.Type, Options: out1},
				{Tag: out2.Tag, Type: out2.Type, Options: out2},
				{Tag: ep1.Tag, Type: ep1.Type, Options: ep1},
			},
		}

		result := removeDuplicates(ctx, curr, list)
		assert.Len(t, result.Servers, 1)
		assert.Equal(t, "http-2", result.Servers[0].Tag)
	})

	t.Run("keeps a server whose options changed", func(t *testing.T) {
		curr := makeOutboundOptsMap(ctx, O.Options{Outbounds: []O.Outbound{out1}})
		changed := O.Outbound{Type: out1.Type, Tag: out1.Tag, Options: &O.HTTPOutboundOptions{
			ServerOptions: O.ServerOptions{Server: "10.0.0.1", ServerPort: 8081},
		}}

		result := removeDuplicates(ctx, curr, servers.ServerList{Servers: []*servers.Server{
			{Tag: changed.Tag, Type: changed.Type, Options: changed},
		}})
		assert.Len(t, result.Servers, 1)
	})

	t.Run("keeps all servers when none are duplicates", func(t *testing.T) {
		var curr lsync.TypedMap[string, []byte]
		list := servers.ServerList{
			Servers: []*servers.Server{
				{Tag: out1.Tag, Type: out1.Type, Options: out1},
				{Tag: socks.Tag, Type: socks.Type, Options: socks},
			},
		}

		result := removeDuplicates(ctx, &curr, list)
		assert.Len(t, result.Servers, 2)
	})

	t.Run("empty list yields empty result", func(t *testing.T) {
		var curr lsync.TypedMap[string, []byte]
		result := removeDuplicates(ctx, &curr, servers.ServerList{})
		assert.Empty(t, result.Servers)
	})
}

func TestContextDone(t *testing.T) {
	ctx := context.Background()
	assert.False(t, contextDone(ctx))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.True(t, contextDone(ctx))
}

func TestMobileMemoryLimitsOrdering(t *testing.T) {
	const iOSFootprintCap = 50 << 20
	assert.Less(t, mobileMemoryLimit, defaultIOSMemLimitBytes, "GOMEMLIMIT must be below the monitor budget")
	assert.Less(t, defaultIOSMemLimitBytes, iOSFootprintCap, "monitor budget must be below the iOS cap")
}

// infoRecorder records whether each routed connection to dest carries client
// info.
type infoRecorder struct {
	dest string
	seen chan bool
}

func (r *infoRecorder) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	if metadata.Destination.String() == r.dest {
		_, ok := clientcontext.InfoFromConn(conn)
		r.seen <- ok
	}
	return conn
}

func (r *infoRecorder) RoutedPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return conn
}

func (r *infoRecorder) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

// startInfoServer starts an HTTP and SOCKS proxy that decodes client info like a lantern
// server, and returns its port and a recorder of connections routed to dest.
func startInfoServer(t *testing.T, dest string) (uint16, *infoRecorder) {
	t.Helper()
	port := freePort(t)

	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	server, err := sbox.New(sbox.Options{Context: box.Context(t.Context()), Options: O.Options{
		Log: &O.LogOptions{Disabled: true},
		Inbounds: []O.Inbound{{Type: C.TypeMixed, Tag: "mixed-in", Options: &O.HTTPMixedInboundOptions{
			ListenOptions: O.ListenOptions{Listen: &listen, ListenPort: port},
		}}},
	}})
	require.NoError(t, err)
	recorder := &infoRecorder{dest: dest, seen: make(chan bool, 4)}
	server.Router().AppendTracker(clientcontext.NewManager(clientcontext.MatchBounds{Inbound: []string{"any"}, Outbound: []string{"any"}}, sblog.NewNOPFactory().NewLogger("")))
	server.Router().AppendTracker(recorder)
	require.NoError(t, server.Start())
	t.Cleanup(func() { server.Close() })
	return port, recorder
}

// testHelperTag is a personal proxy's direct outbound tag (lbA.IsHelperTag).
const testHelperTag = "helper-dff687a0c548"

// TestTunnelClientInfo checks that the tunnel sends client info through
// selectable lantern servers only, including on dials made directly through
// their outbounds rather than the router, as servers are added, replaced and
// removed.
func TestTunnelClientInfo(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(dest.Close)
	// The auto group's probes go here, so they stay offline and apart from dest.
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(probe.Close)
	port, recorder := startInfoServer(t, dest.Listener.Addr().String())

	proxyOutbound := func(tag string) O.Outbound {
		return O.Outbound{Type: C.TypeHTTP, Tag: tag, Options: &O.HTTPOutboundOptions{
			ServerOptions: O.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		}}
	}
	options := O.Options{
		Log: &O.LogOptions{Disabled: true},
		Outbounds: []O.Outbound{
			proxyOutbound("lantern"),
			proxyOutbound("other"),
			proxyOutbound("infra"),
			{Type: lbC.TypeMutableSelector, Tag: ManualSelectTag, Options: &lbO.MutableSelectorOutboundOptions{
				Outbounds: []string{"lantern", "other"},
			}},
			{Type: lbC.TypeMutableAutoSelect, Tag: AutoSelectTag, Options: &lbO.MutableAutoSelectOutboundOptions{
				Outbounds: []string{"lantern", "other"},
				URL:       probe.URL,
			}},
		},
		Route: &O.RouteOptions{Rules: []O.Rule{{
			Type: C.RuleTypeDefault,
			DefaultOptions: O.DefaultRule{
				RawDefaultRule: O.RawDefaultRule{ClashMode: ManualSelectTag},
				RuleAction: O.RuleAction{
					Action:       C.RuleActionTypeRoute,
					RouteOptions: O.RouteActionOptions{Outbound: ManualSelectTag},
				},
			},
		}}},
		Experimental: &O.ExperimentalOptions{
			CacheFile: &O.CacheFileOptions{Enabled: true, Path: filepath.Join(t.TempDir(), "cache.db")},
		},
	}
	// infra is a lantern server declared non-selectable. helper is a personal
	// proxy's outbound, which comes in the same config as lantern servers.
	options.Outbounds = append(options.Outbounds, proxyOutbound(testHelperTag))
	tun := &tunnel{
		dataPath:             t.TempDir(),
		initialLanternTags:   []string{"lantern", "infra", testHelperTag},
		initialNonSelectable: []string{"infra"},
		initialMode:          ManualSelectTag,
	}
	t.Cleanup(func() { assert.NoError(t, tun.close()) })
	require.NoError(t, tun.init(t.Context(), options, nil))
	require.NoError(t, tun.boxInstance.Start())
	tun.optsMap = makeOutboundOptsMap(tun.ctx, options)
	tun.nonSelectableTags = makeNonSelectableTagSet(tun.initialNonSelectable, options)
	mutGrpMgr, err := newMutableGroupManager(tun.ctx, tun.logFactory.NewLogger("groupsManager"), tun.connTracker)
	require.NoError(t, err)
	tun.mutGrpMgr = mutGrpMgr
	t.Cleanup(mutGrpMgr.Close)

	requireInfo := func(t *testing.T, tag string, want bool) {
		t.Helper()
		out, ok := service.FromContext[adapter.OutboundManager](tun.ctx).Outbound(tag)
		require.True(t, ok)
		conn, err := out.DialContext(t.Context(), N.NetworkTCP, M.ParseSocksaddr(recorder.dest))
		require.NoError(t, err)
		defer conn.Close()

		req, err := http.NewRequest(http.MethodGet, dest.URL, nil)
		require.NoError(t, err)
		require.NoError(t, req.Write(conn))
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		require.NoError(t, err, "the frame must not corrupt the stream")
		resp.Body.Close()
		select {
		case got := <-recorder.seen:
			assert.Equal(t, want, got)
		case <-time.After(5 * time.Second):
			t.Fatal("the server routed no connection")
		}
	}
	addServer := func(t *testing.T, tag string, lantern bool) {
		t.Helper()
		require.NoError(t, tun.addOutbounds(servers.ServerList{Servers: []*servers.Server{{
			Tag: tag, Type: C.TypeHTTP, IsLantern: lantern, Options: proxyOutbound(tag),
		}}}))
	}
	// replaceServer loads a SOCKS server under an existing tag, so its options
	// differ and it isn't dropped as a duplicate. Replacing a group member's
	// outbound reports an error once the new outbound is already in place, so
	// only the outcome is checked.
	replaceServer := func(t *testing.T, tag string, lantern bool) {
		t.Helper()
		out := O.Outbound{Type: C.TypeSOCKS, Tag: tag, Options: &O.SOCKSOutboundOptions{
			ServerOptions: O.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		}}
		_ = tun.addOutbounds(servers.ServerList{Servers: []*servers.Server{{
			Tag: tag, Type: C.TypeSOCKS, IsLantern: lantern, Options: out,
		}}})
		got, ok := service.FromContext[adapter.OutboundManager](tun.ctx).Outbound(tag)
		require.True(t, ok)
		require.Equal(t, C.TypeSOCKS, got.Type(), "the replacement must be in place")
	}
	addBrokenLantern := func(t *testing.T, tag string) {
		t.Helper()
		require.Error(t, tun.addOutbounds(servers.ServerList{Servers: []*servers.Server{{
			Tag: tag, Type: "broken", IsLantern: true, Options: O.Outbound{Type: "broken", Tag: tag},
		}}}))
	}

	t.Run("initial", func(t *testing.T) {
		requireInfo(t, "lantern", true)
		requireInfo(t, "other", false)
		requireInfo(t, "infra", false)
		requireInfo(t, testHelperTag, false)
	})
	// A personal proxy's peer box doesn't strip client info, so its outbounds,
	// direct or reverse, never send it, though the config lists them with the
	// lantern servers.
	t.Run("helpers", func(t *testing.T) {
		const added = "helper-0123456789ab"
		addServer(t, added, true)
		requireInfo(t, added, false)
		reverse := testHelperTag + lbA.ReverseTagSuffix
		addServer(t, reverse, true)
		requireInfo(t, reverse, false)
		replaceServer(t, testHelperTag, true)
		requireInfo(t, testHelperTag, false)
	})
	t.Run("added", func(t *testing.T) {
		addServer(t, "added", true)
		requireInfo(t, "added", true)
	})
	// Removing a server disables its tag. Lantern servers never reuse tags, so
	// the only way to observe that is to reuse it for a server that isn't one.
	t.Run("removed", func(t *testing.T) {
		require.NoError(t, tun.removeOutbounds([]string{"added"}))
		// The group manager removes the outbound on its next poll; reusing the
		// tag before then races that removal.
		require.Eventually(t, func() bool {
			_, found := service.FromContext[adapter.OutboundManager](tun.ctx).Outbound("added")
			return !found
		}, 10*time.Second, 50*time.Millisecond)
		addServer(t, "added", false)
		requireInfo(t, "added", false)
	})
	// Lantern servers never reuse tags. The cases below reuse them anyway, to
	// check that injection never reaches a peer that doesn't support it.
	t.Run("replaced", func(t *testing.T) {
		addServer(t, "swap", true)
		requireInfo(t, "swap", true)
		replaceServer(t, "swap", false)
		requireInfo(t, "swap", false)
	})
	// A lantern server whose type fails to build leaves the previous outbound
	// registered.
	t.Run("failed over other", func(t *testing.T) {
		addBrokenLantern(t, "other")
		requireInfo(t, "other", false)
	})
	t.Run("failed then reused", func(t *testing.T) {
		addBrokenLantern(t, "fresh")
		addServer(t, "fresh", false)
		requireInfo(t, "fresh", false)
	})
	t.Run("non-selectable tag", func(t *testing.T) {
		replaceServer(t, "infra", true)
		requireInfo(t, "infra", false)
	})
}

func TestOnPauseUpdate(t *testing.T) {
	// want == "" means no NetworkEvent should be emitted.
	cases := []struct {
		name string
		evt  int
		want NetworkEventType
	}{
		{"device paused ignored", pause.EventDevicePaused, ""},
		{"network paused", pause.EventNetworkPause, NetworkEventPaused},
		{"network wake", pause.EventNetworkWake, NetworkEventWake},
		{"device wake ignored", pause.EventDeviceWake, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan NetworkEventType, 2)
			sub := events.Subscribe(func(evt NetworkEvent) { got <- evt.EventType })
			defer sub.Unsubscribe()

			(&tunnel{}).onPauseUpdate(tc.evt)

			want := tc.want
			if want == "" {
				want = NetworkEventType("test_barrier")
				events.Emit(NetworkEvent{EventType: want})
			}
			select {
			case ev := <-got:
				require.Equal(t, want, ev)
			case <-time.After(2 * time.Second):
				t.Fatal("no NetworkEvent emitted")
			}
		})
	}
}

func TestRemoveDuplicatesKeepsAutoSelectOptions(t *testing.T) {
	opts := &lbO.MutableAutoSelectOutboundOptions{ProbeTimeoutsMs: lbO.ProbeTimeoutsMs{"hysteria2x": 3000}}
	var curr lsync.TypedMap[string, []byte]
	got := removeDuplicates(context.Background(), &curr, servers.ServerList{AutoSelectOptions: opts})
	assert.Same(t, opts, got.AutoSelectOptions)
}

func TestUpdateOutboundsWithAutoSelectOptions(t *testing.T) {
	tun := startPersonalProxiesTestTunnel(t)
	require.NoError(t, tun.mutGrpMgr.SetProbeTimeouts(AutoSelectTag, map[string]uint32{"hysteria2x": 3000}),
		"the auto-select group must accept probe timeouts")
	require.NoError(t, tun.updateOutbounds(servers.ServerList{
		Servers:           []*servers.Server{directServer("lantern-1")},
		AutoSelectOptions: DecodeAutoSelectOptions([]byte(`{"probe_timeouts_ms": {"hysteria2x": 3000}}`)),
	}))
	members := selectorMembers(t, tun, AutoSelectTag)

	// A config with no servers still reaches the setter, and leaves the
	// members alone.
	require.NoError(t, tun.updateOutbounds(servers.ServerList{AutoSelectOptions: DecodeAutoSelectOptions(nil)}))
	assert.Equal(t, members, selectorMembers(t, tun, AutoSelectTag))
}
