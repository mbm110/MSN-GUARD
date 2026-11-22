package vpn

import (
	"fmt"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	O "github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"

	rlog "github.com/getlantern/radiance/log"
)

// proxylessOutbound mimics lantern-cloud's proxyless outbound, with udp set
// when udp is non-nil.
func proxylessOutbound(udp *string) O.Outbound {
	return O.Outbound{
		Type: lbC.TypeOutline,
		Tag:  ProxylessTag,
		Options: &lbO.OutboundOutlineOptions{
			Domains:     []string{"cdn.jsdelivr.net"},
			TestTimeout: "5s",
			TLS:         []string{"", "split:1"},
			UDP:         udp,
		},
	}
}

// withProxyless returns the test config's options plus the server's
// proxyless outbound, listed as non-selectable the way the server sends it.
func withProxyless(t *testing.T, udp *string) BoxOptions {
	cfg := testConfig(t)
	cfg.Options.Outbounds = append(cfg.Options.Outbounds, proxylessOutbound(udp))
	return BoxOptions{
		BasePath:               t.TempDir(),
		Options:                cfg.Options,
		NonSelectableOutbounds: []string{ProxylessTag},
	}
}

// modeRoute returns the outbound the first clash-mode rule for mode routes
// network's traffic to.
func modeRoute(t *testing.T, opts O.Options, mode string, network ...string) string {
	t.Helper()
	net := N.NetworkTCP
	if len(network) > 0 {
		net = network[0]
	}
	for _, r := range opts.Route.Rules {
		raw := r.DefaultOptions.RawDefaultRule
		if raw.ClashMode == mode && (len(raw.Network) == 0 || slices.Contains(raw.Network, net)) {
			return r.DefaultOptions.RuleAction.RouteOptions.Outbound
		}
	}
	t.Fatalf("no rule for clash mode %q and network %s", mode, net)
	return ""
}

func TestBuildOptions_ProxylessHedge(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		bOptions := withProxyless(t, nil)
		bOptions.Proxyless = &ProxylessOptions{Enabled: enabled}
		opts, _, err := buildOptions(bOptions)
		require.NoError(t, err)

		hedge := findOutbound(opts.Outbounds, ProxylessHedgeTag)
		require.NotNil(t, hedge, "smart routing with the server's proxyless outbound builds the hedge")
		hedgeOpts := hedge.Options.(*lbO.HedgeOutboundOptions)
		assert.Equal(t, ProxylessTag, hedgeOpts.First)
		assert.Equal(t, AutoSelectTag, hedgeOpts.Then)
		assert.True(t, hedgeOpts.Disabled, "the hedge starts off, and is switched once the tunnel runs")

		assert.Equal(t, ProxylessHedgeTag, modeRoute(t, opts, AutoSelectTag), "auto mode goes through the hedge")
		assert.Equal(t, ProxylessHedgeTag, modeRoute(t, opts, AutoSelectTag, N.NetworkUDP))
		assert.Equal(t, AutoSelectTag, modeRoute(t, opts, AutoSelectTag, N.NetworkICMP), "ICMP, which the hedge can't carry, goes to auto")
		assert.Equal(t, ManualSelectTag, modeRoute(t, opts, ManualSelectTag), "manual mode never goes proxyless")

		out := findOutbound(opts.Outbounds, ProxylessTag)
		require.NotNil(t, out)
		udp := out.Options.(*lbO.OutboundOutlineOptions).UDP
		require.NotNil(t, udp, "the proxyless outbound gets UDP so QUIC can go proxyless")
		assert.Equal(t, proxylessUDP, *udp)

		auto := findOutbound(opts.Outbounds, AutoSelectTag).Options.(*lbO.MutableAutoSelectOutboundOptions)
		assert.NotContains(t, auto.Outbounds, ProxylessTag, "proxyless is never an auto member")
		assert.NotContains(t, auto.Outbounds, ProxylessHedgeTag, "nor is the hedge")

		served := findOutbound(bOptions.Options.Outbounds, ProxylessTag).Options.(*lbO.OutboundOutlineOptions)
		assert.Nil(t, served.UDP, "the server's config is not modified")
	}
}

func TestBuildOptions_ProxylessKeepsServerUDP(t *testing.T) {
	plain := ""
	bOptions := withProxyless(t, &plain)
	bOptions.Proxyless = &ProxylessOptions{Enabled: true}
	opts, _, err := buildOptions(bOptions)
	require.NoError(t, err)
	udp := findOutbound(opts.Outbounds, ProxylessTag).Options.(*lbO.OutboundOutlineOptions).UDP
	require.NotNil(t, udp)
	assert.Equal(t, "", *udp, "a UDP transport the server chose is kept")
}

func TestBuildOptions_NoProxylessHedge(t *testing.T) {
	t.Run("full tunnel", func(t *testing.T) {
		opts, _, err := buildOptions(withProxyless(t, nil))
		require.NoError(t, err)
		assert.Nil(t, findOutbound(opts.Outbounds, ProxylessHedgeTag), "full tunnel never builds the hedge")
		assert.Equal(t, AutoSelectTag, modeRoute(t, opts, AutoSelectTag))
		udp := findOutbound(opts.Outbounds, ProxylessTag).Options.(*lbO.OutboundOutlineOptions).UDP
		require.NotNil(t, udp, "the UDP default applies in every mode, matching a config update's replacement")
	})
	t.Run("no proxyless outbound from the server", func(t *testing.T) {
		cfg := testConfig(t)
		opts, _, err := buildOptions(BoxOptions{
			BasePath:  t.TempDir(),
			Options:   cfg.Options,
			Proxyless: &ProxylessOptions{Enabled: true},
		})
		require.NoError(t, err)
		assert.Nil(t, findOutbound(opts.Outbounds, ProxylessHedgeTag))
		assert.Equal(t, AutoSelectTag, modeRoute(t, opts, AutoSelectTag))
	})
}

func TestWithProxylessUDP(t *testing.T) {
	served := proxylessOutbound(nil)
	got := WithProxylessUDP(served)
	require.NotNil(t, got.Options.(*lbO.OutboundOutlineOptions).UDP)
	assert.Nil(t, served.Options.(*lbO.OutboundOutlineOptions).UDP, "the input is copied, not modified")

	other := O.Outbound{Type: lbC.TypeOutline, Tag: "not-proxyless", Options: &lbO.OutboundOutlineOptions{}}
	assert.Nil(t, WithProxylessUDP(other).Options.(*lbO.OutboundOutlineOptions).UDP, "only the proxyless outbound")
}

// switchStub is an outbound with the hedge's runtime switch.
type switchStub struct {
	adapter.Outbound
	enabled atomic.Bool
}

func (s *switchStub) SetEnabled(enabled bool) { s.enabled.Store(enabled) }
func (s *switchStub) Enabled() bool           { return s.enabled.Load() }

func TestSetProxylessEnabled(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	assert.ErrorIs(t, c.SetProxylessEnabled(true), ErrTunnelNotConnected)

	tun := newModeTestTunnel(t)
	c.tunnel = tun
	tun.outboundMgr = stubOutboundManager{outbounds: map[string]adapter.Outbound{}}
	assert.NoError(t, c.SetProxylessEnabled(true), "a tunnel without the hedge has nothing to switch")

	hedge := &switchStub{}
	tun.outboundMgr = stubOutboundManager{outbounds: map[string]adapter.Outbound{ProxylessHedgeTag: hedge}}
	require.NoError(t, c.SetProxylessEnabled(true))
	assert.True(t, hedge.enabled.Load())
	require.NoError(t, c.SetProxylessEnabled(false))
	assert.False(t, hedge.enabled.Load())

	tun.outboundMgr = stubOutboundManager{outbounds: map[string]adapter.Outbound{ProxylessHedgeTag: stubGroup{}}}
	assert.Error(t, c.SetProxylessEnabled(true), "an outbound under the hedge's tag without a switch is an error")
}

// namedOutbound is an outbound that only has a tag and a type.
type namedOutbound struct {
	adapter.Outbound
	tag, typ string
}

func (o namedOutbound) Tag() string  { return o.tag }
func (o namedOutbound) Type() string { return o.typ }

// namedGroup is a group with a tag and a current member.
type namedGroup struct {
	adapter.OutboundGroup
	tag, now string
}

func (g namedGroup) Tag() string  { return g.tag }
func (g namedGroup) Type() string { return "group" }
func (g namedGroup) Now() string  { return g.now }

func TestResolveChainFollowsTheHedgeToAuto(t *testing.T) {
	ct := newConnTracker()
	hedge := namedOutbound{tag: ProxylessHedgeTag, typ: lbC.TypeHedge}
	ct.outbound = stubOutboundManager{outbounds: map[string]adapter.Outbound{
		ProxylessHedgeTag: hedge,
		AutoSelectTag:     namedGroup{tag: AutoSelectTag, now: "srv-a"},
		"srv-a":           namedOutbound{tag: "srv-a", typ: "socks"},
	}}
	outbound, _, chain := ct.resolveChain(hedge)
	assert.Equal(t, "srv-a", outbound, "auto-mode traffic stays attributed to the selected server")
	assert.Equal(t, []string{"srv-a", AutoSelectTag, ProxylessHedgeTag}, chain)
}

func TestSelectModeClosesFlowsMatchedToTheHedge(t *testing.T) {
	tun := newModeTestTunnel(t)
	ct := tun.connTracker
	hedged := joinClosable(ct, "srv-a", time.Now(), "srv-a", AutoSelectTag, ProxylessHedgeTag)
	manual := joinClosable(ct, "srv-b", time.Now(), "srv-b", ManualSelectTag)

	require.NoError(t, tun.selectMode(AutoSelectTag))
	assert.False(t, hedged.closed.Load())
	require.NoError(t, tun.selectMode(ManualSelectTag))
	assert.True(t, hedged.closed.Load(), "leaving auto mode closes the flows it routed through the hedge")
	assert.False(t, manual.closed.Load())
}

func TestProxylessStateAppliedToANewTunnel(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	assert.False(t, c.ProxylessEnabled())
	assert.ErrorIs(t, c.SetProxylessEnabled(true), ErrTunnelNotConnected, "set while no tunnel runs")
	assert.True(t, c.ProxylessEnabled(), "the state is remembered")

	hedge := &switchStub{}
	tun := newModeTestTunnel(t)
	tun.outboundMgr = stubOutboundManager{outbounds: map[string]adapter.Outbound{ProxylessHedgeTag: hedge}}
	c.mu.Lock()
	c.setTunnelLocked(tun)
	require.NoError(t, c.restoreProxylessLocked(&ProxylessOptions{Enabled: false}))
	c.mu.Unlock()
	assert.True(t, hedge.enabled.Load(), "a tunnel that starts gets the last requested state, not its build options'")
}

func TestProxylessBuildStateAppliedWhenNoneRequested(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	hedge := &switchStub{}
	tun := newModeTestTunnel(t)
	tun.outboundMgr = stubOutboundManager{outbounds: map[string]adapter.Outbound{ProxylessHedgeTag: hedge}}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setTunnelLocked(tun)
	require.NoError(t, c.restoreProxylessLocked(&ProxylessOptions{Enabled: true}))
	assert.True(t, hedge.enabled.Load(), "with no requested state, the build options' state applies")
	require.NoError(t, c.restoreProxylessLocked(nil))
}

func TestBuildOptions_NoHedgeWhenItsTagIsTaken(t *testing.T) {
	bOptions := withProxyless(t, nil)
	bOptions.Options.Outbounds = append(bOptions.Options.Outbounds, O.Outbound{Type: "direct", Tag: ProxylessHedgeTag, Options: &O.DirectOutboundOptions{}})
	bOptions.Proxyless = &ProxylessOptions{Enabled: true}
	opts, _, err := buildOptions(bOptions)
	require.NoError(t, err)
	n := 0
	for _, o := range opts.Outbounds {
		if o.Tag == ProxylessHedgeTag {
			n++
		}
	}
	assert.Equal(t, 1, n, "a saved outbound with the hedge's tag isn't duplicated")
	assert.Equal(t, AutoSelectTag, modeRoute(t, opts, AutoSelectTag), "and auto mode doesn't route to it")
}

// A saved selection of a user server tagged proxyless-hedge, from before the
// tag was reserved, starts on auto-select instead of failing to build.
func TestBuildOptions_SavedSelectionOfTheReservedHedgeTag(t *testing.T) {
	bOptions := withProxyless(t, nil)
	bOptions.Proxyless = &ProxylessOptions{Enabled: true}
	bOptions.InitialServer = ProxylessHedgeTag
	_, _, err := buildOptions(bOptions)
	require.NoError(t, err)
}

// A switch made while a tunnel is starting, which holds mu for the whole
// start, doesn't wait for it, and is applied once it's done.
func TestSetProxylessEnabledDoesNotWaitOnTunnelStart(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	hedge := &switchStub{}
	tun := newModeTestTunnel(t)
	tun.outboundMgr = stubOutboundManager{outbounds: map[string]adapter.Outbound{ProxylessHedgeTag: hedge}}
	c.mu.Lock() // as start does
	done := make(chan error, 1)
	go func() { done <- c.SetProxylessEnabled(true) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		c.mu.Unlock()
		t.Fatal("SetProxylessEnabled waited on the tunnel's start")
	}
	c.setTunnelLocked(tun)
	c.mu.Unlock()
	require.Eventually(t, func() bool {
		return hedge.enabled.Load()
	}, 2*time.Second, 5*time.Millisecond, "the switch is applied once the start is done")
}

// gatedSwitch is a hedge whose first SetEnabled blocks until released, so a
// test can hold an apply partway.
type gatedSwitch struct {
	switchStub
	entered, release chan struct{}
	once             sync.Once
}

func (g *gatedSwitch) SetEnabled(enabled bool) {
	first := false
	g.once.Do(func() { first = true })
	if first {
		close(g.entered)
		<-g.release
	}
	g.switchStub.SetEnabled(enabled)
}

// An older apply held partway can't land after a newer one: a switch on
// deferred while the tunnel starts, then a switch off once it's up, ends
// off.
func TestSetProxylessEnabledLatestWins(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	hedge := &gatedSwitch{entered: make(chan struct{}), release: make(chan struct{})}
	tun := newModeTestTunnel(t)
	tun.outboundMgr = stubOutboundManager{outbounds: map[string]adapter.Outbound{ProxylessHedgeTag: hedge}}
	c.mu.Lock() // a starting tunnel
	require.NoError(t, c.SetProxylessEnabled(true))
	c.setTunnelLocked(tun)
	c.mu.Unlock()
	<-hedge.entered // the deferred apply of "on" is partway
	off := make(chan error, 1)
	go func() { off <- c.SetProxylessEnabled(false) }()
	time.Sleep(50 * time.Millisecond) // give "off" its chance to land first
	close(hedge.release)
	require.NoError(t, <-off)
	require.False(t, hedge.enabled.Load(), "the older switch on landed after the switch off")
}

// The server's measurement settings reach the hedge.
func TestBuildOptions_ProxylessHedgeMeasurementSettings(t *testing.T) {
	bOptions := withProxyless(t, nil)
	bOptions.Proxyless = &ProxylessOptions{Enabled: true, ExploreRate: 0.05, TelemetrySites: []string{"youtube.com", "", "instagram.com"}}
	opts, _, err := buildOptions(bOptions)
	require.NoError(t, err)
	hedge := findOutbound(opts.Outbounds, ProxylessHedgeTag).Options.(*lbO.HedgeOutboundOptions)
	assert.Equal(t, 0.05, hedge.ExploreRate)
	assert.Equal(t, []string{"youtube.com", "instagram.com"}, hedge.TelemetrySites, "empty names are dropped")
}

// An explore rate the hedge would refuse, which would stop the tunnel
// starting, is dropped instead, and the site list is bounded.
func TestProxylessOptionsSanitizeServerValues(t *testing.T) {
	for _, rate := range []float64{-0.1, 1.5, math.NaN(), math.Inf(1)} {
		p := &ProxylessOptions{ExploreRate: rate}
		got, _ := p.hedgeTelemetryOptions()
		assert.Zero(t, got, "rate %v", rate)
	}
	p := &ProxylessOptions{ExploreRate: 1}
	got, _ := p.hedgeTelemetryOptions()
	assert.Equal(t, 1.0, got, "1 is in range")

	many := make([]string, proxylessMaxTelemetrySites+10)
	for i := range many {
		many[i] = fmt.Sprintf("site%d.example", i)
	}
	_, sites := (&ProxylessOptions{TelemetrySites: many}).hedgeTelemetryOptions()
	assert.Len(t, sites, proxylessMaxTelemetrySites)

	bOptions := withProxyless(t, nil)
	bOptions.Proxyless = &ProxylessOptions{Enabled: true, ExploreRate: math.NaN()}
	_, _, err := buildOptions(bOptions)
	require.NoError(t, err, "a bad rate from the server doesn't stop the tunnel building")
}
