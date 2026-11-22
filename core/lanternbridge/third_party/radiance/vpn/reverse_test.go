package vpn

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	lbA "github.com/getlantern/lantern-box/adapter"
	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"
	"github.com/getlantern/lantern-box/protocol/samizdatreverse"
	"github.com/getlantern/samizdat"

	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/servers"
)

func newReverseTestClient(t *testing.T, tun *tunnel) *VPNClient {
	t.Helper()
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	c.tunnel = tun
	return c
}

func testPortalConfig(t *testing.T, reverseTags ...string) *samizdatreverse.PortalConfig {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	pairings := make(map[[8]byte]string, len(reverseTags))
	for i, tag := range reverseTags {
		pairings[[8]byte{byte(i + 1)}] = tag
	}
	return &samizdatreverse.PortalConfig{
		PrivateKey: priv.Bytes(),
		CertPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:     pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Pairings:   pairings,
	}
}

// livePortal returns the tunnel's portal inbound, or nil when it has none.
func livePortal(t *testing.T, tun *tunnel) *samizdatreverse.Portal {
	t.Helper()
	in, ok := service.FromContext[adapter.InboundManager](tun.ctx).Get(reversePortalTag)
	if !ok {
		return nil
	}
	p, ok := in.(*samizdatreverse.Portal)
	require.True(t, ok)
	return p
}

// requireTornDown waits for the group manager's queued teardown of tag.
func requireTornDown(t *testing.T, tun *tunnel, tag string) {
	t.Helper()
	require.Eventually(t, func() bool { return tun.liveOutbound(tag) == nil },
		10*time.Second, 50*time.Millisecond)
}

func TestReverseOutboundsJoinTheFriendsGroups(t *testing.T) {
	tun, _ := startPersonalProxyTestTunnel(t, friendA)
	c := newReverseTestClient(t, tun)
	revA, revB := lbA.ReverseHelperTag(friendA), lbA.ReverseHelperTag(friendB)

	require.NoError(t, c.SetReverseOutbounds([]string{revA, revB}))
	assert.ElementsMatch(t, []string{friendA, consumer, revA, revB}, personalProxiesMembers(tun))
	for _, groupTag := range []string{ManualSelectTag, AutoSelectTag} {
		assert.Subset(t, selectorMembers(t, tun, groupTag), []string{revA, revB}, groupTag)
	}

	require.NoError(t, tun.selectOutbound(PersonalProxySelection(friendA)))
	assert.ElementsMatch(t, []string{friendA, consumer, revA}, personalProxyMembers(tun))

	// friendB has neither a direct outbound nor a ticket: its reverse
	// outbound alone makes it selectable.
	require.NoError(t, tun.selectOutbound(PersonalProxySelection(friendB)))
	assert.Equal(t, []string{revB}, personalProxyMembers(tun))

	require.NoError(t, c.SetReverseOutbounds([]string{revA}))
	assert.Nil(t, tun.personalProxyGroup(), "friendB's group lost its last member")
	assert.Equal(t, PersonalProxiesTag, selectedInManual(t, tun))
}

// Helper reconciliation and config updates are driven by the server manager,
// which never holds reverse outbounds, so they must leave them alone.
func TestHelperReconciliationKeepsReverseOutbounds(t *testing.T) {
	tun := startPersonalProxiesTestTunnel(t)
	c := newReverseTestClient(t, tun)
	rev := lbA.ReverseHelperTag(testHelper1)
	require.NoError(t, c.SetReverseOutbounds([]string{rev}))
	require.NoError(t, c.ReconcileHelpers(servers.ServerList{Servers: []*servers.Server{directServer(testHelper2)}}))
	require.NoError(t, c.ReconcileHelpers(servers.ServerList{}))
	require.NoError(t, c.UpdateOutbounds(servers.ServerList{Servers: []*servers.Server{directServer("lantern-1")}}))
	require.NoError(t, c.RemoveOutbounds([]string{"lantern-2"}))
	for _, groupTag := range []string{ManualSelectTag, AutoSelectTag} {
		assert.Contains(t, selectorMembers(t, tun, groupTag), rev, groupTag)
	}
	assert.Equal(t, []string{rev}, personalProxiesMembers(tun))
}

func TestReverseOutboundsSwapWithoutEmptyingThePersonalProxiesGroup(t *testing.T) {
	tun := startPersonalProxiesTestTunnel(t)
	c := newReverseTestClient(t, tun)
	revA, revB := lbA.ReverseHelperTag(testHelper1), lbA.ReverseHelperTag(testHelper2)

	require.NoError(t, c.SetReverseOutbounds([]string{revA}))
	group := tun.personalProxiesGroup()
	require.NotNil(t, group)
	require.NoError(t, tun.selectOutbound(PersonalProxiesTag))

	require.NoError(t, c.SetReverseOutbounds([]string{revB}))
	assert.Same(t, group, tun.personalProxiesGroup(), "the group was never withdrawn")
	assert.Equal(t, []string{revB}, personalProxiesMembers(tun))
	assert.Equal(t, PersonalProxiesTag, selectedInManual(t, tun))
	for _, groupTag := range []string{ManualSelectTag, AutoSelectTag} {
		assert.NotContains(t, selectorMembers(t, tun, groupTag), revA, groupTag)
	}

	require.NoError(t, c.SetReverseOutbounds(nil))
	assert.Nil(t, tun.personalProxiesGroup())
	requireTornDown(t, tun, revB)
	assert.Equal(t, AutoSelectTag, tun.clashModeManager.clashMode.Mode())
}

func TestSetReverseOutboundsRefusesOtherTags(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	for _, tag := range []string{"lantern-1", testHelper1, PersonalProxiesTag, ""} {
		assert.Error(t, c.SetReverseOutbounds([]string{tag}), tag)
	}
	assert.Empty(t, c.ReverseOutbounds())
}

func TestReversePortalFollowsItsConfig(t *testing.T) {
	tun := startPersonalProxiesTestTunnel(t)
	c := newReverseTestClient(t, tun)
	rev := lbA.ReverseHelperTag(testHelper1)

	require.NoError(t, c.SetReversePortal(testPortalConfig(t, rev), "a.example.com"))
	portal := livePortal(t, tun)
	require.NotNil(t, portal)
	require.NotNil(t, portal.Addr(), "configured with a pairing, the portal listens")
	port := portal.Addr().(*net.TCPAddr).Port
	require.NoError(t, c.SetReverseOutbounds([]string{rev}))

	require.NoError(t, c.RebindReversePortal())
	require.NotNil(t, portal.Addr())
	assert.Equal(t, port, portal.Addr().(*net.TCPAddr).Port, "a rebind keeps the port")

	require.NoError(t, c.SetReversePortal(testPortalConfig(t, rev), "a.example.com"))
	assert.Same(t, portal, livePortal(t, tun), "the same masquerade keeps the portal")
	require.NoError(t, c.SetReversePortal(testPortalConfig(t, rev), "b.example.com"))
	replaced := livePortal(t, tun)
	require.NotNil(t, replaced)
	assert.NotSame(t, portal, replaced, "a new masquerade replaces the portal")
	assert.Nil(t, portal.Addr(), "the replaced portal is closed")
	require.NotNil(t, replaced.Addr())
	portal = replaced

	bad := testPortalConfig(t, rev)
	bad.PrivateKey = []byte{1, 2, 3}
	assert.Error(t, c.SetReversePortal(bad, "a.example.com"), "a configure error reaches the caller")

	require.NoError(t, c.SetReversePortal(nil, ""))
	assert.Nil(t, livePortal(t, tun))
	assert.Nil(t, portal.Addr())
	requireTornDown(t, tun, rev)
	assert.Nil(t, tun.personalProxiesGroup())
	assert.Empty(t, c.ReverseOutbounds())
	require.NoError(t, c.RebindReversePortal(), "nothing to rebind")
	require.NoError(t, c.SetReversePortal(nil, ""), "nothing to remove")
}

// State set while no tunnel runs is kept and applied to the next tunnel.
func TestReverseStateAppliesToTheNextTunnel(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	rev := lbA.ReverseHelperTag(testHelper1)
	require.NoError(t, c.SetReversePortal(testPortalConfig(t, rev), "a.example.com"))
	require.NoError(t, c.SetReverseOutbounds([]string{rev}))
	require.NoError(t, c.RebindReversePortal())

	for range 2 {
		tun := startPersonalProxiesTestTunnel(t)
		c.mu.Lock()
		c.tunnel = tun
		require.NoError(t, c.restoreReverseLocked())
		c.mu.Unlock()
		portal := livePortal(t, tun)
		require.NotNil(t, portal)
		assert.NotNil(t, portal.Addr())
		assert.NotNil(t, tun.liveOutbound(rev))
		assert.Equal(t, []string{rev}, personalProxiesMembers(tun))
		require.NoError(t, tun.close())
		assert.Nil(t, portal.Addr(), "the portal closes with its tunnel")
		c.mu.Lock()
		c.tunnel = nil
		c.mu.Unlock()
	}
}

// A portal whose restore could not bind on a new tunnel reports no listener,
// and the kept config brings it up once the port is free.
func TestReversePortalListeningAfterAFailedRestore(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	assert.False(t, c.ReversePortalListening(), "no tunnel")
	occupied, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Skipf("no IPv6 listener to block the portal's port: %v", err)
	}
	cfg := testPortalConfig(t, lbA.ReverseHelperTag(testHelper1))
	cfg.ListenPort = uint16(occupied.Addr().(*net.TCPAddr).Port)
	require.NoError(t, c.SetReversePortal(cfg, "a.example.com"))

	tun := startPersonalProxiesTestTunnel(t)
	c.mu.Lock()
	c.tunnel = tun
	assert.Error(t, c.restoreReverseLocked())
	c.mu.Unlock()
	assert.False(t, c.ReversePortalListening())

	require.NoError(t, occupied.Close())
	require.NoError(t, c.SetReversePortal(cfg, "a.example.com"))
	assert.True(t, c.ReversePortalListening())
	require.NoError(t, c.SetReversePortal(nil, ""))
	assert.False(t, c.ReversePortalListening())
}

// A withdrawal of the last reverse outbound after the caller picked the
// personal proxies group, and before the tunnel's options are built, starts
// the tunnel on auto-select instead of failing.
func TestBuildOptionsAfterTheLastReverseOutboundGoes(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	require.NoError(t, c.SetReverseOutbounds([]string{lbA.ReverseHelperTag(friendA)}))
	initial := PersonalProxiesTag // what the caller saw while the outbound was live
	require.NoError(t, c.SetReverseOutbounds(nil))

	options, _ := testBoxOptions(t)
	c.mu.Lock()
	boxOptions := c.withReverse(BoxOptions{BasePath: t.TempDir(), Options: options, InitialServer: initial})
	c.mu.Unlock()
	opts, mode, err := buildOptions(boxOptions)
	require.NoError(t, err)
	assert.Equal(t, AutoSelectTag, mode)
	assert.Nil(t, findOutbound(opts.Outbounds, PersonalProxiesTag))
}

// The kept config owns its buffers, so a caller reusing them after the call
// cannot change what the next tunnel restores.
func TestSetReversePortalKeepsItsOwnCopy(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	cfg := testPortalConfig(t, lbA.ReverseHelperTag(testHelper1))
	old := testPortalConfig(t, lbA.ReverseHelperTag(testHelper1))
	cfg.Previous = &samizdatreverse.PreviousIdentity{
		PrivateKey: old.PrivateKey, CertPEM: old.CertPEM, KeyPEM: old.KeyPEM,
		Until: time.Now().Add(time.Hour),
	}
	want := *cfg
	want.PrivateKey = slices.Clone(cfg.PrivateKey)
	want.CertPEM = slices.Clone(cfg.CertPEM)
	want.KeyPEM = slices.Clone(cfg.KeyPEM)
	want.Pairings = maps.Clone(cfg.Pairings)
	wantPrev := *cfg.Previous
	wantPrev.PrivateKey = slices.Clone(cfg.Previous.PrivateKey)
	wantPrev.CertPEM = slices.Clone(cfg.Previous.CertPEM)
	wantPrev.KeyPEM = slices.Clone(cfg.Previous.KeyPEM)
	want.Previous = &wantPrev
	require.NoError(t, c.SetReversePortal(cfg, "a.example.com"))
	clear(cfg.PrivateKey)
	clear(cfg.CertPEM)
	clear(cfg.KeyPEM)
	clear(cfg.Pairings)
	clear(cfg.Previous.PrivateKey)
	clear(cfg.Previous.CertPEM)
	clear(cfg.Previous.KeyPEM)
	cfg.Previous.Until = time.Time{}
	assert.True(t, reflect.DeepEqual(want, *c.reversePortal), "the kept config changed with the caller's buffers")
}

// A tunnel starts with the kept reverse outbounds and portal in its options,
// so a selection whose only members are reverse outbounds starts on them.
func TestBuildOptionsStartsReverseOnlySelections(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	revA, revB := lbA.ReverseHelperTag(friendA), lbA.ReverseHelperTag(friendB)
	require.NoError(t, c.SetReversePortal(testPortalConfig(t, revA, revB), "cover.example.com"))
	require.NoError(t, c.SetReverseOutbounds([]string{revA, revB}))
	build := func(t *testing.T, initial string) (O.Options, *lbO.MutableSelectorOutboundOptions) {
		t.Helper()
		options, _ := testBoxOptions(t)
		c.mu.Lock()
		boxOptions := c.withReverse(c.withPersonalProxyRooms(BoxOptions{
			BasePath: t.TempDir(), Options: options, InitialServer: initial,
		}))
		c.mu.Unlock()
		opts, _, err := buildOptions(boxOptions)
		require.NoError(t, err)
		return opts, findOutbound(opts.Outbounds, ManualSelectTag).Options.(*lbO.MutableSelectorOutboundOptions)
	}
	groupMembers := func(opts O.Options, tag string) []string {
		group := findOutbound(opts.Outbounds, tag)
		require.NotNil(t, group, tag)
		return group.Options.(*lbO.MutableURLTestOutboundOptions).Outbounds
	}

	opts, manual := build(t, PersonalProxiesTag)
	assert.Equal(t, PersonalProxiesTag, manual.Outbounds[0])
	assert.ElementsMatch(t, []string{revA, revB}, groupMembers(opts, PersonalProxiesTag))
	auto := findOutbound(opts.Outbounds, AutoSelectTag).Options.(*lbO.MutableAutoSelectOutboundOptions)
	assert.Subset(t, auto.Outbounds, []string{revA, revB})
	var portal *O.Inbound
	for i := range opts.Inbounds {
		if opts.Inbounds[i].Tag == reversePortalTag {
			portal = &opts.Inbounds[i]
		}
	}
	require.NotNil(t, portal, "the portal starts with the tunnel")
	assert.Equal(t, lbC.TypeSamizdatPortal, portal.Type)
	assert.Equal(t, "cover.example.com", portal.Options.(*lbO.SamizdatPortalInboundOptions).MasqueradeDomain)

	opts, manual = build(t, PersonalProxySelection(friendB))
	assert.Equal(t, PersonalProxyTag, manual.Outbounds[0])
	assert.Equal(t, []string{revB}, groupMembers(opts, PersonalProxyTag))

	require.NoError(t, c.SetReversePortal(nil, ""))
	opts, _ = build(t, "")
	assert.Nil(t, findOutbound(opts.Outbounds, revA))
	assert.Nil(t, findOutbound(opts.Outbounds, PersonalProxiesTag))
	for _, in := range opts.Inbounds {
		assert.NotEqual(t, reversePortalTag, in.Tag)
	}
}

func TestLogsNeverNameReverseTags(t *testing.T) {
	rev := lbA.ReverseHelperTag(testHelper1)
	assert.Equal(t, []string{"lantern-1", testHelper1, "reverse"}, loggableTags([]string{"lantern-1", testHelper1, rev}))
	assert.NotContains(t, fmt.Sprint(loggableError(rev, errors.New("outbound/x["+rev+"]: failed"))), rev)
}

func TestPhysicalInterfaceControlNeedsATunnel(t *testing.T) {
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	assert.Nil(t, c.PhysicalInterfaceControl())

	tun := startPersonalProxiesTestTunnel(t)
	c.mu.Lock()
	c.tunnel = tun
	c.mu.Unlock()
	t.Cleanup(func() { _ = tun.close() })
	assert.NotPanics(t, func() { _ = c.PhysicalInterfaceControl() })
}

// dialReverseSession dials the portal as the bridge of the pairing with short
// ID id would and serves HTTP/2 on the session, and returns the session's
// connection and a channel closed once serving it ends.
func dialReverseSession(t *testing.T, portal *samizdatreverse.Portal, cfg *samizdatreverse.PortalConfig, id [8]byte) (net.Conn, <-chan struct{}) {
	t.Helper()
	priv, err := ecdh.X25519().NewPrivateKey(cfg.PrivateKey)
	require.NoError(t, err)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(portal.Addr().(*net.TCPAddr).Port))
	client, err := samizdat.NewClient(samizdat.ClientConfig{
		ServerAddr: addr, ServerName: "localhost", PublicKey: priv.PublicKey().Bytes(), ShortID: id,
	})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialSession(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})})
	}()
	return conn, done
}

// loopbackReversePortal puts a portal configured by cfg in the tunnel under
// the portal's tag, created without the tunnel's network manager so that it
// listens on loopback rather than bound to the physical interface, where a
// bridge on this host could not reach it.
func loopbackReversePortal(t *testing.T, tun *tunnel, cfg *samizdatreverse.PortalConfig) *samizdatreverse.Portal {
	t.Helper()
	in := reversePortalInbound("a.example.com")
	router := service.FromContext[adapter.Router](tun.ctx)
	logger := tun.logFactory.NewLogger("inbound/" + reversePortalTag)
	require.NoError(t, service.FromContext[adapter.InboundManager](tun.ctx).Create(
		context.Background(), router, logger, in.Tag, in.Type, in.Options))
	portal := livePortal(t, tun)
	require.NotNil(t, portal)
	require.NoError(t, portal.Configure(*cfg))
	return portal
}

// A configured reverse outbound is live only while the friend's bridge holds
// a session on the portal: not before it dials in, through a replacement, and
// not once the session ends.
func TestReverseSessionLiveFollowsTheSession(t *testing.T) {
	rev := lbA.ReverseHelperTag(testHelper1)
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	cfg := testPortalConfig(t, rev)
	require.NoError(t, c.SetReverseOutbounds([]string{rev}))
	assert.False(t, c.ReverseSessionLive(rev), "no tunnel")

	tun := startPersonalProxiesTestTunnel(t)
	c.mu.Lock()
	c.tunnel = tun
	require.NoError(t, c.restoreReverseLocked())
	c.mu.Unlock()
	t.Cleanup(func() {
		c.mu.Lock()
		c.tunnel = nil
		c.mu.Unlock()
	})
	assert.False(t, c.ReverseSessionLive(rev), "configured, but no portal")
	portal := loopbackReversePortal(t, tun, cfg)
	assert.False(t, c.ReverseSessionLive(rev), "configured, but no session")

	_, firstDone := dialReverseSession(t, portal, cfg, [8]byte{1})
	require.Eventually(t, func() bool { return c.ReverseSessionLive(rev) }, 10*time.Second, 20*time.Millisecond)
	assert.False(t, c.ReverseSessionLive(lbA.ReverseHelperTag(testHelper2)), "another friend has no session")

	second, _ := dialReverseSession(t, portal, cfg, [8]byte{1})
	select {
	case <-firstDone:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the replaced session was not closed")
	}
	assert.True(t, c.ReverseSessionLive(rev), "the confirmed replacement is live")

	require.NoError(t, second.Close())
	require.Eventually(t, func() bool { return !c.ReverseSessionLive(rev) }, 10*time.Second, 20*time.Millisecond)
	assert.Equal(t, []string{rev}, c.ReverseOutbounds(), "the configured set is unchanged")
}
