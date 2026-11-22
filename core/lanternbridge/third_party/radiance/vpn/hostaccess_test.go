package vpn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"
	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	box "github.com/getlantern/lantern-box"

	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/servers"
)

// torPayload returns a tor outbound whose executable creates the returned
// marker file when run.
func torPayload(t *testing.T) (O.Outbound, string) {
	if runtime.GOOS == "windows" {
		t.Skip("payload is a shell script")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	script := filepath.Join(dir, "payload.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o700))
	return O.Outbound{
		Tag:  "tor-out",
		Type: C.TypeTor,
		Options: &O.TorOutboundOptions{
			ExecutablePath: script,
			DataDirectory:  filepath.Join(dir, "data"),
		},
	}, marker
}

func TestTorPayloadExecutesWithoutPolicy(t *testing.T) {
	out, marker := torPayload(t)
	ctx, cancel := context.WithCancel(box.Context(context.Background()))
	defer cancel()
	instance, err := sbox.New(sbox.Options{
		Context: ctx,
		Options: O.Options{Log: &O.LogOptions{Disabled: true}, Outbounds: []O.Outbound{out}},
	})
	require.NoError(t, err)
	defer instance.Close()
	_ = instance.PreStart()
	assert.FileExists(t, marker, "the probe must execute when built directly, or the policy tests prove nothing")
}

func TestRunOfflineURLTestsDoesNotExecute(t *testing.T) {
	out, marker := torPayload(t)
	direct := O.Outbound{Tag: "direct-out", Type: C.TypeDirect, Options: &O.DirectOutboundOptions{}}
	c := NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = c.RunOfflineURLTests(ctx, t.TempDir(), []O.Outbound{direct, out}, nil, nil)
	assert.NoFileExists(t, marker)
}

func TestAllowedServers(t *testing.T) {
	tor := &servers.Server{Tag: "tor-out", Options: O.Outbound{Tag: "tor-out", Type: C.TypeTor}}
	direct := &servers.Server{Tag: "direct-out", Options: O.Outbound{Tag: "direct-out", Type: C.TypeDirect}}
	wg := &servers.Server{Tag: "wg-listen", Options: O.Endpoint{Tag: "wg-listen", Type: C.TypeWireGuard,
		Options: &O.WireGuardEndpointOptions{ListenPort: 51820}}}
	list := servers.ServerList{Servers: []*servers.Server{tor, direct, wg}}

	got := allowedServers(list)
	assert.Equal(t, []string{"direct-out"}, got.Tags())
	assert.Equal(t, []string{"tor-out", "direct-out", "wg-listen"}, list.Tags(), "the caller's list must not be modified")
}

func TestLiveTunnelDoesNotExecute(t *testing.T) {
	out, marker := torPayload(t)
	tun := startPolicyTestTunnel(t)
	list := servers.ServerList{Servers: []*servers.Server{{Tag: out.Tag, Type: out.Type, Options: out}}}

	require.NoError(t, tun.addOutbounds(list))
	require.NoError(t, tun.updateNonSelectableOutbounds(list))
	_, found := service.FromContext[adapter.OutboundManager](tun.ctx).Outbound(out.Tag)
	assert.False(t, found)
	assert.NoFileExists(t, marker)
}

func TestLiveTunnelRejectsCertificatePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.txt")
	require.NoError(t, os.WriteFile(path, []byte("synthetic-certificate-path-secret"), 0o600))
	out := O.Outbound{Tag: "tls-file", Type: C.TypeTrojan, Options: &O.TrojanOutboundOptions{
		ServerOptions: O.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Password:      "test",
		OutboundTLSOptionsContainer: O.OutboundTLSOptionsContainer{TLS: &O.OutboundTLSOptions{
			Enabled: true, CertificatePath: path,
		}},
	}}
	tun := startPolicyTestTunnel(t)
	list := servers.ServerList{Servers: []*servers.Server{{Tag: out.Tag, Type: out.Type, Options: out}}}

	require.NoError(t, tun.addOutbounds(list))
	require.NoError(t, tun.updateNonSelectableOutbounds(list))
	_, found := service.FromContext[adapter.OutboundManager](tun.ctx).Outbound(out.Tag)
	assert.False(t, found)
}

func startPolicyTestTunnel(t *testing.T) *tunnel {
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(probe.Close)
	options := O.Options{
		Log: &O.LogOptions{Disabled: true},
		Outbounds: []O.Outbound{
			{Type: C.TypeDirect, Tag: "direct-out", Options: &O.DirectOutboundOptions{}},
			{Type: lbC.TypeMutableSelector, Tag: ManualSelectTag, Options: &lbO.MutableSelectorOutboundOptions{
				Outbounds: []string{"direct-out"},
			}},
			{Type: lbC.TypeMutableAutoSelect, Tag: AutoSelectTag, Options: &lbO.MutableAutoSelectOutboundOptions{
				Outbounds: []string{"direct-out"},
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
	tun := &tunnel{dataPath: t.TempDir(), initialMode: ManualSelectTag}
	t.Cleanup(func() { assert.NoError(t, tun.close()) })
	require.NoError(t, tun.init(t.Context(), options, nil))
	require.NoError(t, tun.boxInstance.Start())
	tun.optsMap = makeOutboundOptsMap(tun.ctx, options)
	tun.nonSelectableTags = makeNonSelectableTagSet(nil, options)
	mutGrpMgr, err := newMutableGroupManager(tun.ctx, tun.logFactory.NewLogger("groupsManager"), tun.connTracker)
	require.NoError(t, err)
	tun.mutGrpMgr = mutGrpMgr
	t.Cleanup(mutGrpMgr.Close)
	return tun
}
