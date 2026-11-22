package backend

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"

	"github.com/getlantern/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/servers"
	"github.com/getlantern/radiance/vpn"
)

func TestProxylessOn(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))
	require.NoError(t, settings.Set(settings.SmartRoutingKey, true))

	flagOn := &config.Config{Features: map[string]bool{proxylessFeature: true}}
	flagOff := &config.Config{Features: map[string]bool{}}

	assert.True(t, settings.ProxylessEnabled(), "the setting is on until the user turns it off")
	assert.True(t, proxylessOn(flagOn), "flag on and setting on by default")
	assert.False(t, proxylessOn(flagOff), "the server flag is the kill switch")
	assert.False(t, proxylessOn(nil), "no config, no proxyless")

	require.NoError(t, settings.Set(settings.ProxylessKey, false))
	assert.False(t, settings.ProxylessEnabled())
	assert.False(t, proxylessOn(flagOn), "the user's setting turns it off even with the flag on")

	require.NoError(t, settings.Set(settings.ProxylessKey, true))
	assert.True(t, proxylessOn(flagOn))

	require.NoError(t, settings.Set(settings.SmartRoutingKey, false))
	assert.False(t, proxylessOn(flagOn), "full tunnel keeps a hedge built while connecting switched off")
}

// TestGetBoxOptionsProxyless checks that only smart routing builds the
// proxyless hedge: full tunnel sends everything through the proxy.
func TestGetBoxOptionsProxyless(t *testing.T) {
	dataDir := t.TempDir()
	cfg := cachedConfig()
	cfg.Features = map[string]bool{proxylessFeature: true}
	cfg.Proxyless = &common.ProxylessConfig{ExploreRate: 0.05, TelemetrySites: []string{"youtube.com"}}
	buf, err := singjson.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, internal.ConfigFileName), buf, 0o600))
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(dataDir))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srvMgr, err := servers.NewManager(dataDir, log.NoOpLogger())
	require.NoError(t, err)
	r := &LocalBackend{
		ctx:         ctx,
		confHandler: config.NewConfigHandler(ctx, config.Options{DataPath: dataDir, Logger: log.NoOpLogger()}),
		srvManager:  srvMgr,
	}

	require.NoError(t, settings.Set(settings.SmartRoutingKey, false))
	assert.Nil(t, r.getBoxOptions().Proxyless, "full tunnel never builds the proxyless hedge")

	require.NoError(t, settings.Set(settings.SmartRoutingKey, true))
	p := r.getBoxOptions().Proxyless
	require.NotNil(t, p, "smart routing builds the proxyless hedge")
	assert.Equal(t, 0.05, p.ExploreRate, "with the server's measurement settings")
	assert.Equal(t, []string{"youtube.com"}, p.TelemetrySites)
	assert.True(t, p.Enabled)

	require.NoError(t, settings.Set(settings.ProxylessKey, false))
	p = r.getBoxOptions().Proxyless
	require.NotNil(t, p, "the setting switches the hedge; it is still built so it can be switched on live")
	assert.False(t, p.Enabled)
}

func TestNonSelectableProxylessGetsUDP(t *testing.T) {
	cfg := cachedConfig()
	cfg.Options.Outbounds = append(cfg.Options.Outbounds, option.Outbound{
		Type: lbC.TypeOutline, Tag: vpn.ProxylessTag, Options: &lbO.OutboundOutlineOptions{Domains: []string{"cdn.jsdelivr.net"}},
	})
	cfg.NonSelectableOutbounds = []string{vpn.ProxylessTag}
	list := nonSelectableOutboundsFromConfig(cfg)
	require.Len(t, list.Servers, 1)
	opts := list.Servers[0].Options.(option.Outbound).Options.(*lbO.OutboundOutlineOptions)
	require.NotNil(t, opts.UDP, "a config update must not drop the UDP default the tunnel was built with")
}

// proxylessBackend returns a backend whose config handler loaded cfg from
// dataDir, with settings initialized there.
func proxylessBackend(t *testing.T, dataDir string, cfg *config.Config) *LocalBackend {
	t.Helper()
	buf, err := singjson.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, internal.ConfigFileName), buf, 0o600))
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(dataDir))
	require.NoError(t, settings.Set(settings.SmartRoutingKey, true))
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

// TestProxylessFollowsConfigAndSettings checks that a config update and a
// settings change both switch proxyless, before any tunnel runs too.
func TestProxylessFollowsConfigAndSettings(t *testing.T) {
	cfg := cachedConfig()
	cfg.Features = map[string]bool{proxylessFeature: true}
	r := proxylessBackend(t, t.TempDir(), cfg)
	live, err := r.confHandler.GetConfig()
	require.NoError(t, err)

	r.applyConfig(live, false)
	assert.True(t, r.vpnClient.ProxylessEnabled(), "a config with the flag on switches proxyless on")

	require.NoError(t, r.PatchSettings(settings.Settings{settings.ProxylessKey: false}))
	assert.False(t, r.vpnClient.ProxylessEnabled(), "turning the setting off switches proxyless off")

	require.NoError(t, r.PatchSettings(settings.Settings{settings.ProxylessKey: true}))
	assert.True(t, r.vpnClient.ProxylessEnabled())

	require.NoError(t, r.PatchSettings(settings.Settings{settings.SmartRoutingKey: false}))
	assert.False(t, r.vpnClient.ProxylessEnabled(), "turning smart routing off switches proxyless off, even with no restart")
	require.NoError(t, r.PatchSettings(settings.Settings{settings.SmartRoutingKey: true}))
	assert.True(t, r.vpnClient.ProxylessEnabled())

	live.Features = map[string]bool{}
	r.applyConfig(live, false)
	assert.False(t, r.vpnClient.ProxylessEnabled(), "the server's flag turning off is the kill switch")
}

// TestProxylessAppliesTheCurrentConfig checks that applying a stale config,
// as a config update racing a settings change can, still uses the current
// one: a flag the server has since turned off stays off.
func TestProxylessAppliesTheCurrentConfig(t *testing.T) {
	cfg := cachedConfig()
	cfg.Features = map[string]bool{}
	r := proxylessBackend(t, t.TempDir(), cfg)

	stale := cachedConfig()
	stale.Features = map[string]bool{proxylessFeature: true}
	r.applyConfig(stale, false)
	assert.False(t, r.vpnClient.ProxylessEnabled(), "the current config's flag decides, not the one passed in")
}

// TestProxylessSwitchesWhenTheSaveFails checks that turning the setting off
// switches proxyless off even when saving the settings file fails, since the
// live value has already changed and a retry would be an empty diff.
func TestProxylessSwitchesWhenTheSaveFails(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions don't block writes on Windows or as root")
	}
	dataDir := t.TempDir()
	cfg := cachedConfig()
	cfg.Features = map[string]bool{proxylessFeature: true}
	r := proxylessBackend(t, dataDir, cfg)
	r.applyProxyless()
	require.True(t, r.vpnClient.ProxylessEnabled())

	require.NoError(t, os.Chmod(dataDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })
	require.Error(t, r.PatchSettings(settings.Settings{settings.ProxylessKey: false}), "the save fails")
	require.False(t, settings.ProxylessEnabled(), "the live value changed anyway")
	assert.False(t, r.vpnClient.ProxylessEnabled(), "so proxyless follows it")
}

// The server's measurement settings for this client are passed to the hedge.
func TestProxylessOptionsFromConfig(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))
	cfg := &config.Config{
		Features:  map[string]bool{proxylessFeature: true},
		Proxyless: &common.ProxylessConfig{ExploreRate: 0.05, TelemetrySites: []string{"youtube.com"}},
	}
	p := proxylessOptions(cfg)
	assert.Equal(t, 0.05, p.ExploreRate)
	assert.Equal(t, []string{"youtube.com"}, p.TelemetrySites)

	p = proxylessOptions(&config.Config{})
	assert.Zero(t, p.ExploreRate, "no settings from the server leave the hedge's defaults")
	assert.Empty(t, p.TelemetrySites)
}
