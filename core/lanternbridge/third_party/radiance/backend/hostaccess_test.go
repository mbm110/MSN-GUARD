package backend

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/internal/hostaccess"
	"github.com/getlantern/radiance/servers"
)

func torOutbound(tag string) option.Outbound {
	return option.Outbound{Tag: tag, Type: "tor", Options: &option.TorOutboundOptions{ExecutablePath: "/tmp/payload"}}
}

func TestApplyCurrentConfigDropsHostAccessServers(t *testing.T) {
	t.Setenv("RADIANCE_COUNTRY", "US")
	dataDir := t.TempDir()
	cfg := cachedConfig()
	cfg.Options.Outbounds = append(cfg.Options.Outbounds, torOutbound("tor-out"))
	writeCachedConfig(t, dataDir, cfg)
	r := newCachedConfigBackend(t, dataDir)

	r.applyCurrentConfig()

	_, found := r.GetServerByTag("cached-out")
	assert.True(t, found, "one denied server must not block the rest of the config")
	_, found = r.GetServerByTag("tor-out")
	assert.False(t, found)
}

func TestAddServersClearsIsLantern(t *testing.T) {
	r := newCachedConfigBackend(t, t.TempDir())
	srv := &servers.Server{Tag: "user-out", Type: "shadowsocks", IsLantern: true, Options: option.Outbound{
		Tag: "user-out", Type: "shadowsocks", Options: &option.ShadowsocksOutboundOptions{},
	}}

	require.NoError(t, r.AddServers(servers.ServerList{Servers: []*servers.Server{srv}}))
	got, found := r.GetServerByTag("user-out")
	require.True(t, found)
	assert.False(t, got.IsLantern)
}

func TestAddServersRejectsHostAccess(t *testing.T) {
	r := newCachedConfigBackend(t, t.TempDir())
	srv := &servers.Server{Tag: "tor-out", Type: "tor", Options: torOutbound("tor-out")}

	err := r.AddServers(servers.ServerList{Servers: []*servers.Server{srv}})
	require.ErrorIs(t, err, hostaccess.ErrDenied)
	_, found := r.GetServerByTag("tor-out")
	assert.False(t, found)
}
