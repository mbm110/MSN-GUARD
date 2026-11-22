package vpn

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	lcommon "github.com/getlantern/common"
	box "github.com/getlantern/lantern-box"
	lbO "github.com/getlantern/lantern-box/option"
	lbgroup "github.com/getlantern/lantern-box/protocol/group"
	A "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashmode"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClashModeManagerSetModeWhileRejecting(t *testing.T) {
	modes := newTestClashModeManager(t)
	modes.setRejectMode(true)

	prev, err := modes.SetMode("MANUAL")
	require.NoError(t, err)
	assert.Equal(t, AutoSelectTag, prev)
	assert.Equal(t, rejectMode, modes.clashMode.Mode(), "selecting a mode must not lift reject mode")
	assert.Equal(t, ManualSelectTag, modes.selectedMode())

	modes.setRejectMode(false)
	assert.Equal(t, ManualSelectTag, modes.clashMode.Mode(), "lifting reject mode applies the mode selected meanwhile")

	_, err = modes.SetMode(rejectMode)
	assert.Error(t, err, "reject mode is not selectable")
}

// TestTunnelModeRules checks that the box's mode and reject rules follow the
// tunnel's clash mode manager.
func TestTunnelModeRules(t *testing.T) {
	options := O.Options{
		Log: &O.LogOptions{Disabled: true},
		Outbounds: []O.Outbound{
			{Type: C.TypeDirect, Tag: AutoSelectTag, Options: &O.DirectOutboundOptions{}},
			{Type: C.TypeDirect, Tag: ManualSelectTag, Options: &O.DirectOutboundOptions{}},
		},
		Route: &O.RouteOptions{Rules: []O.Rule{
			highMemoryRejectRule(),
			selectModeRule(AutoSelectTag),
			selectModeRule(ManualSelectTag),
		}},
		Experimental: &O.ExperimentalOptions{
			CacheFile: &O.CacheFileOptions{Enabled: true, Path: filepath.Join(t.TempDir(), "cache.db")},
		},
	}
	tun := &tunnel{dataPath: t.TempDir(), initialMode: AutoSelectTag}
	t.Cleanup(func() { assert.NoError(t, tun.close()) })
	require.NoError(t, tun.init(t.Context(), options, nil))
	require.NoError(t, tun.boxInstance.Start())
	require.Same(t, tun.clashModeManager.clashMode, service.PtrFromContext[clashmode.Manager](tun.ctx))

	matchedRule := func() int {
		var metadata A.InboundContext
		for i, rule := range tun.boxInstance.Router().Rules() {
			if rule.Match(&metadata) {
				return i
			}
		}
		return -1
	}
	assert.Equal(t, 1, matchedRule(), "the initial mode")
	_, err := tun.clashModeManager.SetMode(ManualSelectTag)
	require.NoError(t, err)
	assert.Equal(t, 2, matchedRule(), "the selected mode")
	tun.clashModeManager.setRejectMode(true)
	assert.Equal(t, 0, matchedRule(), "reject mode")
	tun.clashModeManager.setRejectMode(false)
	assert.Equal(t, 2, matchedRule(), "lifting reject mode")
}

func TestTunnelSmartRoutingHistory(t *testing.T) {
	tun := &tunnel{dataPath: t.TempDir(), initialMode: ManualSelectTag}
	var previous *urltest.HistoryStorage
	for _, cycle := range []string{"connect", "reconnect"} {
		t.Run(cycle, func(t *testing.T) {
			probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(probe.Close)
			options, err := json.UnmarshalExtendedContext[O.Options](box.Context(t.Context()), []byte(`{
				"outbounds": [{"type": "direct", "tag": "probe"}],
				"route": {"rules": [{"clash_mode": "manual", "outbound": "sr-ai-domains"}]}
			}`))
			require.NoError(t, err)
			options.Experimental = &O.ExperimentalOptions{
				CacheFile: &O.CacheFileOptions{Enabled: true, Path: filepath.Join(t.TempDir(), "cache.db")},
			}
			smartRouting := lcommon.SmartRoutingRules{{Category: "ai-domains", Outbounds: []string{"probe"}}}
			outbounds, _, _ := smartRouting.ToOptions(urlTestInterval, urlTestIdleTimeout)
			outbounds[0].Options.(*O.URLTestOutboundOptions).URL = probe.URL
			options.Outbounds = append(options.Outbounds, outbounds...)

			t.Cleanup(func() { assert.NoError(t, tun.close()) })
			require.NoError(t, tun.init(t.Context(), options, nil))
			history := service.PtrFromContext[urltest.HistoryStorage](tun.ctx)
			require.NotNil(t, history)
			if previous != nil {
				require.NotSame(t, previous, history)
			}
			assert.Nil(t, history.LoadURLTestHistory("probe"))
			previous = history

			require.NoError(t, tun.boxInstance.Start())
			require.Eventually(t, func() bool {
				return history.LoadURLTestHistory("probe") != nil
			}, 3*time.Second, time.Millisecond, "startup must record the background URL test")

			mutable, err := lbgroup.NewMutableURLTest(tun.ctx, nil, tun.logFactory.Logger(), "mutable", lbO.MutableURLTestOutboundOptions{
				Outbounds: []string{"probe"},
				URL:       probe.URL,
			})
			require.NoError(t, err)
			mutableGroup := mutable.(*lbgroup.MutableURLTest)
			t.Cleanup(func() { assert.NoError(t, mutableGroup.Close()) })
			require.NoError(t, mutableGroup.Start())
			native, found := service.FromContext[A.OutboundManager](tun.ctx).Outbound("sr-ai-domains")
			require.True(t, found)
			groups := []struct {
				name  string
				group interface{ CheckOutbounds() }
			}{
				{"native", native.(interface{ CheckOutbounds() })},
				{"mutable", mutableGroup},
			}
			for _, group := range groups {
				t.Run(group.name+"/success", func(t *testing.T) {
					stale := &A.URLTestHistory{Time: time.Now().Add(-time.Hour), Delay: 1}
					history.StoreURLTestHistory("probe", stale)
					require.Eventually(t, func() bool {
						group.group.CheckOutbounds()
						entry := history.LoadURLTestHistory("probe")
						return entry != nil && entry != stale
					}, 3*time.Second, time.Millisecond, "URL tests must update the shared history")
				})
			}

			probe.Close()
			for _, group := range groups {
				t.Run(group.name+"/failure", func(t *testing.T) {
					history.StoreURLTestHistory("probe", &A.URLTestHistory{Time: time.Now(), Delay: 1})
					require.Eventually(t, func() bool {
						group.group.CheckOutbounds()
						return history.LoadURLTestHistory("probe") == nil
					}, 3*time.Second, time.Millisecond, "failed URL tests must remove stale history")
				})
			}
		})
	}
}
