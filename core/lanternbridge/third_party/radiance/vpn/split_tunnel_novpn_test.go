//go:build novpn

package vpn

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoVPNHasNoTunInbound(t *testing.T) {
	for _, in := range baseInbounds() {
		assert.NotEqual(t, "tun", in.Type, "novpn build must not configure a TUN inbound")
	}
}

func TestNoVPNSplitTunnelOptionsEmpty(t *testing.T) {
	assert.Nil(t, splitTunnelRuleSet(t.TempDir()))
	assert.Nil(t, splitTunnelRoutingRules())
}

func TestNoVPNSplitTunnelStubInert(t *testing.T) {
	st, err := NewSplitTunnelHandler(t.TempDir(), slog.Default())
	require.NoError(t, err)
	require.NotNil(t, st)

	assert.False(t, st.IsEnabled())
	assert.NoError(t, st.SetEnabled(true))
	assert.False(t, st.IsEnabled(), "stub must stay disabled")
	assert.Equal(t, SplitTunnelFilter{}, st.Filters())
	assert.NoError(t, st.AddItems(SplitTunnelFilter{Domain: []string{"example.com"}}))
	assert.NoError(t, st.RemoveItems(SplitTunnelFilter{Domain: []string{"example.com"}}))
}
