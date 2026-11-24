package vpn

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/getlantern/radiance/servers"
)

// MSN 3.4.11 SR-REJECT: the Iran-pool pin must be fail-closed. The 3.4.10
// field log showed every config fetch drawing ZERO '-ir-free-' servers (the
// server draws the pool from the fetch's exit IP and geo-detection missed),
// so the old fail-open "keep the previous list" let the worldwide sample
// straight into the tunnel while the user's setting said Iran. These tests
// pin the three properties the field log demanded:
// rejects a draw with no ir-free member, keeps only ir-free from a mixed
// draw, and leaves global unfiltered. The pool filter only reads Tag, so
// these tests build minimal Lantern servers with Options unset.
func TestPinPoolRejectsDrawWithoutIrFreeServers(t *testing.T) {
	t.Setenv("RADIANCE_POOL", "iran")
	global := servers.ServerList{Servers: []*servers.Server{
		{Tag: "shadowsocks-out-ss2022-cardiff-oci-free-vps-1", IsLantern: true},
		{Tag: "samizdat-out-samizdat-free-oci-v2-2", IsLantern: true},
	}}
	got := pinPoolIfRequested(global)
	assert.Empty(t, got.Servers, "a draw with no ir-free member must be rejected whole, not passed through")
}

func TestPinPoolKeepsOnlyIrFreeOfMixedDraw(t *testing.T) {
	t.Setenv("RADIANCE_POOL", "iran")
	ir := "shadowsocks-out-ss2022-triangle-lightsail-fra-ir-free-9dafabd3"
	worldwide := "shadowsocks-out-ss2022-cardiff-oci-free-vps-c5211bf5"
	mixed := servers.ServerList{Servers: []*servers.Server{
		{Tag: worldwide, IsLantern: true},
		{Tag: ir, IsLantern: true},
		{Tag: "vless-out-vless-reality-global-d0d3dfcf", IsLantern: true},
	}}
	got := pinPoolIfRequested(mixed)
	assert.Equal(t, []string{ir}, got.Tags(), "a mixed draw must lose its non-ir-free members")
}

func TestPinPoolLeavesGlobalUnfiltered(t *testing.T) {
	t.Setenv("RADIANCE_POOL", "global")
	draw := servers.ServerList{Servers: []*servers.Server{
		{Tag: "shadowsocks-out-ss2022-cardiff-oci-free-vps-1", IsLantern: true},
		{Tag: "vless-out-vless-reality-global-2", IsLantern: true},
	}}
	got := pinPoolIfRequested(draw)
	assert.Equal(t, draw.Tags(), got.Tags(), "the explicit global choice keeps every draw unfiltered")
}

func TestPinPoolLeavesUnsetUnfiltered(t *testing.T) {
	draw := servers.ServerList{Servers: []*servers.Server{
		{Tag: "shadowsocks-out-ss2022-cardiff-oci-free-vps-1", IsLantern: true},
	}}
	got := pinPoolIfRequested(draw)
	assert.Equal(t, draw.Tags(), got.Tags(), "an unset pool keeps upstream behavior")
}

func TestIrPoolSelectedSpells(t *testing.T) {
	t.Setenv("RADIANCE_POOL", "iran")
	assert.True(t, irPoolSelected())
	assert.True(t, IrPoolSelected())
	t.Setenv("RADIANCE_POOL", "ir")
	assert.True(t, irPoolSelected(), "the 3.4.9 spelling must keep matching")
	t.Setenv("RADIANCE_POOL", "global")
	assert.False(t, irPoolSelected())
	t.Setenv("RADIANCE_POOL", "")
	assert.False(t, irPoolSelected())
}

func TestAllowedServersTreatsRejectedDrawAsEmpty(t *testing.T) {
	t.Setenv("RADIANCE_POOL", "iran")
	rejected := servers.ServerList{Servers: []*servers.Server{
		{Tag: "shadowsocks-out-ss2022-cardiff-oci-free-vps-1", IsLantern: true},
	}}
	got := allowedServers(rejected)
	assert.Empty(t, got.Servers, "the rejected draw must surface as empty, never as the unfiltered worldwide list")
}
