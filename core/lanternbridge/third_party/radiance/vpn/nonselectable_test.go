package vpn

import (
	"testing"

	O "github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
)

// The server declares certain outbounds or endpoints (e.g. a proxyless rule-set
// detour) as non-selectable via NonSelectableOutbounds. They must be merged into the box
// config so their references (download_detour) resolve, but excluded from the
// user-selectable proxy groups.
func TestMergeAndCollectTags_ExcludesNonSelectable(t *testing.T) {
	dst := &O.Options{Route: &O.RouteOptions{}}
	src := &O.Options{
		Outbounds: []O.Outbound{
			{Type: "shadowsocks", Tag: "ss-out-proxy1"},
			{Type: "outline", Tag: "proxyless"}, // server-declared non-selectable
			{Type: "direct", Tag: "direct"},     // base reserved tag
		},
		Endpoints: []O.Endpoint{
			{Type: "wireguard", Tag: "wg-ep-proxy2"},
			{Type: "wireguard", Tag: "infra-ep"}, // server-declared non-selectable endpoint
		},
	}

	tags := mergeAndCollectTags(dst, src, []string{"proxyless", "infra-ep"})

	assert.Contains(t, tags, "ss-out-proxy1", "a real proxy should be selectable")
	assert.Contains(t, tags, "wg-ep-proxy2", "a real endpoint should be selectable")
	assert.NotContains(t, tags, "proxyless", "a server-declared non-selectable outbound must be excluded")
	assert.NotContains(t, tags, "infra-ep", "a server-declared non-selectable endpoint must be excluded")
	assert.NotContains(t, tags, "direct", "a base reserved tag must be excluded")

	// Non-selectable outbounds/endpoints are still merged into the config so their
	// references resolve; they're only kept out of the selectable set.
	outMerged, epMerged := false, false
	for _, o := range dst.Outbounds {
		if o.Tag == "proxyless" {
			outMerged = true
		}
	}
	for _, e := range dst.Endpoints {
		if e.Tag == "infra-ep" {
			epMerged = true
		}
	}
	assert.True(t, outMerged, "the non-selectable outbound must still be merged into the config")
	assert.True(t, epMerged, "the non-selectable endpoint must still be merged into the config")
}

func TestMakeNonSelectableTagSet_OutboundsOnly(t *testing.T) {
	options := O.Options{
		Outbounds: []O.Outbound{
			{Type: "shadowsocks", Tag: "proxy"},
			{Type: "testing", Tag: "testing-out"},
		},
		Endpoints: []O.Endpoint{
			{Type: "wireguard", Tag: "infra-ep"},
		},
	}

	assert.Equal(t, map[string]struct{}{"testing-out": {}},
		makeNonSelectableTagSet([]string{"testing-out", "infra-ep"}, options),
		"only non-selectable outbounds are seeded; endpoints are managed elsewhere")
	assert.Nil(t, makeNonSelectableTagSet(nil, options))
}
