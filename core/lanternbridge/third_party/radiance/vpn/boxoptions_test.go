package vpn

import (
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	box "github.com/getlantern/lantern-box"
	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"

	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/internal/hostaccess"
)

func TestBuildOptions(t *testing.T) {
	options, tags := testBoxOptions(t)
	tests := []struct {
		name        string
		boxOptions  BoxOptions
		shouldError bool
	}{
		{
			name: "success",
			boxOptions: BoxOptions{
				BasePath: t.TempDir(),
				Options:  options,
			},
		},
		{
			name: "no servers available",
			boxOptions: BoxOptions{
				BasePath: t.TempDir(),
			},
			shouldError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, _, err := buildOptions(tt.boxOptions)
			if tt.shouldError {
				require.Error(t, err, "expected error but got none")
				return
			}
			require.NoError(t, err)

			urlTest := urlTestOutbound(AutoSelectTag, tags, nil, nil)
			assert.Contains(t, opts.Outbounds, urlTest, "options should contain auto-select URL test outbound")
			selector := selectorOutbound(ManualSelectTag, tags)
			assert.Contains(t, opts.Outbounds, selector, "options should contain manual-select selector outbound")
		})
	}
}

func TestBuildOptions_Rulesets(t *testing.T) {
	smartRouteJSON := `
	{
		"outbounds": [
			{
				"type": "urltest",
				"tag": "sr-openai",
				"outbounds": ["http1-out", "socks1-out"],
				"url": "https://google.com/generate_204",
				"interval": "3m0s",
				"idle_timeout": "15m"
			}
		],
		"route": {
			"rules": [
				{
					"rule_set": "sr-direct",
					"outbound": "direct"
				},
				{
					"rule_set": "openai",
					"outbound": "sr-openai"
				}
			],
			"rule_set": [
				{
				  "type": "remote",
				  "tag": "sr-direct",
				  "url": "https://ruleset.com/direct.srs",
				  "download_detour": "direct",
				  "update_interval": "24h0m0s"
				},
				{
				  "type": "remote",
				  "tag": "openai",
				  "url": "https://ruleset.com/openai.srs",
				  "download_detour": "direct",
				  "update_interval": "24h0m0s"
				}
			]
		}
	}
	`
	wantSmartRoutingOpts, err := json.UnmarshalExtendedContext[O.Options](box.BaseContext(), []byte(smartRouteJSON))
	require.NoError(t, err)

	t.Run("with smart routing", func(t *testing.T) {
		cfg := testConfig(t)
		boxOptions := BoxOptions{
			BasePath:     t.TempDir(),
			Options:      cfg.Options,
			SmartRouting: cfg.SmartRouting,
		}
		options, _, err := buildOptions(boxOptions)
		require.NoError(t, err)
		// check rules, rulesets, and outbounds are correctly built into options
		assert.Subset(t, options.Route.Rules, wantSmartRoutingOpts.Route.Rules, "missing smart routing rule")
		assert.Subset(t, options.Route.RuleSet, wantSmartRoutingOpts.Route.RuleSet, "missing smart routing ruleset")
		assert.Subset(t, options.Outbounds, wantSmartRoutingOpts.Outbounds, "missing smart routing outbound")
	})
	t.Run("with smart routing and missing outbounds", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.SmartRouting[1].Outbounds = nil
		boxOptions := BoxOptions{
			BasePath:     t.TempDir(),
			Options:      cfg.Options,
			SmartRouting: cfg.SmartRouting,
		}
		options, _, err := buildOptions(boxOptions)
		require.NoError(t, err)
		// sr-direct rule and ruleset should still be present (category still has outbounds)
		assert.Contains(t, options.Route.Rules, wantSmartRoutingOpts.Route.Rules[0], "missing sr-direct rule")
		assert.Contains(t, options.Route.RuleSet, wantSmartRoutingOpts.Route.RuleSet[0], "missing sr-direct ruleset")
		// openai rule/ruleset and sr-openai outbound should be dropped (outbounds were nilled)
		assert.NotContains(t, options.Route.Rules, wantSmartRoutingOpts.Route.Rules[1], "unexpected openai rule")
		assert.NotContains(t, options.Route.RuleSet, wantSmartRoutingOpts.Route.RuleSet[1], "unexpected openai ruleset")
		assert.NotContains(t, options.Outbounds, wantSmartRoutingOpts.Outbounds[0], "unexpected sr-openai outbound")
	})
	t.Run("with ad block", func(t *testing.T) {
		cfg := testConfig(t)
		boxOptions := BoxOptions{
			BasePath: t.TempDir(),
			Options:  cfg.Options,
			AdBlock:  cfg.AdBlock,
		}
		wantRule, wantRulesets := cfg.AdBlock.ToOptions()
		// buildOptions round-trips the options through JSON, which lets sing-box
		// fill in the reject action's default method; ToOptions leaves it unset.
		wantRule.DefaultOptions.RejectOptions.Method = C.RuleActionRejectMethodDefault
		options, _, err := buildOptions(boxOptions)
		require.NoError(t, err)
		// check reject rule and rulesets are correctly built into options
		assert.Contains(t, options.Route.Rules, wantRule, "missing ad block rule")
		assert.Subset(t, options.Route.RuleSet, wantRulesets, "missing ad block ruleset")
	})
}

func TestBuildOptions_BanditURLOverrides(t *testing.T) {
	cfg := testConfig(t)
	overrides := map[string]string{
		cfg.Options.Outbounds[0].Tag: "https://example.com/callback?token=abc",
	}
	boxOptions := BoxOptions{
		BasePath:           t.TempDir(),
		Options:            cfg.Options,
		BanditURLOverrides: overrides,
	}
	opts, _, err := buildOptions(boxOptions)
	require.NoError(t, err)

	out := findOutbound(opts.Outbounds, AutoSelectTag)
	require.NotNil(t, out, "missing auto-select outbound")

	require.IsType(t, &lbO.MutableAutoSelectOutboundOptions{}, out.Options, "auto outbound options should be MutableAutoSelectOutboundOptions")
	autoOpts := out.Options.(*lbO.MutableAutoSelectOutboundOptions)
	assert.Equal(t, overrides, autoOpts.URLOverrides, "URLOverrides should be wired from config")
}

func TestBuildOptions_DropsHostAccess(t *testing.T) {
	cfg := testConfig(t)
	cfg.Options.Outbounds = append(cfg.Options.Outbounds,
		O.Outbound{Tag: "tor-out", Type: C.TypeTor, Options: &O.TorOutboundOptions{ExecutablePath: "/tmp/payload"}},
		O.Outbound{Tag: "water-out", Type: lbC.TypeWATER, Options: &lbO.WATEROutboundOptions{Dir: "/tmp/stale"}},
	)
	cfg.Options.Endpoints = append(cfg.Options.Endpoints, O.Endpoint{
		Tag: "wg-listen", Type: C.TypeWireGuard, Options: &O.WireGuardEndpointOptions{ListenPort: 51820, Name: "../../tmp/x"},
	})
	opts, _, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: cfg.Options})
	require.NoError(t, err)

	assert.False(t, slices.ContainsFunc(opts.Endpoints, func(e O.Endpoint) bool { return e.Tag == "wg-listen" }))
	assert.Nil(t, findOutbound(opts.Outbounds, "tor-out"))
	assert.Nil(t, findOutbound(opts.Outbounds, "water-out"))
	selector := findOutbound(opts.Outbounds, ManualSelectTag)
	require.NotNil(t, selector)
	assert.NotContains(t, selector.Options.(*lbO.MutableSelectorOutboundOptions).Outbounds, "tor-out",
		"a dropped outbound must not be referenced by the selector")
}

func TestBuildOptions_DropsDeniedServices(t *testing.T) {
	cfg := testConfig(t)
	cfg.Options.Services = []O.Service{{Type: C.TypeSSMAPI, Tag: "ssm", Options: &O.SSMAPIServiceOptions{}}}
	opts, _, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: cfg.Options})
	require.NoError(t, err)
	assert.Empty(t, opts.Services)
}

func TestBuildOptions_RejectsHostAccessDNS(t *testing.T) {
	cfg := testConfig(t)
	var dns O.DNSOptions
	if cfg.Options.DNS != nil {
		dns = *cfg.Options.DNS
	}
	dns.Servers = append(slices.Clone(dns.Servers), O.DNSServerOptions{
		Type: C.DNSTypeUDP, Tag: "planted", Options: &O.RemoteDNSServerOptions{
			RawLocalDNSServerOptions: O.RawLocalDNSServerOptions{DialerOptions: O.DialerOptions{AbstractDialerOptions: O.AbstractDialerOptions{NetNs: "/proc/1/ns/net"}}},
			DNSServerAddressOptions:  O.DNSServerAddressOptions{Server: "192.0.2.1"},
		},
	})
	cfg.Options.DNS = &dns
	_, _, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: cfg.Options})
	require.ErrorIs(t, err, hostaccess.ErrDenied)
}

func contains[S ~[]E, E any](t *testing.T, s S, e E) bool {
	for _, v := range s {
		if optsEqual(t, v, e) {
			return true
		}
	}
	return false
}

func optsEqual[T any](t *testing.T, want, got T) bool {
	wantBuf, err := json.Marshal(want)
	require.NoError(t, err, "marshal wanted options")
	gotBuf, err := json.Marshal(got)
	require.NoError(t, err, "marshal got options")
	return string(wantBuf) == string(gotBuf)
}

func filterOutbounds(opts O.Options, typ string) ([]string, []O.Outbound) {
	var outbounds []O.Outbound
	var tags []string
	for _, o := range opts.Outbounds {
		if o.Type == typ {
			outbounds = append(outbounds, o)
			tags = append(tags, o.Tag)
		}
	}
	return tags, outbounds
}

func findOutbound(outs []O.Outbound, tag string) *O.Outbound {
	idx := slices.IndexFunc(outs, func(o O.Outbound) bool {
		return o.Tag == tag
	})
	if idx == -1 {
		return nil
	}
	return &outs[idx]
}

func testConfig(t *testing.T) config.Config {
	buf, err := os.ReadFile("testdata/config.json")
	require.NoError(t, err, "read test config file")

	cfg, err := json.UnmarshalExtendedContext[config.Config](box.BaseContext(), buf)
	require.NoError(t, err, "unmarshal test config")
	return cfg
}

func testBoxOptions(t *testing.T) (O.Options, []string) {
	cfg := testConfig(t)
	var tags []string
	for _, o := range cfg.Options.Outbounds {
		tags = append(tags, o.Tag)
	}
	for _, ep := range cfg.Options.Endpoints {
		tags = append(tags, ep.Tag)
	}
	return cfg.Options, tags
}

// TestBuildOptions_RejectsQUICAfterDirectRules pins the placement of the QUIC
// reject: it must follow the split-tunnel and smart-routing rules (so a
// direct-routed domain keeps its QUIC) and precede the selector rules (so
// QUIC bound for the proxy is rejected).
func TestBuildOptions_RejectsIPv6WhenCaptured(t *testing.T) {
	cfg := testConfig(t)
	opts, _, err := buildOptions(BoxOptions{
		BasePath:     t.TempDir(),
		Options:      cfg.Options,
		SmartRouting: cfg.SmartRouting,
		AdBlock:      cfg.AdBlock,
	})
	require.NoError(t, err)

	isIPv6Reject := func(r O.Rule) bool {
		o := r.DefaultOptions
		return o.RuleAction.Action == "reject" && slices.Contains(o.RawDefaultRule.IPCIDR, "::/0")
	}
	rejectIdx := slices.IndexFunc(opts.Route.Rules, isIPv6Reject)

	if !tunHasIPv6(opts) {
		require.Equal(t, -1, rejectIdx, "no ::/0 reject expected when the TUN has no IPv6 address")
		return
	}

	isSplitTunnel := func(r O.Rule) bool {
		return slices.Contains(r.DefaultOptions.RawDefaultRule.RuleSet, splitTunnelTag)
	}
	isSelector := func(r O.Rule) bool {
		mode := r.DefaultOptions.RawDefaultRule.ClashMode
		return mode == AutoSelectTag || mode == ManualSelectTag
	}
	splitIdx := slices.IndexFunc(opts.Route.Rules, isSplitTunnel)
	selectorIdx := slices.IndexFunc(opts.Route.Rules, isSelector)

	require.NotEqual(t, -1, splitIdx, "expected split-tunnel rule in built options")
	require.NotEqual(t, -1, selectorIdx, "expected at least one selector mode rule in built options")
	assert.Greater(t, rejectIdx, splitIdx, "IPv6 reject must come after split-tunnel so split-direct v6 keeps flowing")
	assert.Less(t, rejectIdx, selectorIdx, "IPv6 reject must come before selector rules so proxied v6 is rejected")
}

func TestRejectIPv6Rule(t *testing.T) {
	r := rejectIPv6Rule()
	assert.Equal(t, "reject", r.DefaultOptions.RuleAction.Action)
	assert.Equal(t, []string{"::/0"}, []string(r.DefaultOptions.RawDefaultRule.IPCIDR))
	assert.NotEqual(t, C.RuleActionRejectMethodDrop, r.DefaultOptions.RuleAction.RejectOptions.Method,
		"must not use the drop method — a silent blackhole stalls instead of failing over to IPv4")
	assert.True(t, r.DefaultOptions.RuleAction.RejectOptions.NoDrop,
		"NoDrop must be set so the reject returns unreachable instead of dropping")
}

func TestTunHasIPv6(t *testing.T) {
	tun := func(addrs ...string) O.Options {
		prefixes := make([]netip.Prefix, len(addrs))
		for i, a := range addrs {
			prefixes[i] = netip.MustParsePrefix(a)
		}
		return O.Options{Inbounds: []O.Inbound{{
			Type:    "tun",
			Options: &O.TunInboundOptions{Address: prefixes},
		}}}
	}
	assert.True(t, tunHasIPv6(tun("10.10.1.1/30", "fdfe:dcba:9876::1/126")),
		"TUN with a v6 address captures IPv6")
	assert.False(t, tunHasIPv6(tun("10.10.1.1/30")), "v4-only TUN does not capture IPv6")
	assert.False(t, tunHasIPv6(O.Options{}), "no inbounds means no IPv6 capture")
}

func helperOutbound(tag string) O.Outbound {
	return O.Outbound{Type: C.TypeDirect, Tag: tag, Options: &O.DirectOutboundOptions{}}
}

func TestBuildOptions_PersonalProxies(t *testing.T) {
	const h1, h2 = "helper-0123456789ab", "helper-ba9876543210"
	withHelpers := func(t *testing.T) O.Options {
		cfg := testConfig(t)
		cfg.Options.Outbounds = append(cfg.Options.Outbounds, helperOutbound(h1), helperOutbound(h2))
		return cfg.Options
	}

	t.Run("groups every helper outbound and is offered by the manual selector", func(t *testing.T) {
		opts, _, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: withHelpers(t)})
		require.NoError(t, err)
		group := findOutbound(opts.Outbounds, PersonalProxiesTag)
		require.NotNil(t, group)
		assert.Equal(t, lbC.TypeMutableURLTest, group.Type)
		assert.Equal(t, []string{h1, h2}, group.Options.(*lbO.MutableURLTestOutboundOptions).Outbounds)
		manual := findOutbound(opts.Outbounds, ManualSelectTag).Options.(*lbO.MutableSelectorOutboundOptions)
		assert.Contains(t, manual.Outbounds, PersonalProxiesTag)
		auto := findOutbound(opts.Outbounds, AutoSelectTag).Options.(*lbO.MutableAutoSelectOutboundOptions)
		assert.NotContains(t, auto.Outbounds, PersonalProxiesTag, "Smart Location uses the helpers directly")
		assert.Contains(t, auto.Outbounds, h1)
	})

	t.Run("does not exist without helper outbounds", func(t *testing.T) {
		options, _ := testBoxOptions(t)
		opts, _, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: options})
		require.NoError(t, err)
		assert.Nil(t, findOutbound(opts.Outbounds, PersonalProxiesTag), "a url-test group must never start empty")
		manual := findOutbound(opts.Outbounds, ManualSelectTag).Options.(*lbO.MutableSelectorOutboundOptions)
		assert.NotContains(t, manual.Outbounds, PersonalProxiesTag)
	})

	t.Run("can be the initial selection while helpers exist", func(t *testing.T) {
		opts, mode, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: withHelpers(t), InitialServer: PersonalProxiesTag})
		require.NoError(t, err)
		manual := findOutbound(opts.Outbounds, ManualSelectTag).Options.(*lbO.MutableSelectorOutboundOptions)
		assert.Equal(t, PersonalProxiesTag, manual.Outbounds[0])
		assert.Equal(t, ManualSelectTag, mode)

		options, _ := testBoxOptions(t)
		opts, mode, err = buildOptions(BoxOptions{BasePath: t.TempDir(), Options: options, InitialServer: PersonalProxiesTag})
		require.NoError(t, err, "without helpers the group starts on auto-select")
		assert.Equal(t, AutoSelectTag, mode)
		assert.Nil(t, findOutbound(opts.Outbounds, PersonalProxiesTag))
	})

	t.Run("is reserved", func(t *testing.T) {
		assert.Contains(t, ReservedTags(), PersonalProxiesTag)
	})
}

func TestDecodeAutoSelectOptions(t *testing.T) {
	assert.Equal(t, &lbO.MutableAutoSelectOutboundOptions{}, DecodeAutoSelectOptions(nil),
		"an absent field gives empty options, so a refresh clears earlier timeouts")
	assert.Equal(t, &lbO.MutableAutoSelectOutboundOptions{},
		DecodeAutoSelectOptions([]byte(`{"background_interval_seconds": "x", "probe_timeouts_ms": {"hysteria2x": 3000}}`)),
		"an object that doesn't decode is ignored whole")

	got := DecodeAutoSelectOptions([]byte(`{"probe_timeouts_ms": {"hysteria2x": 3000, "vless": -1}, "switch_tolerance_percent": 150, "probe_concurrency": 4}`))
	assert.Equal(t, lbO.ProbeTimeoutsMs{"hysteria2x": 3000}, got.ProbeTimeoutsMs, "a bad entry costs only itself")
	assert.Nil(t, got.SwitchTolerancePercent, "a value lantern-box would refuse to build with is dropped")
	assert.EqualValues(t, 4, got.ProbeConcurrency)
}

func TestBuildOptions_AutoSelectOptions(t *testing.T) {
	cfg := testConfig(t)
	overrides := map[string]string{cfg.Options.Outbounds[0].Tag: "https://example.com/callback"}
	base := DecodeAutoSelectOptions([]byte(`{
		"outbounds": ["server-sent"], "url": "https://server.example/", "url_overrides": {"x": "y"},
		"probe_timeouts_ms": {"hysteria2x": 3000}, "probe_concurrency": 4, "switch_tolerance_percent": 150
	}`))
	opts, _, err := buildOptions(BoxOptions{
		BasePath:           t.TempDir(),
		Options:            cfg.Options,
		BanditURLOverrides: overrides,
		AutoSelectOptions:  base,
	})
	require.NoError(t, err, "an out-of-range switch_tolerance_percent must not stop the tunnel from building")

	out := findOutbound(opts.Outbounds, AutoSelectTag)
	require.NotNil(t, out, "missing auto-select outbound")
	autoOpts := out.Options.(*lbO.MutableAutoSelectOutboundOptions)
	assert.Equal(t, lbO.ProbeTimeoutsMs{"hysteria2x": 3000}, autoOpts.ProbeTimeoutsMs)
	assert.EqualValues(t, 4, autoOpts.ProbeConcurrency)
	assert.Equal(t, "https://google.com/generate_204", autoOpts.URL, "radiance owns the probe URL")
	assert.Equal(t, overrides, autoOpts.URLOverrides, "radiance owns the URL overrides")
	assert.NotContains(t, autoOpts.Outbounds, "server-sent", "radiance owns the members")
	assert.EqualValues(t, urlTestInterval/time.Second, autoOpts.BackgroundIntervalSeconds,
		"an unset interval keeps radiance's default")
	assert.Equal(t, []string{"server-sent"}, base.Outbounds, "the shared options are not modified")
}
