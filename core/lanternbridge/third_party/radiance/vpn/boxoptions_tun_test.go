//go:build !novpn

package vpn

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	sbdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	box "github.com/getlantern/lantern-box"

	"github.com/getlantern/radiance/common"

	rlog "github.com/getlantern/radiance/log"
)

func TestBaseOpts_TunIPv6Address(t *testing.T) {
	for _, v6 := range []bool{true, false} {
		t.Run(fmt.Sprintf("v6=%v", v6), func(t *testing.T) {
			setHasGlobalIPv6(t, v6)
			opts := baseOpts(t.TempDir())
			require.NotEmpty(t, opts.Inbounds, "expected inbounds in baseOpts output")

			var tunOpts *O.TunInboundOptions
			for _, in := range opts.Inbounds {
				if in.Type == "tun" {
					var ok bool
					tunOpts, ok = in.Options.(*O.TunInboundOptions)
					require.True(t, ok, "expected *TunInboundOptions for tun inbound")
					break
				}
			}
			require.NotNil(t, tunOpts, "expected a tun inbound")
			require.NotEmpty(t, tunOpts.Address, "expected at least the v4 TUN address")
			assert.Equal(t, "10.10.1.1/30", tunOpts.Address[0].String(), "first TUN address should be the v4 prefix")

			if v6 {
				require.Len(t, tunOpts.Address, 2, "expected v4 + v6 ULA on TUN when system has global v6")
				assert.Equal(t, "fdfe:dcba:9876::1/126", tunOpts.Address[1].String(),
					"v6 ULA should be appended after the v4 address")
			} else {
				require.Len(t, tunOpts.Address, 1, "expected v4-only TUN when system has no global v6")
			}
		})
	}
}

// setHasGlobalIPv6 fixes hasGlobalIPv6 for the test. Tests that call it must not
// run in parallel: hasGlobalIPv6 is a package variable. (Upstream cecc0f9, MSN 3.4.18.)
func setHasGlobalIPv6(t *testing.T, v6 bool) {
	orig := hasGlobalIPv6
	hasGlobalIPv6 = func() bool { return v6 }
	t.Cleanup(func() { hasGlobalIPv6 = orig })
}
}

func TestBaseRoutingRules_RejectsTunSelfDial(t *testing.T) {
	rules := baseRoutingRules()
	selfIdx, privateIdx := -1, -1
	for i, r := range rules {
		raw := r.DefaultOptions.RawDefaultRule
		if r.DefaultOptions.RuleAction.Action == C.RuleActionTypeReject &&
			slices.Contains(raw.IPCIDR, "10.10.1.0/30") {
			selfIdx = i
			assert.Equal(t, []string{inboundTag}, []string(raw.Inbound))
			assert.Contains(t, []string(raw.IPCIDR), "fdfe:dcba:9876::/126")
		}
		if raw.IPIsPrivate && privateIdx == -1 {
			privateIdx = i
		}
	}
	require.NotEqual(t, -1, selfIdx, "expected a reject rule for the TUN subnet")
	require.NotEqual(t, -1, privateIdx, "expected the private-IP direct rule")
	assert.Less(t, selfIdx, privateIdx, "TUN self-dial reject must precede the private-IP direct rule")
}

func TestKernelBelow(t *testing.T) {
	tests := []struct {
		name string
		v    string
		min  string
		want bool
	}{
		{"below major", "4.19.0", "5.10", true},
		{"below minor", "5.4.0", "5.10", true},
		{"equal", "5.10.0", "5.10", false},
		{"above minor", "5.15.0", "5.10", false},
		{"above major", "6.1.0", "5.10", false},
		{"android suffix", "4.19.0-android13", "5.10", true},
		{"android suffix above", "5.15.0-android13", "5.10", false},
		{"empty version", "", "5.10", false},
		{"empty min", "5.10.0", "", false},
		{"both empty", "", "", false},
		{"invalid version", "not-a-version", "5.10", false},
		{"only major", "5", "5.10", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, kernelBelow(tt.v, tt.min))
		})
	}
}

func dnsServer(opts O.Options, tag string) (O.DNSServerOptions, int) {
	var found O.DNSServerOptions
	count := 0
	for _, s := range opts.DNS.Servers {
		if s.Tag == tag {
			found = s
			count++
		}
	}
	return found, count
}

func TestBuildOptions_SplitTunnelResolvesWithSystemDNS(t *testing.T) {
	// Spare capacity lets an in-place append show up in the config's backing array.
	serverDNS := func(servers ...O.DNSServerOptions) *O.DNSOptions {
		return &O.DNSOptions{RawDNSOptions: O.RawDNSOptions{Servers: append(make([]O.DNSServerOptions, 0, 8), servers...)}}
	}
	remote := O.DNSServerOptions{Type: C.DNSTypeLocal, Tag: "dns_remote", Options: &O.LocalDNSServerOptions{}}
	tests := []struct {
		name string
		dns  *O.DNSOptions
	}{
		{name: "base DNS"},
		{name: "config DNS", dns: serverDNS(remote)},
		{name: "config DNS with system server", dns: serverDNS(remote, systemDNSServers()[0])},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options, _ := testBoxOptions(t)
			options.DNS = tt.dns
			var configServers int
			if tt.dns != nil {
				configServers = len(tt.dns.Servers)
			}

			opts, _, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: options})
			require.NoError(t, err)

			server, count := dnsServer(opts, systemDNSTag)
			assert.Equal(t, 1, count, "exactly one system DNS server")
			assert.Equal(t, C.DNSTypeLocal, server.Type)
			if tt.dns != nil {
				spare := tt.dns.Servers[configServers:cap(tt.dns.Servers)]
				assert.Equal(t, make([]O.DNSServerOptions, len(spare)), spare, "config DNS servers must not be modified")
			}

			tags := []string{splitTunnelTag}
			if !common.IsAndroid() {
				tags = append(tags, localNameTag)
			}
			require.Greater(t, len(opts.DNS.Rules), 2*len(tags))
			for i, tag := range tags {
				evaluate := opts.DNS.Rules[2*i].DefaultOptions.DNSRuleAction
				assert.Equal(t, C.RuleActionTypeEvaluate, evaluate.Action, "%s evaluate", tag)
				assert.Equal(t, systemDNSTag, evaluate.EvaluateOptions.Server)
				assert.Equal(t, tag, evaluate.EvaluateOptions.Tag)
				assert.Equal(t, badoption.Duration(systemDNSEvaluateTimeout), evaluate.EvaluateOptions.Timeout)
				assert.Equal(t, C.RuleActionTypeRespond, opts.DNS.Rules[2*i+1].DefaultOptions.DNSRuleAction.Action)
			}
			if !common.IsAndroid() {
				local := opts.DNS.Rules[2].DefaultOptions
				assert.Equal(t, []string{systemDNSTag}, []string(local.PreferredBy))
				assert.Empty(t, local.DomainSuffix, "local-name rule must match only names the system resolver claims")
			}
			assert.Equal(t, C.RuleActionTypePredefined, opts.DNS.Rules[2*len(tags)].DefaultOptions.DNSRuleAction.Action,
				"AAAA suppression must follow the system DNS rules")

			ruleIdx := slices.IndexFunc(opts.Route.Rules, func(r O.Rule) bool {
				return slices.Contains(r.DefaultOptions.RuleSet, splitTunnelTag)
			})
			require.NotEqual(t, -1, ruleIdx, "split-tunnel rules missing")
			require.Less(t, ruleIdx+1, len(opts.Route.Rules))
			resolve := opts.Route.Rules[ruleIdx].DefaultOptions.RuleAction
			assert.Equal(t, C.RuleActionTypeResolve, resolve.Action)
			assert.Equal(t, systemDNSTag, resolve.ResolveOptions.Server)
			assert.Equal(t, O.DomainStrategy(C.DomainStrategyPreferIPv4), resolve.ResolveOptions.Strategy)

			route := opts.Route.Rules[ruleIdx+1].DefaultOptions
			assert.Equal(t, []string{splitTunnelTag}, []string(route.RuleSet))
			assert.Equal(t, C.RuleActionTypeRoute, route.RuleAction.Action)
			assert.Equal(t, "direct", route.RuleAction.RouteOptions.Outbound)
		})
	}
}

// TestBuildOptions_StartsWithSystemDNS starts a box with the real system DNS
// server, which the local-name preferred_by match depends on.
func TestBuildOptions_StartsWithSystemDNS(t *testing.T) {
	options, _ := testBoxOptions(t)
	opts, _, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: options})
	require.NoError(t, err)
	// Without global IPv6 here, as on CI, the TUN gets no v6 address and no early
	// reject; add it anyway so sing-box validates the rule when the box starts.
	if !tunHasIPv6(opts) {
		opts.Route.Rules = withEarlyIPv6Reject(opts.Route.Rules)
	}
	require.True(t, slices.ContainsFunc(opts.Route.Rules, isEarlyIPv6Reject), "start the box with the early IPv6 reject")
	opts.Inbounds = nil
	opts.Log = &O.LogOptions{Disabled: true}
	opts.Experimental = nil

	instance, err := sbox.New(sbox.Options{Context: box.Context(context.Background()), Options: opts})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
}

// TestSplitTunnelDNSEndToEnd runs queries through a started box's DNS router,
// with the system resolver replaced by fixed answers. A split-tunnel domain
// gets its real address only when it is private; otherwise it gets a fake IP
// that maps back to the domain, so routing doesn't depend on sniffing.
func TestSplitTunnelDNSEndToEnd(t *testing.T) {
	dir := t.TempDir()
	st := newSplitTunnel(dir, rlog.NoOpLogger())
	require.NoError(t, st.AddItem(TypeDomainSuffix, "example.com"))
	require.NoError(t, st.SetEnabled(true))

	test := startSystemDNSTest(t, dir, map[string]string{
		"intranet.example.com": "192.168.9.138",
		"public.example.com":   "203.0.113.10",
		"other.org":            "198.51.100.1",
	}, nil, nil)

	assert.Equal(t, netip.MustParseAddr("192.168.9.138"), test.resolve("intranet.example.com", dns.TypeA),
		"private split-tunnel answer is returned as-is")
	for _, domain := range []string{"public.example.com", "other.org"} {
		test.assertFakeIP(domain)
	}
	assert.NotContains(t, test.system.queriedNames(), "other.org")
}

// TestLocalNameDNSEndToEnd checks that a private system answer is returned
// only for names the system resolver claims, and that no other name, however
// local it looks, is sent to it.
func TestLocalNameDNSEndToEnd(t *testing.T) {
	if common.IsAndroid() {
		t.Skip("local-name rules are disabled on Android")
	}
	private := map[string]string{
		"tv.local":                 "192.168.1.40",
		"corp-printer.example.com": "10.1.1.9",
	}
	answers := map[string]string{
		"nas6.local":               "fd00::20",
		"public-hosts.example.net": "203.0.113.9",
		"nas.lan":                  "192.168.1.20",
		"printer.home.arpa":        "192.168.1.30",
		"box.internal":             "10.0.0.5",
		"intranet.example.org":     "192.168.9.1",
		"router":                   "192.168.1.1",
	}
	maps.Copy(answers, private)
	// The local server claims hosts-file entries and .local names.
	claimed := []string{"tv.local", "corp-printer.example.com", "nas6.local", "public-hosts.example.net", "missing.local", "slow.local"}
	test := startSystemDNSTest(t, t.TempDir(), answers, claimed, []string{"slow.local"})

	for domain, addr := range private {
		assert.Equal(t, netip.MustParseAddr(addr), test.resolve(domain, dns.TypeA), domain)
	}
	assert.Equal(t, netip.MustParseAddr("fd00::20"), test.resolve("nas6.local", dns.TypeAAAA),
		"private AAAA answer must precede AAAA suppression")
	unclaimed := []string{"nas.lan", "printer.home.arpa", "box.internal", "intranet.example.org", "router"}
	for _, domain := range append([]string{"public-hosts.example.net", "missing.local", "slow.local"}, unclaimed...) {
		test.assertFakeIP(domain)
	}
	queried := test.system.queriedNames()
	require.Contains(t, queried, "tv.local")
	for _, domain := range unclaimed {
		assert.NotContains(t, queried, domain, "only claimed names may reach the system resolver")
	}
}

type systemDNSTest struct {
	t      *testing.T
	ctx    context.Context
	router adapter.DNSRouter
	fakeIP adapter.FakeIPStore
	system *recordingSystemDNS
}

// startSystemDNSTest starts a box built by buildOptions with the system
// resolver replaced by a recordingSystemDNS that returns answers, claims the
// preferred names, and never answers the stalled ones.
func startSystemDNSTest(t *testing.T, dir string, answers map[string]string, preferred, stalled []string) *systemDNSTest {
	t.Helper()
	options, _ := testBoxOptions(t)
	opts, _, err := buildOptions(BoxOptions{BasePath: dir, Options: options})
	require.NoError(t, err)

	predefined := new(badjson.TypedMap[string, badoption.Listable[netip.Addr]])
	for domain, addr := range answers {
		predefined.Put(domain, badoption.Listable[netip.Addr]{netip.MustParseAddr(addr)})
	}
	i := slices.IndexFunc(opts.DNS.Servers, func(s O.DNSServerOptions) bool { return s.Tag == systemDNSTag })
	require.NotEqual(t, -1, i)
	opts.DNS.Servers[i] = O.DNSServerOptions{
		Type:    recordingSystemDNSType,
		Tag:     systemDNSTag,
		Options: &O.HostsDNSServerOptions{Predefined: predefined},
	}
	opts.Inbounds = nil
	opts.Log = &O.LogOptions{Disabled: true}
	opts.Experimental = nil

	test := &systemDNSTest{t: t}
	registry := include.DNSTransportRegistry()
	sbdns.RegisterTransport(registry, recordingSystemDNSType, func(ctx context.Context, logger log.ContextLogger, tag string, options O.HostsDNSServerOptions) (adapter.DNSTransport, error) {
		inner, err := hosts.NewTransport(ctx, logger, tag, options)
		if err != nil {
			return nil, err
		}
		test.system = &recordingSystemDNS{DNSTransport: inner, preferred: preferred, stalled: stalled}
		return test.system, nil
	})
	ctx := service.ContextWith[O.DNSTransportOptionsRegistry](context.Background(), registry)
	ctx = service.ContextWith[adapter.DNSTransportRegistry](ctx, registry)
	ctx = box.Context(ctx)
	instance, err := sbox.New(sbox.Options{Context: ctx, Options: opts})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close() })

	test.ctx = ctx
	test.router = service.FromContext[adapter.DNSRouter](ctx)
	test.fakeIP = service.FromContext[adapter.DNSTransportManager](ctx).FakeIP().Store()
	return test
}

// resolve returns domain's single answer of qtype.
func (s *systemDNSTest) resolve(domain string, qtype uint16) netip.Addr {
	s.t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(domain), qtype)
	response, err := s.router.Exchange(adapter.WithContext(s.ctx, &adapter.InboundContext{}), query, adapter.DNSQueryOptions{})
	require.NoError(s.t, err, domain)
	require.Len(s.t, response.Answer, 1, domain)
	var ip net.IP
	switch rr := response.Answer[0].(type) {
	case *dns.A:
		ip = rr.A
	case *dns.AAAA:
		ip = rr.AAAA
	default:
		require.Failf(s.t, "unexpected answer type", "%s: %T", domain, rr)
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}

// assertFakeIP checks that domain gets a fake IP mapping back to it.
func (s *systemDNSTest) assertFakeIP(domain string) {
	s.t.Helper()
	addr := s.resolve(domain, dns.TypeA)
	require.True(s.t, s.fakeIP.Contains(addr), "%s should get a fake IP, got %s", domain, addr)
	mapped, ok := s.fakeIP.Lookup(addr)
	require.True(s.t, ok, domain)
	assert.Equal(s.t, domain, mapped, "fake IP must map back to the queried domain")
}

const recordingSystemDNSType = "recording-system"

// recordingSystemDNS stands in for the local system resolver: it claims only
// preferred names for preferred_by, records every name it is asked to resolve,
// and never answers stalled names.
type recordingSystemDNS struct {
	adapter.DNSTransport
	preferred []string
	stalled   []string

	access  sync.Mutex
	queried []string
}

func (r *recordingSystemDNS) PreferredDomain(domain string) bool {
	return slices.ContainsFunc(r.preferred, func(p string) bool { return dns.CanonicalName(p) == domain })
}

func (r *recordingSystemDNS) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	if r.record(message) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return r.DNSTransport.Exchange(ctx, message)
}

func (r *recordingSystemDNS) ExchangeAsync(ctx context.Context, message *dns.Msg, callback func(*dns.Msg, error)) {
	if r.record(message) {
		go func() {
			<-ctx.Done()
			callback(nil, ctx.Err())
		}()
		return
	}
	r.DNSTransport.ExchangeAsync(ctx, message, callback)
}

// record reports whether the queried name is stalled.
func (r *recordingSystemDNS) record(message *dns.Msg) bool {
	name := strings.TrimSuffix(message.Question[0].Name, ".")
	r.access.Lock()
	defer r.access.Unlock()
	r.queried = append(r.queried, name)
	return slices.Contains(r.stalled, name)
}

func (r *recordingSystemDNS) queriedNames() []string {
	r.access.Lock()
	defer r.access.Unlock()
	return slices.Clone(r.queried)
}

// TestBuildOptions_EarlyIPv6RejectFollowsTheTUN pins the full IPv6 clamp:
// no v6 TUN → no early reject and no ::/0 backstop; v6 TUN → the early
// 2000::/3 refuse sits just before sniffing and the ::/0 reject stays after
// split-tunnel, before the selector rules. (Upstream cecc0f9, MSN 3.4.18.)
func TestBuildOptions_EarlyIPv6RejectFollowsTheTUN(t *testing.T) {
	for _, v6 := range []bool{true, false} {
		t.Run(fmt.Sprintf("v6=%v", v6), func(t *testing.T) {
			setHasGlobalIPv6(t, v6)
			options, _ := testBoxOptions(t)
			opts, _, err := buildOptions(BoxOptions{BasePath: t.TempDir(), Options: options})
			require.NoError(t, err)
			require.Equal(t, v6, tunHasIPv6(opts))
			early := slices.IndexFunc(opts.Route.Rules, isEarlyIPv6Reject)
			late := slices.IndexFunc(opts.Route.Rules, func(r O.Rule) bool {
				o := r.DefaultOptions
				return o.RuleAction.Action == C.RuleActionTypeReject && slices.Contains(o.RawDefaultRule.IPCIDR, "::/0")
			})
			if !v6 {
				assert.Equal(t, -1, early)
				assert.Equal(t, -1, late)
				return
			}
			require.NotEqual(t, -1, late, "expected the ::/0 reject with a v6 TUN")
			split := slices.IndexFunc(opts.Route.Rules, func(r O.Rule) bool {
				return slices.Contains(r.DefaultOptions.RawDefaultRule.RuleSet, splitTunnelTag)
			})
			selector := slices.IndexFunc(opts.Route.Rules, func(r O.Rule) bool {
				mode := r.DefaultOptions.RawDefaultRule.ClashMode
				return mode == AutoSelectTag || mode == ManualSelectTag
			})
			assert.Greater(t, late, split, "the ::/0 reject must follow split-tunnel so direct-routed v6 UDP keeps flowing")
			assert.Less(t, late, selector, "the ::/0 reject must precede the selector rules")
			sniff := slices.IndexFunc(opts.Route.Rules, func(r O.Rule) bool {
				return r.DefaultOptions.RuleAction.Action == C.RuleActionTypeSniff
			})
			require.NotEqual(t, -1, early, "expected the early IPv6 reject with a v6 TUN")
			assert.Equal(t, sniff-1, early, "the early IPv6 reject must sit just before sniffing")
		})
	}
}
