package vpn

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel"

	lcommon "github.com/getlantern/common"
	box "github.com/getlantern/lantern-box"
	lbA "github.com/getlantern/lantern-box/adapter"
	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"
	C "github.com/sagernet/sing-box/constant"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/internal/hostaccess"
	"github.com/getlantern/radiance/internal/redact"
	"github.com/getlantern/radiance/log"
)

const (
	AutoSelectTag   = "auto"
	ManualSelectTag = "manual"
	// PersonalProxiesTag is the url-test group over every helper outbound
	// (lbA.IsHelperTag). The tunnel creates it with its first member and
	// removes it with its last, and the manual selector offers it while it
	// exists. It is never a managed server, so it is never listed.
	PersonalProxiesTag = redact.PersonalProxiesTag

	urlTestInterval    = 3 * time.Minute
	urlTestIdleTimeout = 15 * time.Minute

	cacheID              = "lantern"
	cacheFileName        = "lantern.cache"
	cacheClearMarkerName = "lantern.cache.clear"
)

// personalProxiesProbeURL and personalProxiesProbeInterval configure the
// personal proxies group's URL tests. Variables so tests can probe a local
// server, often.
var (
	personalProxiesProbeURL      = "https://google.com/generate_204"
	personalProxiesProbeInterval = urlTestInterval
)

var reservedTags = []string{AutoSelectTag, ManualSelectTag, PersonalProxiesTag, PersonalProxyTag, "direct", "block", ProxylessHedgeTag}

func ReservedTags() []string {
	return slices.Clone(reservedTags)
}

type BoxOptions struct {
	BasePath string `json:"base_path,omitempty"`
	// Options contains the main options that are merged into the base options with the exception of
	// DNS, which replaces the base DNS options; only the AAAA-suppression rule and the system DNS
	// server and its rules are still added. Options should contain all servers (both lantern and user).
	Options O.Options `json:"options"`
	// SmartRouting contains smart routing rules to merge into the final options.
	SmartRouting lcommon.SmartRoutingRules `json:"smart_routing,omitempty"`
	// AdBlock contains ad block rules to merge into the final options.
	AdBlock lcommon.AdBlockRules `json:"ad_block,omitempty"`
	// Proxyless, when set, routes auto mode through a hedge that tries the
	// server's proxyless outbound before the auto group. Only smart routing
	// sets it: full tunnel sends everything through the proxy.
	Proxyless *ProxylessOptions `json:"proxyless,omitempty"`
	// NonSelectableOutbounds lists server-declared tags (outbound or endpoint) that
	// are infrastructure (e.g. the proxyless rule-set detour): merged into the box
	// config so references resolve, but excluded from the selectable proxy groups.
	NonSelectableOutbounds []string `json:"non_selectable_outbounds,omitempty"`
	// InitialServer chooses the outbound selected when the tunnel starts.
	// Empty or AutoSelectTag puts the tunnel in auto mode; any other tag
	// must match an outbound or endpoint, or be a PersonalProxySelection, and
	// forces manual selection. A friend with no member at the start selects
	// PersonalProxiesTag instead, or auto mode without helpers.
	InitialServer string `json:"initial_server,omitempty"`
	// BanditURLOverrides maps outbound tags to per-proxy callback URLs for
	// the bandit Thompson sampling system. When set, these override the
	// default probe URL for each specific outbound, allowing the server to
	// detect which proxies successfully connected.
	BanditURLOverrides map[string]string `json:"bandit_url_overrides,omitempty"`
	// AutoSelectOptions are server-sent settings for the auto-select group,
	// from DecodeAutoSelectOptions. Nil keeps lantern-box's defaults.
	AutoSelectOptions *lbO.MutableAutoSelectOutboundOptions `json:"auto_select_options,omitempty"`
	// SelectionHistorySeed seeds the tunnel's AutoSelectHistoryStorage
	// at startup with the latest persisted snapshot per tag.
	SelectionHistorySeed map[string]lbA.TagHistory `json:"tag_history"`
	// LanternServerTags lists the outbound/endpoint tags in Options that are
	// Lantern servers. Only Lantern servers receive injected client info, so
	// these seed the tunnel's client-info Injector at construction; otherwise
	// outbounds baked into the initial config get no data-usage attribution.
	// The Injector covers outbounds only, so endpoint tags have no effect.
	LanternServerTags []string `json:"lantern_server_tags,omitempty"`

	// personalProxyRooms reports whether a rooms consumer may reach the
	// friend InitialServer selects; the VPN client sets it.
	personalProxyRooms bool
	// reversePortal reports whether the tunnel starts with the reverse
	// portal inbound, created for reverseMasquerade; the VPN client sets
	// both.
	reversePortal     bool
	reverseMasquerade string
}

// baseOpts returns the minimum sing-box options required for the tunnel to
// function. Do not modify without understanding the downstream effects.
func baseOpts(basePath string) O.Options {
	cacheFile := cacheFilePath(basePath)
	inbounds := baseInbounds()

	opts := O.Options{
		Log: &O.LogOptions{
			Level:        "debug",
			Output:       "lantern.log",
			Timestamp:    true,
			DisableColor: true,
		},
		DNS: &O.DNSOptions{
			RawDNSOptions: O.RawDNSOptions{
				Servers: buildDNSServers(),
				Rules:   buildDNSRules(),
				// Fallback DNS when no rules match.
				Final: "dns_local",
			},
		},
		Inbounds: inbounds,
		Outbounds: []O.Outbound{
			{
				Type:    C.TypeDirect,
				Tag:     "direct",
				Options: &O.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeBlock,
				Tag:     "block",
				Options: &O.StubOptions{},
			},
		},
		Route: &O.RouteOptions{
			AutoDetectInterface: true,
			Rules:               baseRoutingRules(),
			RuleSet:             splitTunnelRuleSet(basePath),
			DefaultDomainResolver: &O.DomainResolveOptions{
				Server: "dns_local",
			},
		},
		Experimental: &O.ExperimentalOptions{
			CacheFile: &O.CacheFileOptions{
				Enabled:     true,
				Path:        cacheFile,
				CacheID:     cacheID,
				StoreFakeIP: true,
				StoreRDRC:   true,
			},
		},
	}

	// OverrideAndroidVPN is meaningless without a TUN inbound, so gate on its
	// presence — the novpn build has none.
	if common.Platform == "android" && hasTunInbound(inbounds) {
		opts.Route.OverrideAndroidVPN = true
	}
	if common.IsIOS() {
		opts.Route.Rules = append([]O.Rule{highMemoryRejectRule()}, opts.Route.Rules...)
	}
	return opts
}

func hasTunInbound(inbounds []O.Inbound) bool {
	for _, in := range inbounds {
		if in.Type == "tun" {
			return true
		}
	}
	return false
}

func baseRoutingRules() []O.Rule {
	// routing rules are evaluated in the order they are defined and the first matching rule
	// is applied. So order is important here.
	// The rules MUST be in this order to ensure proper functionality:
	// 0. 	(iOS-only) admission gate for rejecting new connections during high memory usage.
	// 		Only enabled long enough to allow memory to be returned to the OS. Prepended as the
	// 		first rule to minimize any additional memory allocation while it's being reclaimed.
	// 0b.   Reject TCP from the TUN to public IPv6, before sniffing, when the TUN has a
	//       v6 address (earlyRejectIPv6Rule, added in buildOptions).
	// 1.    Enable traffic sniffing
	// 2.    Hijack DNS to allow sing-box to handle DNS requests
	// 3.    Route bypass proxy traffic directly (for kindling connections)
	// 4.    Route private IPs to direct outbound
	// 5.    Split tunnel rule (user-configurable)
	// 6.    Smart-routing, ad-block, and config-file rules (added in buildOptions).
	// 7.    Reject any other IPv6 (::/0) when the TUN has a v6 address: UDP, TCP to port 53,
	//       TCP from other inbounds, and v6 outside 2000::/3 (rejectIPv6Rule, added in
	//       buildOptions).
	// 8,9.  Group rules for auto and manual selector modes (added in buildOptions).
	// 10.   Catch-all blocking rule (added in buildOptions). This ensures that any traffic not covered
	//       by previous rules does not automatically bypass the VPN.
	//
	// * DO NOT change the order of these rules unless you know what you're doing. Changing these
	//   rules or their order can break certain functionalities like DNS resolution, smart connect,
	//   or split tunneling.
	//
	// The default rule type uses the following matching logic:
	// (domain || domain_suffix || domain_keyword || domain_regex || geosite || geoip || ip_cidr || ip_is_private) &&
	// (port || port_range) &&
	// (source_geoip || source_ip_cidr || source_ip_is_private) &&
	// (source_port || source_port_range) &&
	// other fields
	//
	// rule-sets are merged into the appropriate fields before evaluation instead of being evaluated separately.
	rules := []O.Rule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: O.DefaultRule{
				RawDefaultRule: O.RawDefaultRule{
					// skip sniffing the bypass inbound for vpn builds, it forces an early
					// read and reply, breaking IPv6 fallback.
					Inbound: []string{inboundTag},
				},
				RuleAction: O.RuleAction{
					Action: C.RuleActionTypeSniff,
				},
			},
		},
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: O.DefaultRule{
				RawDefaultRule: O.RawDefaultRule{
					Protocol: []string{"dns"},
				},
				RuleAction: O.RuleAction{
					Action: C.RuleActionTypeHijackDNS,
				},
			},
		},
	}
	rules = append(rules, bypassRoutingRules()...)
	rules = append(rules, tunSelfRoutingRules()...)
	rules = append(rules, O.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: O.DefaultRule{
			RawDefaultRule: O.RawDefaultRule{
				IPIsPrivate: true,
			},
			RuleAction: O.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: O.RouteActionOptions{
					Outbound: "direct",
				},
			},
		},
	})
	rules = append(rules, splitTunnelRoutingRules()...)
	return rules
}

func cacheFilePath(basePath string) string {
	return filepath.Join(basePath, cacheFileName)
}

func cacheClearMarkerPath(basePath string) string {
	return filepath.Join(basePath, cacheClearMarkerName)
}

// detourRuleSetsThroughTunnel reroutes remote rule-set downloads through the
// tunnel's auto-select group. MSN 3.4.9 (vendored divergence): upstream
// downloads them via "direct", whose host must be resolved with the direct
// DoH resolvers — dead on the field line (DPI), so ga-ir never loaded and
// retried every 10s (field logs 3.4.7/3.4.8: "fetch rule-set ga-ir ...
// i/o timeout"). Through a proxy outbound the domain is passed to the remote
// server, so no local DNS is needed and the rule-set loads once the tunnel
// is up; sing-box retries the download otherwise.
func detourRuleSetsThroughTunnel(rulesets []O.RuleSet) {
	for i := range rulesets {
		if rulesets[i].Type != C.RuleSetTypeRemote {
			continue
		}
		if d := rulesets[i].RemoteOptions.DownloadDetour; d != "" && d != "direct" {
			continue
		}
		rulesets[i].RemoteOptions.DownloadDetour = AutoSelectTag
	}
}

// removeCacheFile deletes the tunnel cache if it exists.
func removeCacheFile(basePath string) error {
	err := os.Remove(cacheFilePath(basePath))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing cache file: %w", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		slog.Info("removed cache file", "path", cacheFilePath(basePath))
	}
	return nil
}

// writeCacheClearMarker records that cache removal must be retried on the next
// tunnel start.
func writeCacheClearMarker(basePath string) error {
	slog.Debug("writing cache clear marker", "path", cacheClearMarkerPath(basePath))
	if err := atomicfile.WriteFile(cacheClearMarkerPath(basePath), nil, fileperm.File); err != nil {
		return fmt.Errorf("writing cache clear marker: %w", err)
	}
	return nil
}

// consumeCacheClearMarker applies a deferred cache clear during tunnel start
// and removes the marker after a successful cache deletion.
func consumeCacheClearMarker(basePath string) error {
	marker := cacheClearMarkerPath(basePath)
	if _, err := os.Stat(marker); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	if err := removeCacheFile(basePath); err != nil {
		return err
	}
	os.Remove(marker) // we can safely ignore errors here
	return nil
}

// tunHasIPv6 reports whether a TUN inbound was given an IPv6 address, meaning v6
// is captured into the tunnel and must be rejected rather than left to bypass.
func tunHasIPv6(opts O.Options) bool {
	for _, in := range opts.Inbounds {
		t, ok := in.Options.(*O.TunInboundOptions)
		if !ok {
			continue
		}
		for _, addr := range t.Address {
			if addr.Addr().Is6() {
				return true
			}
		}
	}
	return false
}

// buildOptions builds the box options using the config options and user servers,
// and returns the clash mode the tunnel must start in.
// Denied outbounds, endpoints and services are dropped; denied DNS or route
// options fail the build with an error wrapping [hostaccess.ErrDenied].
func buildOptions(bOptions BoxOptions) (O.Options, string, error) {
	_, span := otel.Tracer(tracerName).Start(context.Background(), "buildOptions")
	defer span.End()

	bOptions.Options.Outbounds = allowedOutbounds(bOptions.Options.Outbounds)
	bOptions.Options.Endpoints = allowedEndpoints(bOptions.Options.Endpoints)
	bOptions.Options.Services = allowedServices(bOptions.Options.Services)
	// MSN 3.4.11 SR-REJECT: pin the Iran pool at boot too. getBoxOptions
	// merges the server's config draw with the manager's retained servers,
	// so without this pin a geo-detection miss (a worldwide draw, which on
	// the 3.4.10 field network was EVERY draw) would start the tunnel with
	// six dead worldwide members while the manager holds the ir-free pool.
	// The tunnel filter (allowedServers) covers live updates only; this is
	// the same selection applied to the box's own members at build time.
	// Non-Lantern (user-added) outbounds have no pool and always survive:
	// they arrive from the manager's servers, not the config draw.
	if irPoolSelected() {
		bOptions.Options.Outbounds = slices.DeleteFunc(bOptions.Options.Outbounds, func(o O.Outbound) bool {
			return isLanternOutboundIn(bOptions, o.Tag) && !strings.Contains(o.Tag, "-ir-free-")
		})
		bOptions.Options.Endpoints = slices.DeleteFunc(bOptions.Options.Endpoints, func(e O.Endpoint) bool {
			return isLanternOutboundIn(bOptions, e.Tag) && !strings.Contains(e.Tag, "-ir-free-")
		})
	}
	if err := hostaccess.CheckOptions(bOptions.Options); err != nil {
		return O.Options{}, "", err
	}
	if len(bOptions.Options.Outbounds) == 0 && len(bOptions.Options.Endpoints) == 0 {
		return O.Options{}, "", errors.New("no outbounds or endpoints found in config or user servers")
	}

	slog.Log(nil, log.LevelTrace, "Starting buildOptions", "path", bOptions.BasePath)

	opts := baseOpts(bOptions.BasePath)
	slog.Debug("Base options initialized")

	// add smart routing and ad block rules
	smartRoutingRules := normalizeSmartRoutingRules(bOptions.SmartRouting)
	if len(smartRoutingRules) > 0 {
		slog.Info("Adding smart-routing rules")
		outbounds, rules, rulesets := smartRoutingRules.ToOptions(urlTestInterval, urlTestIdleTimeout)
		opts.Outbounds = append(opts.Outbounds, outbounds...)
		opts.Route.Rules = append(opts.Route.Rules, rules...)
		opts.Route.RuleSet = append(opts.Route.RuleSet, rulesets...)
	} else if len(bOptions.SmartRouting) > 0 && len(smartRoutingRules) == 0 {
		slog.Warn("No valid smart-routing rules found after normalization, skipping smart-routing configuration")
	}
	adBlockRules := normalizeAdBlockRules(bOptions.AdBlock)
	if len(adBlockRules) > 0 {
		slog.Info("Adding ad-block rules")
		rule, rulesets := bOptions.AdBlock.ToOptions()
		opts.Route.Rules = append(opts.Route.Rules, rule)
		opts.Route.RuleSet = append(opts.Route.RuleSet, rulesets...)
	} else if len(bOptions.AdBlock) > 0 && len(adBlockRules) == 0 {
		slog.Warn("No valid ad-block rules found after normalization, skipping ad-block configuration")
	}

	tags := mergeAndCollectTags(&opts, &bOptions.Options, bOptions.NonSelectableOutbounds)
	// The proxyless outbound gets its UDP default whether or not the hedge
	// is built, matching how a config update replaces it, so a full-tunnel
	// update doesn't rebuild it for nothing.
	for i := range opts.Outbounds {
		opts.Outbounds[i] = WithProxylessUDP(opts.Outbounds[i])
	}
	// After the merge, so the hedge is never among the selectable tags.
	hedged := bOptions.Proxyless != nil && addProxylessHedge(&opts, bOptions.Proxyless)
	if hedged {
		slog.Info("Adding proxyless hedge", "enabled", bOptions.Proxyless.Enabled)
	}
	opts.DNS.Servers = appendMissingDNSServers(opts.DNS.Servers, systemDNSServers())
	// Private system-resolver answers must be returned before AAAA suppression drops them.
	opts.DNS.Rules = slices.Concat(splitTunnelDNSRules(), localNameDNSRules(), opts.DNS.Rules)
	if bOptions.reversePortal {
		opts.Inbounds = append(opts.Inbounds, reversePortalInbound(bOptions.reverseMasquerade))
	}
	helpers := helperTags(tags)
	// The manual selector also offers the personal proxies group, which
	// exists only while a helper outbound does: a url-test group must never
	// start empty.
	selectable := tags
	if len(helpers) > 0 {
		selectable = append(slices.Clone(tags), PersonalProxiesTag)
	}

	initial := bOptions.InitialServer
	var friendMembers []string
	if friend, ok := ParsePersonalProxySelection(initial); ok {
		friendMembers = personalProxyStartMembers(friend, helpers, bOptions.Options.Outbounds, bOptions.personalProxyRooms)
		switch {
		case len(friendMembers) > 0:
			selectable = append(slices.Clone(selectable), PersonalProxyTag)
			initial = PersonalProxyTag
		case len(helpers) > 0:
			initial = PersonalProxiesTag
		default:
			initial = AutoSelectTag
		}
	}
	// The last helper can go, a reverse one asynchronously, between the
	// caller picking the group and these options being built. The tunnel
	// then starts on auto-select, as with no member at all.
	if initial == PersonalProxiesTag && len(helpers) == 0 {
		initial = AutoSelectTag
	}
	// A user server saved under proxyless-hedge, before that tag was
	// reserved, isn't selectable any more, so a saved selection of it
	// starts on auto-select rather than failing to connect.
	if initial == ProxylessHedgeTag {
		initial = AutoSelectTag
	}
	mode := modeForServer(initial)
	if mode == ManualSelectTag {
		// The manual selector defaults to its first tag, so place initial at index 0.
		i := slices.Index(selectable, initial)
		if i == -1 {
			return O.Options{}, "", fmt.Errorf("initial server tag %q not found in outbounds or endpoints", initial)
		}
		selectable[0], selectable[i] = selectable[i], selectable[0]
	}

	if tunHasIPv6(opts) {
		// MSN 3.4.18 (upstream cecc0f9): the late ::/0 reject reached TCP
		// clients as a failed TLS handshake mid-connection instead of a
		// refused one, so they never retried over IPv4. Refuse public v6
		// BEFORE the sniff rule with a reset to the SYN (earlyRejectIPv6Rule)
		// and keep the late ::/0 reject as the backstop for everything else.
		opts.Route.Rules = withEarlyIPv6Reject(opts.Route.Rules)
		opts.Route.Rules = append(opts.Route.Rules, rejectIPv6Rule())
	}

	// add mode selector outbounds and rules
	opts.Outbounds = append(opts.Outbounds, urlTestOutbound(AutoSelectTag, tags, bOptions.BanditURLOverrides, bOptions.AutoSelectOptions))
	if len(helpers) > 0 {
		opts.Outbounds = append(opts.Outbounds, personalProxiesOutbound(helpers))
	}
	if len(friendMembers) > 0 {
		opts.Outbounds = append(opts.Outbounds, personalProxyOutbound(friendMembers))
	}
	opts.Outbounds = append(opts.Outbounds, selectorOutbound(ManualSelectTag, selectable))
	// Manual mode never goes proxyless: picking a location asks for that
	// exit.
	opts.Route.Rules = append(opts.Route.Rules, autoModeRules(hedged)...)
	opts.Route.Rules = append(opts.Route.Rules, selectModeRule(ManualSelectTag))

	// catch-all rule to ensure no fallthrough
	opts.Route.Rules = append(opts.Route.Rules, catchAllBlockerRule())

	// MSN 3.4.10: reroute EVERY remote rule-set download through the tunnel,
	// once, over the fully assembled rule-set list — rule-sets reach this
	// point from three sources (the server's own options, smart routing,
	// ad block) and 3.4.9 only patched the latter two, so the server's
	// ga-ir entry kept dialing direct and timing out every 10s (field log
	// 3.4.9: the errors ran the whole session).
	detourRuleSetsThroughTunnel(opts.Route.RuleSet)

	slog.Debug("Finished building options", "env", common.Env())

	opts, err := jsonRoundTrip(bOptions.BasePath, opts)
	if err != nil {
		return opts, "", fmt.Errorf("validating options: %w", err)
	}

	return opts, mode, nil
}

// jsonRoundTrip marshals and unmarshals the options to let sing-box set defaults and validate it.
func jsonRoundTrip(path string, opts O.Options) (O.Options, error) {
	ctx := box.Context(context.Background())
	buf, err := json.MarshalContext(ctx, opts)
	if err != nil {
		return opts, fmt.Errorf("marshal options: %w", err)
	}
	err = atomicfile.WriteFile(filepath.Join(path, internal.DebugBoxOptionsFileName), buf, fileperm.File)
	if err != nil {
		slog.Warn("failed to write debug options", "error", err)
	}
	return json.UnmarshalExtendedContext[O.Options](ctx, buf)
}

//////////////////////
// Helper functions //
//////////////////////

// mergeAndCollectTags merges src into dst and returns the selectable outbound and
// endpoint tags from src. The returned tags become the members of both the auto
// (URLTest) group and the manual selector, so [reservedTags] and nonSelectable
// tags are omitted; they're still merged so references resolve.
func mergeAndCollectTags(dst, src *O.Options, nonSelectable []string) []string {
	dst.Outbounds = append(dst.Outbounds, src.Outbounds...)
	dst.Endpoints = append(dst.Endpoints, src.Endpoints...)
	dst.Services = append(dst.Services, src.Services...)

	if src.Route != nil {
		dst.Route.Rules = append(dst.Route.Rules, src.Route.Rules...)
		dst.Route.RuleSet = append(dst.Route.RuleSet, src.Route.RuleSet...)
		dst.Route.DefaultDomainResolver = src.Route.DefaultDomainResolver
	}
	// overwrite base DNS options with config from src (server)
	if src.DNS != nil {
		dns := *src.DNS
		// prepend the AAAA suppression rule to ensure it fails over quickly.
		dns.Rules = append([]O.DNSRule{suppressAAAARule()}, dns.Rules...)
		dst.DNS = &dns
	}

	skip := func(tag string) bool {
		return slices.Contains(reservedTags, tag) || slices.Contains(nonSelectable, tag)
	}
	var tags []string
	for _, out := range src.Outbounds {
		if !skip(out.Tag) {
			tags = append(tags, out.Tag)
		}
	}
	for _, ep := range src.Endpoints {
		if !skip(ep.Tag) {
			tags = append(tags, ep.Tag)
		}
	}
	return tags
}

// isLanternOutboundIn reports whether tag names a Lantern server among the
// options' members: one of bOptions.LanternServerTags, which getBoxOptions
// seeds from the config draw and the managed servers. User-added and helper
// outbounds never carry IsLantern, so a false keeps them out of the Iran
// pool pin in buildOptions; the tag markers ('-ir-free-') then never apply
// to them at all.
func isLanternOutboundIn(bOptions BoxOptions, tag string) bool {
	return slices.Contains(bOptions.LanternServerTags, tag)
}

// appendMissingDNSServers adds each extra server whose tag is absent, without
// writing to servers' backing array.
func appendMissingDNSServers(servers, extra []O.DNSServerOptions) []O.DNSServerOptions {
	servers = slices.Clip(servers)
	for _, server := range extra {
		if !slices.ContainsFunc(servers, func(s O.DNSServerOptions) bool { return s.Tag == server.Tag }) {
			servers = append(servers, server)
		}
	}
	return servers
}

func normalizeSmartRoutingRules(rules lcommon.SmartRoutingRules) lcommon.SmartRoutingRules {
	normalized := make(lcommon.SmartRoutingRules, 0, len(rules))
	for _, sr := range rules {
		cleaned := make([]string, 0, len(sr.Outbounds))
		for _, outbound := range sr.Outbounds {
			tag := strings.TrimSpace(outbound)
			if tag == "" {
				continue
			}
			cleaned = append(cleaned, tag)
		}

		sr.Outbounds = cleaned
		if len(sr.Outbounds) == 0 {
			slog.Warn("Skipping smart-routing rule with no outbounds", "category", sr.Category)
			continue
		}

		normalized = append(normalized, sr)
	}
	return normalized
}

func normalizeAdBlockRules(rules lcommon.AdBlockRules) lcommon.AdBlockRules {
	normalized := make(lcommon.AdBlockRules, 0, len(rules))
	for _, rule := range rules {
		tag := strings.TrimSpace(rule.Tag)
		if tag == "" {
			slog.Warn("Skipping ad-block rule with empty tag")
			continue
		}
		rule.Tag = tag
		normalized = append(normalized, rule)
	}
	return normalized
}

// DecodeAutoSelectOptions decodes the config response's auto_select_options.
// It never fails: an absent field gives empty options, and so does one that
// doesn't decode, so a bad server value costs the overrides, not the config.
// A switch_tolerance_percent over 100, which lantern-box refuses to build a
// group with, is dropped.
func DecodeAutoSelectOptions(raw []byte) *lbO.MutableAutoSelectOutboundOptions {
	opts := &lbO.MutableAutoSelectOutboundOptions{}
	if len(raw) == 0 {
		return opts
	}
	if err := json.Unmarshal(raw, opts); err != nil {
		slog.Warn("Ignoring auto-select options that don't decode", "error", err)
		return &lbO.MutableAutoSelectOutboundOptions{}
	}
	if p := opts.SwitchTolerancePercent; p != nil && *p > 100 {
		slog.Warn("Ignoring switch_tolerance_percent over 100", "value", *p)
		opts.SwitchTolerancePercent = nil
	}
	return opts
}

// urlTestOutbound builds an auto-select group over outbounds. base supplies
// server-sent settings; the members, probe URLs and URL overrides are always
// radiance's.
func urlTestOutbound(tag string, outbounds []string, urlOverrides map[string]string, base *lbO.MutableAutoSelectOutboundOptions) O.Outbound {
	var opts lbO.MutableAutoSelectOutboundOptions
	if base != nil {
		opts = *base
	}
	opts.Outbounds = outbounds
	opts.URL = "https://google.com/generate_204"
	opts.URLOverrides = urlOverrides
	if opts.BackgroundIntervalSeconds == 0 {
		opts.BackgroundIntervalSeconds = uint32(urlTestInterval / time.Second)
	}
	return O.Outbound{
		Type:    lbC.TypeMutableAutoSelect,
		Tag:     tag,
		Options: &opts,
	}
}

func selectorOutbound(tag string, outbounds []string) O.Outbound {
	return O.Outbound{
		Type: lbC.TypeMutableSelector,
		Tag:  tag,
		Options: &lbO.MutableSelectorOutboundOptions{
			Outbounds: outbounds,
		},
	}
}

func modeForServer(server string) string {
	if server == "" || server == AutoSelectTag {
		return AutoSelectTag
	}
	return ManualSelectTag
}

// helperTags returns the tags in tags that are helper outbounds, reverse
// ones included.
func helperTags(tags []string) []string {
	var out []string
	for _, tag := range tags {
		if lbA.IsHelperTag(tag) || lbA.IsReverseHelperTag(tag) {
			out = append(out, tag)
		}
	}
	return out
}

// personalProxiesOutbound is the url-test group over helpers, which must not
// be empty (see PersonalProxiesTag).
func personalProxiesOutbound(helpers []string) O.Outbound {
	return O.Outbound{
		Type: lbC.TypeMutableURLTest,
		Tag:  PersonalProxiesTag,
		Options: &lbO.MutableURLTestOutboundOptions{
			Outbounds:   helpers,
			URL:         personalProxiesProbeURL,
			Interval:    badoption.Duration(personalProxiesProbeInterval),
			IdleTimeout: badoption.Duration(urlTestIdleTimeout),
		},
	}
}

func selectModeRule(mode string) O.Rule {
	return modeRule(mode, mode)
}

// modeRule routes the traffic of clash mode mode to outbound.
func modeRule(mode, outbound string) O.Rule {
	return O.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: O.DefaultRule{
			RawDefaultRule: O.RawDefaultRule{
				ClashMode: mode,
			},
			RuleAction: O.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: O.RouteActionOptions{
					Outbound: outbound,
				},
			},
		},
	}
}

func rejectRule(rule O.RawDefaultRule) O.Rule {
	return O.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: O.DefaultRule{
			RawDefaultRule: rule,
			RuleAction: O.RuleAction{
				Action: C.RuleActionTypeReject,
				RejectOptions: O.RejectActionOptions{
					Method: C.RuleActionRejectMethodDefault,
				},
			},
		},
	}
}

func catchAllBlockerRule() O.Rule {
	return rejectRule(O.RawDefaultRule{})
}

func highMemoryRejectRule() O.Rule {
	return rejectRule(O.RawDefaultRule{ClashMode: rejectMode})
}

// rejectIPv6Rule rejects all IPv6 with unreachable or a reset, never a silent
// drop, after the direct rules.
func rejectIPv6Rule() O.Rule {
	rule := rejectRule(O.RawDefaultRule{IPCIDR: []string{"::/0"}})
	rule.DefaultOptions.RuleAction.RejectOptions.NoDrop = true
	return rule
}

// earlyRejectIPv6Rule refuses TCP from the TUN to public IPv6 other than DNS.
// Placed before sniffing, it applies before sing-box accepts the connection, so
// clients retry over IPv4. It also precedes the direct rules: a site reachable
// only over public IPv6 can't go direct. (Upstream Radiance cecc0f9, MSN 3.4.18.)
func earlyRejectIPv6Rule() O.Rule {
	return O.Rule{
		Type: C.RuleTypeLogical,
		LogicalOptions: O.LogicalRule{
			RawLogicalRule: O.RawLogicalRule{
				Mode: C.LogicalTypeAnd,
				Rules: []O.Rule{
					{Type: C.RuleTypeDefault, DefaultOptions: O.DefaultRule{RawDefaultRule: O.RawDefaultRule{
						Inbound: []string{inboundTag},
						Network: []string{N.NetworkTCP},
						IPCIDR:  []string{"2000::/3"},
					}}},
					{Type: C.RuleTypeDefault, DefaultOptions: O.DefaultRule{RawDefaultRule: O.RawDefaultRule{
						Port:   []uint16{53},
						Invert: true,
					}}},
				},
			},
			RuleAction: O.RuleAction{
				Action: C.RuleActionTypeReject,
				RejectOptions: O.RejectActionOptions{
					Method: C.RuleActionRejectMethodDefault,
					NoDrop: true,
				},
			},
		},
	}
}

// withEarlyIPv6Reject inserts earlyRejectIPv6Rule just before the TUN's sniff
// rule. Without one, it returns rules unchanged, leaving rejectIPv6Rule.
func withEarlyIPv6Reject(rules []O.Rule) []O.Rule {
	i := slices.IndexFunc(rules, func(r O.Rule) bool {
		o := r.DefaultOptions
		return r.Type == C.RuleTypeDefault && o.RuleAction.Action == C.RuleActionTypeSniff &&
			slices.Contains(o.RawDefaultRule.Inbound, inboundTag)
	})
	if i < 0 {
		return rules
	}
	return slices.Insert(slices.Clone(rules), i, earlyRejectIPv6Rule())
}

func newDNSServerOptions(typ, tag, server, domainResolver string) O.DNSServerOptions {
	var serverOpts any
	remoteOpts := O.RemoteDNSServerOptions{
		DNSServerAddressOptions: O.DNSServerAddressOptions{
			Server: server,
		},
	}
	if domainResolver != "" {
		remoteOpts.RawLocalDNSServerOptions = O.RawLocalDNSServerOptions{
			DialerOptions: O.DialerOptions{
				AbstractDialerOptions: O.AbstractDialerOptions{
					DomainResolver: &O.DomainResolveOptions{
						Server: domainResolver,
					},
				},
			},
		}
	}
	switch typ {
	case C.DNSTypeTCP, C.DNSTypeUDP:
		serverOpts = remoteOpts
	case C.DNSTypeTLS:
		serverOpts = &O.RemoteTLSDNSServerOptions{
			RemoteDNSServerOptions: remoteOpts,
		}
	case C.DNSTypeHTTPS:
		serverOpts = &O.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: O.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: remoteOpts,
			},
		}
	default:
		serverOpts = &O.LocalDNSServerOptions{}
	}

	return O.DNSServerOptions{
		Tag:     tag,
		Type:    typ,
		Options: serverOpts,
	}
}
