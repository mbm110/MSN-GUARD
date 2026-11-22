//go:build !novpn

package vpn

import (
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/getlantern/radiance/bypass"
	"github.com/getlantern/radiance/common"
)

const (
	// minAndroidSystemStackKernel is the minimum Linux kernel version (major.minor)
	// required for the system TUN stack to work reliably on Android only. Devices
	// running a kernel below this version fall back to gvisor. This constant has no
	// effect on other platforms.
	minAndroidSystemStackKernel = "5.10"

	inboundTag = "tun-in"

	tunnelProxyInboundTag = "tunnel-in"

	systemDNSTag = "dns_system"

	localNameTag = "local-names"

	// systemDNSEvaluateTimeout is shorter than sing-box's 10s DNS default because
	// every matching A/AAAA query waits on it. On timeout the query falls through
	// to the remaining DNS rules: a split-tunnel connection still resolves
	// through the system resolver when it dials, but a local name loses its
	// direct route. On Windows and Linux, a .local name not in the hosts file
	// goes over mDNS, which returns its answers only once the full timeout
	// elapses.
	systemDNSEvaluateTimeout = 2 * time.Second
)

var (
	tunPrefix4 = netip.MustParsePrefix("10.10.1.1/30")
	tunPrefix6 = netip.MustParsePrefix("fdfe:dcba:9876::1/126")
)

// baseInbounds returns the tunnel-build inbounds: the TUN device (per-platform
// stack/routing applied here) plus the loopback bypass proxy that carries
// kindling's bootstrap traffic outside the tunnel.
func baseInbounds() []O.Inbound {
	loopbackAddr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))

	// ULA-only interfaces don't indicate real public v6, so gate the TUN v6 address
	// on genuine global v6 connectivity.
	tunAddress := []netip.Prefix{tunPrefix4}
	if common.HasGlobalIPv6() {
		tunAddress = append(tunAddress, tunPrefix6)
		slog.Info("vpn: TUN with IPv6 ULA (system has global v6)")
	} else {
		slog.Info("vpn: TUN IPv4-only (no global v6 detected)")
	}

	tunOpts := &O.TunInboundOptions{
		Address:     tunAddress,
		AutoRoute:   true,
		StrictRoute: true,
		Stack:       "system",
	}
	switch common.Platform {
	case "android":
		// MSN fork delta (upstream 0c920c73b969): ALWAYS gvisor on Android.
		// The upstream kernel check picks the "system" stack on kernels
		// >= 5.10, but that stack terminates TCP through a local listener in
		// the ENGINE PROCESS. In MSN the engine runs as a sidecar fed by an
		// SCM_RIGHTS dup of the app's TUN fd: with the system stack, UDP
		// from apps flows through the fd both ways, while app TCP never
		// reaches the router (field-verified 3.4.5-3.4.7: zero tun-inbound
		// TCP connections while UDP and DNS answers flow). gvisor is pure
		// userspace on the same fd — the path UDP already proves — and is
		// what upstream itself uses on the < 5.10 Android majority.
		tunOpts.Stack = "gvisor"
		tunOpts.EndpointIndependentNat = true
		slog.Info("vpn: gvisor TUN stack (MSN sidecar fork; system stack TCP does not cross the fd handoff)")
	case "ios":
		tunOpts.Stack = ""
		tunOpts.EndpointIndependentNat = true
	case "linux":
		tunOpts.AutoRedirect = true
	}

	return []O.Inbound{
		{
			Type:    "tun",
			Tag:     inboundTag,
			Options: tunOpts,
		},
		{
			Type: C.TypeMixed,
			Tag:  bypass.BypassInboundTag,
			Options: &O.HTTPMixedInboundOptions{
				ListenOptions: O.ListenOptions{
					Listen:     &loopbackAddr,
					ListenPort: bypass.ProxyPort,
				},
			},
		},
		{
			Type: C.TypeMixed,
			Tag:  tunnelProxyInboundTag,
			Options: &O.HTTPMixedInboundOptions{
				ListenOptions: O.ListenOptions{
					Listen:     &loopbackAddr,
					ListenPort: netip.MustParseAddrPort(common.TunnelProxyAddr).Port(),
				},
			},
		},
	}
}

// bypassRoutingRules routes kindling's bypass-proxy traffic directly, keeping it
// out of the tunnel it bootstraps.
func bypassRoutingRules() []O.Rule {
	return []O.Rule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: O.DefaultRule{
				RawDefaultRule: O.RawDefaultRule{
					Inbound: []string{bypass.BypassInboundTag},
				},
				RuleAction: O.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: O.RouteActionOptions{
						Outbound: "direct",
					},
				},
			},
		},
	}
}

// tunSelfRoutingRules rejects tunnel flows addressed to the TUN's own subnet.
// The private-IP direct rule would otherwise dial them straight back into the
// TUN, looping until disconnect.
func tunSelfRoutingRules() []O.Rule {
	return []O.Rule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: O.DefaultRule{
				RawDefaultRule: O.RawDefaultRule{
					Inbound: []string{inboundTag},
					IPCIDR:  []string{tunPrefix4.Masked().String(), tunPrefix6.Masked().String()},
				},
				RuleAction: O.RuleAction{
					Action: C.RuleActionTypeReject,
				},
			},
		},
	}
}

// splitTunnelRuleSet has the side effect of creating the rule file on disk if absent.
func splitTunnelRuleSet(basePath string) []O.RuleSet {
	splitTunnelPath := newSplitTunnel(basePath, slog.Default()).ruleFile
	return []O.RuleSet{
		{
			Type: C.RuleSetTypeLocal,
			Tag:  badoption.Listable[string]{splitTunnelTag},
			LocalOptions: O.LocalRuleSet{
				Path: splitTunnelPath,
			},
			Format: C.RuleSetFormatSource,
		},
	}
}

// splitTunnelRoutingRules resolves split-tunnel destinations with the system
// resolver, as they would resolve with the VPN off, before routing them to
// "direct". A resolve action, rather than a domain resolver on "direct", keeps
// other direct traffic on the route's default resolver.
func splitTunnelRoutingRules() []O.Rule {
	return []O.Rule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: O.DefaultRule{
				RawDefaultRule: O.RawDefaultRule{
					RuleSet: []string{splitTunnelTag},
				},
				RuleAction: O.RuleAction{
					Action: C.RuleActionTypeResolve,
					ResolveOptions: O.RouteActionResolve{
						Server:   systemDNSTag,
						Strategy: O.DomainStrategy(C.DomainStrategyPreferIPv4),
					},
				},
			},
		},
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: O.DefaultRule{
				RawDefaultRule: O.RawDefaultRule{
					RuleSet: []string{splitTunnelTag},
				},
				RuleAction: O.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: O.RouteActionOptions{
						Outbound: "direct",
					},
				},
			},
		},
	}
}

func splitTunnelDNSRules() []O.DNSRule {
	return privateSystemAnswerRules(O.RawDefaultDNSRule{RuleSet: []string{splitTunnelTag}}, splitTunnelTag)
}

// localNameDNSRules matches only names the system resolver claims: hosts-file
// entries and .local names, which it answers on the device or over mDNS. It
// never matches a name a unicast resolver would answer, such as "x.lan": a page
// can make the browser look up any name, and that lookup would reach the
// network's resolver from the user's real IP. For the same reason it is empty
// on Android, whose platform resolver may send .local names to the network's
// unicast resolver. The preferred_by match requires systemDNSTag's server to
// support it, as local servers do, or the box fails to start.
func localNameDNSRules() []O.DNSRule {
	if common.IsAndroid() {
		return nil
	}
	return privateSystemAnswerRules(O.RawDefaultDNSRule{PreferredBy: []string{systemDNSTag}}, localNameTag)
}

// privateSystemAnswerRules answers a query matching match with the system
// resolver's answer when it holds a private address, which routes direct by
// IP. Other answers fall through to the remaining DNS rules. Only A and AAAA
// queries are evaluated, since only address answers can match. tag must be
// unique among the DNS rules' evaluate tags.
func privateSystemAnswerRules(match O.RawDefaultDNSRule, tag string) []O.DNSRule {
	match.QueryType = badoption.Listable[O.DNSQueryType]{O.DNSQueryType(dns.TypeA), O.DNSQueryType(dns.TypeAAAA)}
	return []O.DNSRule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: O.DefaultDNSRule{
				RawDefaultDNSRule: match,
				DNSRuleAction: O.DNSRuleAction{
					Action: C.RuleActionTypeEvaluate,
					EvaluateOptions: O.DNSEvaluateActionOptions{
						Server: systemDNSTag,
						Tag:    tag,
						AbstractDNSRouteActionOptions: O.AbstractDNSRouteActionOptions{
							Timeout: badoption.Duration(systemDNSEvaluateTimeout),
						},
					},
				},
			},
		},
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: O.DefaultDNSRule{
				RawDefaultDNSRule: O.RawDefaultDNSRule{
					MatchResponse: &O.DNSRuleMatchResponse{Enabled: true, Tag: tag},
					IPIsPrivate:   true,
				},
				DNSRuleAction: O.DNSRuleAction{Action: C.RuleActionTypeRespond},
			},
		},
	}
}

func systemDNSServers() []O.DNSServerOptions {
	return []O.DNSServerOptions{
		{
			Type:    C.DNSTypeLocal,
			Tag:     systemDNSTag,
			Options: &O.LocalDNSServerOptions{},
		},
	}
}

// kernelBelow reports whether the kernel version string v is below min.
// Only the first two components (major.minor) are compared, e.g. "5.10" or "4.19.0-android13".
// Returns false if either version string cannot be parsed.
func kernelBelow(v, min string) bool {
	parseKernelMajorMinor := func(s string) (int, int, bool) {
		p := strings.SplitN(s, ".", 3)
		if len(p) < 2 {
			return 0, 0, false
		}
		// Strip non-numeric suffixes (e.g. "19" from "19-android13")
		numericPrefix := func(part string) string {
			for i, r := range part {
				if r < '0' || r > '9' {
					return part[:i]
				}
			}
			return part
		}
		majorStr := numericPrefix(p[0])
		minorStr := numericPrefix(p[1])
		if majorStr == "" || minorStr == "" {
			return 0, 0, false
		}
		major, err := strconv.Atoi(majorStr)
		if err != nil {
			return 0, 0, false
		}
		minor, err := strconv.Atoi(minorStr)
		if err != nil {
			return 0, 0, false
		}
		return major, minor, true
	}
	vMaj, vMin, vok := parseKernelMajorMinor(v)
	mMaj, mMin, mok := parseKernelMajorMinor(min)
	if !vok || !mok {
		return false
	}
	return vMaj < mMaj || (vMaj == mMaj && vMin < mMin)
}
