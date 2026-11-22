package vpn

import (
	"log/slog"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/getlantern/radiance/common/settings"
)

// buildDNSServers returns a list of three DNSServerOptions, a local DNS server
// used for local requests; a remote DNS server (like quad9) for remote websites
// without sharing user private IP; and fake IP dns server, which effectively resolves
// DNS locally while allowing us to route traffic based on domains.
func buildDNSServers() []option.DNSServerOptions {
	local := option.DNSServerOptions{
		Tag:  "dns_local",
		Type: constant.DNSTypeHTTPS,
		Options: &option.RemoteHTTPSDNSServerOptions{
			Path: "/dns-query",
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: option.RemoteDNSServerOptions{
					DNSServerAddressOptions: option.DNSServerAddressOptions{
						Server:     localDNSIP(),
						ServerPort: 443,
					},
				},
			},
		},
	}
	ipv4Prefix := badoption.Prefix(netip.MustParsePrefix("198.18.0.0/15"))
	fakeIP := option.DNSServerOptions{
		Tag:  "dns_fakeip",
		Type: constant.DNSTypeFakeIP,
		Options: &option.FakeIPDNSServerOptions{
			Inet4Range: &ipv4Prefix,
		},
	}

	// quad9 doesn't transmit EDNS Client-Subnet data in order to avoid
	// transmitting the user IP  address to the remote site.
	remote := option.DNSServerOptions{
		Type: constant.DNSTypeHTTPS,
		Tag:  "dns_remote",
		Options: &option.RemoteHTTPSDNSServerOptions{
			Path: "/dns-query",
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: option.RemoteDNSServerOptions{
					DNSServerAddressOptions: option.DNSServerAddressOptions{
						Server:     "9.9.9.9",
						ServerPort: 443,
					},
					RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
						DialerOptions: option.DialerOptions{
							Detour: "auto",
						},
					},
				},
			},
		},
	}
	return []option.DNSServerOptions{
		remote,
		local,
		fakeIP,
	}
}

const (
	aliDNS    = "223.5.5.5"
	yandexDNS = "77.88.8.8"
	quad9DNS  = "9.9.9.9"
)

// Locales where AliDNS is used as local DNS server. Note that AliDNS is
// primarily attractive because it is accessible but is understood to return
// results that are DNS poisoned for many sites. This is fine because our
// DNS and routing rules will send that traffic through Lantern proxies,
// and the final DNS resolution will happen on the proxy side.
var aliDNSLocales = map[string]struct{}{
	"FAIR": {},
	"ZHCN": {},
	"CN":   {},
	"IR":   {},
}

func localDNSIP() string {
	locale := settings.GetString(settings.LocaleKey)
	normalizedLocale := normalizeLocale(locale)
	if _, ok := aliDNSLocales[normalizedLocale]; ok {
		slog.Info("Using AliDNS for locale", "locale", locale)
		return aliDNS
	}
	if normalizedLocale == "RU" || normalizedLocale == "RURU" {
		slog.Info("Using Yandex DNS for locale", "locale", locale)
		return yandexDNS
	}
	// default to Quad9
	slog.Info("Using Quad9 for locale", "locale", locale)
	return quad9DNS
}

// normalizeLocale normalizes the locale string by converting it to upper case
// and removing any hyphens or underscores.
func normalizeLocale(locale string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(locale), "-", ""), "_", "")
}

// buildDNSRules routes A queries to the fake-IP server and suppresses AAAA so
// applications fall back to IPv4.
func buildDNSRules() []option.DNSRule {
	return []option.DNSRule{suppressAAAARule(), fakeipRule()}

}

func fakeipServer() option.DNSServerOptions {
	ipv4Prefix := badoption.Prefix(netip.MustParsePrefix("198.18.0.0/15"))
	return option.DNSServerOptions{
		Tag:  "dns_fakeip",
		Type: constant.DNSTypeFakeIP,
		Options: &option.FakeIPDNSServerOptions{
			Inet4Range: &ipv4Prefix,
		},
	}

}

func fakeipRule() option.DNSRule {
	return option.DNSRule{
		Type: constant.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				QueryType: badoption.Listable[option.DNSQueryType]{option.DNSQueryType(dns.TypeA)},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: constant.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: "dns_fakeip",
				},
			},
		},
	}
}

// suppressAAAARule answers AAAA queries with NODATA (NOERROR and no records) so
// applications see no IPv6 address and connect over IPv4.
func suppressAAAARule() option.DNSRule {
	noError := option.DNSRCode(dns.RcodeSuccess)
	return option.DNSRule{
		Type: constant.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				QueryType: badoption.Listable[option.DNSQueryType]{option.DNSQueryType(dns.TypeAAAA)},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action:            constant.RuleActionTypePredefined,
				PredefinedOptions: option.DNSRouteActionPredefined{Rcode: &noError},
			},
		},
	}
}
