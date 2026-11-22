//go:build novpn

package vpn

import (
	"log/slog"
	"net/netip"

	C "github.com/sagernet/sing-box/constant"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/getlantern/radiance/common/env"
)

const (
	// defaultSocksAddress is the listen address for the novpn build's SOCKS/HTTP
	// inbound when RADIANCE_SOCKS_ADDRESS is unset.
	defaultSocksAddress = "127.0.0.1:1080"

	inboundTag = "http-socks-in"
)

// baseInbounds returns the SOCKS/HTTP proxy inbound. The novpn build has no TUN
// device, so this mixed inbound is the only entry point for traffic.
func baseInbounds() []O.Inbound {
	addr := defaultSocksAddress
	if v, ok := env.Get(env.SocksAddress); ok && v != "" {
		addr = v
	}
	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil {
		slog.Warn("invalid SOCKS address, using default",
			"address", addr, "default", defaultSocksAddress, "error", err)
		addrPort = netip.MustParseAddrPort(defaultSocksAddress)
	}
	listen := badoption.Addr(addrPort.Addr())
	return []O.Inbound{
		{
			Type: C.TypeMixed,
			Tag:  inboundTag,
			Options: &O.HTTPMixedInboundOptions{
				ListenOptions: O.ListenOptions{
					Listen:     &listen,
					ListenPort: addrPort.Port(),
				},
			},
		},
	}
}

func bypassRoutingRules() []O.Rule { return nil }

func tunSelfRoutingRules() []O.Rule { return nil }

func splitTunnelRuleSet(_ string) []O.RuleSet { return nil }

func splitTunnelRoutingRules() []O.Rule { return nil }

func splitTunnelDNSRules() []O.DNSRule { return nil }

func localNameDNSRules() []O.DNSRule { return nil }

func systemDNSServers() []O.DNSServerOptions { return nil }
