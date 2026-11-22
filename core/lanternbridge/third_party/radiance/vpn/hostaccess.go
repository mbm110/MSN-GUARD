package vpn

import (
	"log/slog"
	"slices"
	"strings"

	O "github.com/sagernet/sing-box/option"

	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/internal/hostaccess"
	"github.com/getlantern/radiance/internal/tlsidentity"
	"github.com/getlantern/radiance/servers"
)

func allowedOutbounds(outbounds []O.Outbound) []O.Outbound {
	outbounds = slices.DeleteFunc(slices.Clone(outbounds), func(o O.Outbound) bool {
		return dropDenied("server", o.Tag, hostaccess.CheckOutbound(o))
	})
	for i := range outbounds {
		outbounds[i].Options = tlsidentity.Options(outbounds[i].Options)
	}
	return outbounds
}

func allowedEndpoints(endpoints []O.Endpoint) []O.Endpoint {
	endpoints = slices.DeleteFunc(slices.Clone(endpoints), func(e O.Endpoint) bool {
		return dropDenied("server", e.Tag, hostaccess.CheckEndpoint(e))
	})
	for i := range endpoints {
		endpoints[i].Options = tlsidentity.Options(endpoints[i].Options)
	}
	return endpoints
}

func allowedServices(services []O.Service) []O.Service {
	return slices.DeleteFunc(slices.Clone(services), func(s O.Service) bool {
		return dropDenied("service", s.Tag, hostaccess.CheckService(s))
	})
}

// MSN 3.4.9 (vendored divergence, like the 3.4.8 gvisor pin): the pool the
// server draws follows the EXIT IP of the config fetch, not the country
// header or locale (verified with the server-track probe: from a non-IR
// exit every fetch rotates a global sample; the pinned IR pool only comes
// from an IR exit). Mid-session refreshes that leave through the tunnel
// therefore refilled the auto group with global servers — field log 3.4.8:
// the 17:18 refill swapped in 5 samizdat/cardiff/global servers, the bandit
// picked a dead samizdat, and the session died minutes later.
// RADIANCE_POOL=ir keeps ONLY the pinned IR pool (servers tagged
// '-ir-free-') in the tunnel, the auto group and the picker, whatever any
// fetch drew; a draw with no ir-free members keeps the previous list rather
// than emptying the group.
func pinPoolIfRequested(list servers.ServerList) servers.ServerList {
	if env.GetString("RADIANCE_POOL") != "ir" {
		return list
	}
	irOnly := slices.DeleteFunc(slices.Clone(list.Servers), func(s *servers.Server) bool {
		return !strings.Contains(s.Tag, "-ir-free-")
	})
	if len(irOnly) == 0 {
		slog.Warn("RADIANCE_POOL=ir: draw had no ir-free servers; keeping the previous list")
		return list
	}
	list.Servers = irOnly
	return list
}

func allowedServers(list servers.ServerList) servers.ServerList {
	list = pinPoolIfRequested(list)
	list.Servers = slices.DeleteFunc(slices.Clone(list.Servers), func(s *servers.Server) bool {
		return dropDenied("server", s.Tag, s.CheckHostAccess())
	})
	for i, srv := range list.Servers {
		list.Servers[i] = srv.WithTLSVerification()
	}
	return list
}

func dropDenied(kind, tag string, err error) bool {
	if err == nil {
		return false
	}
	slog.Warn("Dropping "+kind+" whose options grant host access", "tag", tag, "error", err)
	return true
}
