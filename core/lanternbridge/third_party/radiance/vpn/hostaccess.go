package vpn

import (
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
// fetch drew.
//
// MSN 3.4.11 SR-REJECT (field log 3.4.10): the 3.4.9/3.4.10 filter was
// FAIL-OPEN — "a draw with no ir-free members keeps the previous list"
// meant the unfiltered worldwide draw flowed straight into the tunnel. On
// the 3.4.10 network the server-track probe returned ZERO '-ir-free-'
// servers on every fetch (verified 2026-11-23 from two non-IR exits and
// from repeated same-account fetches; the x-lantern-client-country header,
// the fa-IR locale and preferred_location=IR are all ignored, and Lantern's
// geo-detection did not serve the IR pool to the fetching IP either), so
// the default Iran setting filtered nothing while the device ran six
// worldwide servers, the s0 probe died at connect twice, and the session
// that did come up ran NL/US exits until auto-select exhausted itself and
// the tunnel died at 11:00 — exactly the user's report: "does not connect
// to the Iran pool, connects to the worldwide pool; connection dies at
// the start or in the middle." SR-REJECT closes that: when Iran is
// selected, a draw with NO ir-free members is REJECTED as a whole via
// irPoolSelected(); updateServers then skips the non-ir-free offers so the
// manager, the picker, the auto group and the boot box options keep the
// ir-free servers they already hold, and the tunnel keeps serving them
// instead of rotating into a dead worldwide draw. Only a setting of
// "global" (the explicit user choice) leaves every draw unfiltered.
func pinPoolIfRequested(list servers.ServerList) servers.ServerList {
	// The stored setting value is "iran" (LanternPool.IRAN.coreName); 3.4.9
	// shipped the filter keyed on "ir" and it never matched — the 3.4.9
	// field log shows "ir-free filter off" with the IR draw arriving by
	// geo-detection luck alone.
	if p := env.GetString("RADIANCE_POOL"); p != "iran" && p != "ir" {
		return list
	}
	irOnly := slices.DeleteFunc(slices.Clone(list.Servers), func(s *servers.Server) bool {
		return !strings.Contains(s.Tag, "-ir-free-")
	})
	if len(irOnly) == 0 {
		return nil
	}
	list.Servers = irOnly
	return list
}

// irPoolSelected reports whether the Iran pool is pinned for this process.
func irPoolSelected() bool {
	p := env.GetString("RADIANCE_POOL")
	return p == "iran" || p == "ir"
}

// IrPoolSelected is the exported form for the backend, which pins the
// manager's pool (updateServers) with the same setting the tunnel filter
// uses, so the picker, the boot box options and the running tunnel all
// enforce one choice.
func IrPoolSelected() bool { return irPoolSelected() }

func allowedServers(list servers.ServerList) servers.ServerList {
	if list = pinPoolIfRequested(list); list.Servers == nil {
		// A rejected draw carries no servers; the caller (updateOutbounds,
		// updateNonSelectableOutbounds) treats an empty server list as
		// "nothing to change" and keeps the tunnel on its current pool.
		return list
	}
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
