package vpn

import (
	"errors"
	"fmt"
	"slices"

	"github.com/getlantern/common"
	lbA "github.com/getlantern/lantern-box/adapter"
	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

const (
	// ProxylessTag is the server's proxyless (Outline smart-dialer) outbound,
	// lantern-cloud's proxylessDetourTag. It reaches sites directly, with
	// DNS and TLS evasions instead of a proxy server.
	ProxylessTag = "proxyless"
	// ProxylessHedgeTag is the hedge auto mode routes through when proxyless
	// is built: it tries ProxylessTag first and falls back to AutoSelectTag,
	// per connection, remembering which sites need the proxy.
	ProxylessHedgeTag = "proxyless-hedge"
	// proxylessUDP is the proxyless outbound's UDP transport when the server
	// sets none: Outline's QUIC prelude, a decoy Initial ahead of each QUIC
	// ClientHello, so HTTP/3 can go proxyless too.
	proxylessUDP = "quicprelude:count=1"
)

// ProxylessOptions builds the proxyless hedge into the tunnel. The hedge is
// built only when the server sent its proxyless outbound. It starts switched
// off and is switched on, after the tunnel starts, to the state last given to
// [VPNClient.SetProxylessEnabled], or to Enabled when none was. A switch made
// while the tunnel starts therefore can't be overtaken by a stale Enabled.
//
// ExploreRate and TelemetrySites tune how the hedge is measured; the server
// sets them per country. They apply when the hedge is built, so a change
// takes effect at the next tunnel start.
type ProxylessOptions struct {
	Enabled bool `json:"enabled"`
	// ExploreRate is the fraction, from 0 to 1, of connections the hedge
	// could send directly that it sends through the proxy instead, so the
	// two paths can be compared on the same sites.
	ExploreRate float64 `json:"explore_rate,omitempty"`
	// TelemetrySites are the registered domains the hedge's telemetry may
	// name; every other site is reported as "other".
	TelemetrySites []string `json:"telemetry_sites,omitempty"`
}

// proxylessMaxTelemetrySites bounds the sites a server can have named, which
// bounds the telemetry's cardinality.
const proxylessMaxTelemetrySites = common.MaxProxylessTelemetrySites

// hedgeTelemetryOptions returns p's measurement settings in the range the
// hedge accepts. The hedge refuses to build with an explore_rate outside
// [0, 1], which would stop the tunnel starting, so a value that isn't in it
// is dropped rather than passed on. The backend already sends the server's
// values through common.ProxylessConfig.Sanitize; this is a deliberate
// second guard, since the tunnel not starting is the cost of a miss.
func (p *ProxylessOptions) hedgeTelemetryOptions() (exploreRate float64, sites []string) {
	if p.ExploreRate > 0 && p.ExploreRate <= 1 {
		exploreRate = p.ExploreRate
	}
	for _, site := range p.TelemetrySites {
		if len(sites) == proxylessMaxTelemetrySites {
			break
		}
		if site != "" {
			sites = append(sites, site)
		}
	}
	return exploreRate, sites
}

// WithProxylessUDP returns out with proxylessUDP as its UDP transport when out
// is the server's proxyless outbound and the server set none. Other
// outbounds, and one the server gave a UDP transport, are returned as is. The
// options are copied, so the server's config isn't changed.
func WithProxylessUDP(out O.Outbound) O.Outbound {
	if out.Tag != ProxylessTag || out.Type != lbC.TypeOutline {
		return out
	}
	opts, ok := out.Options.(*lbO.OutboundOutlineOptions)
	if !ok || opts == nil || opts.UDP != nil {
		return out
	}
	withUDP := *opts
	udp := proxylessUDP
	withUDP.UDP = &udp
	out.Options = &withUDP
	return out
}

// addProxylessHedge adds the hedge, switched off, in front of the auto group.
// It reports false, changing nothing, when the server sent no proxyless
// outbound, or when an outbound or endpoint already has the hedge's tag (a
// user server saved before the tag was reserved), which would otherwise stop
// the tunnel from starting.
func addProxylessHedge(opts *O.Options, p *ProxylessOptions) bool {
	i := slices.IndexFunc(opts.Outbounds, func(o O.Outbound) bool {
		return o.Tag == ProxylessTag && o.Type == lbC.TypeOutline
	})
	if i < 0 {
		return false
	}
	if slices.ContainsFunc(opts.Outbounds, func(o O.Outbound) bool { return o.Tag == ProxylessHedgeTag }) ||
		slices.ContainsFunc(opts.Endpoints, func(e O.Endpoint) bool { return e.Tag == ProxylessHedgeTag }) {
		return false
	}
	exploreRate, sites := p.hedgeTelemetryOptions()
	opts.Outbounds = append(opts.Outbounds, O.Outbound{
		Type: lbC.TypeHedge,
		Tag:  ProxylessHedgeTag,
		Options: &lbO.HedgeOutboundOptions{
			First:          ProxylessTag,
			Then:           AutoSelectTag,
			Disabled:       true,
			ExploreRate:    exploreRate,
			TelemetrySites: sites,
		},
	})
	return true
}

// autoModeRules route auto mode to the auto group, or through the hedge in
// front of it. The hedge carries only TCP and UDP, and sing-box finds an
// ICMP-capable outbound only through groups, which the hedge isn't, so ICMP
// skips the hedge and goes to the auto group directly.
func autoModeRules(hedged bool) []O.Rule {
	if !hedged {
		return []O.Rule{modeRule(AutoSelectTag, AutoSelectTag)}
	}
	viaHedge := modeRule(AutoSelectTag, ProxylessHedgeTag)
	viaHedge.DefaultOptions.RawDefaultRule.Network = badoption.Listable[string]{N.NetworkTCP, N.NetworkUDP}
	return []O.Rule{viaHedge, modeRule(AutoSelectTag, AutoSelectTag)}
}

// SetProxylessEnabled switches the running tunnel's proxyless hedge on or
// off for new connections, without restarting the tunnel. The state is also
// remembered and applied to the next tunnel when it starts, so a switch made
// while one is starting isn't lost. With no hedge, because the tunnel isn't
// in smart routing or the server sent no proxyless outbound, there is nothing
// to switch and it returns nil.
//
// It doesn't wait for a tunnel that is starting or stopping, which holds mu
// for its whole start: the state is stored first, and applied once mu is
// free, by restoreProxylessLocked as the tunnel starts or by a background
// apply of the latest stored state.
func (c *VPNClient) SetProxylessEnabled(enabled bool) error {
	c.proxyless.Store(&enabled)
	if !c.mu.TryRLock() {
		go func() {
			c.mu.RLock()
			defer c.mu.RUnlock()
			if err := c.applyLatestProxylessRLocked(); err != nil && !errors.Is(err, ErrTunnelNotConnected) {
				c.logger.Warn("Failed to apply the proxyless state", "error", err)
			}
		}()
		return nil
	}
	defer c.mu.RUnlock()
	return c.applyLatestProxylessRLocked()
}

// applyLatestProxylessRLocked applies the latest requested proxyless state,
// not the caller's, under proxylessApplyMu: applies run in some order, so
// whichever runs last must apply the newest state. Caller holds mu for
// reading.
func (c *VPNClient) applyLatestProxylessRLocked() error {
	c.proxylessApplyMu.Lock()
	defer c.proxylessApplyMu.Unlock()
	if c.tunnel == nil {
		return ErrTunnelNotConnected
	}
	latest := c.proxyless.Load()
	if latest == nil {
		return nil
	}
	return c.tunnel.setProxylessEnabled(*latest)
}

// ProxylessEnabled reports the proxyless state last set with
// SetProxylessEnabled, false until it is first set.
func (c *VPNClient) ProxylessEnabled() bool {
	enabled := c.proxyless.Load()
	return enabled != nil && *enabled
}

// restoreProxylessLocked switches on a tunnel's hedge, which starts off, to
// the last requested state, or to opts' when none was requested. Caller holds
// mu.
func (c *VPNClient) restoreProxylessLocked(opts *ProxylessOptions) error {
	if c.tunnel == nil {
		return nil
	}
	if enabled := c.proxyless.Load(); enabled != nil {
		return c.tunnel.setProxylessEnabled(*enabled)
	}
	if opts == nil {
		return nil
	}
	return c.tunnel.setProxylessEnabled(opts.Enabled)
}

func (t *tunnel) setProxylessEnabled(enabled bool) error {
	out := t.liveOutbound(ProxylessHedgeTag)
	if out == nil {
		return nil
	}
	sw, ok := out.(lbA.Switchable)
	if !ok {
		return fmt.Errorf("outbound %s (%T) has no proxyless switch", ProxylessHedgeTag, out)
	}
	sw.SetEnabled(enabled)
	return nil
}
