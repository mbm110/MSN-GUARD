package hostaccess

import (
	"context"
	"reflect"
	"regexp"
	"slices"
	"testing"

	box "github.com/getlantern/lantern-box"
	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckOutboundDenied(t *testing.T) {
	tls := func(o option.OutboundTLSOptions) option.OutboundTLSOptionsContainer {
		return option.OutboundTLSOptionsContainer{TLS: &o}
	}
	tests := []struct {
		name string
		out  option.Outbound
	}{
		{"tor", option.Outbound{Type: C.TypeTor, Options: &option.TorOutboundOptions{}}},
		{"water", option.Outbound{Type: lbC.TypeWATER, Options: &lbO.WATEROutboundOptions{}}},
		{"bridge", option.Outbound{Type: C.TypeBridge, Options: &option.BridgeOutboundOptions{}}},
		{"tls spoof", option.Outbound{Type: C.TypeTrojan, Options: &option.TrojanOutboundOptions{
			OutboundTLSOptionsContainer: tls(option.OutboundTLSOptions{Enabled: true, Spoof: "example.com"}),
		}}},
		{"tls certificate", option.Outbound{Type: C.TypeTrojan, Options: &option.TrojanOutboundOptions{
			OutboundTLSOptionsContainer: tls(option.OutboundTLSOptions{Enabled: true, CertificatePath: "/etc/ca.pem"}),
		}}},
		{"tls client certificate", option.Outbound{Type: C.TypeTrojan, Options: &option.TrojanOutboundOptions{
			OutboundTLSOptionsContainer: tls(option.OutboundTLSOptions{Enabled: true, ClientCertificatePath: "/etc/cert.pem"}),
		}}},
		{"tls client key", option.Outbound{Type: C.TypeVLESS, Options: &option.VLESSOutboundOptions{
			OutboundTLSOptionsContainer: tls(option.OutboundTLSOptions{Enabled: true, ClientKeyPath: "/etc/key.pem"}),
		}}},
		{"ssh private key", option.Outbound{Type: C.TypeSSH, Options: &option.SSHOutboundOptions{PrivateKeyPath: "/root/.ssh/id_ed25519"}}},
		{"reflex cert", option.Outbound{Type: lbC.TypeReflex, Options: &lbO.ReflexOutboundOptions{CertPath: "/etc/cert.pem"}}},
		{"reflex key", option.Outbound{Type: lbC.TypeReflex, Options: &lbO.ReflexOutboundOptions{KeyPath: "/etc/key.pem"}}},
		{"twiddle hello pool", option.Outbound{Type: lbC.TypeTwiddle, Options: &lbO.TwiddleOutboundOptions{HelloPoolPath: "/etc/shadow"}}},
		{"twiddle device hello pool", option.Outbound{Type: lbC.TypeTwiddle, Options: &lbO.TwiddleOutboundOptions{HelloPoolDevicePath: "/etc/shadow"}}},
		{"bandit probe proxy environment", option.Outbound{Type: lbC.TypeBanditProbe, Options: &lbO.BanditProbeOutboundOptions{UseProxyEnvironment: true}}},
		{"outline strategy cache path", option.Outbound{Type: lbC.TypeOutline, Options: &lbO.OutboundOutlineOptions{StrategyCachePath: "/etc/cron.d/x"}}},
		{"dialer protect path", option.Outbound{Type: C.TypeShadowsocks, Options: &option.ShadowsocksOutboundOptions{
			DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{ProtectPath: "/run/protect.sock"}},
		}}},
		{"dialer netns", option.Outbound{Type: C.TypeDirect, Options: &option.DirectOutboundOptions{
			DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{NetNs: "/proc/1/ns/net"}},
		}}},
		{"options by value", option.Outbound{Type: C.TypeSSH, Options: option.SSHOutboundOptions{PrivateKeyPath: "/k"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, CheckOutbound(tt.out), ErrDenied)
		})
	}
}

func TestCheckOutboundAllowed(t *testing.T) {
	tests := []struct {
		name string
		out  option.Outbound
	}{
		{"nil options", option.Outbound{Type: C.TypeDirect}},
		{"outline with a udp transport", option.Outbound{Type: lbC.TypeOutline, Options: &lbO.OutboundOutlineOptions{
			Domains: []string{"cdn.jsdelivr.net"}, UDP: new("quicprelude:count=1"),
		}}},
		{"hedge", option.Outbound{Type: lbC.TypeHedge, Options: &lbO.HedgeOutboundOptions{First: "proxyless", Then: "auto"}}},
		{"shadowsocks", option.Outbound{Type: C.TypeShadowsocks, Options: &option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 443},
			Method:        "chacha20-ietf-poly1305",
			Password:      "pw",
		}}},
		{"inline tls material and ech path", option.Outbound{Type: C.TypeTrojan, Options: &option.TrojanOutboundOptions{
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
				Enabled:           true,
				Certificate:       []string{"-----BEGIN CERTIFICATE-----"},
				ClientCertificate: []string{"-----BEGIN CERTIFICATE-----"},
				ClientKey:         []string{"-----BEGIN PRIVATE KEY-----"},
				ECH:               &option.OutboundECHOptions{Enabled: true, ConfigPath: "/etc/ech.pem"},
			}},
		}}},
		{"ssh inline key", option.Outbound{Type: C.TypeSSH, Options: &option.SSHOutboundOptions{PrivateKey: []string{"key"}}}},
		{"reflex inline", option.Outbound{Type: lbC.TypeReflex, Options: &lbO.ReflexOutboundOptions{CertPEM: "c", KeyPEM: "k"}}},
		{"twiddle inline pool", option.Outbound{Type: lbC.TypeTwiddle, Options: &lbO.TwiddleOutboundOptions{HelloPool: "00"}}},
		{"bandit probe without proxy environment", option.Outbound{Type: lbC.TypeBanditProbe, Options: &lbO.BanditProbeOutboundOptions{
			CallbackURL:   "https://api.iantem.io/v1/bandit/callback",
			ReportStalled: true,
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NoError(t, CheckOutbound(tt.out))
		})
	}
}

func TestCheckEndpoint(t *testing.T) {
	denied := []option.Endpoint{
		{Type: C.TypeTailscale, Options: &option.TailscaleEndpointOptions{}},
		{Type: C.TypeOpenConnect, Options: &option.OpenConnectEndpointOptions{}},
		{Type: C.TypeOpenVPNClient, Options: &option.OpenVPNClientEndpointOptions{}},
		{Type: C.TypeOpenVPNServer, Options: &option.OpenVPNServerEndpointOptions{}},
		{Type: C.TypeWireGuard, Options: &option.WireGuardEndpointOptions{ListenPort: 51820, Name: "../../tmp/x"}},
		{Type: lbC.TypeAmnezia, Options: &lbO.AmneziaEndpointOptions{
			WireGuardEndpointOptions: option.WireGuardEndpointOptions{ListenPort: 51820},
		}},
	}
	for _, e := range denied {
		assert.ErrorIs(t, CheckEndpoint(e), ErrDenied, "%+v", e.Options)
	}
	assert.NoError(t, CheckEndpoint(option.Endpoint{Type: C.TypeWireGuard, Options: &option.WireGuardEndpointOptions{System: true, Name: "wg0"}}),
		"Lantern's desktop WireGuard servers use a system interface")
}

func TestHostInputFieldsWalksSkippedFields(t *testing.T) {
	fields := hostInputFields(reflect.TypeFor[option.V2RayTransportOptions](), map[reflect.Type]bool{})
	assert.Len(t, fields, 3, "fields filled by a custom unmarshaler must still be walked")
}

// hostInputName matches JSON field names that may name a host file, directory,
// program, socket, interface, environment variable or proxy setting.
var hostInputName = regexp.MustCompile(`path|dir|file|exec|args|command|socket|netns|listen|system|interface|env|proxy`)

// reviewedFields maps an options struct type to its host-input-looking fields
// that are allowed, and why.
var reviewedFields = map[reflect.Type]map[string]string{
	reflect.TypeFor[option.OutboundECHOptions](): {
		"config_path": "TLS ECH config; read and parsed, never sent",
	},
	reflect.TypeFor[option.AbstractDialerOptions](): {
		"tcp_multi_path": "bool enabling MPTCP",
		"bind_interface": "binds an outgoing connection to an existing interface",
	},
	reflect.TypeFor[option.QUICOptions]():              {"disable_path_mtu_discovery": "bool disabling QUIC path MTU discovery"},
	reflect.TypeFor[option.Hysteria2OutboundOptions](): {"bbr_profile": "BBR congestion-control profile name"},
	reflect.TypeFor[option.MDNSDNSServerOptions]():     {"interface": "existing interfaces to send mDNS queries on"},
	reflect.TypeFor[option.RemoteRuleSet]():            {"initial_path": "rule-set file loaded before the first download; read and parsed, never sent"},
	reflect.TypeFor[option.HTTPOutboundOptions]():      {"path": "URL path of the proxy request"},
	reflect.TypeFor[option.V2RayHTTPOptions]():         {"path": "URL path of the transport request"},
	reflect.TypeFor[option.V2RayHTTPUpgradeOptions]():  {"path": "URL path of the transport request"},
	reflect.TypeFor[option.V2RayWebsocketOptions]():    {"path": "URL path of the transport request"},
	reflect.TypeFor[option.WireGuardEndpointOptions](): {
		"system": "WireGuard interface used by Lantern's desktop servers; executes and writes nothing",
	},
	reflect.TypeFor[lbO.DNSEntryConfig]():                 {"system": "selects the system DNS resolver"},
	reflect.TypeFor[lbO.UnboundedOutboundOptions]():       {"direct_exit": "Hysteria2 SNI for volunteer direct exits; names no host file or program"},
	reflect.TypeFor[option.RemoteHTTPSDNSServerOptions](): {"path": "URL path of the DoH request"},
	reflect.TypeFor[option.HostsDNSServerOptions]():       {"path": "hosts files; read and parsed, never sent"},
	reflect.TypeFor[option.LocalRuleSet]():                {"path": "rule-set file; read and parsed, never sent"},
	reflect.TypeFor[option.GeoIPOptions]():                {"path": "never read by sing-box"},
	reflect.TypeFor[option.GeositeOptions]():              {"path": "never read by sing-box"},
	reflect.TypeFor[option.RawDefaultRule](): {
		"process_path": "matcher", "process_path_regex": "matcher",
		"interface_address": "matcher", "network_interface_address": "matcher", "default_interface_address": "matcher",
	},
	reflect.TypeFor[option.DefaultHeadlessRule](): {
		"process_path": "matcher", "process_path_regex": "matcher",
		"network_interface_address": "matcher", "default_interface_address": "matcher",
	},
	reflect.TypeFor[option.RawDefaultDNSRule](): {
		"process_path": "matcher", "process_path_regex": "matcher",
		"interface_address": "matcher", "network_interface_address": "matcher", "default_interface_address": "matcher",
	},
	reflect.TypeFor[option.RouteOptions](): {
		"auto_detect_interface": "selects an existing interface",
		"default_interface":     "selects an existing interface",
		"dhcp_lease_files":      "DHCP lease files; read and parsed for neighbor matching, never sent",
	},
	reflect.TypeFor[option.DirectOutboundOptions](): {"proxy_protocol": "PROXY protocol version number; deprecated and ignored"},
}

// TestRegisteredOptionFieldsReviewed fails when a registered outbound,
// endpoint or DNS transport type, or the route or DNS options, gains a field
// that looks like a host input but is neither denied nor reviewed.
func TestRegisteredOptionFieldsReviewed(t *testing.T) {
	type registry interface {
		CreateOptions(string) (any, bool)
		Registered() []string
	}
	ctx := box.Context(context.Background())
	registries := map[string]registry{
		"outbound": service.FromContext[option.OutboundOptionsRegistry](ctx).(registry),
		"endpoint": service.FromContext[option.EndpointOptionsRegistry](ctx).(registry),
		"dns":      service.FromContext[option.DNSTransportOptionsRegistry](ctx).(registry),
		"service":  service.FromContext[option.ServiceOptionsRegistry](ctx).(registry),
	}
	assertReviewed := func(kind, typ string, opts reflect.Type) {
		for _, f := range hostInputFields(opts, map[reflect.Type]bool{}) {
			if slices.Contains(deniedFields[f.owner], f.name) {
				continue
			}
			_, reviewed := reviewedFields[f.owner][f.name]
			assert.True(t, reviewed, "%s %q: field %q of %v is unreviewed: deny it or add it to reviewedFields", kind, typ, f.name, f.owner)
		}
	}
	for kind, registry := range registries {
		types := registry.Registered()
		require.NotEmpty(t, types, kind)
		slices.Sort(types)
		for _, typ := range types {
			switch kind {
			case "dns":
				if deniedDNSTypes[typ] {
					continue
				}
			case "service":
				if !allowedServiceTypes[typ] {
					continue
				}
			default:
				if !TypeAllowed(typ) {
					continue
				}
			}
			opts, ok := registry.CreateOptions(typ)
			require.True(t, ok, typ)
			assertReviewed(kind, typ, reflect.TypeOf(opts))
		}
	}
	assertReviewed("options", "route", reflect.TypeFor[option.RouteOptions]())
	assertReviewed("options", "dns", reflect.TypeFor[option.DNSOptions]())
}

type ownedField struct {
	owner reflect.Type
	name  string
}

func hostInputFields(t reflect.Type, seen map[reflect.Type]bool) []ownedField {
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return hostInputFields(t.Elem(), seen)
	case reflect.Struct:
	default:
		return nil
	}
	if seen[t] {
		return nil
	}
	seen[t] = true
	var fields []ownedField
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		if name, ok := jsonName(f); ok && name != "" && hostInputName.MatchString(name) {
			fields = append(fields, ownedField{owner: t, name: name})
		}
		fields = append(fields, hostInputFields(f.Type, seen)...)
	}
	return fields
}

func TestCheckOptions(t *testing.T) {
	dnsServer := func(opts any) option.Options {
		return option.Options{DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{{Type: C.DNSTypeTLS, Tag: "dot", Options: opts}},
		}}}
	}
	actionRule := func(a option.RuleAction) option.Options {
		return option.Options{Route: &option.RouteOptions{Rules: []option.Rule{{
			Type:           C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{RuleAction: a},
		}}}}
	}
	directRule := func(d option.DirectActionOptions) option.Options {
		return actionRule(option.RuleAction{Action: C.RuleActionTypeDirect, DirectOptions: d})
	}
	denied := map[string]option.Options{
		"dns netns": dnsServer(&option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: option.RemoteDNSServerOptions{
			RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{NetNs: "/proc/1/ns/net"}}},
		}}),
		"dns tls client key": dnsServer(&option.RemoteTLSDNSServerOptions{OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, ClientKeyPath: "/etc/key.pem"},
		}}),
		"direct action protect path": directRule(option.DirectActionOptions{AbstractDialerOptions: option.AbstractDialerOptions{ProtectPath: "/run/protect.sock"}}),
		"route action tls spoof": actionRule(option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{
			RawRouteOptionsActionOptions: option.RawRouteOptionsActionOptions{TLSSpoof: "example.com"},
		}}),
		"route-options action tls spoof": actionRule(option.RuleAction{Action: C.RuleActionTypeRouteOptions,
			RouteOptionsOptions: option.RouteOptionsActionOptions{TLSSpoof: "example.com"},
		}),
		"denied outbound": {Outbounds: []option.Outbound{{Type: C.TypeTor}}},
		"denied service":  {Services: []option.Service{{Type: C.TypeSSMAPI, Options: &option.SSMAPIServiceOptions{}}}},
		"openvpn dns server": {DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{{Type: C.DNSTypeOpenVPN, Tag: "openvpn"}},
		}}},
		"dhcp dns server": {DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{{Type: C.DNSTypeDHCP, Tag: "dhcp", Options: &option.DHCPDNSServerOptions{}}},
		}}},
		"http client netns": {HTTPClients: []option.HTTPClient{{Tag: "client",
			DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{NetNs: "/proc/1/ns/net"}},
		}}},
		"http client tls spoof": {HTTPClients: []option.HTTPClient{{Tag: "client",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, Spoof: "example.com"}},
		}}},
		"remote rule set http client netns": {Route: &option.RouteOptions{RuleSet: []option.RuleSet{{
			Type: C.RuleSetTypeRemote,
			RemoteOptions: option.RemoteRuleSet{HTTPClient: &option.HTTPClientOptions{
				DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{NetNs: "/proc/1/ns/net"}},
			}},
		}}}},
		"certificate provider": {CertificateProviders: []option.CertificateProvider{{
			Type: C.TypeCloudflareOriginCA, Tag: "origin-ca", Options: &option.CloudflareOriginCACertificateProviderOptions{},
		}}},
	}
	for name, o := range denied {
		assert.ErrorIs(t, CheckOptions(o), ErrDenied, name)
	}
	assert.NoError(t, CheckOptions(dnsServer(&option.RemoteTLSDNSServerOptions{})))
	assert.NoError(t, CheckOptions(directRule(option.DirectActionOptions{})))
	assert.NoError(t, CheckOptions(option.Options{HTTPClients: []option.HTTPClient{{Tag: "client"}}}))
	assert.NoError(t, CheckOptions(option.Options{}))
}
