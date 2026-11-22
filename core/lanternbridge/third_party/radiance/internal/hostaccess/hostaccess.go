// Package hostaccess rejects sing-box options that would let a server
// definition act on the host beyond making network connections.
package hostaccess

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	lbC "github.com/getlantern/lantern-box/constant"
	lbO "github.com/getlantern/lantern-box/option"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// ErrDenied means the options would make the process execute a program, write
// to the host, open a listening socket, or use a host credential, namespace or
// file whose contents can reach the server. It is permanent for those options.
var ErrDenied = errors.New("server options grant host access")

var deniedTypes = map[string]bool{
	C.TypeTor:       true,
	C.TypeTailscale: true,
	lbC.TypeWATER:   true,
	// Creates interfaces and installs firewall, NAT and routing rules.
	C.TypeBridge: true,
	// Runs its wrapper_path programs and reads host keys and certificates.
	C.TypeOpenConnect: true,
	// Reads host keys and certificates; the server also listens.
	C.TypeOpenVPNClient: true,
	C.TypeOpenVPNServer: true,
}

// allowedServiceTypes is an allowlist: most sing-box services listen on the
// device or drive host components.
var allowedServiceTypes = map[string]bool{
	// TODO: use lbC.TypeOutboundEval once the lantern-box version radiance
	// pins defines it; until then the constant does not exist.
	"outbound-eval": true,
}

var deniedDNSTypes = map[string]bool{
	C.DNSTypeDHCP:        true,
	C.DNSTypeTailscale:   true,
	C.DNSTypeOpenConnect: true,
	C.DNSTypeOpenVPN:     true,
}

var deniedFields = map[reflect.Type][]string{
	// spoof opens raw sockets and, on Windows, installs the WinDivert driver.
	reflect.TypeFor[option.OutboundTLSOptions]():           {"certificate_path", "client_certificate_path", "client_key_path", "spoof"},
	reflect.TypeFor[option.AbstractDialerOptions]():        {"protect_path", "netns"},
	reflect.TypeFor[option.RawRouteOptionsActionOptions](): {"tls_spoof"},
	reflect.TypeFor[option.RouteOptionsActionOptions]():    {"tls_spoof"},
	reflect.TypeFor[option.SSHOutboundOptions]():           {"private_key_path"},
	reflect.TypeFor[option.WireGuardEndpointOptions]():     {"listen_port"},
	reflect.TypeFor[lbO.ReflexOutboundOptions]():           {"cert_path", "key_path"},
	reflect.TypeFor[lbO.TwiddleOutboundOptions]():          {"hello_pool_path", "hello_pool_device_path"},
	// Routes the callback through the host's HTTPS_PROXY, which can carry
	// credentials; a server must not make a client use them.
	reflect.TypeFor[lbO.BanditProbeOutboundOptions](): {"use_proxy_environment"},
	// Writes the smart dialer's strategy cache to this path, creating its
	// directory; a server must not choose where the client writes.
	reflect.TypeFor[lbO.OutboundOutlineOptions](): {"strategy_cache_path"},
}

// TypeAllowed reports whether options of the given outbound or endpoint type
// may be built at all.
func TypeAllowed(typ string) bool {
	return !deniedTypes[typ]
}

// CheckOutbound returns an error wrapping [ErrDenied] if o may not be built.
func CheckOutbound(o option.Outbound) error {
	return check(o.Type, o.Tag, o.Options)
}

// CheckEndpoint returns an error wrapping [ErrDenied] if e may not be built.
func CheckEndpoint(e option.Endpoint) error {
	return check(e.Type, e.Tag, e.Options)
}

// CheckOptions returns an error wrapping [ErrDenied] if any outbound, endpoint,
// service, DNS server, HTTP client, certificate provider or route rule in o may
// not be built.
func CheckOptions(o option.Options) error {
	for _, out := range o.Outbounds {
		if err := CheckOutbound(out); err != nil {
			return err
		}
	}
	for _, ep := range o.Endpoints {
		if err := CheckEndpoint(ep); err != nil {
			return err
		}
	}
	for _, s := range o.Services {
		if err := CheckService(s); err != nil {
			return err
		}
	}
	if o.DNS != nil {
		for _, server := range o.DNS.Servers {
			if err := checkDNS(server.Type, server.Tag, nil); err != nil {
				return err
			}
		}
	}
	for _, c := range o.HTTPClients {
		if field := setDeniedField(reflect.ValueOf(c)); field != "" {
			return fmt.Errorf("%w: http client %q: %s is set", ErrDenied, c.Tag, field)
		}
	}
	for _, p := range o.CertificateProviders {
		if err := checkCertificateProvider(p.Type, p.Tag, p.Options); err != nil {
			return err
		}
	}
	if field := setDeniedField(reflect.ValueOf(o.DNS)); field != "" {
		return fmt.Errorf("%w: dns: %s is set", ErrDenied, field)
	}
	if field := setDeniedField(reflect.ValueOf(o.Route)); field != "" {
		return fmt.Errorf("%w: route: %s is set", ErrDenied, field)
	}
	return nil
}

// CheckService returns an error wrapping [ErrDenied] if s may not be built.
func CheckService(s option.Service) error {
	return checkService(s.Type, s.Tag, s.Options)
}

func checkService(typ, tag string, opts any) error {
	return checkKind("service ", allowedServiceTypes[typ], typ, tag, opts)
}

// checkCertificateProvider denies every certificate provider: they write
// certificate state to the host, and radiance has no use for one.
func checkCertificateProvider(typ, tag string, opts any) error {
	return checkKind("certificate provider ", false, typ, tag, opts)
}

func checkDNS(typ, tag string, opts any) error {
	return checkKind("dns server ", !deniedDNSTypes[typ], typ, tag, opts)
}

func check(typ, tag string, opts any) error {
	return checkKind("", TypeAllowed(typ), typ, tag, opts)
}

func checkKind(kind string, typeAllowed bool, typ, tag string, opts any) error {
	if !typeAllowed {
		return fmt.Errorf("%w: %s%s %q: type not allowed", ErrDenied, kind, typ, tag)
	}
	if field := setDeniedField(reflect.ValueOf(opts)); field != "" {
		return fmt.Errorf("%w: %s%s %q: %s is set", ErrDenied, kind, typ, tag, field)
	}
	return nil
}

// setDeniedField returns the JSON name of the first non-zero denied field in v.
func setDeniedField(v reflect.Value) string {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return ""
		}
		return setDeniedField(v.Elem())
	case reflect.Struct:
		t := v.Type()
		denied := deniedFields[t]
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			fv := v.Field(i)
			if name, ok := jsonName(f); ok && name != "" && !fv.IsZero() && slices.Contains(denied, name) {
				return name
			}
			// Walk json:"-" fields too: a custom unmarshaler may fill them.
			if field := setDeniedField(fv); field != "" {
				return field
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			if field := setDeniedField(v.Index(i)); field != "" {
				return field
			}
		}
	case reflect.Map:
		for iter := v.MapRange(); iter.Next(); {
			if field := setDeniedField(iter.Value()); field != "" {
				return field
			}
		}
	}
	return ""
}

// jsonName returns the name f is encoded under, or "" for an untagged embedded
// struct, whose fields are inlined. ok is false if f's tag is "-".
func jsonName(f reflect.StructField) (name string, ok bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", false
	}
	name, _, _ = strings.Cut(tag, ",")
	if name == "" && !(f.Anonymous && isStruct(f.Type)) {
		name = f.Name
	}
	return name, true
}

func isStruct(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Kind() == reflect.Struct
}
