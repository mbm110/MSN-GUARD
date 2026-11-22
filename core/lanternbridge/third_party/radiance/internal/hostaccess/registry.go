package hostaccess

import (
	"context"

	box "github.com/getlantern/lantern-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/service"
)

// Context returns ctx with the sing-box and lantern-box registries that
// box.Context adds, wrapped so every create a box built from it makes,
// including ones made after the box starts, fails with an error wrapping
// [ErrDenied] for options that may not be built. box.Context keeps registries
// already in ctx, and those are wrapped in place at most once.
func Context(ctx context.Context) context.Context {
	return ContextWithDNSTransport(ctx, nil)
}

// ContextWithDNSTransport is [Context], with `local` DNS servers resolved
// through platform's local DNS transport when it provides one.
func ContextWithDNSTransport(ctx context.Context, platform box.PlatformInterface) context.Context {
	ctx = box.ContextWithDNSTransport(ctx, platform)
	wrap[adapter.OutboundRegistry, outboundRegistry](ctx, func(r adapter.OutboundRegistry) adapter.OutboundRegistry {
		return outboundRegistry{r}
	})
	wrap[adapter.EndpointRegistry, endpointRegistry](ctx, func(r adapter.EndpointRegistry) adapter.EndpointRegistry {
		return endpointRegistry{r}
	})
	wrap[adapter.DNSTransportRegistry, dnsTransportRegistry](ctx, func(r adapter.DNSTransportRegistry) adapter.DNSTransportRegistry {
		return dnsTransportRegistry{r}
	})
	wrap[adapter.ServiceRegistry, serviceRegistry](ctx, func(r adapter.ServiceRegistry) adapter.ServiceRegistry {
		return serviceRegistry{r}
	})
	wrap[adapter.CertificateProviderRegistry, certificateProviderRegistry](ctx, func(r adapter.CertificateProviderRegistry) adapter.CertificateProviderRegistry {
		return certificateProviderRegistry{r}
	})
	return ctx
}

// wrap replaces ctx's R with newWrapper's result unless a W already wraps it.
func wrap[R, W any](ctx context.Context, newWrapper func(R) R) {
	r := service.FromContext[R](ctx)
	if _, wrapped := common.Cast[W](r); !wrapped {
		service.MustRegister[R](ctx, newWrapper(r))
	}
}

type outboundRegistry struct{ adapter.OutboundRegistry }

func (r outboundRegistry) Upstream() any { return r.OutboundRegistry }

func (r outboundRegistry) CreateOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag, typ string, options any) (adapter.Outbound, error) {
	if err := check(typ, tag, options); err != nil {
		return nil, err
	}
	return r.OutboundRegistry.CreateOutbound(ctx, router, logger, tag, typ, options)
}

type endpointRegistry struct{ adapter.EndpointRegistry }

func (r endpointRegistry) Upstream() any { return r.EndpointRegistry }

func (r endpointRegistry) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag, typ string, options any) (adapter.Endpoint, error) {
	if err := check(typ, tag, options); err != nil {
		return nil, err
	}
	return r.EndpointRegistry.Create(ctx, router, logger, tag, typ, options)
}

type dnsTransportRegistry struct{ adapter.DNSTransportRegistry }

func (r dnsTransportRegistry) Upstream() any { return r.DNSTransportRegistry }

func (r dnsTransportRegistry) CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag, typ string, options any) (adapter.DNSTransport, error) {
	if err := checkDNS(typ, tag, options); err != nil {
		return nil, err
	}
	return r.DNSTransportRegistry.CreateDNSTransport(ctx, logger, tag, typ, options)
}

type serviceRegistry struct{ adapter.ServiceRegistry }

func (r serviceRegistry) Upstream() any { return r.ServiceRegistry }

func (r serviceRegistry) Create(ctx context.Context, logger log.ContextLogger, tag, typ string, options any) (adapter.Service, error) {
	if err := checkService(typ, tag, options); err != nil {
		return nil, err
	}
	return r.ServiceRegistry.Create(ctx, logger, tag, typ, options)
}

type certificateProviderRegistry struct {
	adapter.CertificateProviderRegistry
}

func (r certificateProviderRegistry) Upstream() any { return r.CertificateProviderRegistry }

func (r certificateProviderRegistry) Create(ctx context.Context, logger log.ContextLogger, tag, typ string, options any) (adapter.CertificateProviderService, error) {
	if err := checkCertificateProvider(typ, tag, options); err != nil {
		return nil, err
	}
	return r.CertificateProviderRegistry.Create(ctx, logger, tag, typ, options)
}
