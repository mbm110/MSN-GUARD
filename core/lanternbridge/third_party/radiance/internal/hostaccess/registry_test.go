package hostaccess

import (
	"context"
	"fmt"
	"testing"

	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCheckedBox(t *testing.T, options option.Options) (*sbox.Box, context.Context, error) {
	t.Helper()
	ctx := Context(context.Background())
	options.Log = &option.LogOptions{Disabled: true}
	instance, err := sbox.New(sbox.Options{Context: ctx, Options: options})
	if err == nil {
		t.Cleanup(func() { instance.Close() })
	}
	return instance, ctx, err
}

func TestContextDeniesConfiguredOptions(t *testing.T) {
	denied := map[string]option.Options{
		"outbound": {Outbounds: []option.Outbound{{Type: C.TypeTor, Tag: "tor", Options: &option.TorOutboundOptions{}}}},
		"endpoint": {Endpoints: []option.Endpoint{{Type: C.TypeOpenVPNClient, Tag: "ovpn", Options: &option.OpenVPNClientEndpointOptions{}}}},
		"dns server": {DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{{Type: C.DNSTypeOpenVPN, Tag: "ovpn-dns"}},
		}}},
		"service": {Services: []option.Service{{Type: C.TypeSSMAPI, Tag: "ssm", Options: &option.SSMAPIServiceOptions{}}}},
		"certificate provider": {CertificateProviders: []option.CertificateProvider{{
			Type: C.TypeCloudflareOriginCA, Tag: "origin-ca", Options: &option.CloudflareOriginCACertificateProviderOptions{},
		}}},
	}
	for name, options := range denied {
		_, _, err := newCheckedBox(t, options)
		assert.ErrorIs(t, err, ErrDenied, name)
	}
}

func TestContextDeniesRuntimeCreate(t *testing.T) {
	instance, ctx, err := newCheckedBox(t, option.Options{})
	require.NoError(t, err)
	logger := log.NewNOPFactory().NewLogger("test")

	err = instance.Outbound().Create(ctx, instance.Router(), logger, "tor", C.TypeTor, &option.TorOutboundOptions{})
	assert.ErrorIs(t, err, ErrDenied)
	err = instance.Endpoint().Create(ctx, instance.Router(), logger, "ovpn", C.TypeOpenVPNClient, &option.OpenVPNClientEndpointOptions{})
	assert.ErrorIs(t, err, ErrDenied)

	_, err = service.FromContext[adapter.CertificateProviderRegistry](ctx).Create(ctx, logger, "", C.TypeACME, &option.ACMECertificateProviderOptions{})
	assert.ErrorIs(t, err, ErrDenied, "inline certificate providers are created through the registry")

	require.NoError(t, instance.Outbound().Create(ctx, instance.Router(), logger, "direct", C.TypeDirect, &option.DirectOutboundOptions{}))
	_, found := instance.Outbound().Outbound("direct")
	assert.True(t, found)
}

func TestContextWrapsOnce(t *testing.T) {
	ctx := Context(Context(context.Background()))
	r, ok := service.FromContext[adapter.OutboundRegistry](ctx).(outboundRegistry)
	require.True(t, ok)
	_, nested := common.Cast[outboundRegistry](r.OutboundRegistry)
	assert.False(t, nested)
}

type stubLocalDNSTransport struct{}

func (stubLocalDNSTransport) Raw() bool                                            { return true }
func (stubLocalDNSTransport) Lookup(*libbox.ExchangeContext, string, string) error { return nil }
func (stubLocalDNSTransport) Exchange(*libbox.ExchangeContext, []byte) error       { return nil }

type stubPlatform struct{}

func (stubPlatform) LocalDNSTransport() libbox.LocalDNSTransport { return stubLocalDNSTransport{} }

func TestContextWithDNSTransport(t *testing.T) {
	ctx := ContextWithDNSTransport(context.Background(), stubPlatform{})
	registry := service.FromContext[adapter.DNSTransportRegistry](ctx)
	_, wrapped := registry.(dnsTransportRegistry)
	require.True(t, wrapped)
	logger := log.NewNOPFactory().NewLogger("test")

	transport, err := registry.CreateDNSTransport(ctx, logger, "system", C.DNSTypeLocal, &option.LocalDNSServerOptions{})
	require.NoError(t, err)
	assert.Equal(t, "*libbox.platformTransport", fmt.Sprintf("%T", transport))

	_, err = registry.CreateDNSTransport(ctx, logger, "ovpn-dns", C.DNSTypeOpenVPN, &option.OpenVPNDNSServerOptions{})
	assert.ErrorIs(t, err, ErrDenied)
}
