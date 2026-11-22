package unbounded

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	box "github.com/getlantern/lantern-box"
	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/internal/hostaccess"
)

func exitBoxContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(box.BaseContext())
	t.Cleanup(cancel)
	return hostaccess.Context(ctx)
}

func TestNewExitBoxStartsAMinimalBox(t *testing.T) {
	b, err := newExitBox(exitBoxContext(t), `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	require.NotNil(t, b.Router())
	// RunExit checks rule sets through the router, so it must keep sing-box's lookup.
	_, ok := b.Router().(interface {
		RuleSet(tag string) (adapter.RuleSet, bool)
	})
	assert.True(t, ok, "the router must look up rule sets by tag")
	b.ResetNetwork()
}

func TestNewExitBoxRefusesHostAccess(t *testing.T) {
	_, err := newExitBox(exitBoxContext(t), `{"outbounds":[{"type":"tor","tag":"tor"},{"type":"direct","tag":"direct"}]}`)
	require.Error(t, err)
	assert.ErrorIs(t, err, hostaccess.ErrDenied)
}

func TestNewExitBoxRejectsBadJSON(t *testing.T) {
	_, err := newExitBox(exitBoxContext(t), `{`)
	require.Error(t, err)
}

func TestNewExitBoxUsesThePlatformMonitor(t *testing.T) {
	platform := &exitPlatform{}
	ctx, cancel := context.WithCancel(exitContext(platform))
	t.Cleanup(cancel)
	// RunExit forces auto_detect_interface on every exit box.
	b, err := newExitBox(ctx, `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","auto_detect_interface":true}}`)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	assert.Equal(t, int32(1), platform.monitorStarts.Load(), "the box must watch the default interface through the platform")
}

// recordingDNS is a platform's local DNS transport that records each exchange.
type recordingDNS struct{ exchanges atomic.Int32 }

func (*recordingDNS) Raw() bool { return true }
func (*recordingDNS) Lookup(*libbox.ExchangeContext, string, string) error {
	return errors.New("lookup unsupported")
}
func (d *recordingDNS) Exchange(*libbox.ExchangeContext, []byte) error {
	d.exchanges.Add(1)
	return errors.New("no answer")
}

type dnsPlatform struct {
	exitPlatform
	dns *recordingDNS
}

func (p *dnsPlatform) LocalDNSTransport() libbox.LocalDNSTransport { return p.dns }

func TestExitBoxesResolveLocalDNSThroughThePlatform(t *testing.T) {
	platform := &dnsPlatform{dns: &recordingDNS{}}
	ctx, cancel := context.WithCancel(exitContext(platform))
	t.Cleanup(cancel)
	ctx = newExitBoxContext(ctx)
	registry := service.FromContext[adapter.DNSTransportRegistry](ctx)
	require.NotNil(t, registry)
	transport, err := registry.CreateDNSTransport(ctx, sblog.NewNOPFactory().NewLogger("dns"), "local", C.DNSTypeLocal, &option.LocalDNSServerOptions{})
	require.NoError(t, err)
	msg := new(mDNS.Msg)
	msg.SetQuestion("example.com.", mDNS.TypeA)
	_, _ = transport.Exchange(ctx, msg)
	assert.Equal(t, int32(1), platform.dns.exchanges.Load(), "a local DNS server must resolve through the platform")

	// The exit's protocols and host access checks must still be there.
	_, err = newExitBox(exitContext(platform), `{"outbounds":[{"type":"tor","tag":"tor"},{"type":"direct","tag":"direct"}]}`)
	assert.ErrorIs(t, err, hostaccess.ErrDenied)
}
