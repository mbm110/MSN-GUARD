//go:build !novpn

package vpn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	box "github.com/getlantern/lantern-box"
	"github.com/miekg/dns"
	sbox "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/bypass"
	"github.com/getlantern/radiance/internal/testutil"
)

// fakeResolver echoes each packet back prefixed with its name, and reports the
// source each packet arrived from.
type fakeResolver struct {
	name string
	pc   net.PacketConn
	seen chan seenPacket
}

type seenPacket struct {
	from    *net.UDPAddr
	payload []byte
}

func newFakeResolver(t *testing.T, name string) *fakeResolver {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { pc.Close() })
	r := &fakeResolver{name: name, pc: pc, seen: make(chan seenPacket, 16)}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			r.seen <- seenPacket{from.(*net.UDPAddr), append([]byte(nil), buf[:n]...)}
			pc.WriteTo(append([]byte(name), buf[:n]...), from)
		}
	}()
	return r
}

// startBypassBox runs sing-box with the tunnel build's bypass inbound and real
// routing rules, minus the TUN device, which needs root.
func startBypassBox(t *testing.T) *sbox.Box {
	loopback := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	opts := O.Options{
		Log: &O.LogOptions{Disabled: true},
		DNS: &O.DNSOptions{RawDNSOptions: O.RawDNSOptions{
			Servers: []O.DNSServerOptions{{Tag: "dns_local", Type: C.DNSTypeLocal, Options: &O.LocalDNSServerOptions{}}},
			Final:   "dns_local",
		}},
		Inbounds: []O.Inbound{{
			Type: C.TypeMixed,
			Tag:  bypass.BypassInboundTag,
			Options: &O.HTTPMixedInboundOptions{ListenOptions: O.ListenOptions{
				Listen:     &loopback,
				ListenPort: bypass.ProxyPort,
			}},
		}},
		Outbounds: []O.Outbound{
			{Type: C.TypeDirect, Tag: "direct", Options: &O.DirectOutboundOptions{}},
			{Type: C.TypeBlock, Tag: "block", Options: &O.StubOptions{}},
		},
		Route: &O.RouteOptions{
			Rules:   append(baseRoutingRules(), catchAllBlockerRule()),
			RuleSet: splitTunnelRuleSet(t.TempDir()),
		},
	}
	instance, err := sbox.New(sbox.Options{Context: box.Context(context.Background()), Options: opts})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	bypass.ProxyStateChanged()
	return instance
}

func stopBypassBox(t *testing.T, b *sbox.Box) {
	require.NoError(t, b.Close())
	bypass.ProxyStateChanged()
}

// exchange sends a TXT query to each resolver until one leaves by the wanted
// route (proxied or direct; the conn switches in the background), and checks it
// arrives byte for byte (not answered by sing-box's DNS hijack) and the reply
// comes back from the right address.
func exchange(t *testing.T, pc net.PacketConn, wantProxied bool, resolvers ...*fakeResolver) {
	for i, r := range resolvers {
		q := new(dns.Msg)
		q.SetQuestion(fmt.Sprintf("q%d.t.example.com.", i), dns.TypeTXT)
		q.Id = uint16(i + 1)
		wire, err := q.Pack()
		require.NoError(t, err)
		to := r.pc.LocalAddr().(*net.UDPAddr)

		require.Eventually(t, func() bool {
			// The route can switch in the background mid-attempt, so a packet from either
			// socket (before the send or after the reply) left directly; only the proxy's
			// outbound socket is neither.
			before := pc.LocalAddr().(*net.UDPAddr).Port
			if _, err := pc.WriteTo(wire, to); err != nil {
				return false // lost while the route switches
			}
			select {
			case got := <-r.seen:
				if !assert.Equal(t, wire, got.payload, "query altered in transit") {
					return false
				}
				after := pc.LocalAddr().(*net.UDPAddr).Port
				direct := got.from.Port == before || got.from.Port == after
				return direct != wantProxied
			case <-time.After(200 * time.Millisecond):
				return false
			}
		}, 5*time.Second, 10*time.Millisecond, "query to %s never left by the wanted route", r.name)

		buf := make([]byte, 2048)
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
		for {
			n, from, err := pc.ReadFrom(buf)
			require.NoError(t, err)
			if string(buf[:n]) != r.name+string(wire) {
				continue // a reply to a retry above
			}
			require.Equal(t, to.String(), from.String())
			break
		}
		require.NoError(t, pc.SetReadDeadline(time.Time{}))
	}
}

func TestBypassUDPFollowsProxy(t *testing.T) {
	t.Cleanup(testutil.LockBypassPort())
	if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bypass.ProxyPort)); err != nil {
		t.Skipf("bypass port busy (VPN running?): %v", err)
	} else {
		l.Close()
	}
	a, b := newFakeResolver(t, "a"), newFakeResolver(t, "b")

	// Opened before the VPN: a plain socket.
	pc, err := bypass.ListenPacket(context.Background(), "udp", ":0")
	require.NoError(t, err)
	defer pc.Close()
	exchange(t, pc, false, a, b)

	// VPN up: the same conn moves into a UDP association, and DNS-shaped
	// packets reach the resolvers untouched rather than being hijacked.
	instance := startBypassBox(t)
	exchange(t, pc, true, a, b)

	// VPN down: back to a plain socket.
	stopBypassBox(t, instance)
	exchange(t, pc, false, a, b)

	// And up again.
	instance = startBypassBox(t)
	defer stopBypassBox(t, instance)
	exchange(t, pc, true, a, b)
}
