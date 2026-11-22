//go:build darwin

package vpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/control"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultIPv4Interface returns the interface holding the source address of
// an unscoped route to the probe address, if there is one.
func defaultIPv4Interface(t *testing.T) *control.Interface {
	conn, err := net.Dial("udp4", netip.AddrPortFrom(netip.AddrFrom4(sourceProbeAddr), 53).String())
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, ni := range ifaces {
		addrs, err := interfaceIPv4s(&ni)
		require.NoError(t, err)
		for _, a := range addrs {
			if a == local {
				return &control.Interface{Name: ni.Name, Index: ni.Index}
			}
		}
	}
	return nil
}

// localAddrConn reports a chosen local address, standing in for a socket the
// kernel gave that source.
type localAddrConn struct {
	net.Conn
	local net.Addr
}

func (c localAddrConn) LocalAddr() net.Addr { return c.local }

func dialWithSource(src netip.Addr) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "udp4", netip.AddrPortFrom(netip.AddrFrom4(sourceProbeAddr), 53).String())
		if err != nil {
			return nil, err
		}
		return localAddrConn{Conn: conn, local: net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, 1234))}, nil
	}
}

// TestCheckSourceAddrDefaultInterface runs the check as a tunnel does, through
// a default dialer built from a context (here one with no box, so the
// dialer adds no binding, as on the platform path's default interface).
func TestCheckSourceAddrDefaultInterface(t *testing.T) {
	iface := defaultIPv4Interface(t)
	check := newDialerSourceCheck(context.Background(), &fakeInterfaceMonitor{})
	if iface == nil {
		res := check(&control.Interface{Name: "none", Index: 1 << 20})
		assert.Equal(t, sourceUnknown, res.status)
		t.Skip("no default IPv4 interface")
	}
	res := check(iface)
	t.Logf("iface=%s index=%d addrs=%v source=%s", res.iface, res.index, res.addrs, res.source)
	assert.Equal(t, sourceHealthy, res.status)
	assert.Contains(t, res.addrs, res.source)
	assert.Empty(t, res.bound, "the bound socket is tried only when stale")
}

func TestCheckSourceAddrClassifiesSource(t *testing.T) {
	res := checkSourceAddr(&control.Interface{Name: "gone", Index: 1 << 20}, dialWithSource(netip.MustParseAddr("192.0.2.22")), nil)
	assert.Equal(t, sourceUnknown, res.status)
	assert.Equal(t, "iface_gone", res.source)

	iface := defaultIPv4Interface(t)
	if iface == nil {
		t.Skip("no default IPv4 interface")
	}

	// A source no interface holds: the removed address.
	res = checkSourceAddr(iface, dialWithSource(netip.MustParseAddr("192.0.2.22")), nil)
	assert.Equal(t, sourceStale, res.status)
	assert.Equal(t, ".22", res.source)
	assert.Equal(t, "ok", res.bound, "an unscoped socket bound to the current address connects with it")
	assert.True(t, res.boundOK)

	// A source on the tunnel's own interface, or on another interface, is no
	// evidence about this one.
	loopback := netip.MustParseAddr("127.0.0.1")
	lo, err := interfaceHolding(loopback)
	require.NoError(t, err)
	require.NotEmpty(t, lo)
	res = checkSourceAddr(iface, dialWithSource(loopback), []string{lo})
	assert.Equal(t, sourceUnknown, res.status)
	assert.Equal(t, ".1 tunnel", res.source)
	res = checkSourceAddr(iface, dialWithSource(loopback), nil)
	assert.Equal(t, sourceUnknown, res.status)
	assert.Equal(t, ".1 other_iface", res.source)
}

// A source no interface was seen to hold is stale only when every interface's
// addresses could be read.
func TestCheckSourceAddrLookupErrors(t *testing.T) {
	iface := defaultIPv4Interface(t)
	if iface == nil {
		t.Skip("no default IPv4 interface")
	}
	prevList, prevAddrs := listInterfaces, interfaceAddrs
	t.Cleanup(func() { listInterfaces, interfaceAddrs = prevList, prevAddrs })
	removed := dialWithSource(netip.MustParseAddr("192.0.2.22"))

	listInterfaces = func() ([]net.Interface, error) { return nil, errors.New("list failed") }
	res := checkSourceAddr(iface, removed, nil)
	assert.Equal(t, sourceUnknown, res.status)
	assert.Equal(t, ".22 lookup_error", res.source)
	assert.Empty(t, res.bound)

	// Another interface's addresses can't be read.
	listInterfaces = prevList
	interfaceAddrs = func(ni *net.Interface) ([]net.Addr, error) {
		if ni.Index != iface.Index {
			return nil, errors.New("addrs failed")
		}
		return prevAddrs(ni)
	}
	res = checkSourceAddr(iface, removed, nil)
	assert.Equal(t, sourceUnknown, res.status)
	assert.Equal(t, ".22 lookup_error", res.source)

	// The default interface's own addresses can't be read.
	interfaceAddrs = func(*net.Interface) ([]net.Addr, error) { return nil, errors.New("addrs failed") }
	res = checkSourceAddr(iface, removed, nil)
	assert.Equal(t, sourceUnknown, res.status)
	assert.Equal(t, "addrs_error", res.source)
}
