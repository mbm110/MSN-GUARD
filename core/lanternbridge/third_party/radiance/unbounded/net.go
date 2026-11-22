package unbounded

import (
	"context"
	"net"
	"sync"

	lbunbounded "github.com/getlantern/lantern-box/protocol/unbounded"
	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
)

// tunnelNet is the widget's pion Net. The widget runs in the VPN's own process, whose sockets skip
// the tunnel, but pion would still gather a candidate on the tunnel's interface and resolve TURN
// hosts through the tunnel's DNS. While a tunnel runs, each call goes to lantern-box's protected Net
// for it; with none, to the host stack as before. It looks the tunnel up on every call, so a widget
// started before the VPN connects, or kept after it disconnects, follows it without a restart.
type tunnelNet struct {
	boxCtx       func() context.Context
	newProtected func(context.Context) (transport.Net, error)
	newStd       func() (transport.Net, error)

	mu  sync.Mutex
	ctx context.Context
	net transport.Net
}

var _ transport.Net = (*tunnelNet)(nil)

func newTunnelNet(boxCtx func() context.Context) *tunnelNet {
	return &tunnelNet{
		boxCtx:       boxCtx,
		newProtected: lbunbounded.NewProtectedNet,
		newStd:       func() (transport.Net, error) { return stdnet.NewNet() },
	}
}

// current is the Net for the running tunnel, built once per tunnel, or a fresh host-stack Net with
// none (stdnet captures the interfaces when it is made). With none it drops the last tunnel's,
// which would otherwise keep that box alive until the next tunnel.
func (t *tunnelNet) current() (transport.Net, error) {
	var ctx context.Context
	if t.boxCtx != nil {
		ctx = t.boxCtx()
	}
	if ctx == nil {
		t.mu.Lock()
		t.ctx, t.net = nil, nil
		t.mu.Unlock()
		return t.newStd()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.net != nil && t.ctx == ctx {
		return t.net, nil
	}
	n, err := t.newProtected(ctx)
	if err != nil {
		return nil, err
	}
	t.ctx, t.net = ctx, n
	return n, nil
}

func (t *tunnelNet) ListenPacket(network, address string) (net.PacketConn, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.ListenPacket(network, address)
}

func (t *tunnelNet) ListenUDP(network string, laddr *net.UDPAddr) (transport.UDPConn, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.ListenUDP(network, laddr)
}

func (t *tunnelNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.ListenTCP(network, laddr)
}

func (t *tunnelNet) Dial(network, address string) (net.Conn, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.Dial(network, address)
}

func (t *tunnelNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.DialUDP(network, laddr, raddr)
}

func (t *tunnelNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.DialTCP(network, laddr, raddr)
}

func (t *tunnelNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.ResolveIPAddr(network, address)
}

func (t *tunnelNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.ResolveUDPAddr(network, address)
}

func (t *tunnelNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.ResolveTCPAddr(network, address)
}

func (t *tunnelNet) Interfaces() ([]*transport.Interface, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.Interfaces()
}

func (t *tunnelNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.InterfaceByIndex(index)
}

func (t *tunnelNet) InterfaceByName(name string) (*transport.Interface, error) {
	n, err := t.current()
	if err != nil {
		return nil, err
	}
	return n.InterfaceByName(name)
}

// CreateDialer and CreateListenConfig can't fail, so with no Net to hand them to they return ones
// whose every call fails: the host stack's would route the widget's sockets into a running tunnel.
func (t *tunnelNet) CreateDialer(d *net.Dialer) transport.Dialer {
	n, err := t.current()
	if err != nil {
		return failingDialer{err}
	}
	return n.CreateDialer(d)
}

func (t *tunnelNet) CreateListenConfig(lc *net.ListenConfig) transport.ListenConfig {
	n, err := t.current()
	if err != nil {
		return failingListenConfig{err}
	}
	return n.CreateListenConfig(lc)
}

type failingDialer struct{ err error }

func (f failingDialer) Dial(string, string) (net.Conn, error) { return nil, f.err }

type failingListenConfig struct{ err error }

func (f failingListenConfig) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, f.err
}

func (f failingListenConfig) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, f.err
}
