package bypass

import (
	"context"
	"errors"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

const (
	// ProxyPort is the port for the local bypass proxy listener.
	ProxyPort = 14985

	// BypassInboundTag is the sing-box inbound tag used for routing bypass traffic to direct.
	BypassInboundTag = "bypass-in"

	dialTimeout   = 30 * time.Second
	dialKeepAlive = 30 * time.Second
)

// proxyClient dials through the local bypass proxy. We use SOCKS5
// because sing-box's HTTP inbound returns 200 OK for CONNECT before
// the upstream connection is established, falsely signaling success
// to callers.
var proxyClient = socks.NewClient(
	proxyDialer{N.SystemDialer},
	M.ParseSocksaddrHostPort("127.0.0.1", uint16(ProxyPort)),
	socks.Version5,
	"", "",
)

// proxyDialer tags a failure to reach the local bypass proxy so DialContext can
// tell a down proxy apart from a SOCKS handshake or upstream dial failure.
type proxyDialer struct{ N.Dialer }

func (d proxyDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, &proxyUnreachable{err}
	}
	return conn, nil
}

type proxyUnreachable struct{ err error }

func (e *proxyUnreachable) Error() string { return e.err.Error() }
func (e *proxyUnreachable) Unwrap() error { return e.err }

// DialContext dials addr through the local SOCKS5 bypass proxy. It falls back to
// a direct dial only when the proxy itself is unreachable (VPN not running); a
// handshake or upstream failure propagates so the smart dialer can fail over
// rather than silently succeeding via a route that skips the proxy.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := proxyClient.DialContext(ctx, network, M.ParseSocksaddr(addr))
	if err == nil {
		return &tunneledConn{conn}, nil
	}
	var unreachable *proxyUnreachable
	if !errors.As(err, &unreachable) {
		return nil, err
	}
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: dialKeepAlive,
	}
	return dialer.DialContext(ctx, network, addr)
}

// tunneledConn masks the loopback socket to the bypass proxy so StreamDialer
// keeps it away from strategies like disorder that manipulate the target
// socket directly.
type tunneledConn struct {
	net.Conn
}

// Dial is a convenience wrapper without context, suitable for use with
// amp.WithDialer which expects func(network, addr string) (net.Conn, error).
func Dial(network, addr string) (net.Conn, error) {
	return DialContext(context.Background(), network, addr)
}
