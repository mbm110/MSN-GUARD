package bypass

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

// generation counts bypass-proxy starts and stops, so long-lived packet conns
// know when to re-pick their route.
var generation atomic.Uint64

// ProxyStateChanged tells packet conns from ListenPacket that the bypass proxy
// came up or went down. The tunnel calls it after the proxy starts and after it
// stops; the conns switch route on their next write.
func ProxyStateChanged() { generation.Add(1) }

const (
	reopenBackoff = time.Second
	// reopenTimeout bounds a replacement association's handshake with the local
	// proxy, which answers in milliseconds unless it is wedged.
	reopenTimeout = 5 * time.Second
	// proxyProbeInterval paces checks, while sending on a plain socket, for a
	// bypass proxy that came up unannounced: one started by another process
	// (a mobile VPN extension) never reaches ProxyStateChanged here.
	proxyProbeInterval = 5 * time.Second
)

// ListenPacket returns a UDP PacketConn that stays outside the VPN tunnel. While
// the bypass proxy runs it relays through a SOCKS5 UDP association; otherwise it
// is a plain socket. Unlike a dialed stream, it outlives VPN starts and stops,
// re-picking its route whenever the proxy state changes or its association dies.
func ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	c := &packetConn{network: network, address: address}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if err := c.reopen(ctx, nil); err != nil {
		c.cancel()
		return nil, err
	}
	return c, nil
}

type packetConn struct {
	network, address string
	ctx              context.Context // canceled by Close, ending any reopen
	cancel           context.CancelFunc

	mu          sync.Mutex
	cur         net.PacketConn
	gen         uint64
	closed      bool
	reopening   bool
	lastAttempt time.Time
	direct      bool // cur is a plain socket, not an association
	lastProbe   time.Time
	// Deadlines carry over to replacement conns.
	readDeadline, writeDeadline time.Time
}

func (c *packetConn) current() (net.PacketConn, uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur, c.gen, c.closed
}

// reopen replaces old (nil for the first open) with a conn routed for the
// proxy's current state, unless another goroutine already replaced it.
func (c *packetConn) reopen(ctx context.Context, old net.PacketConn) error {
	gen := generation.Load()
	pc, proxied, err := openPacket(ctx, c.network, c.address)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if closed := c.closed; closed || c.cur != old {
		c.mu.Unlock()
		pc.Close()
		if closed {
			return net.ErrClosed
		}
		return nil
	}
	pc.SetReadDeadline(c.readDeadline)
	pc.SetWriteDeadline(c.writeDeadline)
	c.cur, c.gen, c.direct, c.lastProbe = pc, gen, !proxied, time.Now()
	c.mu.Unlock()
	if old != nil {
		old.Close() // unblocks ReadFrom, which moves to the new conn
	}
	return nil
}

// reopenContext bounds a reopen by Close, reopenTimeout, and deadline if set.
func (c *packetConn) reopenContext(deadline time.Time) (context.Context, context.CancelFunc) {
	d := time.Now().Add(reopenTimeout)
	if !deadline.IsZero() && deadline.Before(d) {
		d = deadline
	}
	return context.WithDeadline(c.ctx, d)
}

// switchRoute reopens old in the background, one attempt at a time, so a write
// never waits on the proxy: callers like Soar write while holding their own lock.
func (c *packetConn) switchRoute(old net.PacketConn) {
	c.mu.Lock()
	if c.closed || c.reopening || time.Since(c.lastAttempt) < reopenBackoff {
		c.mu.Unlock()
		return
	}
	c.reopening, c.lastAttempt = true, time.Now()
	c.mu.Unlock()
	go func() {
		ctx, cancel := c.reopenContext(time.Time{})
		defer cancel()
		c.reopen(ctx, old)
		c.mu.Lock()
		c.reopening = false
		c.mu.Unlock()
	}()
}

// WriteTo sends on the current conn. After a proxy state change, or when the
// conn fails, it starts the switch; meanwhile packets go out the old route or
// fail, which callers see as ordinary loss.
func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	pc, gen, closed := c.current()
	if closed {
		return 0, net.ErrClosed
	}
	if gen != generation.Load() {
		c.switchRoute(pc)
	} else if c.probeDue() {
		go func() {
			if proxyListening(c.ctx) {
				c.switchRoute(pc)
			}
		}()
	}
	n, err := pc.WriteTo(p, addr)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return n, err
		}
		c.switchRoute(pc) // the association died under us
	}
	return n, err
}

// probeDue reports, at most once per proxyProbeInterval, that a plain socket
// should check whether the bypass proxy has come up.
func (c *packetConn) probeDue() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.direct || c.closed || time.Since(c.lastProbe) < proxyProbeInterval {
		return false
	}
	c.lastProbe = time.Now()
	return true
}

func proxyListening(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ProxyPort)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		pc, _, closed := c.current()
		if closed {
			return 0, nil, net.ErrClosed
		}
		n, addr, err := pc.ReadFrom(p)
		if err == nil {
			return n, addr, nil
		}
		if next, _, closed := c.current(); closed {
			return 0, nil, net.ErrClosed
		} else if next != pc {
			continue // swapped under us
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return 0, nil, err
		}
		// The association died (proxy stopped or idled it out) or the socket
		// failed: route afresh, backing off so a dead network doesn't spin.
		c.mu.Lock()
		deadline := c.readDeadline
		c.mu.Unlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		ctx, cancel := c.reopenContext(deadline)
		err = c.reopen(ctx, pc)
		cancel()
		if err != nil {
			wait := reopenBackoff
			if !deadline.IsZero() {
				wait = min(wait, time.Until(deadline))
			}
			select {
			case <-c.ctx.Done():
			case <-time.After(wait):
			}
		}
	}
}

func (c *packetConn) Close() error {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.cur.Close()
}

func (c *packetConn) LocalAddr() net.Addr {
	pc, _, _ := c.current()
	return pc.LocalAddr()
}

func (c *packetConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline, c.writeDeadline = t, t
	return c.cur.SetDeadline(t)
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return c.cur.SetReadDeadline(t)
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return c.cur.SetWriteDeadline(t)
}

// openPacket associates through the bypass proxy, or, when the proxy isn't
// listening (VPN not running), opens a plain socket.
func openPacket(ctx context.Context, network, address string) (pc net.PacketConn, proxied bool, err error) {
	pc, err = associate(ctx)
	if err == nil {
		return pc, true, nil
	}
	var unreachable *proxyUnreachable
	if !errors.As(err, &unreachable) {
		return nil, false, err
	}
	var lc net.ListenConfig
	pc, err = lc.ListenPacket(ctx, network, address)
	return pc, false, err
}

// associate opens a SOCKS5 UDP association. Its lifetime is the control TCP
// conn's, so a watcher closes the UDP side when the proxy hangs up.
func associate(ctx context.Context) (net.PacketConn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	server := M.ParseSocksaddrHostPort("127.0.0.1", uint16(ProxyPort))
	tcp, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, &proxyUnreachable{err}
	}
	if deadline, ok := ctx.Deadline(); ok {
		tcp.SetDeadline(deadline)
	}
	// The handshake blocks on the socket, not ctx: a cancel (Close) closes it.
	stop := context.AfterFunc(ctx, func() { tcp.Close() })
	resp, err := socks.ClientHandshake5(tcp, socks5.CommandUDPAssociate, M.Socksaddr{}, "", "")
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		tcp.Close()
		return nil, err
	}
	tcp.SetDeadline(time.Time{})
	bind := resp.Bind
	if !bind.Addr.IsValid() || bind.Addr.IsUnspecified() {
		bind.Addr = server.Addr
	}
	udp, err := (&net.Dialer{}).DialContext(ctx, "udp", bind.String())
	if err != nil {
		tcp.Close()
		return nil, err
	}
	go func() {
		io.Copy(io.Discard, tcp)
		udp.Close()
	}()
	return associatedConn{socks.NewAssociatePacketConn(udp, M.Socksaddr{}, tcp), udp}, nil
}

// associatedConn keeps the SOCKS5 UDP header out of what the caller sees:
// AssociatePacketConn counts it in writes and decodes into the caller's buffer.
type associatedConn struct {
	*socks.AssociatePacketConn
	udp net.Conn // the association's relay socket, read directly
}

const socksUDPHeadroom = 3 + M.MaxSocksaddrLength

var readBufs = sync.Pool{New: func() any { return new([]byte) }}

// WriteTo reports the payload written, not the payload plus SOCKS header.
func (c associatedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if _, err := c.AssociatePacketConn.WriteTo(p, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c associatedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bp := readBufs.Get().(*[]byte)
	defer readBufs.Put(bp)
	if need := len(p) + socksUDPHeadroom; cap(*bp) < need {
		*bp = make([]byte, need)
	}
	buf := (*bp)[:len(p)+socksUDPHeadroom]
	// Decoded here rather than by AssociatePacketConn.ReadFrom, which records each sender in a
	// shared field and so races under concurrent reads.
	n, err := c.udp.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < 3 {
		return 0, nil, socks.ErrInvalidPacket
	}
	r := bytes.NewReader(buf[3:n])
	from, err := M.SocksaddrSerializer.ReadAddrPort(r)
	if err != nil {
		return 0, nil, err
	}
	return copy(p, buf[n-r.Len():n]), from.UDPAddr(), nil
}
