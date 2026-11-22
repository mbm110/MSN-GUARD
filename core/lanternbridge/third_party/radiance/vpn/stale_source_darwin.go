//go:build darwin

package vpn

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

// sourceProbeAddr is where the check's sockets connect. A connected UDP
// socket only selects its route and source; nothing is sent.
var sourceProbeAddr = [4]byte{1, 1, 1, 1}

const sourceDialTimeout = 2 * time.Second

// newSourceCheck returns the check for the box whose context is ctx; nil
// where there is no stale source checker. A var so tests can fake it.
var newSourceCheck = newDialerSourceCheck

// newDialerSourceCheck dials through a default dialer built from the box's
// context, so the check's socket gets the control funcs sing-box's direct
// dials get: with a platform interface, none on the default interface (no
// IP_BOUND_IF, no local address); without one, its auto-detect binding.
func newDialerSourceCheck(ctx context.Context, monitor defaultInterfaceMonitor) sourceCheckFunc {
	d, err := dialer.NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		// Then a plain socket in this process: on the platform path the same
		// unscoped lookup sing-box's sockets make.
		slog.Debug("Stale source check falling back to an unscoped socket", "error", err)
		d = nil
	}
	probe := M.SocksaddrFrom(netip.AddrFrom4(sourceProbeAddr), 53)
	dial := func(ctx context.Context) (net.Conn, error) {
		if d == nil {
			var nd net.Dialer
			return nd.DialContext(ctx, "udp4", probe.String())
		}
		return d.DialContext(ctx, "udp", probe)
	}
	return func(iface *control.Interface) sourceCheckResult {
		return checkSourceAddr(iface, dial, monitor.MyInterfaces())
	}
}

// checkSourceAddr dials with dial and compares the socket's source with
// iface's current IPv4 addresses. A source no interface holds any more is
// stale; one on the tunnel's own interfaces, or on another interface, says
// nothing about this one and is unknown.
func checkSourceAddr(iface *control.Interface, dial func(context.Context) (net.Conn, error), myInterfaces []string) sourceCheckResult {
	res := sourceCheckResult{iface: iface.Name, index: iface.Index}
	ni, err := net.InterfaceByIndex(iface.Index)
	if err != nil {
		res.source = "iface_gone"
		return res
	}
	addrs, err := interfaceIPv4s(ni)
	if err != nil {
		res.source = "addrs_error"
		return res
	}
	for _, a := range addrs {
		res.addrs = append(res.addrs, lastOctet(a))
	}
	if len(addrs) == 0 {
		res.source = "no_ipv4"
		return res
	}
	src, err := dialSource(dial)
	switch {
	case err == nil:
		res.source = lastOctet(src)
		if slices.Contains(addrs, src) {
			res.status = sourceHealthy
			return res
		}
		switch owner, err := interfaceHolding(src); {
		case err != nil:
			// Without every interface's addresses, a source missing from
			// them is no evidence it was removed.
			res.source += " lookup_error"
			return res
		case owner == "":
			res.status = sourceStale
		case slices.Contains(myInterfaces, owner):
			res.source += " tunnel"
			return res
		default:
			res.source += " other_iface"
			return res
		}
	case errors.Is(err, unix.EADDRNOTAVAIL):
		res.source = errnoClass(err)
		res.status = sourceStale
	default:
		res.source = errnoClass(err)
		return res
	}
	// Would binding to the current address, as sing-box doesn't, get past it?
	bound, err := connectBound(addrs[0])
	switch {
	case err != nil:
		res.bound = errnoClass(err)
	case bound != addrs[0]:
		res.bound = "source " + lastOctet(bound)
	default:
		res.bound = "ok"
		res.boundOK = true
	}
	return res
}

func dialSource(dial func(context.Context) (net.Conn, error)) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sourceDialTimeout)
	defer cancel()
	conn, err := dial(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = conn.Close() }()
	src := M.SocksaddrFromNet(conn.LocalAddr()).Addr.Unmap()
	if !src.IsValid() {
		return netip.Addr{}, errors.New("no local address")
	}
	return src, nil
}

// connectBound connects an unscoped UDP socket bound to local and returns
// its source address.
func connectBound(local netip.Addr) (netip.Addr, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	unix.CloseOnExec(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: local.As4()}); err != nil {
		return netip.Addr{}, err
	}
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: 53, Addr: sourceProbeAddr}); err != nil {
		return netip.Addr{}, err
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return netip.Addr{}, err
	}
	sa4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		return netip.Addr{}, errors.New("not an IPv4 socket address")
	}
	return netip.AddrFrom4(sa4.Addr), nil
}

// Vars so tests can fail the lookups.
var (
	listInterfaces = net.Interfaces
	interfaceAddrs = (*net.Interface).Addrs
)

// interfaceHolding returns the name of the interface holding addr, or ""
// when every interface's addresses were read and none holds it.
func interfaceHolding(addr netip.Addr) (string, error) {
	ifaces, err := listInterfaces()
	if err != nil {
		return "", err
	}
	for i := range ifaces {
		addrs, err := interfaceIPv4s(&ifaces[i])
		if err != nil {
			return "", err
		}
		if slices.Contains(addrs, addr) {
			return ifaces[i].Name, nil
		}
	}
	return "", nil
}

func interfaceIPv4s(ni *net.Interface) ([]netip.Addr, error) {
	ifAddrs, err := interfaceAddrs(ni)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	for _, a := range ifAddrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ipNet.IP); ok && addr.Unmap().Is4() {
			addrs = append(addrs, addr.Unmap())
		}
	}
	return addrs, nil
}

// errnoClass names err's errno, so a log line carries no address.
func errnoClass(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if name := unix.ErrnoName(errno); name != "" {
			return name
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "other"
}
