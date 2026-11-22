//go:build android

package lanternbridge

// Android bans netlink sockets for unprivileged apps, so Go's own
// net.Interfaces()/net.InterfaceAddrs() fail with
// "route ip+net: netlinkrib: permission denied" on devices with a modern
// targetSdk. That leaves sing-box with an empty interface list and every
// outbound dial fails with "no available network interface". The stock
// Lantern app solves this in Kotlin via java.net.NetworkInterface, which is
// getifaddrs in bionic. This sidecar enumerates interfaces the same way,
// through getifaddrs via cgo: no netlink involved.

/*
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

struct iface_result {
	char name[IFNAMSIZ];
	int  index;
	int  flags;
	int  mtu;
	int  family;
	char addr[48];
	char mask[48];
};

static int enumerate_interfaces(struct iface_result *out, int max) {
	struct ifaddrs *ifap = NULL, *ifa;
	int n = 0;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (getifaddrs(&ifap) != 0) {
		if (fd >= 0) close(fd);
		return -1;
	}
	for (ifa = ifap; ifa != NULL && n < max; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		int family = ifa->ifa_addr->sa_family;
		if (family != AF_INET && family != AF_INET6) continue;
		struct iface_result *r = &out[n];
		memset(r, 0, sizeof(*r));
		strncpy(r->name, ifa->ifa_name, IFNAMSIZ - 1);
		r->index = if_nametoindex(ifa->ifa_name);
		r->flags = (int)ifa->ifa_flags;
		r->family = family;
		r->mtu = 0;
		if (fd >= 0) {
			struct ifreq ifr;
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
			if (ioctl(fd, SIOCGIFMTU, &ifr) == 0) {
				r->mtu = (int)ifr.ifr_mtu;
			}
		}
		const void *ap;
		const void *mp = NULL;
		if (family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
			ap = &sin->sin_addr;
			if (ifa->ifa_netmask != NULL) {
				struct sockaddr_in *min = (struct sockaddr_in *)ifa->ifa_netmask;
				mp = &min->sin_addr;
			}
		} else {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			ap = &sin6->sin6_addr;
			if (ifa->ifa_netmask != NULL) {
				struct sockaddr_in6 *min6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
				mp = &min6->sin6_addr;
			}
		}
		if (!inet_ntop(family, ap, r->addr, sizeof(r->addr))) continue;
		if (mp != NULL && !inet_ntop(family, mp, r->mask, sizeof(r->mask))) {
			r->mask[0] = 0;
		}
		n++;
	}
	freeifaddrs(ifap);
	if (fd >= 0) close(fd);
	return n;
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	box "github.com/sagernet/sing-box/experimental/libbox"

	"github.com/getlantern/radiance/vpn"
)

// androidPlatform implements radiance's vpn.PlatformInterface for the novpn
// sidecar. The stock Android app supplies this from Kotlin over gomobile; the
// sidecar cannot, and without it sing-box tries to create a netlink network
// monitor, which Android bans for unprivileged apps
// ("netlink socket in Android is banned by Google"). Providing the platform
// interface routes interface monitoring through StartDefaultInterfaceMonitor
// instead.
type androidPlatform struct {
	stop chan struct{}
}

var _ vpn.PlatformInterface = (*androidPlatform)(nil)

func newPlatformInterface() vpn.PlatformInterface {
	return &androidPlatform{stop: make(chan struct{})}
}

// Radiance lifecycle hooks (vpn.PlatformInterface additions).

func (p *androidPlatform) RestartService() error { return nil }
func (p *androidPlatform) PostServiceClose()     {}

// platformLog writes diagnostics the app's sidecar log filter forwards: the
// Kotlin filter only passes lines containing error/warn/connected.
func platformLog(message string) {
	fmt.Fprintln(os.Stderr, "lantern/platform warn: "+message)
}

type rawInterface struct {
	Name  string
	Index int
	MTU   int
	Flags uint32
	Addrs []*net.IPNet
}

const (
	ifaceFlagUp       = 1 << 0 // IFF_UP
	ifaceFlagLoopback = 1 << 3 // IFF_LOOPBACK
)

// enumerateInterfaces lists interfaces via bionic getifaddrs. This is the
// same source java.net.NetworkInterface uses, and it works without netlink.
func enumerateInterfaces() ([]rawInterface, error) {
	var arr [64]C.struct_iface_result
	n := int(C.enumerate_interfaces(&arr[0], C.int(len(arr))))
	if n < 0 {
		return nil, errors.New("getifaddrs failed")
	}
	byName := make(map[string]*rawInterface, n)
	var order []string
	for i := 0; i < n; i++ {
		r := &arr[i]
		name := C.GoString(&r.name[0])
		ip := net.ParseIP(C.GoString(&r.addr[0]))
		if ip == nil {
			continue
		}
		var mask net.IPMask
		if maskStr := C.GoString(&r.mask[0]); maskStr != "" {
			maskIP := net.ParseIP(maskStr)
			if maskIP != nil {
				mask = net.IPMask(maskIP.To16())
			}
		}
		if mask == nil {
			if v4 := ip.To4(); v4 != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
		}
		entry, ok := byName[name]
		if !ok {
			entry = &rawInterface{Name: name, Index: int(r.index), MTU: int(r.mtu), Flags: uint32(r.flags)}
			byName[name] = entry
			order = append(order, name)
		}
		entry.Addrs = append(entry.Addrs, &net.IPNet{IP: ip, Mask: mask})
	}
	result := make([]rawInterface, 0, len(order))
	for _, name := range order {
		result = append(result, *byName[name])
	}
	return result, nil
}

// isTunnelInterface guards against binding outbounds to the VPN's own TUN,
// which would loop traffic back through the proxy chain. Matches the stock
// Android client, whose GetInterfaces also excludes the VPN TUN.
func isTunnelInterface(name string) bool {
	return strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap")
}

func (raw *rawInterface) isUsable() bool {
	return raw.Flags&ifaceFlagUp != 0 &&
		raw.Flags&ifaceFlagLoopback == 0 &&
		!isTunnelInterface(raw.Name)
}

func (raw *rawInterface) hasIPv4() bool {
	for _, addr := range raw.Addrs {
		if addr.IP.To4() != nil && !addr.IP.IsLoopback() && !addr.IP.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// Default-interface monitoring: report a real egress interface, then re-check
// periodically so Wi-Fi/mobile switches are picked up.
func (p *androidPlatform) StartDefaultInterfaceMonitor(listener box.InterfaceUpdateListener) error {
	platformLog("interface monitor starting")
	// Report the first result synchronously: the router dispatches its
	// initial interface update right after box start, and every outbound
	// dial fails while DefaultInterface() is nil.
	last := int32(-1)
	if ifIndex, name, ok, detail := detectDefaultInterface(); ok {
		listener.UpdateDefaultInterface(name, ifIndex, false, false)
		last = ifIndex
		platformLog("initial default interface: " + name)
	} else {
		platformLog("initial detection failed: " + detail)
	}
	go func() {
		for {
			if ifIndex, name, ok, detail := detectDefaultInterface(); ok {
				if ifIndex != last {
					listener.UpdateDefaultInterface(name, ifIndex, false, false)
					platformLog("default interface changed: " + name)
					last = ifIndex
				}
			} else if last == -1 {
				// Only complain while we have nothing to report; once a
				// working interface is known, transient probe failures are
				// not worth logging every poll.
				platformLog("detection failed: " + detail)
			}
			select {
			case <-p.stop:
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()
	return nil
}

func detectDefaultInterface() (int32, string, bool, string) {
	ifaces, err := enumerateInterfaces()
	if err != nil {
		return -1, "", false, "enumerate interfaces: " + err.Error()
	}
	// TEST-NET / real-target UDP connects: the kernel resolves the route and
	// source address without emitting a packet, and without netlink. The
	// VPN's own TUN does not apply to this app (the service excludes its own
	// package), so this is the physical default route.
	for _, target := range []string{"192.0.2.1:53", "198.51.100.1:53", "8.8.8.8:53"} {
		conn, err := net.Dial("udp", target)
		if err != nil {
			continue
		}
		local := conn.LocalAddr().(*net.UDPAddr).IP
		_ = conn.Close()
		for i := range ifaces {
			iface := &ifaces[i]
			if !iface.isUsable() {
				continue
			}
			for _, addr := range iface.Addrs {
				if addr.IP.Equal(local) {
					return int32(iface.Index), iface.Name, true, ""
				}
			}
		}
	}
	// No usable kernel route (offline, or restricted routing): still report
	// the best physical candidate so outbounds have an interface to bind to
	// instead of failing every dial with ErrNoRoute.
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.isUsable() && iface.hasIPv4() {
			return int32(iface.Index), iface.Name, true, "fallback: " + iface.Name
		}
	}
	return -1, "", false, "no up non-tunnel interface with an IPv4 address"
}

func (p *androidPlatform) CloseDefaultInterfaceMonitor(box.InterfaceUpdateListener) error {
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	return nil
}

// GetInterfaces feeds sing-box's NetworkInterfaces() path: the outbound
// dialer picks the egress interface from this list (selectInterfaces), so it
// must be populated even though Go's net.Interfaces() is banned on Android.
func (p *androidPlatform) GetInterfaces() (box.NetworkInterfaceIterator, error) {
	ifaces, err := enumerateInterfaces()
	if err != nil {
		return nil, err
	}
	items := make([]*box.NetworkInterface, 0, len(ifaces))
	for i := range ifaces {
		iface := &ifaces[i]
		var addrs []string
		for _, addr := range iface.Addrs {
			addrs = append(addrs, addr.String())
		}
		items = append(items, &box.NetworkInterface{
			Index:     int32(iface.Index),
			MTU:       int32(iface.MTU),
			Name:      iface.Name,
			Addresses: newStringIterator(addrs),
			Flags:     int32(iface.Flags),
			Type:      interfaceType(iface.Name),
		})
	}
	return &networkInterfaceIterator{items: items}, nil
}

func interfaceType(name string) int32 {
	switch {
	case strings.HasPrefix(name, "wlan"), name == "eth0":
		return box.InterfaceTypeWIFI
	case strings.HasPrefix(name, "rmnet"), strings.HasPrefix(name, "ccmni"),
		strings.HasPrefix(name, "usb"):
		return box.InterfaceTypeCellular
	default:
		return box.InterfaceTypeOther
	}
}

type networkInterfaceIterator struct {
	items []*box.NetworkInterface
	next  int
}

func (i *networkInterfaceIterator) HasNext() bool { return i.next < len(i.items) }

func (i *networkInterfaceIterator) Next() *box.NetworkInterface {
	if !i.HasNext() {
		return nil
	}
	item := i.items[i.next]
	i.next++
	return item
}

type stringIterator struct {
	values []string
	next   int
}

var _ box.StringIterator = (*stringIterator)(nil)

func newStringIterator(values []string) *stringIterator { return &stringIterator{values: values} }

func (s *stringIterator) Len() int32    { return int32(len(s.values)) }
func (s *stringIterator) HasNext() bool { return s.next < len(s.values) }

func (s *stringIterator) Next() string {
	if !s.HasNext() {
		return ""
	}
	value := s.values[s.next]
	s.next++
	return value
}

// The remaining surface is unused by the novpn build; stubs keep the tunnel
// constructor on its platform path without pulling in Android runtime APIs.

var errUnsupported = errors.New("unsupported by the Lantern sidecar platform")

func (p *androidPlatform) LocalDNSTransport() box.LocalDNSTransport { return nil }
func (p *androidPlatform) UsePlatformAutoDetectInterfaceControl() bool {
	return false
}
func (p *androidPlatform) AutoDetectInterfaceControl(fd int32) error { return nil }
// OpenTun is the official-app data path, reference semantics: sing-tun calls
// this DURING the tunnel start, and the platform answers with a freshly
// established VpnService fd built from the ENGINE'S OWN TunOptions — exactly
// what getlantern/lantern's LanternVpnService.openTun does with
// createVPNBuilder(tunOptions). The split-process twin relays the serialized
// options over the handoff socket; the app mirrors createVPNBuilder,
// closes any previous interface first (the reference's stale-descriptor
// comment), establish()es and returns the fd via SCM_RIGHTS.
func (p *androidPlatform) OpenTun(options box.TunOptions) (int32, error) {
	payload, err := serializeTunOptions(options)
	if err != nil {
		platformLog("tun handoff refused: " + err.Error())
		return -1, err
	}
	fd, err := requestTun(payload, 120*time.Second)
	if err != nil {
		platformLog("tun handoff refused: " + err.Error())
		return -1, err
	}
	platformLog(fmt.Sprintf("tun handoff: passing fd %d to sing-box (mtu=%d auto-route=%v)",
		fd, options.GetMTU(), options.GetAutoRoute()))
	return int32(fd), nil
}

// tunRequestOptions is the OPEN payload the app's Builder mirror consumes —
// the exact field set the reference's createVPNBuilder reads from TunOptions.
type tunRequestOptions struct {
	MTU           int32    `json:"mtu"`
	Inet4Address  []string `json:"inet4_address"`  // "10.10.1.1/30"
	Inet6Address  []string `json:"inet6_address"`  // "fdfe:dcba:9876::1/126"
	AutoRoute     bool     `json:"auto_route"`
	DNSServers    []string `json:"dns_servers"`
	Routes4       []string `json:"routes4"`        // inet4_route_address
	Routes6       []string `json:"routes6"`        // inet6_route_address
	Excludes4     []string `json:"excludes4"`      // inet4_route_exclude_address
	Excludes6     []string `json:"excludes6"`      // inet6_route_exclude_address
	RouteRanges4  []string `json:"route_ranges4"`  // pre-TIRAMISU fallback
	RouteRanges6  []string `json:"route_ranges6"`
}

func serializeTunOptions(options box.TunOptions) ([]byte, error) {
	req := tunRequestOptions{
		MTU:       options.GetMTU(),
		AutoRoute: options.GetAutoRoute(),
	}
	var err error
	if req.Inet4Address, err = routePrefixes(options.GetInet4Address()); err != nil {
		return nil, err
	}
	if req.Inet6Address, err = routePrefixes(options.GetInet6Address()); err != nil {
		return nil, err
	}
	if req.Routes4, err = routePrefixes(options.GetInet4RouteAddress()); err != nil {
		return nil, err
	}
	if req.Routes6, err = routePrefixes(options.GetInet6RouteAddress()); err != nil {
		return nil, err
	}
	if req.Excludes4, err = routePrefixes(options.GetInet4RouteExcludeAddress()); err != nil {
		return nil, err
	}
	if req.Excludes6, err = routePrefixes(options.GetInet6RouteExcludeAddress()); err != nil {
		return nil, err
	}
	if req.RouteRanges4, err = routePrefixes(options.GetInet4RouteRange()); err != nil {
		return nil, err
	}
	if req.RouteRanges6, err = routePrefixes(options.GetInet6RouteRange()); err != nil {
		return nil, err
	}
	if dnsIter, dnsErr := options.GetDNSServerAddress(); dnsErr == nil {
		for it := dnsIter; it.HasNext(); {
			req.DNSServers = append(req.DNSServers, it.Next())
		}
	}
	return json.Marshal(req)
}

func routePrefixes(iter box.RoutePrefixIterator) ([]string, error) {
	var out []string
	for iter.HasNext() {
		prefix := iter.Next()
		if prefix == nil {
			continue
		}
		out = append(out, prefix.String())
	}
	return out, nil
}
func (p *androidPlatform) UseProcFS() bool { return false }
func (p *androidPlatform) FindConnectionOwner(int32, string, int32, string, int32) (*box.ConnectionOwner, error) {
	return nil, errUnsupported
}
func (p *androidPlatform) UnderNetworkExtension() bool   { return false }
func (p *androidPlatform) IncludeAllNetworks() bool      { return false }
func (p *androidPlatform) ReadWIFIState() *box.WIFIState { return nil }
func (p *androidPlatform) ClearDNSCache()                {}
func (p *androidPlatform) SendNotification(*box.Notification) error {
	return errUnsupported
}
func (p *androidPlatform) CancelNotification(string, int32) error { return nil }
func (p *androidPlatform) StartNeighborMonitor(box.NeighborUpdateListener) error {
	return errUnsupported
}
func (p *androidPlatform) CloseNeighborMonitor(box.NeighborUpdateListener) error {
	return nil
}
func (p *androidPlatform) RegisterMyInterface(string) {}
func (p *androidPlatform) UsePlatformShell() bool      { return false }
func (p *androidPlatform) CheckPlatformShell() error   { return errUnsupported }
func (p *androidPlatform) OpenShellSession(*box.PlatformUser, string, box.StringIterator, string, int32, int32) (box.ShellSession, error) {
	return nil, errUnsupported
}
func (p *androidPlatform) LookupUser(string) (*box.PlatformUser, error) {
	return nil, errUnsupported
}
func (p *androidPlatform) LookupSFTPServer() (string, error)     { return "", errUnsupported }
func (p *androidPlatform) ReadSystemSSHHostKey() (string, error) { return "", errUnsupported }
func (p *androidPlatform) TailscaleHostname() string             { return "" }
func (p *androidPlatform) UsePlatformBridge() bool               { return false }
func (p *androidPlatform) CreateBridge(*box.BridgeOptions) (box.BridgeSession, error) {
	return nil, errUnsupported
}
