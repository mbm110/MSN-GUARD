//go:build android

package lanternbridge

import (
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
// instead, which we implement in pure Go.
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

// Default-interface monitoring: detect the real egress interface with a UDP
// connect (no packet leaves the device) and report it, then re-check
// periodically so Wi-Fi/mobile switches are picked up.
func (p *androidPlatform) StartDefaultInterfaceMonitor(listener box.InterfaceUpdateListener) error {
	platformLog("interface monitor starting")
	// Report the first result synchronously: the router dispatches its
	// initial interface update right after box start, and every outbound
	// dial fails with tun.ErrNoRoute while DefaultInterface() is nil.
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

func platformLog(message string) {
	// Sidecar stderr is piped into the app connection log.
	fmt.Fprintln(os.Stderr, "lantern/platform: "+message)
}

func detectDefaultInterface() (int32, string, bool, string) {
	// TEST-NET / real-target UDP connects: the kernel resolves the route and
	// source address without emitting a packet. The VPN's own TUN does not
	// apply to this app (the service excludes its own package), so this is
	// the physical default route.
	ifaces, err := net.Interfaces()
	if err != nil {
		return -1, "", false, "enumerate interfaces: " + err.Error()
	}
	for _, target := range []string{"192.0.2.1:53", "198.51.100.1:53", "8.8.8.8:53"} {
		conn, err := net.Dial("udp", target)
		if err != nil {
			continue
		}
		local := conn.LocalAddr().(*net.UDPAddr).IP
		_ = conn.Close()
		for _, ifce := range ifaces {
			if ifce.Flags&net.FlagUp == 0 || ifce.Flags&net.FlagLoopback != 0 {
				continue
			}
			if isTunnelInterface(ifce.Name) {
				// Binding outbound dials to the VPN TUN would loop traffic
				// back through the proxy chain. Skip it even if the kernel
				// currently routes via TUN (exclusion misconfig); the
				// physical-interface fallback below takes over.
				continue
			}
			addrs, err := ifce.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				if ipNet.IP.Equal(local) {
					return int32(ifce.Index), ifce.Name, true, ""
				}
			}
		}
	}
	// No usable kernel route (offline, or restricted routing): still report
	// the best physical candidate so outbounds have an interface to bind to
	// instead of failing every dial with ErrNoRoute.
	for _, ifce := range ifaces {
		if ifce.Flags&net.FlagUp == 0 || ifce.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isTunnelInterface(ifce.Name) {
			continue
		}
		addrs, err := ifce.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				return int32(ifce.Index), ifce.Name, true, "fallback: " + ifce.Name
			}
		}
	}
	return -1, "", false, "no up non-tunnel interface with an IPv4 address"
}

// isTunnelInterface guards against binding outbounds to the VPN's own TUN.
func isTunnelInterface(name string) bool {
	return strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap")
}

func (p *androidPlatform) CloseDefaultInterfaceMonitor(box.InterfaceUpdateListener) error {
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	return nil
}

// GetInterfaces feeds sing-box's NetworkInterfaces() path, which the wrapper
// reaches whenever the reported default interface changes.
func (p *androidPlatform) GetInterfaces() (box.NetworkInterfaceIterator, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	items := make([]*box.NetworkInterface, 0, len(ifaces))
	for _, ifce := range ifaces {
		var addrs []string
		if list, err := ifce.Addrs(); err == nil {
			for _, addr := range list {
				addrs = append(addrs, addr.String())
			}
		}
		items = append(items, &box.NetworkInterface{
			Index:     int32(ifce.Index),
			MTU:       int32(ifce.MTU),
			Name:      ifce.Name,
			Addresses: newStringIterator(addrs),
			Flags:     int32(uint32(ifce.Flags)),
			Type:      interfaceType(ifce.Name),
		})
	}
	return &networkInterfaceIterator{items: items}, nil
}

func interfaceType(name string) int32 {
	switch {
	case len(name) >= 4 && name[:4] == "wlan", len(name) >= 4 && name[:4] == "eth0":
		return box.InterfaceTypeWIFI
	case len(name) >= 5 && name[:5] == "rmnet", len(name) >= 5 && name[:5] == "ccmni",
		len(name) >= 3 && name[:3] == "usb":
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
func (p *androidPlatform) OpenTun(box.TunOptions) (int32, error) {
	return -1, errUnsupported
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
func (p *androidPlatform) LookupSFTPServer() (string, error)      { return "", errUnsupported }
func (p *androidPlatform) ReadSystemSSHHostKey() (string, error) { return "", errUnsupported }
func (p *androidPlatform) TailscaleHostname() string              { return "" }
func (p *androidPlatform) UsePlatformBridge() bool                { return false }
func (p *androidPlatform) CreateBridge(*box.BridgeOptions) (box.BridgeSession, error) {
	return nil, errUnsupported
}
