package common

import (
	"fmt"
	"net"
)

// isGlobalIPv6 reports whether ip is in 2000::/3. Not net.IP.IsGlobalUnicast,
// which also accepts ULA — ULA-only interfaces (Tailscale, corp VPNs) don't
// indicate real public-v6 connectivity. Reserved-but-in-range prefixes like
// 2001:db8::/32 (documentation) and 2002::/16 (6to4) still return true; their
// presence on a real interface still signals "system is configured for v6".
func isGlobalIPv6(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	// 2000::/3: first three bits are 001, first-byte mask 0xe0 == 0x20.
	return ip16[0]&0xe0 == 0x20
}

// ifaceSnapshot is the test seam: the data HasGlobalIPv6 reads per interface,
// decoupled from net.Interface so tests can simulate any network config.
type ifaceSnapshot struct {
	name  string
	flags net.Flags
	addrs []net.Addr
}

func snapshotInterfaces() ([]ifaceSnapshot, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces: %w", err)
	}
	out := make([]ifaceSnapshot, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			addrs = nil
		}
		out = append(out, ifaceSnapshot{name: iface.Name, flags: iface.Flags, addrs: addrs})
	}
	return out, nil
}

// HasGlobalIPv6 reports whether the device has an up, non-loopback interface
// carrying an IPv6 address in 2000::/3. It does not verify routing or internet
// connectivity.
func HasGlobalIPv6() bool {
	return hasGlobalIPv6Using(snapshotInterfaces)
}

// hasGlobalIPv6Using is HasGlobalIPv6 with an injectable interface source; it
// returns false if getSnapshots fails.
func hasGlobalIPv6Using(getSnapshots func() ([]ifaceSnapshot, error)) bool {
	snaps, err := getSnapshots()
	if err != nil {
		return false
	}
	for _, s := range snaps {
		if s.flags&net.FlagUp == 0 || s.flags&net.FlagLoopback != 0 {
			continue
		}
		for _, a := range s.addrs {
			// Addrs() may return *net.IPNet or *net.IPAddr depending on platform.
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if isGlobalIPv6(ip) {
				return true
			}
		}
	}
	return false
}
