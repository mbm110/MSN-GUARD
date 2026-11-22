package common

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsGlobalIPv6(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		// Inside 2000::/3 — predicate returns true regardless of whether
		// the specific sub-prefix is globally routable in practice.
		// Real-world global unicast:
		{"comcast global", "2603:8000:d0f0:5950::1", true},
		{"google global", "2607:f8b0:4006:80b::200e", true},
		{"cloudflare global", "2606:4700::1111", true},
		// Reserved-but-in-range — predicate returns true; see isGlobalIPv6
		// docstring for why we accept these.
		{"documentation prefix (2001:db8::/32, reserved)", "2001:db8::1", true},
		{"6to4 (2002::/16, deprecated)", "2002:c612:1::1", true},

		// Outside 2000::/3 — predicate returns false.
		{"link-local", "fe80::1", false},
		{"ULA fc", "fc00::1", false},
		{"ULA fd", "fdfe:dcba:9876::1", false},
		{"loopback", "::1", false},
		{"unspecified", "::", false},
		{"multicast", "ff02::1", false},

		// IPv4 in any representation — predicate returns false.
		{"ipv4 private", "192.168.1.1", false},
		{"ipv4 public", "8.8.8.8", false},
		{"v4-mapped v6", "::ffff:192.168.1.1", false},
		{"v4-compatible v6 (deprecated)", "::192.168.1.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "test input %q failed to parse", tt.ip)
			assert.Equal(t, tt.want, isGlobalIPv6(ip), "isGlobalIPv6(%s)", tt.ip)
		})
	}
}

// TestHasGlobalIPv6Using pins the gate's behavior on configs the local
// machine can't reproduce — Android multi-interface and v6-only cellular
// shapes especially. Test names flag known overcounts where the pinned
// behavior is "current" rather than "obviously right."
func TestHasGlobalIPv6Using(t *testing.T) {
	v4 := func(s string) net.Addr {
		return &net.IPNet{IP: net.ParseIP(s).To4(), Mask: net.CIDRMask(24, 32)}
	}
	v6 := func(s string) net.Addr {
		return &net.IPNet{IP: net.ParseIP(s).To16(), Mask: net.CIDRMask(64, 128)}
	}
	// *net.IPAddr (no netmask) — what some platforms return instead of *net.IPNet.
	v6Addr := func(s string) net.Addr {
		return &net.IPAddr{IP: net.ParseIP(s).To16()}
	}

	const (
		comcastV6  = "2603:8000:d0f0:5950::1" // residential dual-stack
		tmobileV6  = "2607:fb90:abcd:1234::1" // cellular global (T-Mobile-shaped)
		ulaLantern = "fdfe:dcba:9876::1"      // our own TUN ULA
		ulaTail    = "fd7a:115c:a1e0::1"      // Tailscale ULA
	)

	tests := []struct {
		name  string
		snaps []ifaceSnapshot
		want  bool
	}{
		// ─── macOS-shaped baselines (refactor-fidelity check) ───
		{
			name: "macOS dual-stack: en0 with v4 + Comcast v6",
			snaps: []ifaceSnapshot{
				{name: "en0", flags: net.FlagUp | net.FlagBroadcast, addrs: []net.Addr{
					v4("192.168.1.50"), v6(comcastV6),
				}},
			},
			want: true,
		},
		{
			name: "macOS v4-only: en0 with v4 only",
			snaps: []ifaceSnapshot{
				{name: "en0", flags: net.FlagUp | net.FlagBroadcast, addrs: []net.Addr{
					v4("192.168.1.50"),
				}},
			},
			want: false,
		},
		{
			name: "Tailscale up but no other v6 (ULA shouldn't count)",
			snaps: []ifaceSnapshot{
				{name: "en0", flags: net.FlagUp | net.FlagBroadcast, addrs: []net.Addr{
					v4("192.168.1.50"),
				}},
				{name: "utun7", flags: net.FlagUp, addrs: []net.Addr{
					v6(ulaTail),
				}},
			},
			want: false,
		},

		// ─── Android-shaped cases (the motivation for this refactor) ───
		{
			name: "Android wifi-only v4: wlan0 with v4 only",
			snaps: []ifaceSnapshot{
				{name: "wlan0", flags: net.FlagUp | net.FlagBroadcast, addrs: []net.Addr{
					v4("192.168.4.123"),
				}},
			},
			want: false,
		},
		{
			name: "Android wifi-only dual-stack: wlan0 with v4 + v6",
			snaps: []ifaceSnapshot{
				{name: "wlan0", flags: net.FlagUp | net.FlagBroadcast, addrs: []net.Addr{
					v4("192.168.4.123"), v6(comcastV6),
				}},
			},
			want: true,
		},
		{
			name: "Android cellular-only v6 (T-Mobile / v6 + NAT64)",
			snaps: []ifaceSnapshot{
				{name: "rmnet_data0", flags: net.FlagUp, addrs: []net.Addr{
					v6(tmobileV6),
				}},
			},
			want: true,
		},
		{
			// Pins current behavior: any UP non-loopback v6 counts. If this
			// proves problematic in the field, refine to check the active
			// default route.
			name: "Android wifi v4 active + cellular v6 idle (multi-interface overcount)",
			snaps: []ifaceSnapshot{
				{name: "wlan0", flags: net.FlagUp | net.FlagBroadcast, addrs: []net.Addr{
					v4("192.168.4.123"),
				}},
				{name: "rmnet_data0", flags: net.FlagUp, addrs: []net.Addr{
					v6(tmobileV6),
				}},
			},
			want: true,
		},
		{
			name: "Android with Lantern TUN ULA already up (own ULA must not count)",
			snaps: []ifaceSnapshot{
				{name: "wlan0", flags: net.FlagUp | net.FlagBroadcast, addrs: []net.Addr{
					v4("192.168.4.123"),
				}},
				{name: "tun0", flags: net.FlagUp, addrs: []net.Addr{
					v6(ulaLantern), // ULA — must be filtered out
				}},
			},
			want: false,
		},
		{
			name: "Android *net.IPAddr (no netmask) variant — must still detect v6",
			snaps: []ifaceSnapshot{
				{name: "rmnet_data0", flags: net.FlagUp, addrs: []net.Addr{
					v6Addr(tmobileV6),
				}},
			},
			want: true,
		},

		// ─── Degenerate / lockdown cases ───
		{
			name: "loopback only (no usable interfaces)",
			snaps: []ifaceSnapshot{
				{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []net.Addr{
					v6("::1"), v4("127.0.0.1"),
				}},
			},
			want: false,
		},
		{
			name: "interface down with v6 address (must be ignored)",
			snaps: []ifaceSnapshot{
				{name: "wlan0", flags: 0 /* not Up */, addrs: []net.Addr{
					v6(comcastV6),
				}},
			},
			want: false,
		},
		{
			name:  "Android lockdown: snapshot returns empty list",
			snaps: []ifaceSnapshot{},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := func() ([]ifaceSnapshot, error) {
				return tt.snaps, nil
			}
			assert.Equal(t, tt.want, hasGlobalIPv6Using(provider))
		})
	}

	t.Run("snapshot provider returns error", func(t *testing.T) {
		provider := func() ([]ifaceSnapshot, error) {
			return nil, fmt.Errorf("simulated netlink failure / permission denied")
		}
		assert.False(t, hasGlobalIPv6Using(provider),
			"errored snapshot should result in false (defensive default)")
	})
}
