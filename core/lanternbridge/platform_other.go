//go:build !android

package lanternbridge

import (
	"github.com/getlantern/radiance/vpn"
)

// newPlatformInterface is nil off Android: only the Android sidecar runs
// unprivileged without gomobile bindings, which is the one combination that
// needs the platform interface to bypass sing-box's banned netlink monitor.
func newPlatformInterface() vpn.PlatformInterface { return nil }
