package vpn

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sagernet/sing-box/option"
)

const maxTUNIdentityRetries = 3

// isTUNIdentityCollision reports whether err is Wintun refusing to create the
// adapter because a device with its identity already exists. An adapter that
// was created but never came up is not a collision.
func isTUNIdentityCollision(err error) bool {
	if err == nil || !errors.Is(err, os.ErrExist) {
		return false
	}
	return strings.Contains(err.Error(), "create adapter")
}

// tunIdentityName avoids the tunN names other sing-box clients use: sing-tun
// falls back to opening an existing adapter by name, so a retry landing on
// another app's live adapter would try to take it over.
func tunIdentityName(attempt int) string {
	return fmt.Sprintf("lantern%d", attempt)
}

// setTUNInterfaceName sets the TUN inbound's interface name in place, visible
// through every copy of options, and reports false if there is no TUN inbound.
func setTUNInterfaceName(options option.Options, name string) bool {
	for _, inbound := range options.Inbounds {
		if inbound.Tag != inboundTag {
			continue
		}
		tunOpts, ok := inbound.Options.(*option.TunInboundOptions)
		if !ok {
			return false
		}
		tunOpts.InterfaceName = name
		return true
	}
	return false
}
