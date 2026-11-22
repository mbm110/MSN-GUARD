package vpn

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	O "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func wrapLikeTunnelStart(inner error) error {
	err := E.Cause(inner, "configure tun interface")
	err = E.Cause(err, "start inbound/tun[tun-in]")
	err = fmt.Errorf("starting libbox service: %w", err)
	return fmt.Errorf("connecting tunnel: %w", err)
}

// wintunCollision uses os.ErrExist in place of Windows' ERROR_ALREADY_EXISTS,
// whose Errno.Is reports os.ErrExist, so the test runs on every platform.
func wintunCollision() error {
	return wrapLikeTunnelStart(E.Errors(
		E.Cause(os.ErrExist, "create adapter"),
		E.Cause(errors.New("Element not found."), "open existing adapter"),
	))
}

func TestIsTUNIdentityCollision(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "adapter identity already exists",
			err:  wintunCollision(),
			want: true,
		},
		{
			name: "adapter created but never came up",
			err: wrapLikeTunnelStart(E.Cause(
				errors.New("The property set specified does not exist on the object."),
				"create adapter",
			)),
			want: false,
		},
		{
			name: "unrelated ErrExist elsewhere in bring-up",
			err:  fmt.Errorf("connecting tunnel: %w", fmt.Errorf("opening cache: %w", os.ErrExist)),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isTUNIdentityCollision(tt.err))
		})
	}
}

func TestTunIdentityNameAvoidsSingBoxDefaults(t *testing.T) {
	seen := map[string]bool{}
	for attempt := 1; attempt <= maxTUNIdentityRetries; attempt++ {
		name := tunIdentityName(attempt)
		assert.False(t, strings.HasPrefix(name, "tun"), "retry name %q collides with sing-box's tunN names", name)
		assert.False(t, seen[name], "duplicate retry name %q", name)
		seen[name] = true
	}
}

func TestSetTUNInterfaceName(t *testing.T) {
	tunOpts := &O.TunInboundOptions{}
	opts := O.Options{Inbounds: []O.Inbound{{Type: "tun", Tag: inboundTag, Options: tunOpts}}}

	require.True(t, setTUNInterfaceName(opts, "lantern1"))
	assert.Equal(t, "lantern1", tunOpts.InterfaceName)
}

func TestSetTUNInterfaceNameWithoutTUNInbound(t *testing.T) {
	opts := O.Options{Inbounds: []O.Inbound{{Type: "mixed", Tag: inboundTag, Options: &O.HTTPMixedInboundOptions{}}}}
	assert.False(t, setTUNInterfaceName(opts, "lantern1"))
}
