package unbounded

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// taggedNet is a Net the test can tell apart.
type taggedNet struct {
	*stdnet.Net
	tag string
}

func newTagged(t *testing.T, tag string) transport.Net {
	t.Helper()
	n, err := stdnet.NewNet()
	require.NoError(t, err)
	return &taggedNet{Net: n, tag: tag}
}

type tunnelKey struct{}

func TestTunnelNetFollowsTheTunnel(t *testing.T) {
	var box context.Context
	built := 0
	tn := newTunnelNet(func() context.Context { return box })
	tn.newProtected = func(ctx context.Context) (transport.Net, error) {
		built++
		return newTagged(t, "protected"), nil
	}
	tn.newStd = func() (transport.Net, error) { return newTagged(t, "std"), nil }

	n, err := tn.current()
	require.NoError(t, err)
	assert.Equal(t, "std", n.(*taggedNet).tag, "no VPN: the host stack")

	box = context.WithValue(context.Background(), tunnelKey{}, 1)
	n, err = tn.current()
	require.NoError(t, err)
	assert.Equal(t, "protected", n.(*taggedNet).tag)
	_, err = tn.current()
	require.NoError(t, err)
	assert.Equal(t, 1, built, "one protected Net per tunnel")

	box = context.WithValue(context.Background(), tunnelKey{}, 2)
	_, err = tn.current()
	require.NoError(t, err)
	assert.Equal(t, 2, built, "a new tunnel gets a new Net")

	box = nil
	n, err = tn.current()
	require.NoError(t, err)
	assert.Equal(t, "std", n.(*taggedNet).tag, "VPN off again: the host stack")
	tn.mu.Lock()
	assert.Nil(t, tn.ctx, "the dead tunnel's context is dropped")
	assert.Nil(t, tn.net, "the dead tunnel's Net is dropped")
	tn.mu.Unlock()
}

func TestTunnelNetWithoutASource(t *testing.T) {
	tn := newTunnelNet(nil)
	ifs, err := tn.Interfaces()
	require.NoError(t, err)
	assert.NotEmpty(t, ifs)
}

func TestTunnelNetPassesErrorsOn(t *testing.T) {
	boom := errors.New("boom")
	tn := newTunnelNet(func() context.Context { return context.Background() })
	tn.newProtected = func(context.Context) (transport.Net, error) { return nil, boom }
	_, err := tn.Interfaces()
	assert.ErrorIs(t, err, boom)
}

func TestTunnelNetDialerAndListenConfigFailWithoutAProtectedNet(t *testing.T) {
	boom := errors.New("boom")
	tn := newTunnelNet(func() context.Context { return context.Background() })
	tn.newProtected = func(context.Context) (transport.Net, error) { return nil, boom }

	_, err := tn.CreateDialer(&net.Dialer{}).Dial("tcp", "127.0.0.1:1")
	assert.ErrorIs(t, err, boom, "no falling back to the host stack, whose routes go into the tunnel")

	lc := tn.CreateListenConfig(&net.ListenConfig{})
	_, err = lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	assert.ErrorIs(t, err, boom)
	_, err = lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	assert.ErrorIs(t, err, boom)
}
