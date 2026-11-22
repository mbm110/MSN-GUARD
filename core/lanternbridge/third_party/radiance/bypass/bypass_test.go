package bypass

import (
	"context"
	"fmt"
	"net"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lbox "github.com/getlantern/lantern-box"
)

// newSingboxServer starts a sing-box mixed inbound on ProxyPort that routes to
// the default direct outbound, standing in for the production bypass proxy. It
// is torn down on test cleanup so the fixed port is free for the next test.
func newSingboxServer(t *testing.T) *box.Box {
	t.Helper()
	opts := fmt.Sprintf(`{
	"inbounds": [
		{
			"type": "mixed",
			"tag": "socks-in",
			"listen": "127.0.0.1",
			"listen_port": %d
		}
	]
}`, ProxyPort)
	ctx := lbox.BaseContext()
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(opts))
	require.NoError(t, err)
	server, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	require.NoError(t, err)
	require.NoError(t, server.Start())
	t.Cleanup(func() { server.Close() })
	return server
}

// newEchoServer starts a TCP listener that accepts one connection,
// reads data, and echoes it back. The listener is cleaned up via t.Cleanup.
func newEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	return ln.Addr().String()
}

// deadTCPAddr returns a 127.0.0.1 address with no listener, so a dial to it is
// refused deterministically.
func deadTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func TestDialContext_ThroughProxy(t *testing.T) {
	newSingboxServer(t)
	echoAddr := newEchoServer(t)

	conn, err := DialContext(context.Background(), "tcp", echoAddr)
	require.NoError(t, err)
	defer conn.Close()

	_, ok := conn.(*tunneledConn)
	require.True(t, ok, "expected the proxy path (tunneledConn), not the direct fallback")

	msg := []byte("hello bypass")
	_, err = conn.Write(msg)
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, string(msg), string(buf[:n]))
}

func TestDialContext_UpstreamUnreachable(t *testing.T) {
	newSingboxServer(t)
	deadEnd := deadTCPAddr(t)

	_, err := DialContext(context.Background(), "tcp", deadEnd)
	require.Error(t, err, "an unreachable upstream must error so Happy Eyeballs can fail over")
}

func TestDialContext_FallbackWhenProxyDown(t *testing.T) {
	echoAddr := newEchoServer(t)

	conn, err := DialContext(context.Background(), "tcp", echoAddr)
	require.NoError(t, err, "DialContext should fall back to direct dial when the proxy is down")
	defer conn.Close()

	msg := []byte("direct fallback")
	_, err = conn.Write(msg)
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, string(msg), string(buf[:n]))
}

func TestStreamDialer_ProxyPathMasksTCPConn(t *testing.T) {
	newSingboxServer(t)
	echoAddr := newEchoServer(t)

	conn, err := StreamDialer().DialStream(context.Background(), echoAddr)
	require.NoError(t, err)
	defer conn.Close()

	_, ok := conn.(*net.TCPConn)
	assert.False(t, ok, "proxy path must not expose the loopback socket as *net.TCPConn, or disorder would poke the wrong socket")
}

func TestStreamDialer_DirectReturnsTCPConn(t *testing.T) {
	echoAddr := newEchoServer(t)

	conn, err := StreamDialer().DialStream(context.Background(), echoAddr)
	require.NoError(t, err)
	defer conn.Close()

	_, ok := conn.(*net.TCPConn)
	assert.True(t, ok, "direct dial should return *net.TCPConn so disorder strategy can type-assert it")
}

func TestDialContext_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := DialContext(ctx, "tcp", "127.0.0.1:1")
	require.Error(t, err, "expected error with cancelled context")
}
