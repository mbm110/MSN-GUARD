package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/getlantern/lantern-box"
	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	O "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rlog "github.com/getlantern/radiance/log"
)

type closePanicOutbound struct {
	adapter.Outbound
}

func (o *closePanicOutbound) Close() error {
	panic("close")
}

func TestOfflineClosePanicE2E(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the leaked network monitor is measured through netlink, which is Linux-only")
	}
	t.Skip("sing-box-minimal's Box.Close stops at a panicking Close and leaks the network monitor; unskip once radiance pins a version that keeps closing")
	useTempCrashLog(t)

	var proxiedHits, clientHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/proxied":
			proxiedHits.Add(1)
		case "/client":
			clientHits.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	serverPort := freePort(t)
	serverCtx, cancelServer := context.WithCancel(box.Context(context.Background()))
	t.Cleanup(cancelServer)
	serverOpts := loadBoxOptions(t, serverCtx, "testdata/http_server.json")
	setListenPort(t, &serverOpts.Inbounds[0], serverPort)
	server := startBox(t, serverCtx, serverOpts)
	t.Cleanup(func() { assert.NoError(t, server.Close()) })

	runOfflineTest := func(closePanic bool) (map[string]uint16, error) {
		ctx, cancel := context.WithCancel(box.Context(t.Context()))
		defer cancel()
		httpOut := findOutbound(loadBoxOptions(t, ctx, "testdata/boxopts.json").Outbounds, "http-out")
		require.NotNil(t, httpOut)
		setServerPort(t, httpOut, serverPort)
		outbounds := []O.Outbound{*httpOut}
		urls := map[string]string{"http-out": target.URL + "/proxied"}
		if closePanic {
			registerWrappedDirect(ctx, "close-panic", func(_ context.Context, ob adapter.Outbound) adapter.Outbound {
				return &closePanicOutbound{Outbound: ob}
			})
			outbounds = append([]O.Outbound{{Type: "close-panic", Tag: "close-panic", Options: &O.DirectOutboundOptions{}}}, outbounds...)
			urls["close-panic"] = target.URL + "/direct"
		}
		return NewVPNClient(t.TempDir(), rlog.NoOpLogger(), nil).RunOfflineURLTests(ctx, "", outbounds, urls, nil)
	}

	baseline := settledSnapshot(t)

	results, err := runOfflineTest(false)
	require.NoError(t, err)
	assert.Contains(t, results, "http-out")
	afterClean := settledSnapshot(t)
	assert.Equal(t, baseline.monitor(), afterClean.monitor(), "a clean run left goroutines behind:\n%s", afterClean.minus(baseline))
	assert.Equal(t, baseline.netlinkFDs, afterClean.netlinkFDs, "a clean run left netlink sockets open")

	proxied := proxiedHits.Load()
	results, err = runOfflineTest(true)
	require.ErrorContains(t, err, "panic running offline URL tests: close")
	assert.Nil(t, results)
	require.Greater(t, proxiedHits.Load(), proxied, "the panicking run never reached the target through the server")
	afterPanic := settledSnapshot(t)
	assert.Equal(t, afterClean.monitor(), afterPanic.monitor(), "a recovered close panic left goroutines behind:\n%s", afterPanic.minus(afterClean))
	assert.Equal(t, afterClean.netlinkFDs, afterPanic.netlinkFDs, "a recovered close panic left netlink sockets open")

	clientPort := freePort(t)
	clientCtx, cancelClient := context.WithCancel(box.Context(context.Background()))
	defer cancelClient()
	clientOpts := loadBoxOptions(t, clientCtx, "testdata/boxopts.json")
	clientOpts.Experimental.CacheFile.Path = filepath.Join(t.TempDir(), "cache.db")
	setListenPort(t, &clientOpts.Inbounds[0], clientPort)
	for i := range clientOpts.Outbounds {
		if tag := clientOpts.Outbounds[i].Tag; tag == "http-out" || tag == "socks-out" {
			setServerPort(t, &clientOpts.Outbounds[i], serverPort)
		}
	}
	clientBox := startBox(t, clientCtx, clientOpts)
	t.Cleanup(func() {
		if err := clientBox.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("closing client box: %v", err)
		}
	})
	proxyURL := &url.URL{Scheme: "socks5", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(clientPort)))}
	httpClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	resp, err := httpClient.Get(target.URL + "/client")
	require.NoError(t, err, "a sing-box instance started after the panicked run could not proxy a request")
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, int32(1), clientHits.Load())
	httpClient.CloseIdleConnections()
	require.NoError(t, clientBox.Close())
	cancelClient()
	afterClient := settledSnapshot(t)
	assert.Equal(t, afterPanic.monitor(), afterClient.monitor(), "the client box left goroutines behind:\n%s", afterClient.minus(afterPanic))
	assert.Equal(t, afterPanic.netlinkFDs, afterClient.netlinkFDs, "the client box left netlink sockets open")
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func loadBoxOptions(t *testing.T, ctx context.Context, path string) O.Options {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	opts, err := json.UnmarshalExtendedContext[O.Options](ctx, data)
	require.NoError(t, err)
	return opts
}

func setListenPort(t *testing.T, in *O.Inbound, port uint16) {
	t.Helper()
	wrapper, ok := in.Options.(O.ListenOptionsWrapper)
	require.True(t, ok, "inbound %q has no listen options", in.Tag)
	listen := wrapper.TakeListenOptions()
	listen.ListenPort = port
	wrapper.ReplaceListenOptions(listen)
}

func setServerPort(t *testing.T, out *O.Outbound, port uint16) {
	t.Helper()
	wrapper, ok := out.Options.(O.ServerOptionsWrapper)
	require.True(t, ok, "outbound %q has no server options", out.Tag)
	server := wrapper.TakeServerOptions()
	server.ServerPort = port
	wrapper.ReplaceServerOptions(server)
}

func startBox(t *testing.T, ctx context.Context, opts O.Options) *sbox.Box {
	t.Helper()
	instance, err := sbox.New(sbox.Options{Context: ctx, Options: opts})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	return instance
}

type runtimeSnapshot struct {
	netlinkFDs int
	goroutines map[string]int
}

func (s runtimeSnapshot) monitor() int {
	var n int
	for key, count := range s.goroutines {
		if strings.Contains(key, "sagernet/netlink.") || strings.Contains(key, "(*networkUpdateMonitor)") {
			n += count
		}
	}
	return n
}

func (s runtimeSnapshot) minus(base runtimeSnapshot) string {
	var lines []string
	for key, n := range s.goroutines {
		if d := n - base.goroutines[key]; d > 0 {
			lines = append(lines, fmt.Sprintf("  %d × %s", d, key))
		}
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// settledSnapshot samples only after the goroutine count holds steady, so goroutines that are
// still exiting aren't counted as leaked.
func settledSnapshot(t *testing.T) runtimeSnapshot {
	t.Helper()
	var prev, stable int
	deadline := time.Now().Add(10 * time.Second)
	for stable < 5 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		if n := runtime.NumGoroutine(); n == prev {
			stable++
		} else {
			prev, stable = n, 0
		}
	}
	require.Equal(t, 5, stable, "goroutine count never settled")

	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	s := runtimeSnapshot{goroutines: map[string]int{}, netlinkFDs: netlinkFDs(t)}
	for _, g := range strings.Split(string(buf), "\n\n") {
		lines := strings.Split(g, "\n")
		if len(lines) < 2 {
			continue
		}
		key := frameFunc(lines[1])
		for _, line := range lines {
			if creator, ok := strings.CutPrefix(line, "created by "); ok {
				creator, _, _ = strings.Cut(creator, " in goroutine")
				key += " ← " + strings.TrimSpace(creator)
			}
		}
		s.goroutines[key]++
	}
	return s
}

func frameFunc(frame string) string {
	if i := strings.LastIndex(frame, "("); i > 0 {
		frame = frame[:i]
	}
	return strings.TrimSpace(frame)
}

func netlinkFDs(t *testing.T) int {
	t.Helper()
	table, err := os.ReadFile("/proc/net/netlink")
	require.NoError(t, err)
	inodes := map[string]bool{}
	for _, line := range strings.Split(string(table), "\n")[1:] {
		if fields := strings.Fields(line); len(fields) > 0 {
			inodes[fields[len(fields)-1]] = true
		}
	}
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	var n int
	for _, e := range entries {
		link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue
		}
		if inode, ok := strings.CutPrefix(link, "socket:["); ok && inodes[strings.TrimSuffix(inode, "]")] {
			n++
		}
	}
	return n
}
