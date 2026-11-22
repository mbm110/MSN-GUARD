package smart

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/transport"

	"github.com/getlantern/radiance/internal/testsocks"
)

// networkTestEnv gates the tests below. They need real egress and they hit the
// production config hosts, so they stay out of the default suite and out of CI.
const networkTestEnv = "RADIANCE_SMART_NETWORK_TEST"

// configURLs are two hosts with different blocking profiles, the shape the
// production fetch races a pair in.
var configURLs = []string{
	"https://raw.githubusercontent.com/getlantern/domainfront/refs/heads/main/fronted.yaml.gz",
	"https://cdn.jsdelivr.net/gh/firetweet/domainfront@main/fronted.yaml.gz",
}

const (
	realHostName = "raw.githubusercontent.com"
	realHostAddr = realHostName + ":443"
)

// searchTimeout bounds one host's fetch. The strategy search races a resolver
// list and a strategy list at 250 ms intervals with a 5 s per-test timeout, so
// a cold search on a slow emulator can legitimately take tens of seconds.
const searchTimeout = 90 * time.Second

// requireNetworkTests parses rather than checking for non-empty, so that an
// explicit 0 or false disables the tests instead of enabling them.
func requireNetworkTests(t *testing.T) {
	t.Helper()
	on, err := strconv.ParseBool(os.Getenv(networkTestEnv))
	if err != nil || !on {
		t.Skipf("set %s=1 to run tests that need real egress", networkTestEnv)
	}
}

// searchLog collects the strategy finder's output, which is the only place the
// selected strategy and the per-strategy failures are reported.
type searchLog struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *searchLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *searchLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *searchLog) report(t *testing.T) {
	t.Helper()
	for line := range strings.SplitSeq(l.String(), "\n") {
		if strings.Contains(line, "selected") || strings.Contains(line, "❌") {
			t.Log(line)
		}
	}
}

// fetchThroughSmartClient returns the number of hosts that turned out to be
// reachable, since one blocked host is an expected outcome rather than a
// failure.
func fetchThroughSmartClient(t *testing.T, log *searchLog) int {
	t.Helper()

	client, err := NewHTTPClientWithSmartTransport(log, configURLs...)
	require.NoError(t, err)

	var reached int
	for _, url := range configURLs {
		t.Run(url, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), searchTimeout)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			require.NoError(t, err)

			res, err := client.Do(req)
			if err != nil {
				t.Logf("unreachable: %v", err)
				return
			}
			defer res.Body.Close()
			assert.Equal(t, http.StatusOK, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			assert.NotEmpty(t, body)
			reached++
		})
	}
	return reached
}

// TestStrategiesReachRealHost runs every strategy against a real host rather
// than letting the search race them, so a strategy that only ever loses the
// race is still exercised. The loopback tests cannot stand in for this one:
// disorder relies on a TTL-limited packet being dropped in transit, which no
// loopback path can reproduce.
func TestStrategiesReachRealHost(t *testing.T) {
	requireNetworkTests(t)
	requireNoBypassProxy(t)

	roots, err := x509.SystemCertPool()
	require.NoError(t, err)
	for _, strategy := range parseDialerConfig(t).TLS {
		t.Run(strategyName(strategy), func(t *testing.T) {
			assert.NoError(t, handshakeThrough(t, &transport.TCPDialer{}, strategy, realHostAddr, roots, realHostName))
		})
	}
}

// TestSmartClientFetchesConfigDirectly is the pre-tunnel shape: no bypass proxy
// is listening, so the base dialer falls through to a direct dial.
func TestSmartClientFetchesConfigDirectly(t *testing.T) {
	requireNetworkTests(t)
	requireNoBypassProxy(t)

	log := &searchLog{}
	reached := fetchThroughSmartClient(t, log)
	log.report(t)
	assert.Positive(t, reached, "no config host was reachable through any strategy")
}

// TestSmartClientFetchesConfigThroughBypassProxy is the connected shape: every
// probe goes through the local SOCKS proxy, so the strategies that need a raw
// socket drop out of the search and a working strategy must still be found
// among the rest.
func TestSmartClientFetchesConfigThroughBypassProxy(t *testing.T) {
	requireNetworkTests(t)
	requireNoBypassProxy(t)
	testsocks.Listen(t, bypassProxyAddr())

	log := &searchLog{}
	reached := fetchThroughSmartClient(t, log)
	log.report(t)
	assert.Positive(t, reached,
		"the search must survive losing the strategies that need a raw socket")
}
