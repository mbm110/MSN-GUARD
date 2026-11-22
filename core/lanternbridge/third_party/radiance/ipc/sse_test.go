package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/vpn"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// eofAfter is a stream body that ends after the given duration.
type eofAfter time.Duration

func (d eofAfter) Read([]byte) (int, error) {
	time.Sleep(time.Duration(d))
	return 0, io.EOF
}

// autoSelectedTunnel reports a settable current and announced auto selection and
// signals each announced read; its other methods are the nil VPNClient's and must
// not be called.
type autoSelectedTunnel struct {
	*vpn.VPNClient
	mu        sync.Mutex
	current   string
	announced string
	reads     chan struct{}
}

func newAutoSelectedTunnel(current, announced string) *autoSelectedTunnel {
	return &autoSelectedTunnel{current: current, announced: announced, reads: make(chan struct{}, 1)}
}

func (a *autoSelectedTunnel) announce(tag string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.announced = tag
}

func (a *autoSelectedTunnel) CurrentAutoSelectedServer() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current, nil
}

func (a *autoSelectedTunnel) AnnouncedAutoSelectedServer() string {
	a.mu.Lock()
	tag := a.announced
	a.mu.Unlock()
	select {
	case a.reads <- struct{}{}:
	default:
	}
	return tag
}

func openStream(t *testing.T, b *backend.LocalBackend, endpoint string) *bufio.Reader {
	t.Helper()
	srv := httptest.NewServer(newLocalAPI(b, false))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+endpoint, nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return bufio.NewReader(resp.Body)
}

func readFrame(t *testing.T, body *bufio.Reader) string {
	t.Helper()
	line, err := body.ReadString('\n')
	require.NoError(t, err)
	data, ok := strings.CutPrefix(strings.TrimSpace(line), "data: ")
	require.True(t, ok, line)
	_, err = body.ReadString('\n')
	require.NoError(t, err)
	return data
}

func readAutoSelected(t *testing.T, body *bufio.Reader) string {
	t.Helper()
	var evt vpn.AutoSelectedEvent
	require.NoError(t, json.Unmarshal([]byte(readFrame(t, body)), &evt))
	return evt.Selected
}

func TestConfigEventsStreamSendsOnSubscribe(t *testing.T) {
	body := openStream(t, &backend.LocalBackend{}, configEventsEndpoint)
	require.Equal(t, "{}", readFrame(t, body))
	events.Emit(backend.ConfigAppliedEvent{})
	require.Equal(t, "{}", readFrame(t, body))
}

func TestAutoSelectedEventsStream(t *testing.T) {
	subscribe := func(t *testing.T, tun *autoSelectedTunnel) *bufio.Reader {
		b := &backend.LocalBackend{}
		b.SetLiveTunnelForTest(tun)
		return openStream(t, b, serverAutoSelectedEventsEndpoint)
	}

	// The tunnel's current pick differs from the announced one in each case: the
	// stream must send only what the change listener announced, or a pick that
	// reverts before the listener's next poll would never be corrected.
	t.Run("sends the announced selection on subscribe and on each event", func(t *testing.T) {
		tun := newAutoSelectedTunnel("unannounced", "fastest")
		body := subscribe(t, tun)
		require.Equal(t, "fastest", readAutoSelected(t, body))

		tun.announce("next")
		events.Emit(vpn.AutoSelectedEvent{Selected: "stale"})
		require.Equal(t, "next", readAutoSelected(t, body))
	})

	t.Run("sends nothing before an announcement", func(t *testing.T) {
		tun := newAutoSelectedTunnel("unannounced", "")
		body := subscribe(t, tun)
		// The first read happens after the handler subscribes.
		select {
		case <-tun.reads:
		case <-time.After(5 * time.Second):
			t.Fatal("handler never read the announced selection")
		}

		tun.announce("next")
		events.Emit(vpn.AutoSelectedEvent{Selected: "next"})
		require.Equal(t, "next", readAutoSelected(t, body))
	})
}

func TestSSERetryLoopResetsBackoffAfterStableStream(t *testing.T) {
	const failures = 20
	tests := []struct {
		name      string
		accept    bool
		lasts     time.Duration
		wantReset bool
	}{
		{name: "stable stream", accept: true, lasts: 2 * sseStableAfter, wantReset: true},
		{name: "immediately closed stream", accept: true, lasts: 0, wantReset: false},
		{name: "slow failed connect", accept: false, lasts: 2 * sseStableAfter, wantReset: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				refused := &net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}
				var attempts []time.Time
				c := newClient()
				c.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
					attempts = append(attempts, time.Now())
					switch n := len(attempts); {
					case n <= failures:
						return nil, refused
					case n == failures+1 && tt.accept:
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(eofAfter(tt.lasts)),
							Header:     make(http.Header),
						}, nil
					case n == failures+1:
						time.Sleep(tt.lasts)
						return nil, refused
					default:
						cancel()
						return nil, context.Canceled
					}
				})

				require.ErrorIs(t, c.sseRetryLoop(ctx, "/test/events", func([]byte) {}), context.Canceled)
				require.Len(t, attempts, failures+2)

				wait := attempts[failures+1].Sub(attempts[failures]) - tt.lasts
				if tt.wantReset {
					// First backoff step: 10ms with ±20% jitter.
					require.LessOrEqual(t, wait, 12*time.Millisecond)
				} else {
					// Step failures+1 without a reset: 10ms × 21² with -20% jitter.
					require.GreaterOrEqual(t, wait, 3*time.Second)
				}
			})
		})
	}
}
