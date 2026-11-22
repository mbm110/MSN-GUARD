package kindling

import (
	"context"
	"net/http"
	"testing"

	"github.com/getlantern/kindling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	transports := []kindling.TransportName{
		kindling.TransportDomainfront,
		kindling.TransportSmart,
		kindling.TransportAMP,
	}

	for _, tr := range transports {
		t.Run(string(tr), func(t *testing.T) {
			for _, name := range transports {
				EnabledTransports[name] = false
			}
			EnabledTransports[kindling.TransportDNSTunnel] = false
			EnabledTransports[tr] = true

			Close()

			newK, err := NewKindling(t.TempDir())
			require.NoError(t, err)
			require.NotNil(t, newK)
			SetKindling(newK)

			t.Cleanup(func() { Close() })

			cli := HTTPClient()
			require.NotNil(t, cli)

			req, err := http.NewRequest(http.MethodPost, "https://df.iantem.io/api/v1/config-new", http.NoBody)
			require.NoError(t, err)

			resp, err := cli.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.NotNil(t, resp)
		})
	}
}

type fakePausable struct{ paused, resumed int }

func (f *fakePausable) Pause()  { f.paused++ }
func (f *fakePausable) Resume() { f.resumed++ }

func TestApplyPauseNoPausers(t *testing.T) {
	c := &Client{}
	mu.Lock()
	defer mu.Unlock()
	c.applyPauseLocked(true)
	c.applyPauseLocked(false)
}

func restorePackageState(t *testing.T) {
	t.Helper()
	mu.Lock()
	prevK, prevPaused, prevInitialized, prevTransport := k, paused, initialized, transport
	k, paused, initialized, transport = nil, false, false, nil
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		k, paused, initialized, transport = prevK, prevPaused, prevInitialized, prevTransport
		mu.Unlock()
	})
}

func TestPauseHeldForClientInstalledLater(t *testing.T) {
	restorePackageState(t)
	p := &fakePausable{}

	SetNetworkPaused(t.Context(), true)
	mu.Lock()
	setClient(&Client{pausers: []pausable{p}})
	mu.Unlock()

	assert.Equal(t, 1, p.paused, "a client installed while paused must start paused")
}

func TestPauseResumeDelegateToLiveClient(t *testing.T) {
	restorePackageState(t)
	first, second := &fakePausable{}, &fakePausable{}
	mu.Lock()
	setClient(&Client{pausers: []pausable{first, second}})
	mu.Unlock()

	SetNetworkPaused(t.Context(), true)
	SetNetworkPaused(t.Context(), false)

	for _, p := range []*fakePausable{first, second} {
		assert.Equal(t, 1, p.paused, "every pauser must receive the pause")
		assert.Equal(t, 1, p.resumed, "every pauser must receive the resume")
	}
}

func TestPauseResumeIgnoreRedundantCalls(t *testing.T) {
	restorePackageState(t)
	p := &fakePausable{}
	mu.Lock()
	setClient(&Client{pausers: []pausable{p}})
	mu.Unlock()

	SetNetworkPaused(t.Context(), true)
	SetNetworkPaused(t.Context(), true)
	SetNetworkPaused(t.Context(), false)
	SetNetworkPaused(t.Context(), false)

	assert.Equal(t, 1, p.paused, "a redundant Pause must not reach the transports")
	assert.Equal(t, 1, p.resumed, "a redundant Resume must not reach the transports")
}

func TestCloseClearsHeldPause(t *testing.T) {
	restorePackageState(t)
	p := &fakePausable{}

	SetNetworkPaused(t.Context(), true)
	require.NoError(t, Close())
	mu.Lock()
	setClient(&Client{pausers: []pausable{p}})
	mu.Unlock()

	assert.Equal(t, 0, p.paused, "Close must not leak the pause into the next instance")
}

func TestResumeClearsHeldPause(t *testing.T) {
	restorePackageState(t)
	p := &fakePausable{}

	SetNetworkPaused(t.Context(), true)
	SetNetworkPaused(t.Context(), false)
	mu.Lock()
	setClient(&Client{pausers: []pausable{p}})
	mu.Unlock()

	assert.Equal(t, 0, p.paused, "a client installed after resume must start running")
	assert.Equal(t, 0, p.resumed, "a client installed unpaused must not be touched")
}

func TestSetNetworkPausedIgnoresCanceledUpdates(t *testing.T) {
	for _, tc := range []struct {
		name string
		next bool
	}{
		{name: "pause", next: true},
		{name: "wake", next: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restorePackageState(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			SetNetworkPaused(t.Context(), !tc.next)
			p := &fakePausable{}
			mu.Lock()
			setClient(&Client{pausers: []pausable{p}})
			mu.Unlock()
			before := *p

			SetNetworkPaused(ctx, tc.next)

			assert.Equal(t, before, *p, "canceled updates must not reach a live transport")
			assert.Equal(t, !tc.next, paused, "canceled updates must not change the held state")
		})
	}
}

func TestSetNetworkPausedCanceledPauseAfterClose(t *testing.T) {
	restorePackageState(t)
	ctx, cancel := context.WithCancel(t.Context())
	SetNetworkPaused(ctx, true)
	cancel()
	require.NoError(t, Close())

	SetNetworkPaused(ctx, true)
	p := &fakePausable{}
	mu.Lock()
	setClient(&Client{pausers: []pausable{p}})
	mu.Unlock()

	assert.Zero(t, p.paused, "a canceled backend must not pause the next client")
	SetNetworkPaused(t.Context(), true)
	assert.Equal(t, 1, p.paused, "the next backend must still be able to pause")
}
