//go:build android || ios || (darwin && !standalone)

package ipc

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	wire "github.com/getlantern/common/usermessage"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/events"
	"github.com/getlantern/radiance/vpn"
)

func TestFallbackOptionsPreserveUserMessageCapabilities(t *testing.T) {
	capabilities := wire.ClientCapabilities{
		Version:  wire.CapabilityUserMessagesV1,
		Surfaces: []wire.Surface{wire.SurfaceSnackbar},
		Actions:  []wire.ActionType{wire.ActionTypeOpenPlans},
	}
	client := newClient()
	client.opts = cloneBackendOptions(backend.Options{
		UserMessageCapabilities: capabilities,
		EnvOverrides:            map[string]string{"RADIANCE_ENV": "staging"},
	})

	fallback := client.fallbackOptions()
	require.Equal(t, capabilities, fallback.UserMessageCapabilities)
	require.Equal(t, "staging", fallback.EnvOverrides["RADIANCE_ENV"])

	fallback.UserMessageCapabilities.Surfaces[0] = "changed"
	fallback.EnvOverrides["RADIANCE_ENV"] = "changed"
	require.Equal(t, wire.SurfaceSnackbar, client.opts.UserMessageCapabilities.Surfaces[0])
	require.Equal(t, "staging", client.opts.EnvOverrides["RADIANCE_ENV"])
}

type remoteTransport func(*http.Request) (*http.Response, error)

func (f remoteTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRemoteClientNeverCreatesFallback(t *testing.T) {
	client := NewRemoteClient()
	require.Nil(t, client.localapi)
	defer client.Close()
	for _, connectionErr := range []error{syscall.ENOENT, syscall.ECONNREFUSED} {
		client.http.Transport = remoteTransport(func(*http.Request) (*http.Response, error) {
			return nil, connectionErr
		})
		_, err := client.do(context.Background(), http.MethodGet, "/settings", nil)
		require.ErrorIs(t, err, ErrIPCNotRunning)
		require.ErrorIs(t, err, connectionErr)
		err = client.sseStream(context.Background(), "/config/events", func([]byte) {}, nil)
		require.ErrorIs(t, err, ErrIPCNotRunning)
		require.ErrorIs(t, err, connectionErr)
		require.Nil(t, client.localapi)
	}
	client.http.Transport = remoteTransport(func(r *http.Request) (*http.Response, error) {
		body := "{}"
		if r.Header.Get("Accept") == "text/event-stream" {
			body = "data: connected\n\n"
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	body, err := client.do(context.Background(), http.MethodGet, "/settings", nil)
	require.NoError(t, err)
	require.Equal(t, "{}", string(body))
	var event string
	require.NoError(t, client.sseStream(context.Background(), "/config/events", func(data []byte) { event = string(data) }, nil))
	require.Equal(t, "connected", event)
	client.Close()
	require.Nil(t, client.localapi)
}

// The in-process subscription cannot hear a save made before it, so the
// handler runs once on subscribing, then once per save.
func TestSelectionSavedEventsLocalCallsOnSubscribe(t *testing.T) {
	client := newClient()
	client.localOnly = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan struct{}, 4)
	done := make(chan struct{})
	go func() {
		_ = client.SelectionSavedEvents(ctx, func(vpn.SelectionSavedEvent) { calls <- struct{}{} })
		close(done)
	}()
	waitCall := func() {
		t.Helper()
		select {
		case <-calls:
		case <-time.After(2 * time.Second):
			t.Fatal("handler not called")
		}
	}
	waitCall()
	events.Emit(vpn.SelectionSavedEvent{})
	waitCall()
	cancel()
	<-done
}

// The fallback backend applies its cached config before ConfigEvents subscribes, so the
// handler runs once on subscribing, then once per applied config.
func TestConfigEventsLocalCallsOnSubscribe(t *testing.T) {
	client := newClient()
	client.localOnly = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan struct{}, 4)
	done := make(chan struct{})
	go func() {
		_ = client.ConfigEvents(ctx, func() { calls <- struct{}{} })
		close(done)
	}()
	waitCall := func() {
		t.Helper()
		select {
		case <-calls:
		case <-time.After(2 * time.Second):
			t.Fatal("handler not called")
		}
	}
	waitCall()
	events.Emit(backend.ConfigAppliedEvent{})
	waitCall()
	cancel()
	<-done
}

// The bus worker must not call handler while the on-subscribe call is still running.
func TestConfigEventsLocalCallsDoNotOverlap(t *testing.T) {
	client := newClient()
	client.localOnly = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var first atomic.Bool
	first.Store(true)
	done := make(chan struct{})
	go func() {
		_ = client.ConfigEvents(ctx, func() {
			entered <- struct{}{}
			if first.CompareAndSwap(true, false) {
				<-release
			}
		})
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("on-subscribe call not made")
	}

	events.Emit(backend.ConfigAppliedEvent{})
	select {
	case <-entered:
		t.Fatal("handler ran while the on-subscribe call was in progress")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("event call not made after the on-subscribe call returned")
	}
	cancel()
	<-done
}
