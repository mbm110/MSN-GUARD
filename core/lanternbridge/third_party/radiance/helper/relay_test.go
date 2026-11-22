package helper

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
)

func TestRelayForwardsAllowedOps(t *testing.T) {
	prev := settings.GetString(settings.DeviceIDKey)
	require.NoError(t, settings.Set(settings.DeviceIDKey, "device-R"))
	t.Cleanup(func() { _ = settings.Set(settings.DeviceIDKey, prev) })
	var gotPath, gotDevice, gotBody, gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotDevice, gotType = r.URL.Path, r.Header.Get(common.DeviceIDHeader), r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"pairing_id":"p"}`))
	}))
	defer srv.Close()
	rl := NewRelayer(srv.Client(), srv.URL+"/v1", nil)
	for op, path := range relayPaths {
		res, err := rl.Relay(context.Background(), op, []byte(`{"x":1}`))
		require.NoError(t, err, op)
		assert.Equal(t, path, gotPath[len("/v1"):], op)
		assert.Equal(t, "device-R", gotDevice)
		assert.Equal(t, "application/json", gotType)
		assert.JSONEq(t, `{"x":1}`, gotBody)
		assert.Equal(t, http.StatusOK, res.Status)
		assert.JSONEq(t, `{"pairing_id":"p"}`, string(res.Body))
		assert.Empty(t, res.Error)
	}
	res, err := rl.Relay(context.Background(), "pairings", nil)
	require.NoError(t, err)
	assert.Equal(t, "{}", gotBody, "an empty body is sent as {}")
	assert.Equal(t, http.StatusOK, res.Status)
}

func TestRelayRefusesOtherOps(t *testing.T) {
	rl := NewRelayer(http.DefaultClient, "http://127.0.0.1:1/v1", nil)
	for _, op := range []string{"", "tickets", "ticket-key", "../peer/register", "invites/../../peer"} {
		_, err := rl.Relay(context.Background(), op, nil)
		assert.ErrorIs(t, err, ErrUnknownOp, op)
	}
}

func TestRelayReportsErrorsAsResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invite already claimed or expired", http.StatusConflict)
	}))
	defer srv.Close()
	res, err := NewRelayer(srv.Client(), srv.URL+"/v1", nil).Relay(context.Background(), "invites/claim", []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, http.StatusConflict, res.Status)
	assert.Equal(t, "invite already claimed or expired", res.Error)
	assert.Nil(t, res.Body)
}

// The error text is cut to maxRelayErrLen bytes, never inside a rune.
func TestRelayCutsLongErrorsOnARuneBoundary(t *testing.T) {
	prefix := strings.Repeat("a", maxRelayErrLen-1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, prefix+"é and more", http.StatusBadRequest)
	}))
	defer srv.Close()
	res, err := NewRelayer(srv.Client(), srv.URL+"/v1", nil).Relay(context.Background(), "invites", nil)
	require.NoError(t, err)
	assert.True(t, utf8.ValidString(res.Error), "no split rune")
	assert.Equal(t, prefix, res.Error)
}

// spanEventer stands in for kindling's race observer, which adds events to
// the span in a request's context.
type spanEventer struct{ next http.RoundTripper }

func (s spanEventer) RoundTrip(r *http.Request) (*http.Response, error) {
	trace.SpanFromContext(r.Context()).AddEvent("kindling.attempt")
	return s.next.RoundTrip(r)
}

// The relay detaches the caller's span, so nothing about a helper call is
// recorded on it.
func TestRelayDetachesTheCallersSpan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(mem))
	ctx, span := tp.Tracer("test").Start(context.Background(), "caller")
	client := &http.Client{Transport: spanEventer{next: srv.Client().Transport}}
	_, err := NewRelayer(client, srv.URL+"/v1", nil).Relay(ctx, "pairings", nil)
	require.NoError(t, err)
	span.End()
	spans := mem.GetSpans()
	require.Len(t, spans, 1)
	assert.Empty(t, spans[0].Events)
}

func TestRelayRejectsANonJSONSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>captive portal</html>"))
	}))
	defer srv.Close()
	_, err := NewRelayer(srv.Client(), srv.URL+"/v1", nil).Relay(context.Background(), "pairings", nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "captive", "an error never quotes the body")
}

// lantern-cloud answers an Empty with no body unless its binding says
// otherwise: a success, relayed as {}.
func TestRelayTakesAnEmptySuccessAsAnEmptyObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	for _, op := range []string{"invites", "invites/claim", "pairings/end"} {
		res, err := NewRelayer(srv.Client(), srv.URL+"/v1", nil).Relay(context.Background(), op, []byte(`{}`))
		require.NoError(t, err, op)
		assert.Equal(t, http.StatusOK, res.Status, op)
		assert.JSONEq(t, `{}`, string(res.Body), op)
	}
}

// A pairing change runs onChange, so the backend's ticket Source fetches at
// its next read and a new pairing's rooms work within one read, not one
// refresh interval.
func TestRelayCallsOnChangeWhenPairingsChange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"pairing_id": "p"})
	}))
	defer srv.Close()
	var changes atomic.Int32
	rl := NewRelayer(srv.Client(), srv.URL+"/v1", func() { changes.Add(1) })
	for _, op := range []string{"invites", "invites/get", "pairings"} {
		_, err := rl.Relay(context.Background(), op, []byte(`{}`))
		require.NoError(t, err)
	}
	assert.Zero(t, changes.Load(), "creating, reading and listing change no pairing")
	for _, op := range []string{"invites/claim", "invites/decide", "pairings/end", OpRefreshTickets} {
		_, err := rl.Relay(context.Background(), op, []byte(`{}`))
		require.NoError(t, err)
	}
	assert.Equal(t, int32(4), changes.Load())
}

// A relayed body carries invite hashes, public keys and encrypted names, so a
// redirect to another origin must not replay it there.
func TestRelayRefusesCrossOriginRedirects(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var other atomic.Int32
			elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				other.Add(1)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer elsewhere.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, elsewhere.URL+r.URL.Path, code)
			}))
			defer srv.Close()
			var changes atomic.Int32

			_, err := NewRelayer(srv.Client(), srv.URL+"/v1", func() { changes.Add(1) }).
				Relay(context.Background(), "invites/claim", []byte(`{"invite_hash":"h"}`))
			require.Error(t, err)
			assert.Zero(t, other.Load(), "the other origin never receives the body")
			assert.Zero(t, changes.Load())
		})
	}
}
