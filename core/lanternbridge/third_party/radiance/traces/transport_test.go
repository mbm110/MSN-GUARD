package traces

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	bfcommon "github.com/getlantern/broflake/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type okTransport struct{}

func (okTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

// Room tickets are bearer credentials carrying a pairing ID; no part of them
// may reach a trace.
func TestHeaderAnnotationNeverRecordsRoomTickets(t *testing.T) {
	require.Equal(t, roomTicketsHeader, strings.ToLower(bfcommon.RoomTicketsHeader))
	const ticket = "eyJ2IjoxLCJrIjoiYzUxYzUwNzUiLCJwIjoiNmYxYzJiMGUifQ.c2lnbmF0dXJl"
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(mem))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "subscribe")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://freddie.example/v1/signal", nil)
	require.NoError(t, err)
	req.Header.Set(bfcommon.RoomTicketsHeader, ticket+","+ticket)
	req.Header.Set("X-Other", "kept")
	_, err = NewHeaderAnnotatingRoundTripper(okTransport{}).RoundTrip(req)
	require.NoError(t, err)
	span.End()

	spans := mem.GetSpans()
	require.Len(t, spans, 1)
	var keys []string
	for _, kv := range spans[0].Attributes {
		keys = append(keys, string(kv.Key))
		assert.NotContains(t, kv.Value.Emit(), ticket[:4], string(kv.Key))
	}
	assert.NotContains(t, keys, "http.request.header.x-bf-room-tickets")
	assert.Contains(t, keys, "http.request.header.x-other")
}

// Helper-invite requests carry the device ID and say the device uses helper
// invites, so the production wrapper records no span for them; other API
// requests still get one.
func TestRoundTripperSkipsHelperRequests(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(mem))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	rt := NewRoundTripper(NewHeaderAnnotatingRoundTripper(okTransport{}))
	send := func(path string) {
		req, err := http.NewRequest(http.MethodPost, "https://api.example"+path, nil)
		require.NoError(t, err)
		req.Header.Set("X-Lantern-Device-Id", "device-1")
		resp, err := rt.RoundTrip(req)
		require.NoError(t, err)
		_ = resp.Body.Close() // ends otelhttp's span
	}
	for _, p := range []string{"/v1/helper/invites/claim", "/v1/helper/pairings", "/v1/helper/tickets", "/api/v1/helper/invites"} {
		send(p)
	}
	assert.Empty(t, mem.GetSpans(), "no span for a helper request")
	send("/v1/config-new")
	assert.Len(t, mem.GetSpans(), 1, "other requests are still traced")
}

// A helper request made under a recording span (the ticket fetch does not
// detach its caller's) must add nothing to that span.
func TestRoundTripperDetachesTheCallersSpanFromHelperRequests(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(mem))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	rt := NewRoundTripper(NewHeaderAnnotatingRoundTripper(okTransport{}))
	ctx, parent := tp.Tracer("test").Start(context.Background(), "caller")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.example/v1/helper/tickets", nil)
	require.NoError(t, err)
	req.Header.Set("X-Lantern-Device-Id", "device-1")
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	parent.End()

	spans := mem.GetSpans()
	require.Len(t, spans, 1, "only the caller's own span")
	assert.Equal(t, "caller", spans[0].Name)
	assert.Empty(t, spans[0].Attributes)
	assert.Empty(t, spans[0].Events)
}

// http.Client builds a redirect from the original request's context, so an
// Untraced request stays untraced when it is redirected off /helper/.
func TestUntracedSurvivesARedirectOffHelper(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(mem))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/helper/") {
			http.Redirect(w, r, "/v1/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: NewRoundTripper(NewHeaderAnnotatingRoundTripper(http.DefaultTransport))}

	ctx, parent := tp.Tracer("test").Start(context.Background(), "caller")
	req, err := http.NewRequestWithContext(Untraced(ctx), http.MethodPost, srv.URL+"/v1/helper/tickets", strings.NewReader("{}"))
	require.NoError(t, err)
	req.Header.Set("X-Lantern-Device-Id", "device-1")
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.NotNil(t, resp.Request)
	assert.Equal(t, "/v1/elsewhere", resp.Request.URL.Path, "the redirect was followed")
	parent.End()

	spans := mem.GetSpans()
	require.Len(t, spans, 1, "no span for either hop")
	assert.Equal(t, "caller", spans[0].Name)
	assert.Empty(t, spans[0].Attributes)
	assert.Empty(t, spans[0].Events)
}
