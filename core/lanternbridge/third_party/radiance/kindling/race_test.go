package kindling

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/getlantern/kindling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/getlantern/radiance/traces"
)

func TestRecordRace(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	ctx, span := tp.Tracer("test").Start(context.Background(), "config_fetcher.send")
	recordRace(ctx, kindling.Race{
		Winner: "smart",
		Attempts: []kindling.Attempt{
			{Transport: "smart", Outcome: kindling.OutcomeWon, StatusCode: 200, Elapsed: 700 * time.Millisecond},
			{Transport: "domainfront", Outcome: kindling.OutcomeRetryStatus, StatusCode: 403, Elapsed: 300 * time.Millisecond},
			{Transport: "amp", Outcome: kindling.OutcomeConnectFailed, Err: errors.New("dial: blocked")},
		},
	})
	span.End()

	spans := rec.Ended()
	require.Len(t, spans, 1)
	attrs := map[attribute.Key]attribute.Value{}
	for _, kv := range spans[0].Attributes() {
		attrs[kv.Key] = kv.Value
	}
	assert.Equal(t, "smart", attrs["kindling.winner"].AsString())
	assert.Equal(t, "won", attrs["kindling.smart.outcome"].AsString())
	assert.Equal(t, int64(700), attrs["kindling.smart.elapsed_ms"].AsInt64())
	assert.Equal(t, "retry_status", attrs["kindling.domainfront.outcome"].AsString())
	assert.Equal(t, int64(403), attrs["kindling.domainfront.status"].AsInt64())
	assert.Equal(t, "connect_failed", attrs["kindling.amp.outcome"].AsString())
	_, hasStatus := attrs["kindling.amp.status"]
	assert.False(t, hasStatus, "no status without a response")

	events := spans[0].Events()
	require.Len(t, events, 3)
	var ampErr string
	for _, e := range events {
		assert.Equal(t, "kindling.attempt", e.Name)
		for _, kv := range e.Attributes {
			if kv.Key == "kindling.error" {
				ampErr = kv.Value.AsString()
			}
		}
	}
	assert.Equal(t, "dial: blocked", ampErr)
	for _, e := range events {
		for _, kv := range e.Attributes {
			if kv.Key == "kindling.status" {
				assert.NotZero(t, kv.Value.AsInt64(), "no status without a response")
			}
		}
	}
}

func TestTruncateUTF8(t *testing.T) {
	s := strings.Repeat("a", 255) + "é"
	got := truncateUTF8(s, 256)
	assert.True(t, utf8.ValidString(got))
	assert.Equal(t, strings.Repeat("a", 255), got)
	assert.Equal(t, "short", truncateUTF8("short", 256))
	assert.True(t, utf8.ValidString(truncateUTF8("bad \xff byte", 256)))
}

func TestRecordRaceWithoutSpan(t *testing.T) {
	recordRace(context.Background(), kindling.Race{Winner: "smart", Attempts: []kindling.Attempt{{Transport: "smart"}}})
}

type okTransport struct{}

func (okTransport) NewRoundTripper(context.Context, string) (http.RoundTripper, error) {
	return roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	}), nil
}
func (okTransport) MaxLength() int                { return 0 }
func (okTransport) IsStreamable() bool            { return true }
func (okTransport) Name() string                  { return "smart" }
func (okTransport) RequestTimeout() time.Duration { return 0 }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Through radiance's otelhttp wrapper, the race lands on the request's HTTP
// client span, a child of the caller's span (config_fetcher.send for config).
func TestRecordRaceThroughTracedTransport(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	k, err := kindling.NewKindling("test", kindling.WithTransport(okTransport{}), kindling.WithRaceObserver(recordRace))
	require.NoError(t, err)
	client := &http.Client{Transport: traces.NewRoundTripper(k.NewHTTPClient().Transport)}

	ctx, parent := tp.Tracer("test").Start(context.Background(), "config_fetcher.send")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://df.iantem.io/api/v1/config-new", http.NoBody)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	parent.End()

	var httpSpan sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		if s.Parent().SpanID() == parent.SpanContext().SpanID() {
			httpSpan = s
		}
	}
	require.NotNil(t, httpSpan, "otelhttp starts a child span for the request")
	var winner string
	for _, kv := range httpSpan.Attributes() {
		if kv.Key == "kindling.winner" {
			winner = kv.Value.AsString()
		}
	}
	assert.Equal(t, "smart", winner)
}
