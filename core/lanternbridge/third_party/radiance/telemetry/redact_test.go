package telemetry

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/getlantern/radiance/vpn"
)

const helperTag = "helper-0123456789ab"

func TestSpanExportRedactsHelperTags(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(newRedactingExporter(mem)))
	_, span := tp.Tracer("test").Start(context.Background(), "dial "+helperTag)
	span.SetAttributes(
		attribute.String("outbound", helperTag),
		attribute.StringSlice("chain", []string{"auto", helperTag}),
		attribute.Int("latency_ms", 7),
	)
	span.AddEvent("url_test_result", trace.WithAttributes(attribute.String("outbound", helperTag)))
	span.RecordError(errors.New("outbound/unbounded[" + helperTag + "]: dial failed"))
	span.SetStatus(codes.Error, "outbound/unbounded["+helperTag+"]: dial failed")
	span.End()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	spans := mem.GetSpans()
	require.Len(t, spans, 1)
	s := spans[0]
	assert.Equal(t, "dial helper", s.Name)
	for _, kv := range s.Attributes {
		assert.NotContains(t, kv.Value.Emit(), helperTag, string(kv.Key))
	}
	assert.Contains(t, s.Attributes, attribute.Int("latency_ms", 7), "other attributes are kept")
	require.Len(t, s.Events, 2)
	for _, ev := range s.Events {
		for _, kv := range ev.Attributes {
			assert.NotContains(t, kv.Value.Emit(), helperTag, ev.Name+"."+string(kv.Key))
		}
	}
	assert.Equal(t, "outbound/unbounded[helper]: dial failed", s.Status.Description)
}

func TestConnMetricAttributesRedactHelperTags(t *testing.T) {
	set := newConnAttributeSet(vpn.ConnAttrs{
		FromOutbound: helperTag,
		Outbound:     helperTag,
		Rule:         "final => " + helperTag,
		ChainList:    []string{"auto", helperTag},
	})
	for _, kv := range set.ToSlice() {
		assert.NotContains(t, kv.Value.Emit(), helperTag, string(kv.Key))
	}
	v, _ := set.Value("outbound_name")
	assert.Equal(t, "helper", v.AsString())
}

func TestSpanExportRedactsVolunteerAddresses(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(newRedactingExporter(mem)))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	_, span := tp.Tracer("test").Start(context.Background(), "connect")
	span.RecordError(errors.New("outbound/samizdat[" + helperTag + "]: dial tcp [2001:db8::7]:443"))
	span.SetStatus(codes.Error, "outbound/samizdat["+helperTag+"]: dial tcp 203.0.113.7:443")
	span.SetAttributes(attribute.String("peer", "198.51.100.9:443"))
	span.End()

	s := mem.GetSpans()[0]
	assert.Equal(t, "outbound/samizdat[helper]: dial tcp [REDACTED]", s.Status.Description)
	evAttrs := attribute.NewSet(s.Events[0].Attributes...)
	msg, _ := evAttrs.Value("exception.message")
	assert.Equal(t, "outbound/samizdat[helper]: dial tcp [REDACTED]", msg.AsString())
	assert.Contains(t, s.Attributes, attribute.String("peer", "[REDACTED]"), "the span names a helper, so every address in it goes")
}

func TestRedactedSpanReturnsOriginalsWhenNothingChanges(t *testing.T) {
	ro := tracetest.SpanStub{
		Name:   "clean",
		Events: []sdktrace.Event{{Name: "e", Attributes: []attribute.KeyValue{attribute.String("k", "v")}}},
		Links:  []sdktrace.Link{{Attributes: []attribute.KeyValue{attribute.String("k", "v")}}},
	}.Snapshot()
	rs := redactedSpan{ReadOnlySpan: ro}
	assert.Same(t, &ro.Events()[0], &rs.Events()[0])
	assert.Same(t, &ro.Links()[0], &rs.Links()[0])
}

// Defense in depth: a room-tickets header attribute never leaves the client,
// whoever records it.
func TestSpanExportDropsRoomTicketHeaders(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(newRedactingExporter(mem)))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	_, span := tp.Tracer("test").Start(context.Background(), "subscribe")
	span.SetAttributes(
		attribute.StringSlice("http.request.header.x-bf-room-tickets", []string{"eyJ2IjoxfQ.c2ln"}),
		attribute.String("http.request.method", "GET"),
	)
	span.End()
	s := mem.GetSpans()[0]
	assert.Equal(t, []attribute.KeyValue{attribute.String("http.request.method", "GET")}, s.Attributes)
}

// lantern-box records a helper's dial failure as an event whose outbound
// attribute is already "helper" and whose error attribute carries the address,
// so a span naming a helper anywhere loses every address. Other spans keep
// theirs.
func TestSpanExportRedactsAddressesInSpansNamingAHelper(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(newRedactingExporter(mem)))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	tr := tp.Tracer("test")

	_, span := tr.Start(context.Background(), "mutableurltest.dial")
	span.SetAttributes(attribute.String("server", "198.51.100.9:443"))
	span.AddEvent("dial_failed", trace.WithAttributes(
		attribute.String("outbound", "helper"),
		attribute.String("error", "dial tcp 203.0.113.7:443: connect: connection refused"),
	))
	span.End()
	_, other := tr.Start(context.Background(), "mutableurltest.dial")
	other.AddEvent("dial_failed", trace.WithAttributes(
		attribute.String("outbound", "lantern-1"),
		attribute.String("error", "dial tcp 198.51.100.9:443: connect: connection refused"),
	))
	other.End()

	spans := mem.GetSpans()
	require.Len(t, spans, 2)
	assert.Contains(t, spans[0].Attributes, attribute.String("server", "[REDACTED]"))
	assert.Contains(t, spans[0].Events[0].Attributes, attribute.String("error", "dial tcp [REDACTED]: connect: connection refused"))
	assert.Contains(t, spans[1].Events[0].Attributes, attribute.String("error", "dial tcp 198.51.100.9:443: connect: connection refused"),
		"a span that names no helper keeps its addresses")
}

func TestConnMetricAttributesRedactThePersonalProxiesTag(t *testing.T) {
	set := newConnAttributeSet(vpn.ConnAttrs{
		FromOutbound: "personal-proxies",
		Outbound:     helperTag,
		Rule:         "final => personal-proxies",
		ChainList:    []string{"manual", "personal-proxies", helperTag},
	})
	for _, kv := range set.ToSlice() {
		assert.NotContains(t, kv.Value.Emit(), "personal-proxies", string(kv.Key))
		assert.NotContains(t, kv.Value.Emit(), helperTag, string(kv.Key))
	}
	chain, _ := set.Value("chain_list")
	assert.Equal(t, []string{"manual", "helper", "helper"}, chain.AsStringSlice())
}

func TestSpanExportRedactsThePersonalProxiesTag(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(newRedactingExporter(mem)))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	_, span := tp.Tracer("test").Start(context.Background(), "url test")
	span.SetAttributes(attribute.String("tag", "personal-proxies"), attribute.String("peer", "198.51.100.9:443"))
	span.SetStatus(codes.Error, "outbound/mutableurltest[personal-proxies]: dial tcp 203.0.113.7:443")
	span.End()

	s := mem.GetSpans()[0]
	for _, kv := range s.Attributes {
		assert.NotContains(t, kv.Value.Emit(), "personal-proxies", string(kv.Key))
		assert.NotContains(t, kv.Value.Emit(), "198.51.100.9", string(kv.Key), "a span naming the group loses every address")
	}
	assert.Equal(t, "outbound/mutableurltest[helper]: dial tcp [REDACTED]", s.Status.Description)
}
