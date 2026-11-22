package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/getlantern/common"

	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/config"
	"github.com/getlantern/radiance/telemetry"
)

// serviceName is the service the tester's spans are reported under, apart
// from the radiance client's own.
const serviceName = "radiance-tester"

// phaseGrace is how long a run past its deadline is given to return, so
// the phase it was in ends its span; flushGrace then bounds the export of
// the spans still buffered. Both fit inside the time the pinger leaves
// the container after the deadline.
const (
	phaseGrace = 2 * time.Second
	flushGrace = 4 * time.Second
)

// parentContext returns ctx carrying the W3C trace context in TRACEPARENT,
// so the tester's spans join the trace of the run that started it. Without
// one, or with an invalid one, the tester starts a trace of its own.
func parentContext(ctx context.Context) context.Context {
	tp := os.Getenv("TRACEPARENT")
	if tp == "" {
		return ctx
	}
	extracted := propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{"traceparent": tp})
	if !trace.SpanContextFromContext(extracted).IsValid() {
		return ctx
	}
	return extracted
}

// exporterEndpoint reduces OTEL_EXPORTER_OTLP_ENDPOINT, which may be a URL
// as the OTel specification has it, to the host:port radiance's exporter
// takes; a bare host:port is kept. The exporter only speaks TLS, so a URL
// with any scheme but https is refused rather than exported to in vain.
func exporterEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return value, nil
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT: scheme %q is not supported, only https", u.Scheme)
	}
	return u.Host, nil
}

// spanURL is target without any credentials in it, for span attributes;
// a target that does not parse is left out rather than exported as is.
func spanURL(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	u.User = nil
	return u.String()
}

// exporterHeaders parses OTEL_EXPORTER_OTLP_HEADERS, a comma-separated
// list of key=value pairs with percent-encoded values; a literal "+" is
// kept, as it is not an encoded space there.
func exporterHeaders(value string) map[string]string {
	headers := map[string]string{}
	for pair := range strings.SplitSeq(value, ",") {
		key, raw, ok := strings.Cut(pair, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		raw = strings.TrimSpace(raw)
		if decoded, err := url.PathUnescape(raw); err == nil {
			raw = decoded
		}
		headers[key] = raw
	}
	return headers
}

// startTelemetry exports the tester's traces to the OTLP/gRPC collector at
// OTEL_EXPORTER_OTLP_ENDPOINT with OTEL_EXPORTER_OTLP_HEADERS, when set;
// every span is kept so a sampled parent loses nothing. The provider is the
// tester's own: the backend's Close stops the client's telemetry, and the
// tester's run span outlives it. The returned function flushes what is
// buffered and stops the exporter.
func startTelemetry(ctx context.Context) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	endpoint, err := exporterEndpoint(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	cfg := config.Config{
		Country: env.GetString(env.Country),
		OTEL: common.OTEL{
			Endpoint:         endpoint,
			Headers:          exporterHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")),
			TracesSampleRate: 1,
		},
	}
	provider, err := telemetry.NewTracerProvider(ctx, serviceName, os.Getenv("DEVICE_ID"), cfg)
	if err != nil {
		return nil, err
	}
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}
