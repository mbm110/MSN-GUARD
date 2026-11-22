package traces

import (
	"context"
	"net/url"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// ExtractBanditTraceContext extracts the W3C traceparent from any
// bandit callback URL that carries one (as a "tp" query parameter).
// Since overrides is a map, iteration order is nondeterministic;
// in practice all override URLs carry the same traceparent.
// Returns the context and true if a valid trace was found.
func ExtractBanditTraceContext(overrides map[string]string) (context.Context, bool) {
	for _, rawURL := range overrides {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		tp := u.Query().Get("tp")
		if tp == "" {
			continue
		}
		carrier := propagation.MapCarrier{"traceparent": tp}
		ctx := otel.GetTextMapPropagator().Extract(context.Background(), carrier)
		if trace.SpanContextFromContext(ctx).IsValid() {
			return ctx, true
		}
	}
	return context.Background(), false
}
