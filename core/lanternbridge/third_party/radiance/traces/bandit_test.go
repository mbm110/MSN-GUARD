package traces

import (
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func init() {
	otel.SetTextMapPropagator(propagation.TraceContext{})
}

func TestExtractBanditTraceContext(t *testing.T) {
	validTP := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	tests := []struct {
		name      string
		overrides map[string]string
		wantOK    bool
		wantTrace string
	}{
		{
			name:      "valid tp parameter",
			overrides: map[string]string{"route1": "https://example.com/callback?tp=" + validTP},
			wantOK:    true,
			wantTrace: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
		{
			name:      "tp with other params",
			overrides: map[string]string{"route1": "https://example.com/callback?token=abc&tp=" + validTP},
			wantOK:    true,
			wantTrace: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
		{
			name:      "tp inside another param value should not match",
			overrides: map[string]string{"route1": "https://example.com/callback?notp=foo"},
			wantOK:    false,
		},
		{
			name:      "no tp parameter",
			overrides: map[string]string{"route1": "https://example.com/callback?other=value"},
			wantOK:    false,
		},
		{
			name:      "empty overrides",
			overrides: map[string]string{},
			wantOK:    false,
		},
		{
			name:      "nil overrides",
			overrides: nil,
			wantOK:    false,
		},
		{
			name:      "invalid traceparent value",
			overrides: map[string]string{"route1": "https://example.com/callback?tp=not-a-valid-traceparent"},
			wantOK:    false,
		},
		{
			name:      "malformed URL is skipped",
			overrides: map[string]string{"route1": "://bad-url", "route2": "https://example.com/callback?tp=" + validTP},
			wantOK:    true,
			wantTrace: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
		{
			name:      "url-encoded tp value",
			overrides: map[string]string{"route1": "https://example.com/callback?tp=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
			wantOK:    true,
			wantTrace: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ok := ExtractBanditTraceContext(tt.overrides)
			if ok != tt.wantOK {
				t.Fatalf("got ok=%v, want %v", ok, tt.wantOK)
			}
			if tt.wantOK {
				sc := trace.SpanContextFromContext(ctx)
				if !sc.IsValid() {
					t.Fatal("expected valid span context")
				}
				if got := sc.TraceID().String(); got != tt.wantTrace {
					t.Errorf("trace ID = %s, want %s", got, tt.wantTrace)
				}
			}
		})
	}
}
