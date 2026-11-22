// Package traces provides utilities for working with OpenTelemetry traces.
package traces

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

// RecordError records the given error in the current span. If error is nil, it is noop.
func RecordError(ctx context.Context, err error, options ...trace.EventOption) error {
	if err == nil {
		return nil
	}
	span := trace.SpanFromContext(ctx)
	span.RecordError(err, options...)
	return err
}
