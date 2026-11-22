package kindling

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/getlantern/kindling"
	"github.com/getlantern/semconv"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const maxAttemptErr = 256

// recordRace keeps per-transport results as span attributes, which queries can
// group by, and errors on events.
func recordRace(ctx context.Context, race kindling.Race) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(semconv.KindlingWinnerKey.String(race.Winner))
	for _, a := range race.Attempts {
		attrs := []attribute.KeyValue{
			semconv.KindlingTransportAttr(a.Transport, semconv.KindlingOutcomeKey).String(string(a.Outcome)),
			semconv.KindlingTransportAttr(a.Transport, semconv.KindlingElapsedMsKey).Int64(a.Elapsed.Milliseconds()),
		}
		event := []attribute.KeyValue{
			semconv.KindlingTransportKey.String(a.Transport),
			semconv.KindlingOutcomeKey.String(string(a.Outcome)),
			semconv.KindlingElapsedMsKey.Int64(a.Elapsed.Milliseconds()),
		}
		if a.StatusCode != 0 {
			attrs = append(attrs, semconv.KindlingTransportAttr(a.Transport, semconv.KindlingStatusKey).Int(a.StatusCode))
			event = append(event, semconv.KindlingStatusKey.Int(a.StatusCode))
		}
		if a.Err != nil {
			event = append(event, semconv.KindlingErrorKey.String(truncateUTF8(a.Err.Error(), maxAttemptErr)))
		}
		span.SetAttributes(attrs...)
		span.AddEvent("kindling.attempt", trace.WithAttributes(event...))
	}
}

// truncateUTF8 returns valid UTF-8 of at most n bytes, since OTLP rejects
// invalid UTF-8.
func truncateUTF8(s string, n int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
