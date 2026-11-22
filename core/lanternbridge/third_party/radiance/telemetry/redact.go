package telemetry

import (
	"bytes"
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/getlantern/radiance/internal/logsafe"
	"github.com/getlantern/radiance/internal/redact"
)

// redactingExporter applies redact.Helper to every span it exports: the name,
// string attributes, events (including recorded errors), links and the status
// description. A helper tag is a client-side pseudonym for one of the user's
// pairings, and an error naming a helper outbound may carry the helper's
// address; clients must export neither. sing-box errors name the failing
// outbound, so any span that records one can carry both.
// roomTicketsHeaderAttr is the attribute traces' header annotation would give
// broflake's X-BF-Room-Tickets header. traces never records it; the exporter
// drops it too, in case anything else does.
const roomTicketsHeaderAttr attribute.Key = "http.request.header.x-bf-room-tickets"

type redactingExporter struct {
	sdktrace.SpanExporter
}

func newRedactingExporter(e sdktrace.SpanExporter) sdktrace.SpanExporter {
	return redactingExporter{SpanExporter: e}
}

func (e redactingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		out[i] = redactedSpan{ReadOnlySpan: s, helper: spanNamesHelper(s)}
	}
	return e.SpanExporter.ExportSpans(ctx, out)
}

// redactedSpan is a span on its way out. helper says whether anything in the
// span names a helper outbound, in which case every address anywhere in it is
// redacted: lantern-box records a helper's dial failure as an event whose
// outbound attribute says "helper" and whose separate error attribute carries
// the address.
type redactedSpan struct {
	sdktrace.ReadOnlySpan
	helper bool
}

// spanNamesHelper reports whether s's name, attributes, events, links or
// status may name a helper outbound.
func spanNamesHelper(s sdktrace.ReadOnlySpan) bool {
	if redact.NamesHelper(s.Name()) || attrsNameHelper(s.Attributes()) || redact.NamesHelper(s.Status().Description) {
		return true
	}
	for _, ev := range s.Events() {
		if redact.NamesHelper(ev.Name) || attrsNameHelper(ev.Attributes) {
			return true
		}
	}
	for _, l := range s.Links() {
		if attrsNameHelper(l.Attributes) {
			return true
		}
	}
	return false
}

func attrsNameHelper(attrs []attribute.KeyValue) bool {
	for _, kv := range attrs {
		switch kv.Value.Type() {
		case attribute.STRING:
			if redact.NamesHelper(kv.Value.AsString()) {
				return true
			}
		case attribute.STRINGSLICE:
			for _, v := range kv.Value.AsStringSlice() {
				if redact.NamesHelper(v) {
					return true
				}
			}
		}
	}
	return false
}

// redactText redacts helper tags in v, every address too when helper is set,
// and otherwise the addresses on lines that name a helper outbound.
func redactText(v string, helper bool) string {
	if helper {
		v = redact.Addresses(v)
	}
	return redact.Helper(v)
}

func (s redactedSpan) Name() string {
	return redactText(s.ReadOnlySpan.Name(), s.helper)
}

func (s redactedSpan) Attributes() []attribute.KeyValue {
	return redactAttrs(s.ReadOnlySpan.Attributes(), s.helper)
}

// Events returns the span's events, copied only if one needs redacting.
func (s redactedSpan) Events() []sdktrace.Event {
	events := s.ReadOnlySpan.Events()
	var out []sdktrace.Event
	for i, ev := range events {
		name := redactText(ev.Name, s.helper)
		attrs := redactAttrs(ev.Attributes, s.helper)
		if out == nil && name == ev.Name && sameAttrs(attrs, ev.Attributes) {
			continue
		}
		if out == nil {
			out = append(make([]sdktrace.Event, 0, len(events)), events[:i]...)
		}
		ev.Name, ev.Attributes = name, attrs
		out = append(out, ev)
	}
	if out == nil {
		return events
	}
	return out
}

// Links returns the span's links, copied only if one needs redacting.
func (s redactedSpan) Links() []sdktrace.Link {
	links := s.ReadOnlySpan.Links()
	var out []sdktrace.Link
	for i, l := range links {
		attrs := redactAttrs(l.Attributes, s.helper)
		if out == nil && sameAttrs(attrs, l.Attributes) {
			continue
		}
		if out == nil {
			out = append(make([]sdktrace.Link, 0, len(links)), links[:i]...)
		}
		l.Attributes = attrs
		out = append(out, l)
	}
	if out == nil {
		return links
	}
	return out
}

func (s redactedSpan) Status() sdktrace.Status {
	st := s.ReadOnlySpan.Status()
	st.Description = redactText(st.Description, s.helper)
	return st
}

// sameAttrs reports whether redactAttrs returned its input unchanged.
func sameAttrs(a, b []attribute.KeyValue) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// redactAttrs returns attrs with string values redacted, with every address
// when helper is set. It returns attrs itself when none needs it.
func redactAttrs(attrs []attribute.KeyValue, helper bool) []attribute.KeyValue {
	var out []attribute.KeyValue
	for i, kv := range attrs {
		if kv.Key == roomTicketsHeaderAttr {
			// Bearer credentials: drop the attribute outright.
			if out == nil {
				out = append(make([]attribute.KeyValue, 0, len(attrs)), attrs[:i]...)
			}
			continue
		}
		red, changed := redactValue(kv, helper)
		if !changed {
			if out != nil {
				out = append(out, kv)
			}
			continue
		}
		if out == nil {
			out = append(make([]attribute.KeyValue, 0, len(attrs)), attrs[:i]...)
		}
		out = append(out, red)
	}
	if out == nil {
		return attrs
	}
	return out
}

func redactValue(kv attribute.KeyValue, helper bool) (attribute.KeyValue, bool) {
	switch kv.Value.Type() {
	case attribute.STRING:
		v := kv.Value.AsString()
		if !helper && !strings.Contains(v, "helper") {
			return kv, false
		}
		r := redactText(v, helper)
		return attribute.String(string(kv.Key), r), r != v
	case attribute.STRINGSLICE:
		vs := kv.Value.AsStringSlice()
		changed := false
		for i, v := range vs {
			if r := redactText(v, helper); r != v {
				vs[i] = r
				changed = true
			}
		}
		if !changed {
			return kv, false
		}
		return attribute.StringSlice(string(kv.Key), vs), true
	}
	return kv, false
}

// redactingLogExporter applies [redactLogText] to each log record's body and
// attribute values, and [redactText] to attribute keys, before export. It
// redacts every address, since a log line, unlike a span, rarely says which
// outbound its addresses belong to.
type redactingLogExporter struct {
	sdklog.Exporter
}

func newRedactingLogExporter(e sdklog.Exporter) sdklog.Exporter {
	return redactingLogExporter{Exporter: e}
}

func (e redactingLogExporter) Export(ctx context.Context, records []sdklog.Record) error {
	out := make([]sdklog.Record, len(records))
	for i := range records {
		r := records[i].Clone()
		r.SetBody(redactLogValue(r.Body()))
		attrs := make([]attribute.KeyValue, 0, r.AttributesLen())
		r.WalkAttributes(func(kv attribute.KeyValue) bool {
			attrs = append(attrs, redactLogKeyValue(kv))
			return true
		})
		r.SetAttributes(attrs...)
		out[i] = r
	}
	return e.Exporter.Export(ctx, out)
}

func redactLogValue(v attribute.Value) attribute.Value {
	switch v.Type() {
	case attribute.STRING:
		return attribute.StringValue(redactLogText(v.AsString()))
	case attribute.STRINGSLICE:
		vs := v.AsStringSlice()
		for i, s := range vs {
			vs[i] = redactLogText(s)
		}
		return attribute.StringSliceValue(vs)
	case attribute.SLICE:
		vs := v.AsSlice()
		for i, e := range vs {
			vs[i] = redactLogValue(e)
		}
		return attribute.SliceValue(vs...)
	case attribute.MAP:
		kvs := v.AsMap()
		for i, kv := range kvs {
			kvs[i] = redactLogKeyValue(kv)
		}
		return attribute.MapValue(kvs...)
	}
	return v
}

var (
	// bearerCredential matches any token after "Bearer".
	bearerCredential = regexp.MustCompile(`(?i)\b(bearer)(\s+)[A-Za-z0-9._~+/=-]+`)
	// basicToken matches the word after "Basic"; isBasicCredential decides
	// whether it is a credential.
	basicToken = regexp.MustCompile(`(?i)\b(basic\s+)([A-Za-z0-9._~+/=-]+)`)
)

// isBasicCredential reports whether tok may be a Basic credential. It errs
// toward redacting, so a long word such as "authentication" counts too.
func isBasicCredential(tok string) bool {
	if len(tok) >= 12 || strings.ContainsAny(tok, "0123456789+/=") {
		return true
	}
	b, err := base64.RawStdEncoding.DecodeString(tok)
	return err == nil && bytes.IndexByte(b, ':') >= 0
}

// redactLogText is redactText for log records, which also carry credentials
// in free text, such as an Authorization header a dial error quotes.
func redactLogText(s string) string {
	// Before redactText: an address placeholder inside a credential would cut its match short.
	s = bearerCredential.ReplaceAllString(s, "${1}${2}"+logsafe.Redacted)
	s = basicToken.ReplaceAllStringFunc(s, func(m string) string {
		sub := basicToken.FindStringSubmatch(m)
		if !isBasicCredential(sub[2]) {
			return m
		}
		return sub[1] + logsafe.Redacted
	})
	return redactText(s, true)
}

func redactLogKeyValue(kv attribute.KeyValue) attribute.KeyValue {
	return attribute.KeyValue{Key: attribute.Key(redactText(string(kv.Key), true)), Value: redactLogValue(kv.Value)}
}
