package traces

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// NewRoundTripper wraps the provided http.RoundTripper with OpenTelemetry instrumentation.
// Helper-invite requests are not traced (see untracedRequest).
func NewRoundTripper(original http.RoundTripper) http.RoundTripper {
	if original == nil {
		original = http.DefaultTransport
	}
	return detachingRoundTripper{next: otelhttp.NewTransport(original,
		otelhttp.WithClientTrace(httpTrace),
		otelhttp.WithFilter(func(r *http.Request) bool { return !untracedRequest(r) }))}
}

// detachingRoundTripper strips the caller's span from helper-invite requests.
// otelhttp's filter only stops a new span; without this, the header
// annotator and kindling's race observer would record on the caller's.
type detachingRoundTripper struct {
	next http.RoundTripper
}

func (d detachingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if untracedRequest(r) {
		r = r.WithContext(Untraced(r.Context()))
	}
	return d.next.RoundTrip(r)
}

type untracedKey struct{}

// Untraced marks ctx so that requests made with it are never traced, and
// detaches the caller's span. http.Client builds each redirect from the
// original request's context, so the mark covers a redirect off /helper/,
// which the path check alone would not.
func Untraced(ctx context.Context) context.Context {
	ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	return context.WithValue(ctx, untracedKey{}, true)
}

// untracedRequest reports whether r is a helper-invite request: one made
// with an Untraced context, or any request under /helper/ (the HelperService
// calls and the ticket fetch). A span for one would carry the device ID
// header and show the device uses helper invites, and how often; with no
// span, and the caller's span detached, the header annotator and kindling's
// race observer find nothing to record on.
func untracedRequest(r *http.Request) bool {
	if marked, _ := r.Context().Value(untracedKey{}).(bool); marked {
		return true
	}
	return r.URL != nil && strings.Contains(r.URL.Path, "/helper/")
}

func httpTrace(ctx context.Context) *httptrace.ClientTrace {
	span := trace.SpanFromContext(ctx)
	return &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			span.SetAttributes(attribute.String("host_port", hostPort))
		},
		TLSHandshakeStart: func() {
			span.SetAttributes(attribute.Bool("handshake_started", true))
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err != nil {
				RecordError(ctx, err)
				return
			}
			span.SetAttributes(attribute.Bool("handshake_complete", cs.HandshakeComplete))
		},
		DNSStart: func(di httptrace.DNSStartInfo) {
			span.SetAttributes(attribute.String("dns_host", di.Host))
		},
		DNSDone: func(di httptrace.DNSDoneInfo) {
			RecordError(ctx, di.Err)
		},
		ConnectStart: func(network, addr string) {
			span.SetAttributes(attribute.String("network", network))
		},
		ConnectDone: func(network, addr string, err error) {
			RecordError(ctx, err)
		},
	}
}

type headerAnnotatingRoundTripper struct {
	next http.RoundTripper
}

func (h *headerAnnotatingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	span := trace.SpanFromContext(ctx)

	if span != nil {
		for k, v := range req.Header {
			headerName := strings.ToLower(k)
			if isUnrecordedHeader(headerName) {
				continue
			}
			if isSensitiveHeader(headerName) {
				if len(v) > 0 && len(v[0]) > 5 {
					span.SetAttributes(
						attribute.StringSlice(fmt.Sprintf("http.request.header.%s", headerName), []string{fmt.Sprintf("%s...", v[0][0:4])}),
					)
				} else {
					span.SetAttributes(
						attribute.StringSlice(fmt.Sprintf("http.request.header.%s", headerName), []string{"REDACTED"}),
					)
				}
			} else {
				span.SetAttributes(
					attribute.StringSlice(fmt.Sprintf("http.request.header.%s", headerName), v),
				)
			}
		}
	}

	return h.next.RoundTrip(req)
}

// roomTicketsHeader is broflake's common.RoomTicketsHeader, lowercased.
const roomTicketsHeader = "x-bf-room-tickets"

// isUnrecordedHeader reports whether a header must not appear in traces at
// all, not even as a prefix. Helper room tickets are short-lived bearer
// credentials whose payload carries the pairing ID.
func isUnrecordedHeader(header string) bool {
	return header == roomTicketsHeader
}

func isSensitiveHeader(header string) bool {
	switch header {
	case "authorization", "x-lantern-pro-token":
		return true
	default:
		return false
	}
}

// NewHeaderAnnotatingRoundTripper reads the request headers during the roundtrip
// operation and adds the information as attributes. Please be aware that
// requests must have a context otherwise the info won't be added.
func NewHeaderAnnotatingRoundTripper(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &headerAnnotatingRoundTripper{next: base}
}
