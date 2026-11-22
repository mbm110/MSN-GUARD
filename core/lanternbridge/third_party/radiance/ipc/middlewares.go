package ipc

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	semconv "github.com/getlantern/semconv"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	rlog "github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/traces"
)

func logger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		r = r.WithContext(ctx)
		// Helper-invite routes are neither annotated nor logged: an
		// in-process call carries the caller's span here, and a /helper/
		// route on it, or a log line, would show the device uses helper
		// invites, and how often.
		if !strings.HasPrefix(r.URL.Path, "/helper/") {
			span := trace.SpanFromContext(r.Context())
			span.SetAttributes(semconv.HTTPRouteKey.String(r.URL.Path))
			slog.Log(r.Context(), rlog.LevelTrace, "IPC request", "method", r.Method, "path", r.URL.Path)
		}
		h.ServeHTTP(w, r)
	})
}

func tracer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := otel.Tracer(tracerName).Start(r.Context(), r.URL.Path)
		defer span.End()

		r = r.WithContext(ctx)
		var buf bytes.Buffer
		ww := &statusRecorder{ResponseWriter: w, body: &buf}
		next.ServeHTTP(ww, r)
		if ww.status >= 400 {
			traces.RecordError(ctx, fmt.Errorf("status %d: %s", ww.status, buf.String()))
		}
	})
}

// statusRecorder wraps http.ResponseWriter to capture the status code and response body.
type statusRecorder struct {
	http.ResponseWriter
	status int
	body   *bytes.Buffer
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// Flush implements http.Flusher if the underlying ResponseWriter supports it.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type peerLookupKey struct{}
type peerKey struct{}
type ownerSIDKey struct{}

func authPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookup, ok := r.Context().Value(peerLookupKey{}).(func() (usr, error))
		if !ok {
			http.Error(w, "could not get credentials", http.StatusUnauthorized)
			return
		}
		peer, err := lookup()
		if err != nil || peer.uid == "" {
			http.Error(w, "could not get credentials", http.StatusUnauthorized)
			return
		}
		ownerSID, _ := r.Context().Value(ownerSIDKey{}).(string)
		if !peerCanAccess(peer, ownerSID) {
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		if !peer.isAdmin && r.URL.Path == envEndpoint {
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, peer)))
	})
}

func peerCanAccess(peer usr, ownerSID string) bool {
	return peer.isAdmin || (peer.uid != "" && peer.uid == ownerSID)
}
