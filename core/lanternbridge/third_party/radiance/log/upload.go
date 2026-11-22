package log

import (
	"context"
	"log/slog"
	"slices"
	"sync/atomic"

	"github.com/getlantern/radiance/internal/logsafe"
)

var uploadSink atomic.Pointer[slog.Handler]

// SetUploadHandler makes loggers from [NewLogger] also send each record they
// log to h, at the same level, with the credential redaction the log file
// gets. A nil h stops it. Records logged with a context from [WithoutUpload]
// are never sent.
func SetUploadHandler(h slog.Handler) {
	if h == nil {
		uploadSink.Store(nil)
		return
	}
	uploadSink.Store(&h)
}

type noUploadKey struct{}

// WithoutUpload returns a context whose records go to the log file but not to
// the upload handler, for logging the upload's own failures without feeding
// them back into it.
func WithoutUpload(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, noUploadKey{}, true)
}

type teeHandler struct {
	slog.Handler
	// ops is replayed onto the upload handler, which may be set after
	// WithAttrs and WithGroup ran.
	ops []handlerOp
}

// handlerOp is a WithGroup when group is set and a WithAttrs otherwise.
type handlerOp struct {
	group string
	attrs []slog.Attr
}

func newTeeHandler(local slog.Handler) slog.Handler {
	return &teeHandler{Handler: local}
}

func (h *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	err := h.Handler.Handle(ctx, r)
	if sink := uploadSink.Load(); sink != nil && !uploadSuppressed(ctx) {
		upload(ctx, *sink, h.ops, r)
	}
	return err
}

func uploadSuppressed(ctx context.Context) bool {
	return ctx != nil && ctx.Value(noUploadKey{}) != nil
}

func (h *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return &teeHandler{Handler: h.Handler.WithAttrs(attrs), ops: append(slices.Clip(h.ops), handlerOp{attrs: attrs})}
}

func (h *teeHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &teeHandler{Handler: h.Handler.WithGroup(name), ops: append(slices.Clip(h.ops), handlerOp{group: name})}
}

// upload sends a redacted copy of r to sink and drops sink's error; export
// failures surface through OpenTelemetry's error handler.
func upload(ctx context.Context, sink slog.Handler, ops []handlerOp, r slog.Record) {
	if ctx == nil {
		ctx = context.Background()
	}
	var groups []string
	for _, op := range ops {
		if op.group != "" {
			sink = sink.WithGroup(op.group)
			groups = append(groups, op.group)
			continue
		}
		attrs := make([]slog.Attr, len(op.attrs))
		for i, a := range op.attrs {
			attrs[i] = redactUploadAttr(groups, a)
		}
		sink = sink.WithAttrs(attrs)
	}
	if !sink.Enabled(ctx, r.Level) {
		return
	}
	out := slog.NewRecord(r.Time, r.Level, redactString(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redactUploadAttr(groups, a))
		return true
	})
	_ = sink.Handle(ctx, out)
}

// redactUploadAttr applies the log file's attribute redaction to a, including
// the members of a group, which the file's handler redacts one by one.
func redactUploadAttr(groups []string, a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() != slog.KindGroup {
		a = redactAttr(groups, a)
		// The text handler recovers from an Error method that panics, as on
		// a nil pointer; the upload handler does not.
		if err, ok := a.Value.Any().(error); ok {
			s, ok := errorString(err)
			if !ok {
				s = "<nil>"
			}
			a.Value = slog.StringValue(redactString(s))
		}
		return a
	}
	if logsafe.IsSecretKey(a.Key) || slices.ContainsFunc(groups, logsafe.IsSecretKey) {
		return slog.String(a.Key, logsafe.Redacted)
	}
	inner := groups
	if a.Key != "" {
		inner = append(slices.Clip(groups), a.Key)
	}
	members := a.Value.Group()
	out := make([]any, len(members))
	for i, m := range members {
		out[i] = redactUploadAttr(inner, m)
	}
	return slog.Group(a.Key, out...)
}
