package log

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingHandler struct {
	mu      *sync.Mutex
	records *[]slog.Record
	attrs   []slog.Attr
	groups  []string
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{mu: new(sync.Mutex), records: new([]slog.Record)}
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	r = r.Clone()
	r.AddAttrs(h.attrs...)
	*h.records = append(*h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &c
}

func (h *recordingHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.groups = append(append([]string(nil), h.groups...), name)
	return &c
}

func (h *recordingHandler) got() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]slog.Record(nil), *h.records...)
}

func recordAttrs(r slog.Record) map[string]slog.Value {
	out := map[string]slog.Value{}
	r.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value
		return true
	})
	return out
}

func TestTeeUploadsOnlyWhileHandlerSet(t *testing.T) {
	t.Cleanup(func() { SetUploadHandler(nil) })
	var local bytes.Buffer
	logger := slog.New(newTeeHandler(slog.NewTextHandler(&local, nil)))
	sink := newRecordingHandler()

	logger.Info("before")
	SetUploadHandler(sink)
	logger.Info("during")
	logger.Log(WithoutUpload(context.Background()), slog.LevelInfo, "suppressed")
	SetUploadHandler(nil)
	logger.Info("after")

	got := sink.got()
	require.Len(t, got, 1)
	assert.Equal(t, "during", got[0].Message)
	for _, msg := range []string{"before", "during", "suppressed", "after"} {
		assert.Contains(t, local.String(), msg)
	}
}

func TestRootHandlerUploads(t *testing.T) {
	t.Cleanup(func() { SetUploadHandler(nil) })
	var local bytes.Buffer
	logger := slog.New(newRootHandler(&local, slog.LevelInfo))
	sink := newRecordingHandler()
	SetUploadHandler(sink)

	logger.Info("uploaded")

	got := sink.got()
	require.Len(t, got, 1)
	assert.Equal(t, "uploaded", got[0].Message)
	assert.Contains(t, local.String(), "uploaded")
}

type derefError struct{ msg string }

func (e *derefError) Error() string { return e.msg }

func TestUploadSurvivesNilPointerError(t *testing.T) {
	t.Cleanup(func() { SetUploadHandler(nil) })
	logger := slog.New(newRootHandler(&bytes.Buffer{}, slog.LevelInfo))
	sink := newRecordingHandler()
	SetUploadHandler(sink)

	var nilErr *derefError
	require.NotPanics(t, func() { logger.Info("failed", "error", nilErr) })
	logger.Info("failed", "error", &derefError{msg: "dial https://example.com/?key=abc"})

	got := sink.got()
	require.Len(t, got, 2)
	nilAttr := recordAttrs(got[0])["error"]
	assert.Equal(t, slog.KindString, nilAttr.Kind())
	assert.Equal(t, "<nil>", nilAttr.String())
	assert.Equal(t, "dial https://example.com/", recordAttrs(got[1])["error"].String())
}

func TestTeeRespectsLocalLevel(t *testing.T) {
	t.Cleanup(func() { SetUploadHandler(nil) })
	logger := slog.New(newTeeHandler(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})))
	sink := newRecordingHandler()
	SetUploadHandler(sink)

	logger.Info("filtered")
	logger.Warn("kept")

	got := sink.got()
	require.Len(t, got, 1)
	assert.Equal(t, "kept", got[0].Message)
}

func TestTeeRedactsCredentialsAndReplaysWith(t *testing.T) {
	t.Cleanup(func() { SetUploadHandler(nil) })
	var local bytes.Buffer
	logger := slog.New(newTeeHandler(slog.NewTextHandler(&local, nil)))
	sink := newRecordingHandler()

	// Attrs bound before upload starts still reach the upload handler.
	logger = logger.With("token", "secret-token-value", "component", "vpn")
	SetUploadHandler(sink)
	logger.Info("connect https://example.com/path?auth=abc", "password", "hunter2", "server", "s1")

	got := sink.got()
	require.Len(t, got, 1)
	assert.Equal(t, "connect https://example.com/path", got[0].Message)
	attrs := recordAttrs(got[0])
	assert.Equal(t, "vpn", attrs["component"].String())
	assert.Equal(t, "s1", attrs["server"].String())
	assert.NotContains(t, attrs["token"].String(), "secret-token-value")
	assert.NotContains(t, attrs["password"].String(), "hunter2")
}
