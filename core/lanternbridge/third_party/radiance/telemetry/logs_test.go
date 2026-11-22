package telemetry

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/getlantern/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/config"
)

type memoryLogExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *memoryLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range records {
		e.records = append(e.records, r.Clone())
	}
	return nil
}

func (e *memoryLogExporter) Shutdown(context.Context) error   { return nil }
func (e *memoryLogExporter) ForceFlush(context.Context) error { return nil }

// exportedText returns every string the exporter received, in bodies and
// attribute values at any depth.
func (e *memoryLogExporter) exportedText() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	var walk func(v attribute.Value)
	walk = func(v attribute.Value) {
		switch v.Type() {
		case attribute.STRING:
			out = append(out, v.AsString())
		case attribute.STRINGSLICE:
			out = append(out, v.AsStringSlice()...)
		case attribute.SLICE:
			for _, e := range v.AsSlice() {
				walk(e)
			}
		case attribute.MAP:
			for _, kv := range v.AsMap() {
				out = append(out, string(kv.Key))
				walk(kv.Value)
			}
		}
	}
	for _, r := range e.records {
		walk(r.Body())
		r.WalkAttributes(func(kv attribute.KeyValue) bool {
			out = append(out, string(kv.Key))
			walk(kv.Value)
			return true
		})
	}
	return out
}

func TestUploadedLogsRedactAddresses(t *testing.T) {
	exp := &memoryLogExporter{}
	provider := newLoggerProvider(resource.Empty(), sdklog.NewSimpleProcessor(newRedactingLogExporter(exp)))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	logger := slog.New(newUploadHandler(provider))

	const (
		v4     = "203.0.113.7"
		v6     = "2001:db8::7"
		v4Port = "198.51.100.9:8443"
		v6Port = "[2001:db8::9]:443"
	)
	logger.With("peer", v4Port).WithGroup("conn").Error(
		"dial "+v4+" and "+v6+" via "+v4Port+" and "+v6Port+" failed",
		"ipv4", v4, "ipv6", v6, "hostport", v4Port, "ipv6port", v6Port,
		"many", []string{v4, v6Port},
		slog.Group("nested", "addr", v4Port),
		"by_peer", map[string]int{v4Port: 1, "helper-0123456789ab": 2},
		v6Port, true,
	)
	logger.Info("ungrouped", v4Port, true, "helper-0123456789ab", 1)

	text := exp.exportedText()
	require.NotEmpty(t, text)
	joined := strings.Join(text, "\n")
	for _, addr := range []string{"203.0.113.7", "2001:db8::7", "198.51.100.9", "2001:db8::9", "helper-0123456789ab"} {
		assert.NotContains(t, joined, addr)
	}
	assert.Contains(t, joined, "dial [REDACTED] and [REDACTED] via [REDACTED] and [REDACTED] failed")
}

func TestRedactLogValueRedactsAuthCredentials(t *testing.T) {
	for in, want := range map[string]string{
		"Authorization: Bearer s3cr3t-token":     "Authorization: Bearer [REDACTED]",
		"proxy said basic dXNlcjpwYXNz rejected": "proxy said basic [REDACTED] rejected",
		"Basic Zm9vOmJhcjE= sent":                "Basic [REDACTED] sent",
		"basic auth failed":                      "basic auth failed",
		"Basic authentication failed":            "Basic [REDACTED] failed",
		"Authorization: Basic dTpwYXNz":          "Authorization: Basic [REDACTED]",
		"Bearer 203.0.113.7-privateSuffix":       "Bearer [REDACTED]",
		"Authorization: bearer abcdefgh":         "Authorization: bearer [REDACTED]",
	} {
		assert.Equal(t, want, redactLogValue(attribute.StringValue(in)).AsString())
	}
}

func TestRedactLogValueKeepsNonAddressText(t *testing.T) {
	v := redactLogValue(attribute.StringValue("connected to example.com in 1.5s"))
	assert.Equal(t, "connected to example.com in 1.5s", v.AsString())
	assert.Equal(t, attribute.INT64, redactLogValue(attribute.Int64Value(443)).Type())
}

func TestUpdateLogUploadFollowsSetting(t *testing.T) {
	settings.Reset()
	require.NoError(t, settings.InitSettings(t.TempDir()))
	t.Cleanup(func() {
		require.NoError(t, CloseContext(context.Background()))
		settings.Reset()
	})
	require.NoError(t, settings.Set(settings.TelemetryKey, true))
	require.NoError(t, settings.Set(settings.SendLogsToSigNozKey, true))

	require.NoError(t, UpdateLogUpload())
	assert.Nil(t, logProvider, "upload must not start before telemetry is initialized")

	require.NoError(t, Initialize("device", config.Config{OTEL: common.OTEL{Endpoint: "127.0.0.1:1"}}, false))
	assert.NotNil(t, logProvider)

	require.NoError(t, settings.Set(settings.SendLogsToSigNozKey, false))
	require.NoError(t, UpdateLogUpload())
	assert.Nil(t, logProvider)

	require.NoError(t, settings.Set(settings.SendLogsToSigNozKey, true))
	require.NoError(t, UpdateLogUpload())
	assert.NotNil(t, logProvider)

	require.NoError(t, settings.Set(settings.TelemetryKey, false))
	require.NoError(t, UpdateLogUpload())
	assert.Nil(t, logProvider, "upload must stop when telemetry consent is withdrawn")
	require.NoError(t, settings.Set(settings.TelemetryKey, true))
	require.NoError(t, UpdateLogUpload())
	assert.NotNil(t, logProvider)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, CloseContext(canceled))
	assert.Nil(t, logProvider)
	assert.Nil(t, logTarget)
}
