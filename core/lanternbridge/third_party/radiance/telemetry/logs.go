package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/getlantern/common"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc/credentials"

	"github.com/getlantern/radiance/common/settings"
	rlog "github.com/getlantern/radiance/log"
)

// logShutdownTimeout bounds the final flush when log upload stops, which can
// run on the settings IPC path.
const logShutdownTimeout = 5 * time.Second

// Guarded by initMutex.
var (
	// logTarget is where logs go while upload is on: set while telemetry is
	// initialized with an endpoint, nil otherwise.
	logTarget   *logUploadTarget
	logProvider *sdklog.LoggerProvider
)

type logUploadTarget struct {
	attrs Attributes
	cfg   common.OTEL
}

var setErrorHandlerOnce sync.Once

// setErrorHandler logs OpenTelemetry's errors, such as failed exports, without
// uploading them. otel's default handler writes them to the standard logger,
// which slog.SetDefault routes into the log handler, so a failing log export
// would upload its own failure.
func setErrorHandler() {
	setErrorHandlerOnce.Do(func() {
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			slog.Log(rlog.WithoutUpload(context.Background()), slog.LevelWarn, "OpenTelemetry error", "error", err)
		}))
	})
}

// UpdateLogUpload starts or stops uploading the log to match
// [settings.SendLogsToSigNozKey]. Upload runs only while telemetry is
// initialized with an endpoint and [settings.TelemetryKey] is true.
func UpdateLogUpload() error {
	initMutex.Lock()
	defer initMutex.Unlock()
	return applyLogUploadLocked()
}

func applyLogUploadLocked() error {
	if logTarget == nil || !settings.GetBool(settings.TelemetryKey) || !settings.GetBool(settings.SendLogsToSigNozKey) {
		return stopLogUploadLocked()
	}
	if logProvider != nil {
		return nil
	}
	ctx := context.Background()
	res, err := resource.New(ctx, resource.WithAttributes(buildResources("radiance", logTarget.attrs)...))
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}
	exporter, err := otlploggrpc.New(ctx,
		otlploggrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")),
		otlploggrpc.WithEndpoint(logTarget.cfg.Endpoint),
		otlploggrpc.WithHeaders(logTarget.cfg.Headers),
	)
	if err != nil {
		return fmt.Errorf("failed to create log exporter: %w", err)
	}
	logProvider = newLoggerProvider(res, sdklog.NewBatchProcessor(newRedactingLogExporter(exporter)))
	rlog.SetUploadHandler(newUploadHandler(logProvider))
	slog.Info("Uploading logs to the telemetry collector")
	return nil
}

func newLoggerProvider(res *resource.Resource, p sdklog.Processor) *sdklog.LoggerProvider {
	return sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(p))
}

func newUploadHandler(p *sdklog.LoggerProvider) slog.Handler {
	return otelslog.NewHandler("radiance", otelslog.WithLoggerProvider(p), otelslog.WithSource(true))
}

func stopLogUploadLocked() error {
	if logProvider == nil {
		return nil
	}
	rlog.SetUploadHandler(nil)
	// Not the caller's context: the SDK never closes the batch worker and
	// exporter if Shutdown starts on a done one.
	ctx, cancel := context.WithTimeout(context.Background(), logShutdownTimeout)
	defer cancel()
	err := logProvider.Shutdown(ctx)
	logProvider = nil
	slog.Info("Stopped uploading logs to the telemetry collector")
	if err != nil {
		return fmt.Errorf("failed to shutdown logger provider: %w", err)
	}
	return nil
}
