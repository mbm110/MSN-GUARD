// Package telemetry provides OpenTelemetry setup for radiance
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/getlantern/common"
	"github.com/getlantern/osversion"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	metricNoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	traceNoop "go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/credentials"

	semconv "github.com/getlantern/semconv"

	rcommon "github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/config"
)

var (
	initMutex    sync.Mutex
	shutdownOTEL func(context.Context) error
)

type Attributes struct {
	App        string
	AppVersion string
	// BuildCommit and BuildTime identify the exact build, which AppVersion doesn't:
	// every beta of a release shares its version.
	BuildCommit    string
	BuildTime      string
	DeviceID       string
	GeoCountry     string
	GoVersion      string
	LocaleLanguage string
	LocaleCountry  string
	Platform       string
	OSName         string
	OSArch         string
	OSVersion      string
	Timezone       string
	Pro            bool
}

func Initialize(deviceID string, configResponse config.Config, pro bool) error {
	initMutex.Lock()
	defer initMutex.Unlock()

	if configResponse.OTEL.Endpoint == "" {
		slog.Debug("No otel endpoint configured, skipping OpenTelemetry initialization")
		return nil
	}

	if shutdownOTEL != nil {
		slog.Info("Shutting down existing OpenTelemetry SDK")
		if err := shutdownOTEL(context.Background()); err != nil {
			slog.Error("Failed to shutdown OpenTelemetry SDK", "error", err)
			return fmt.Errorf("failed to shutdown OpenTelemetry SDK: %w", err)
		}
		shutdownOTEL = nil
	}
	setErrorHandler()
	logTarget = nil
	if err := stopLogUploadLocked(); err != nil {
		slog.Error("Failed to stop log upload", "error", err)
	}

	attrs := Attributes{
		App:         "radiance",
		DeviceID:    deviceID,
		AppVersion:  rcommon.GetVersion(),
		BuildCommit: rcommon.Commit,
		BuildTime:   rcommon.BuildTime,
		Platform:    rcommon.Platform,
		GoVersion:   runtime.Version(),
		OSName:      runtime.GOOS,
		OSArch:      runtime.GOARCH,
		GeoCountry:  configResponse.Country,
		Pro:         pro,
	}
	if osStr, err := osversion.GetHumanReadable(); err == nil {
		attrs.OSVersion = osStr
	}

	shutdown, err := setupOTelSDK(context.Background(), attrs, configResponse)
	if err != nil {
		slog.Error("Failed to start OpenTelemetry SDK", "error", err)
		return fmt.Errorf("failed to start OpenTelemetry SDK: %w", err)
	}

	shutdownOTEL = shutdown
	logTarget = &logUploadTarget{attrs: attrs, cfg: configResponse.OTEL}
	if err := applyLogUploadLocked(); err != nil {
		slog.Error("Failed to start log upload", "error", err)
	}
	return nil
}

func Close() error {
	return CloseContext(context.Background())
}

func CloseContext(ctx context.Context) error {
	initMutex.Lock()
	defer initMutex.Unlock()

	var errs error

	if shutdownOTEL != nil {
		slog.Info("Shutting down existing OpenTelemetry SDK")
		if err := shutdownOTEL(ctx); err != nil {
			slog.Error("Failed to shutdown OpenTelemetry SDK", "error", err)
			errs = errors.Join(errs, fmt.Errorf("failed to shutdown OpenTelemetry SDK: %w", err))
		}
		shutdownOTEL = nil
	}
	logTarget = nil
	if err := stopLogUploadLocked(); err != nil {
		errs = errors.Join(errs, err)
	}
	otel.SetTracerProvider(traceNoop.NewTracerProvider())
	otel.SetMeterProvider(metricNoop.NewMeterProvider())
	return errs
}

func buildResources(serviceName string, a Attributes) []attribute.KeyValue {
	e := "prod"
	if v := env.GetString(env.ENV); v != "" {
		e = v
	}
	return []attribute.KeyValue{
		semconv.ServiceNameKey.String(serviceName),
		semconv.ServiceVersionKey.String(a.AppVersion),
		semconv.VCSRefHeadRevisionKey.String(a.BuildCommit),
		semconv.BuildTimeKey.String(a.BuildTime),
		semconv.DeploymentEnvironmentNameKey.String(e),
		semconv.OSNameKey.String(a.OSName),
		semconv.OSVersionKey.String(a.OSVersion),
		semconv.HostArchKey.String(a.OSArch),
		semconv.GeoCountryISOCodeKey.String(a.GeoCountry),
		semconv.ClientDeviceIDKey.String(a.DeviceID),
		semconv.ClientPlatformKey.String(a.Platform),
		semconv.ClientIsProKey.Bool(a.Pro),
		attribute.String("library.language", "go"),
		attribute.String("library.language.version", a.GoVersion),
		attribute.String("locale.language", a.LocaleLanguage),
		attribute.String("locale.country", a.LocaleCountry),
		attribute.String("timezone", a.Timezone),
	}
}

// setupOTelSDK bootstraps the OpenTelemetry pipeline.
// If it does not return an error, make sure to call shutdown for proper cleanup.
func setupOTelSDK(ctx context.Context, attributes Attributes, cfg config.Config) (func(context.Context) error, error) {
	if cfg.Features == nil {
		cfg.Features = make(map[string]bool)
	}
	val, ok := cfg.Features[common.TRACES]
	tracesEnabled := ok && val
	val, ok = cfg.Features[common.METRICS]
	metricsEnabled := ok && val
	if !tracesEnabled && !metricsEnabled {
		// No need to initialize anything if all are disabled.
		return func(_ context.Context) error { return nil }, nil
	}
	var shutdownFuncs []func(context.Context) error
	var err error
	shutdown := func(ctx context.Context) error {
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}
	serviceName := "radiance"
	res, err := resource.New(ctx,
		resource.WithAttributes(
			buildResources(serviceName, attributes)...,
		),
	)
	if err != nil {
		return shutdown, fmt.Errorf("failed to create resource: %w", err)
	}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if tracesEnabled {
		shutdownFunc, err := initTracer(ctx, res, cfg.OTEL)
		if err != nil {
			return shutdown, fmt.Errorf("failed to initialize tracer: %w", err)
		}
		shutdownFuncs = append(shutdownFuncs, shutdownFunc)
		slog.Info("OpenTelemetry tracer initialized")
	}

	if metricsEnabled {
		// Initialize the meter provider with the same gRPC connection.
		// This is useful to avoid creating multiple connections to the same endpoint.
		mp, err := initMeterProvider(ctx, res, cfg.OTEL)
		if err != nil {
			return shutdown, fmt.Errorf("failed to initialize meter provider: %w", err)
		}
		shutdownFuncs = append(shutdownFuncs, mp)
	}

	return shutdown, nil
}

// NewTracerProvider builds a tracer provider reporting under serviceName to
// the collector in cfg, without installing it as the global one; the caller
// shuts it down. Programs embedding radiance whose own spans outlive the
// backend's telemetry, which [Close] stops, use it.
func NewTracerProvider(ctx context.Context, serviceName, deviceID string, cfg config.Config) (*sdktrace.TracerProvider, error) {
	attrs := Attributes{
		App:         serviceName,
		DeviceID:    deviceID,
		AppVersion:  rcommon.GetVersion(),
		BuildCommit: rcommon.Commit,
		BuildTime:   rcommon.BuildTime,
		Platform:    rcommon.Platform,
		GoVersion:   runtime.Version(),
		OSName:      runtime.GOOS,
		OSArch:      runtime.GOARCH,
		GeoCountry:  cfg.Country,
	}
	if osStr, err := osversion.GetHumanReadable(); err == nil {
		attrs.OSVersion = osStr
	}
	res, err := resource.New(ctx, resource.WithAttributes(buildResources(serviceName, attrs)...))
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}
	tracerProvider, _, err := newTracerProvider(ctx, res, cfg.OTEL)
	return tracerProvider, err
}

// newTracerProvider is the exporter and provider both Initialize and
// NewTracerProvider build; shutting the provider down also stops the
// exporter.
func newTracerProvider(ctx context.Context, res *resource.Resource, cfg common.OTEL) (*sdktrace.TracerProvider, *otlptrace.Exporter, error) {
	exporter, err := otlptrace.New(
		ctx,
		otlptracegrpc.NewClient(
			otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")),
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
			otlptracegrpc.WithHeaders(cfg.Headers),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create exporter: %w", err)
	}
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.TracesSampleRate))),
		sdktrace.WithBatcher(newRedactingExporter(exporter)),
		sdktrace.WithResource(res),
	)
	return tracerProvider, exporter, nil
}

func initTracer(ctx context.Context, res *resource.Resource, cfg common.OTEL) (func(context.Context) error, error) {
	tracerProvider, exporter, err := newTracerProvider(ctx, res, cfg)
	if err != nil {
		return nil, err
	}

	otel.SetTracerProvider(tracerProvider)
	return func(ctx context.Context) error {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown tracer provider: %w", err)
		}
		if err := exporter.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown exporter: %w", err)
		}
		return nil
	}, nil
}

// Initializes an OTLP exporter, and configures the corresponding meter provider.
func initMeterProvider(ctx context.Context, res *resource.Resource, cfg common.OTEL) (func(context.Context) error, error) {
	metricExporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")),
		otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
		otlpmetricgrpc.WithHeaders(cfg.Headers),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics exporter: %w", err)
	}

	opts := []sdkmetric.Option{
		sdkmetric.WithResource(res),
	}
	if cfg.MetricsInterval > 0 {
		opts = append(opts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter,
			sdkmetric.WithInterval(time.Duration(cfg.MetricsInterval)*time.Second))))
	} else {
		opts = append(opts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)))
	}
	// Metric attributes are exported as recorded: unlike spans and logs there
	// is no redacting layer here. Any attribute built from an outbound tag (see
	// newConnAttributeSet) must go through redact.Tag, since helper-
	// tags are client-side pseudonyms that must not leave the client.
	meterProvider := sdkmetric.NewMeterProvider(
		opts...,
	)
	otel.SetMeterProvider(meterProvider)

	return meterProvider.Shutdown, nil
}
