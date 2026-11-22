package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/getlantern/semconv"

	"github.com/getlantern/radiance/backend"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/traces"
	"github.com/getlantern/radiance/vpn"
)

const tracerName = "github.com/getlantern/radiance/tester"

func run(ctx context.Context) error {
	dir, target := os.Getenv("DATA"), os.Getenv("TARGET_URL")
	if dir == "" {
		return errors.New("DATA is required")
	}
	for _, name := range []string{"success", "fetch.json", "connection.txt", "output.txt", "timing.txt"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	seconds := 20
	if target == "" {
		return errors.New("TARGET_URL is required")
	}
	if value := os.Getenv("FETCH_TIMEOUT_SECONDS"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 || n > 600 {
			return errors.New("FETCH_TIMEOUT_SECONDS must be between 1 and 600")
		}
		seconds = n
	}
	timeout := time.Duration(seconds) * time.Second
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(semconv.URLFullKey.String(spanURL(target)), semconv.TesterFetchTimeoutSecondsKey.Int(seconds))
	if os.Getenv("DIRECT") == "true" {
		span.SetAttributes(semconv.TesterModeKey.String("direct"))
		return fetch(ctx, target, "", dir, timeout)
	}
	if env := os.Getenv("RADIANCE_ENV"); env != "staging" && env != "production" {
		return errors.New("RADIANCE_ENV must explicitly select staging or production")
	}
	sticky := os.Getenv("STICKY") == "true"
	tag := os.Getenv("TARGET_TAG")
	span.SetAttributes(semconv.TesterModeKey.String("client"), semconv.TesterStickyKey.Bool(sticky), semconv.TesterTargetTagKey.String(tag))
	clientDir, err := os.MkdirTemp(dir, "client-")
	if err != nil {
		return err
	}
	for key, value := range map[string]string{
		"RADIANCE_DATA_PATH": clientDir, "RADIANCE_LOG_PATH": clientDir,
		"RADIANCE_DISABLE_FETCH_CONFIG": strconv.FormatBool(sticky),
	} {
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	if sticky {
		if tag == "" {
			return errors.New("TARGET_TAG is required with STICKY")
		}
		data, err := os.ReadFile(filepath.Join(dir, "config.json"))
		if err != nil {
			return fmt.Errorf("sticky config: %w", err)
		}
		if err := os.WriteFile(filepath.Join(clientDir, "config.json"), data, fileperm.Private); err != nil {
			return err
		}
	} else {
		tag = vpn.AutoSelectTag
	}
	uid, err := strconv.ParseInt(os.Getenv("USER_ID"), 10, 64)
	if err != nil || uid <= 0 || os.Getenv("TOKEN") == "" || os.Getenv("DEVICE_ID") == "" {
		return errors.New("USER_ID, TOKEN and DEVICE_ID are required")
	}
	be, err := backend.NewLocalBackend(ctx, backend.Options{DataDir: clientDir, LogDir: clientDir, Locale: "en-US"})
	if err != nil {
		return fmt.Errorf("create radiance: %w", err)
	}
	defer be.Close()
	settings.Set(settings.UserIDKey, uid)
	settings.Set(settings.TokenKey, os.Getenv("TOKEN"))
	settings.Set(settings.DevicesKey, []settings.Device{{ID: os.Getenv("DEVICE_ID"), Name: "pinger"}})
	settings.Set(settings.ConfigFetchDisabledKey, sticky)
	be.Start()
	if sticky {
		if _, found := be.GetServerByTag(tag); !found {
			return errors.New("assigned target is absent from sticky configuration")
		}
	}
	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := os.WriteFile(filepath.Join(dir, "connection.txt"), []byte("connecting"), fileperm.Private); err != nil {
		return err
	}
	if err := connect(connectCtx, be, tag); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "connection.txt"), []byte("connected"), fileperm.Private); err != nil {
		return err
	}
	defer be.DisconnectVPN()
	proxy := os.Getenv("RADIANCE_SOCKS_ADDRESS")
	if proxy == "" {
		proxy = "127.0.0.1:1080"
	}
	return fetch(ctx, target, proxy, dir, timeout)
}

// connect brings up the assigned target as a span of its own, so the time
// the tunnel took is read apart from the fetch that followed. Child spans
// come from the run span's provider, not the global one, which the backend
// replaces on Close.
func connect(ctx context.Context, be *backend.LocalBackend, tag string) error {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer(tracerName).Start(ctx, "tester.connect")
	defer span.End()
	if err := be.ConnectVPN(ctx, tag); err != nil {
		err = fmt.Errorf("connect assigned target: %w", err)
		span.SetStatus(codes.Error, err.Error())
		return traces.RecordError(ctx, err)
	}
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	seconds, _ := strconv.Atoi(os.Getenv("FETCH_TIMEOUT_SECONDS"))
	if seconds <= 0 || seconds > 600 {
		seconds = 20
	}
	// The pinger removes the container phaseGrace+flushGrace after this
	// deadline.
	ctx, deadline := context.WithTimeout(ctx, time.Duration(2*seconds+8)*time.Second)
	defer deadline()
	flush, err := startTelemetry(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "telemetry:", err)
		flush = func(context.Context) error { return nil }
	}
	// The tracer is taken once: the backend's Close replaces the global
	// provider with a no-op one, and the spans started here must outlive it.
	tracer := otel.GetTracerProvider().Tracer(tracerName)
	ctx, span := tracer.Start(parentContext(ctx), "tester.run",
		trace.WithAttributes(semconv.TesterRunIDKey.String(os.Getenv("RUN_ID"))))
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		runErr = ctx.Err()
		// The phase in flight ends its span when run returns; a tunnel
		// bring-up detached from ctx may not, so the wait is bounded.
		select {
		case <-done:
		case <-time.After(phaseGrace):
		}
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, runErr)
		span.SetStatus(codes.Error, runErr.Error())
		span.RecordError(runErr)
	}
	span.End()
	flushCtx, cancelFlush := context.WithTimeout(context.WithoutCancel(ctx), flushGrace)
	defer cancelFlush()
	if err := flush(flushCtx); err != nil {
		fmt.Fprintln(os.Stderr, "telemetry flush:", err)
	}
	if runErr != nil {
		os.Exit(1)
	}
}
